"""Inbound webhook receiver for the AdvisoryHub GitHub App.

This module owns the *receiving* side: signature verification,
idempotency, and a minimal sync ack. All heavy lifting (mutating
advisories, installation rows) is delegated to :mod:`ghsa.services` via a
Celery task so the endpoint can return a 202 well inside GitHub's
10-second delivery timeout.

Security:

* HMAC-SHA256 of the raw body against ``GITHUB_APP_WEBHOOK_SECRET``, using
  :func:`hmac.compare_digest` — never a plain ``==``.
* The body is parsed *only after* signature verification succeeds.
* Idempotency uses GitHub's ``X-GitHub-Delivery`` id; a unique constraint
  on :class:`ghsa.models.WebhookDelivery` makes replays a 200 no-op.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from audit.models import Action
from audit.services import record

from .models import WebhookDelivery, WebhookDeliveryStatus

logger = logging.getLogger(__name__)


def verify_signature(secret: bytes, signature_header: str | None, body: bytes) -> bool:
    """Constant-time HMAC-SHA256 check against the ``X-Hub-Signature-256`` header.

    GitHub sends the header as ``sha256=<hex>``. An empty/missing header
    or a bad prefix returns False without computing the HMAC; an empty
    secret always returns False (we never accept unsigned webhooks).
    """
    if not secret or not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    received = signature_header[len("sha256=") :]
    return hmac.compare_digest(expected, received)


def _webhook_secret_bytes() -> bytes:
    raw = getattr(settings, "GITHUB_APP_WEBHOOK_SECRET", "") or ""
    return raw.encode("utf-8")


@csrf_exempt
@require_http_methods(["POST"])
def webhook(request: HttpRequest) -> HttpResponse:
    """GitHub webhook entry point.

    Order of operations is important — signature first, parsing second.
    Audit entries are written for both accepted and rejected deliveries
    so a steady stream of rejections is visible to operators.
    """
    secret = _webhook_secret_bytes()
    signature = request.headers.get("X-Hub-Signature-256") or request.META.get(
        "HTTP_X_HUB_SIGNATURE_256"
    )
    body = request.body or b""
    if not verify_signature(secret, signature, body):
        record(
            action=Action.GHSA_WEBHOOK_REJECTED,
            metadata={
                "reason": "bad_signature",
                "delivery_id": request.headers.get("X-GitHub-Delivery", "")[:64],
                "event": request.headers.get("X-GitHub-Event", "")[:64],
            },
        )
        return HttpResponse(status=401)

    event = (request.headers.get("X-GitHub-Event") or "")[:64]
    delivery_id = (request.headers.get("X-GitHub-Delivery") or "")[:64]
    if not event or not delivery_id:
        return JsonResponse({"error": "missing event or delivery headers"}, status=400)

    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        record(
            action=Action.GHSA_WEBHOOK_REJECTED,
            metadata={"reason": "malformed_json", "delivery_id": delivery_id, "event": event},
        )
        return JsonResponse({"error": "malformed JSON"}, status=400)

    action = (payload.get("action") or "")[:64]
    installation_id = ((payload.get("installation") or {}).get("id")) or None
    try:
        with transaction.atomic():
            delivery = WebhookDelivery.objects.create(
                delivery_id=delivery_id,
                event=event,
                action=action,
                installation_id=installation_id,
                status=WebhookDeliveryStatus.RECEIVED,
            )
    except IntegrityError:
        # Replay — GitHub retries on 5xx but also occasionally re-fires
        # the same delivery. Treat as success without re-processing.
        return JsonResponse({"status": "already_processed"}, status=200)

    record(
        action=Action.GHSA_WEBHOOK_RECEIVED,
        metadata={
            "delivery_id": delivery_id,
            "event": event,
            "action": action,
            "installation_id": installation_id,
        },
    )

    # Hand the parsed payload to a Celery task so the response stays fast.
    # We pass it through Celery rather than passing only the pk so the
    # worker doesn't have to re-parse the body (which we deliberately
    # don't persist on the row).
    def _enqueue() -> None:
        try:
            from .tasks import process_webhook

            process_webhook.delay(delivery.pk, payload)
        except Exception:  # pragma: no cover — broker offline
            logger.warning(
                "broker offline; webhook %s left in 'received' for manual retry",
                delivery_id,
            )

    transaction.on_commit(_enqueue)
    return JsonResponse({"status": "accepted", "delivery_id": delivery_id}, status=202)
