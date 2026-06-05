"""Unit tests for the uniform toast-feedback substrate.

Covers :class:`common.middleware.HtmxMessagesMiddleware` (the HX-Trigger
serialisation + the full-reload skip), the ``toast_payload`` template filter
that feeds the page-load island, and the middleware's placement in the
configured stack.
"""

from __future__ import annotations

import json

from django.contrib import messages
from django.contrib.messages import constants
from django.contrib.messages.storage.base import Message
from django.contrib.messages.storage.cookie import CookieStorage
from django.http import HttpResponse
from django.shortcuts import redirect

from common.middleware import HtmxMessagesMiddleware
from common.templatetags.advisoryhub_tags import toast_payload


def _request(rf, *, htmx=True):
    request = rf.post("/x")
    request.htmx = htmx  # set by django_htmx.HtmxMiddleware in the real stack
    request._messages = CookieStorage(request)  # DB-free message storage
    return request


def _mw(view):
    return HtmxMessagesMiddleware(view)


# --------------------------------------------------------------- middleware


def test_serialises_messages_on_htmx_swap(rf):
    request = _request(rf)
    messages.success(request, "Saved.")
    messages.error(request, "Nope.")

    response = _mw(lambda r: HttpResponse("ok"))(request)

    data = json.loads(response["HX-Trigger"])
    assert data["advisoryhub:messages"]["messages"] == [
        {"level": "success", "message": "Saved."},
        {"level": "error", "message": "Nope."},
    ]


def test_no_header_when_no_messages(rf):
    request = _request(rf)
    response = _mw(lambda r: HttpResponse("ok"))(request)
    assert "HX-Trigger" not in response


def test_skips_when_not_htmx(rf):
    request = _request(rf, htmx=False)
    messages.success(request, "Saved.")
    response = _mw(lambda r: HttpResponse("ok"))(request)
    # Full-page responses are handled by the #toast-data island instead.
    assert "HX-Trigger" not in response


def test_skips_and_preserves_on_redirect(rf):
    request = _request(rf)
    messages.success(request, "Saved.")
    response = _mw(lambda r: redirect("/elsewhere"))(request)
    assert "HX-Trigger" not in response
    # Not consumed — htmx follows the redirect and the message surfaces there.
    assert [m.message for m in request._messages] == ["Saved."]


def test_skips_and_preserves_on_hx_refresh(rf):
    request = _request(rf)
    messages.success(request, "Flagged for admin routing.")

    def view(_request):
        resp = HttpResponse(status=204)
        resp["HX-Refresh"] = "true"
        return resp

    response = _mw(view)(request)
    assert "HX-Trigger" not in response
    # Survives in storage so the reloaded page's island renders it.
    assert [m.message for m in request._messages] == ["Flagged for admin routing."]


def test_merges_with_existing_hx_trigger(rf):
    request = _request(rf)
    messages.success(request, "Saved.")

    def view(_request):
        resp = HttpResponse("ok")
        resp["HX-Trigger"] = json.dumps({"other:event": {"n": 1}})
        return resp

    response = _mw(view)(request)
    data = json.loads(response["HX-Trigger"])
    assert data["other:event"] == {"n": 1}
    assert data["advisoryhub:messages"]["messages"][0]["message"] == "Saved."


# --------------------------------------------------------------- template tag


def test_toast_payload_maps_level_and_text():
    payload = toast_payload(
        [Message(constants.SUCCESS, "Hi"), Message(constants.WARNING, "Careful")]
    )
    assert payload == [
        {"level": "success", "message": "Hi"},
        {"level": "warning", "message": "Careful"},
    ]


# --------------------------------------------------------------- placement


def test_middleware_registered_after_message_and_htmx(settings):
    mw = settings.MIDDLEWARE
    assert "common.middleware.HtmxMessagesMiddleware" in mw
    here = mw.index("common.middleware.HtmxMessagesMiddleware")
    # Below MessageMiddleware so its response phase consumes the storage first
    # (no double-show); below HtmxMiddleware so request.htmx is already set.
    assert here > mw.index("django.contrib.messages.middleware.MessageMiddleware")
    assert here > mw.index("django_htmx.middleware.HtmxMiddleware")
