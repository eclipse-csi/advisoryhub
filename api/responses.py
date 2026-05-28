"""Common JSON response helpers and decorators."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import wraps

from django.core.exceptions import PermissionDenied
from django.http import (
    HttpRequest,
    HttpResponseNotAllowed,
    JsonResponse,
)


def json_response(payload, status: int = 200) -> JsonResponse:
    return JsonResponse(payload, status=status, json_dumps_params={"sort_keys": True})


def error(code: str, message: str, status: int = 400, **extra) -> JsonResponse:
    body = {"error": code, "message": message}
    body.update(extra)
    return json_response(body, status=status)


def parse_json(request: HttpRequest) -> dict:
    """Parse JSON body or fall back to form-encoded POST data.

    The internal API accepts either Content-Type=application/json or
    standard form-encoded posts so HTMX/htmx-through-fetch and Postman
    both work without extra ceremony.
    """
    if request.content_type == "application/json":
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid json: {exc.msg}") from exc
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data
    return {k: v for k, v in request.POST.items()}


def require_methods_json(methods: list[str]) -> Callable:
    """Like require_http_methods but returns JSON 405 instead of HTML."""

    def deco(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if request.method not in methods:
                return HttpResponseNotAllowed(methods)
            return view(request, *args, **kwargs)

        return wrapper

    return deco


def login_required_json(view):
    """Reject unauthenticated requests with 401 JSON instead of an HTML redirect."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return error("not_authenticated", "Authentication required.", status=401)
        return view(request, *args, **kwargs)

    return wrapper


def map_permission_denied(view):
    """Return 403 JSON when the inner view raises PermissionDenied."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        try:
            return view(request, *args, **kwargs)
        except PermissionDenied as exc:
            return error("forbidden", str(exc) or "Forbidden.", status=403)

    return wrapper
