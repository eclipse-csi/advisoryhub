"""Request-id middleware.

Honors an upstream ``X-Request-ID`` header (so a load balancer or API
gateway can stitch its trace id together with ours) and otherwise mints
a fresh UUID. The id is:

* attached to ``request.request_id``,
* set in a :class:`ContextVar` so :class:`common.logging.JSONFormatter`
  can include it on every log record automatically,
* echoed back to the client in the response's ``X-Request-ID`` header.
"""

from __future__ import annotations

import uuid

from common.logging import reset_request_id, set_request_id


class RequestIDMiddleware:
    HEADER = "HTTP_X_REQUEST_ID"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        rid = request.META.get(self.HEADER) or uuid.uuid4().hex
        request.request_id = rid
        token = set_request_id(rid)
        try:
            response = self.get_response(request)
        finally:
            reset_request_id(token)
        response["X-Request-ID"] = rid
        return response
