from .base import *  # noqa: F403

DEBUG = True
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
# __Host- requires HTTPS; dev runs over HTTP, so use the unprefixed names.
SESSION_COOKIE_NAME = "sessionid"
CSRF_COOKIE_NAME = "csrftoken"
ALLOWED_HOSTS = ["*"]
