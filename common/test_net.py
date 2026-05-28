"""Tests for :func:`common.net.client_ip` trusted-proxy resolution."""

from __future__ import annotations

from django.test import RequestFactory, override_settings

from common.net import client_ip

_rf = RequestFactory()


def _req(xff: str | None = None, remote: str = "10.0.0.1"):
    extra = {"REMOTE_ADDR": remote}
    if xff is not None:
        extra["HTTP_X_FORWARDED_FOR"] = xff
    return _rf.get("/", **extra)


@override_settings(TRUSTED_PROXY_COUNT=0)
def test_count_zero_ignores_xff_entirely():
    # A spoofed XFF must never override the direct peer when no proxy is trusted.
    assert client_ip(_req(xff="1.2.3.4, 5.6.7.8", remote="9.9.9.9")) == "9.9.9.9"


@override_settings(TRUSTED_PROXY_COUNT=1)
def test_count_one_takes_rightmost_entry():
    # Single trusted proxy → the address it observed is the last XFF entry;
    # the prepended "6.6.6.6" is client-supplied and must be ignored.
    assert client_ip(_req(xff="6.6.6.6, 203.0.113.7", remote="10.0.0.1")) == "203.0.113.7"


@override_settings(TRUSTED_PROXY_COUNT=2)
def test_count_two_takes_second_from_right():
    # parts[-2] is what the outermost trusted proxy observed (the real client).
    assert client_ip(_req(xff="6.6.6.6, 203.0.113.7, 198.51.100.2")) == "203.0.113.7"


@override_settings(TRUSTED_PROXY_COUNT=2)
def test_header_shorter_than_chain_falls_back_to_remote_addr():
    assert client_ip(_req(xff="203.0.113.7", remote="172.16.0.5")) == "172.16.0.5"


@override_settings(TRUSTED_PROXY_COUNT=1)
def test_missing_xff_uses_remote_addr():
    assert client_ip(_req(xff=None, remote="172.16.0.5")) == "172.16.0.5"
