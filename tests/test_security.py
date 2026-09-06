import socket

import pytest

from app.security import (
    TargetValidationError,
    normalize_hostname,
    validate_target,
)


def test_normalize_hostname():
    assert normalize_hostname(" Example.COM. ") == "example.com"


@pytest.mark.parametrize(
    "target",
    [
        "",
        "localhost",
        "127.0.0.1",
        "https://example.com",
        "example.com:443",
        "example.com/path",
    ],
)
def test_normalize_hostname_rejects_invalid_targets(target):
    with pytest.raises(TargetValidationError):
        normalize_hostname(target)


def test_validate_target_accepts_public_address(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    hostname, addresses = validate_target("example.com")

    assert hostname == "example.com"
    assert addresses == ["93.184.216.34"]


def test_validate_target_rejects_private_address(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.168.50.6", 443),
            )
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(
        TargetValidationError,
        match="non-public address",
    ):
        validate_target("internal.example.com")
