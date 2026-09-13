import socket

import pytest

from app.security import (
    TargetValidationError,
    normalize_hostname,
    resolve_target,
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


def test_resolve_target_ipv4_only(monkeypatch):
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

    target = resolve_target("example.com")

    assert target.hostname == "example.com"
    assert target.ipv4_addresses == ("93.184.216.34",)
    assert target.ipv6_addresses == ()


def test_resolve_target_ipv6_only(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0),
            )
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    target = resolve_target("example.com")

    assert target.hostname == "example.com"
    assert target.ipv4_addresses == ()
    assert target.ipv6_addresses == (
        "2606:2800:220:1:248:1893:25c8:1946",
    )


def test_resolve_target_dual_stack(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            ),
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    target = resolve_target("example.com")

    assert target.hostname == "example.com"
    assert target.ipv4_addresses == ("93.184.216.34",)
    assert target.ipv6_addresses == (
        "2606:2800:220:1:248:1893:25c8:1946",
    )


def test_resolve_target_rejects_dual_stack_target_with_private_address(
    monkeypatch,
):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("fd00::1", 443, 0, 0),
            ),
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
        resolve_target("example.com")