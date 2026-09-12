from app.checks.http import HttpTrace, ResponseSnapshot
from app.presentation import build_redirect_hops


def snapshot(url: str, status: int = 200) -> ResponseSnapshot:
    return ResponseSnapshot(
        url=url,
        address="93.184.216.34",
        status=status,
        reason="OK",
        headers={},
    )


def test_build_redirect_hops_marks_scheme_upgrade():
    trace = HttpTrace(
        responses=[
            snapshot("http://example.com/", 301),
            snapshot("https://example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "SCHEME UPGRADE"
    ]
    assert hops[0].changes[0].kind == "upgrade"
    assert hops[1].changes == ()


def test_build_redirect_hops_marks_hostname_change():
    trace = HttpTrace(
        responses=[
            snapshot("https://example.com/", 302),
            snapshot("https://www.example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "HOSTNAME CHANGE"
    ]
    assert hops[0].changes[0].kind == "hostname"


def test_build_redirect_hops_can_mark_multiple_changes():
    trace = HttpTrace(
        responses=[
            snapshot("http://example.com/", 301),
            snapshot("https://www.example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "SCHEME UPGRADE",
        "HOSTNAME CHANGE",
    ]


def test_build_redirect_hops_marks_scheme_downgrade():
    trace = HttpTrace(
        responses=[
            snapshot("https://example.com/", 302),
            snapshot("http://example.com/"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert [change.label for change in hops[0].changes] == [
        "SCHEME DOWNGRADE"
    ]
    assert hops[0].changes[0].kind == "downgrade"


def test_build_redirect_hops_leaves_same_origin_unannotated():
    trace = HttpTrace(
        responses=[
            snapshot("https://example.com/start", 302),
            snapshot("https://example.com/final"),
        ]
    )

    hops = build_redirect_hops(trace)

    assert hops[0].changes == ()
    assert hops[1].changes == ()
