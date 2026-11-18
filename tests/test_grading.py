"""End-to-end grading through /scan: header VALUES now affect the score."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.scanner import SECURITY_HEADERS
from tests.fakenet import SECURE_HEADERS

client = TestClient(app)


def scan_with(net, headers: dict[str, str]) -> dict:
    net.routes["public.example"] = lambda req: httpx.Response(200, headers=headers)
    resp = client.get("/scan", params={"url": "https://public.example"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def by_name(body: dict) -> dict[str, dict]:
    return {h["name"]: h for h in body["headers"]}


def test_secure_defaults_still_grade_a_with_full_score(net):
    body = scan_with(net, SECURE_HEADERS)
    assert body["grade"] == "A"
    assert body["score"] == 100
    for h in body["headers"]:
        assert h["issues"] == []
        assert h["points"] == SECURITY_HEADERS[h["name"]][0]


def test_score_is_the_sum_of_per_header_points(net):
    body = scan_with(net, {**SECURE_HEADERS, "content-security-policy": "default-src *"})
    assert body["score"] == sum(h["points"] for h in body["headers"])


def test_hsts_max_age_zero_earns_no_hsts_points(net):
    body = scan_with(
        net, {**SECURE_HEADERS, "strict-transport-security": "max-age=0"}
    )
    hsts = by_name(body)["strict-transport-security"]
    assert hsts["present"] is True
    assert hsts["points"] == 0
    assert any("max-age=0" in i for i in hsts["issues"])
    assert body["score"] == 75
    assert body["grade"] == "B"


def test_weak_csp_lowers_the_grade_even_though_it_is_present(net):
    body = scan_with(
        net,
        {
            **SECURE_HEADERS,
            "content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
        },
    )
    csp = by_name(body)["content-security-policy"]
    assert csp["present"] is True
    assert 0 <= csp["points"] < 25
    assert csp["issues"]
    assert body["grade"] != "A"


def test_missing_header_has_zero_points_and_advice(net):
    headers = {k: v for k, v in SECURE_HEADERS.items() if k != "content-security-policy"}
    csp = by_name(scan_with(net, headers))["content-security-policy"]
    assert csp["present"] is False
    assert csp["points"] == 0
    assert csp["advice"]


def test_every_header_is_now_value_graded(net):
    weak = {
        **SECURE_HEADERS,
        "x-frame-options": "whatever",
        "x-content-type-options": "sniff",
        "referrer-policy": "unsafe-url",
        "permissions-policy": "fullscreen=*",
    }
    headers = by_name(scan_with(net, weak))
    for name in weak.keys() - {"strict-transport-security", "content-security-policy"}:
        h = headers[name]
        assert h["present"] is True
        assert h["points"] < SECURITY_HEADERS[name][0], name
        assert h["issues"], name


def test_frame_ancestors_covers_a_missing_xfo(net):
    headers = {k: v for k, v in SECURE_HEADERS.items() if k != "x-frame-options"}
    headers["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'"
    body = scan_with(net, headers)
    xfo = by_name(body)["x-frame-options"]
    assert xfo["present"] is False
    assert xfo["points"] == 15
    assert "frame-ancestors" in xfo["advice"]
    assert body["score"] == 100
