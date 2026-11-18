"""Unit tests for value-based header rules (pure functions, no network).

Each rule returns ``(credit, issues)``: credit is the share of the header's
weight it earns (0.0-1.0), issues are human-readable reasons for lost credit.
"""

import pytest

from app.rules import check_csp, check_hsts

# ── HSTS ───────────────────────────────────────────────────────────────────


def test_hsts_strong_gets_full_credit():
    credit, issues = check_hsts("max-age=31536000; includeSubDomains")
    assert credit == 1.0
    assert issues == []


def test_hsts_directives_are_case_insensitive_and_spacing_tolerant():
    credit, _ = check_hsts("  Max-Age=63072000 ;INCLUDESUBDOMAINS; preload")
    assert credit == 1.0


def test_hsts_quoted_max_age_is_accepted():
    # RFC 6797 allows max-age="31536000".
    assert check_hsts('max-age="31536000"; includeSubDomains')[0] == 1.0


def test_hsts_exactly_180_days_is_enough():
    assert check_hsts("max-age=15552000; includeSubDomains")[0] == 1.0


def test_hsts_without_include_subdomains_loses_the_bonus():
    credit, issues = check_hsts("max-age=31536000")
    assert 0 < credit < 1.0
    assert any("includeSubDomains" in i for i in issues)


def test_hsts_short_max_age_is_partial():
    credit, issues = check_hsts("max-age=86400; includeSubDomains")
    assert 0 < credit < check_hsts("max-age=15552000; includeSubDomains")[0]
    assert any("max-age" in i for i in issues)


def test_hsts_max_age_zero_disables_hsts():
    # max-age=0 tells the browser to FORGET the policy: worth nothing,
    # even with includeSubDomains.
    credit, issues = check_hsts("max-age=0; includeSubDomains")
    assert credit == 0.0
    assert any("max-age=0" in i for i in issues)


@pytest.mark.parametrize(
    "value", ["", "includeSubDomains", "max-age=abc", "max-age=-5", "max-age="]
)
def test_hsts_missing_or_invalid_max_age_gets_nothing(value):
    credit, issues = check_hsts(value)
    assert credit == 0.0
    assert issues


# ── CSP ────────────────────────────────────────────────────────────────────


def test_csp_default_src_self_gets_full_credit():
    assert check_csp("default-src 'self'") == (1.0, [])


def test_csp_strict_policy_gets_full_credit():
    value = "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'"
    assert check_csp(value) == (1.0, [])


@pytest.mark.parametrize("keyword", ["'unsafe-inline'", "'unsafe-eval'"])
def test_csp_unsafe_keywords_are_penalized(keyword):
    credit, issues = check_csp(f"default-src 'self'; script-src 'self' {keyword}")
    assert credit < 1.0
    assert any(keyword in i for i in issues)


def test_csp_unsafe_inline_is_ignored_by_browsers_when_a_nonce_is_present():
    # CSP2+: a nonce or hash in the same directive disables 'unsafe-inline';
    # sites add it only as a fallback for very old browsers.
    value = "default-src 'self'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'"
    assert check_csp(value) == (1.0, [])


def test_csp_unsafe_inline_with_hash_is_also_ignored():
    value = "default-src 'self'; script-src 'sha256-abc=' 'unsafe-inline'"
    assert check_csp(value) == (1.0, [])


def test_csp_bare_wildcard_is_penalized():
    credit, issues = check_csp("default-src *")
    assert credit < 1.0
    assert any("'*'" in i for i in issues)


def test_csp_wildcard_subdomain_is_not_a_bare_wildcard():
    assert check_csp("default-src 'self' https://*.example.com") == (1.0, [])


def test_csp_without_default_src_is_partial():
    credit, issues = check_csp("script-src 'self'; object-src 'none'")
    assert 0 < credit < 1.0
    assert any("default-src" in i for i in issues)


def test_csp_without_default_src_or_object_src_is_lower_still():
    with_object = check_csp("script-src 'self'; object-src 'none'")[0]
    credit, issues = check_csp("script-src 'self'")
    assert 0 < credit < with_object
    assert any("object-src" in i for i in issues)


def test_csp_each_problem_is_counted_once():
    # The same unsafe keyword in two directives is one problem, not two.
    once = check_csp("default-src 'self'; script-src 'unsafe-eval'")[0]
    twice = check_csp("default-src 'self' 'unsafe-eval'; script-src 'unsafe-eval'")[0]
    assert once == twice


def test_csp_worst_case_is_clamped_at_zero():
    credit, _ = check_csp("script-src * 'unsafe-inline' 'unsafe-eval'")
    assert credit == 0.0


def test_csp_empty_policy_gets_nothing():
    credit, issues = check_csp(" ; ")
    assert credit == 0.0
    assert issues
