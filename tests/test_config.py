"""Configuration parsing: safe defaults, and bad values fail loudly."""

from __future__ import annotations

import ipaddress

import pytest

from app.config import load_settings


def test_defaults_are_safe_when_nothing_is_configured():
    settings = load_settings({})
    assert settings.rate_limit == "10/minute"
    assert settings.trusted_proxies == ()  # X-Forwarded-For trusted from nobody
    assert settings.scan_deadline_seconds == 10.0
    assert settings.max_concurrent_scans == 10


def test_values_are_read_from_the_environment():
    settings = load_settings(
        {
            "SECSCAN_RATE_LIMIT": "30/minute",
            "SECSCAN_TRUSTED_PROXIES": "10.244.0.0/16, 192.168.1.7",
            "SECSCAN_SCAN_DEADLINE_SECONDS": "7.5",
            "SECSCAN_MAX_CONCURRENT_SCANS": "4",
        }
    )
    assert settings.rate_limit == "30/minute"
    assert settings.trusted_proxies == (
        ipaddress.ip_network("10.244.0.0/16"),
        ipaddress.ip_network("192.168.1.7/32"),
    )
    assert settings.scan_deadline_seconds == 7.5
    assert settings.max_concurrent_scans == 4


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SECSCAN_RATE_LIMIT", "banana"),
        ("SECSCAN_RATE_LIMIT", ""),
        ("SECSCAN_TRUSTED_PROXIES", "10.0.0.0/8, not-a-network"),
        ("SECSCAN_SCAN_DEADLINE_SECONDS", "soon"),
        ("SECSCAN_SCAN_DEADLINE_SECONDS", "0"),
        ("SECSCAN_SCAN_DEADLINE_SECONDS", "-5"),
        ("SECSCAN_MAX_CONCURRENT_SCANS", "0"),
        ("SECSCAN_MAX_CONCURRENT_SCANS", "2.5"),
    ],
)
def test_invalid_value_stops_startup_and_names_the_variable(name, value):
    with pytest.raises(ValueError, match=name):
        load_settings({name: value})
