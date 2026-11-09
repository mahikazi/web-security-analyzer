import pytest

from websec.headers import analyze_headers
from websec.models import Status

def findings_by_id(headers, url="https://example.com"):
    findings = analyze_headers(headers, url)

    return {
        finding.check_id: finding
        for finding in findings
    }

def test_five_header_findings_returned():
    findings = analyze_headers({}, "https://example.com")

    assert len(findings) == 5
    assert {finding.check_id for finding in findings} == {
        "HDR-001",
        "HDR-002",
        "HDR-003",
        "HDR-004",
        "HDR-005"
    }

def test_secure_header_configuration():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    findings = analyze_headers(headers, "https://example.com")

    assert all(finding.status == Status.PASS for finding in findings)

@pytest.mark.parametrize(
    "value",
    [
        "max-age=0",
        "max-age=abc",
        "max-age=-1",
        "includeSubDomains",
        "max-age=100; max-age=200"
    ],
)

def test_invalid_or_disabled_hsts(value):
    findings = findings_by_id({
        "Strict-Transport-Security": value,
    })

    assert findings["HDR-001"].status != Status.PASS

def test_hsts_on_http_is_unknown():
    findings = findings_by_id(
        {"Strict-Transport-Security": "max-age=31536000"},
        url="http://example.com",
    )

    assert findings["HDR-001"].status == Status.UNKNOWN

def test_missing_hsts_fails_on_https():
    findings = findings_by_id({})

    assert findings["HDR-001"].status == Status.FAIL

@pytest.mark.parametrize(
    "value",
    [
        "script-src 'unsafe-inline'",
        "script-src 'unsafe-eval'",
        "script-src *",
        "default-src *",
    ],
)

def test_permissive_csp_warns(value):
    findings = findings_by_id({
        "Content-Security-Policy": value,
    })

    assert findings["HDR-002"].status == Status.WARNING

def test_missing_csp_warns():
    findings = findings_by_id({})

    assert findings["HDR-002"].status == Status.WARNING

@pytest.mark.parametrize(
    "value",
    ["DENY", "SAMEORIGIN", "deny"],
)

def test_valid_x_frame_options(value):
    findings = findings_by_id({
        "X-Frame-Options": value,
    })

    assert findings["HDR-003"].status == Status.PASS

def test_invalid_x_frame_options_warns():
    findings = findings_by_id({
        "X-Frame-Options": "ALLOW-FROM https://example.com",
    })

    assert findings["HDR-003"].status == Status.WARNING

def test_nosniff_passed():
    findings = findings_by_id({
        "X-Content-Type-Options": "nosniff",
    })

    assert findings["HDR-004"].status == Status.PASS

def test_invalid_nosniff_warns():
    findings = findings_by_id({
        "X-Content-Type-Options": "sniff",
    })

    assert findings["HDR-004"].status == Status.WARNING

def test_unsafe_referrer_policy_warns():
    findings = findings_by_id({
        "Referrer-Policy": "unsafe-url",
    })

    assert findings["HDR-005"].status == Status.WARNING

def test_referrer_policy_fallback_uses_last_recognized_value():
    findings = findings_by_id({
        "Referrer-Policy": "unsafe-url, strict-origin",
    })

    assert findings["HDR-005"].status == Status.PASS

def test_header_names_are_case_insensitive():
    findings = findings_by_id({
        "x-content-type-options": "nosniff",
        "X-FRAME-OPTIONS": "DENY",
    })

    assert findings["HDR-003"].status == Status.PASS
    assert findings["HDR-004"].status == Status.PASS