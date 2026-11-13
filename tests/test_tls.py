import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from websec.models import Status
from websec.tls import TLSResult, analyze_tls, collect_tls

def finding_by_id(findings, check_id):
    return next(
        finding for finding in findings
        if finding.check_id == check_id
    )

def test_valid_certificate_passes():
    result = TLSResult(
        target="https://example.com",
        verified=True,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
    )

    findings = analyze_tls(result)

    assert finding_by_id(findings, "TLS-001").status == Status.PASS
    assert finding_by_id(findings, "TLS-002").status == Status.PASS
    assert finding_by_id(findings, "TLS-003").status == Status.PASS

def test_certificate_expiring_soon_warns():
    result = TLSResult(
        target="https://example.com",
        verified=True,
        expires_at=datetime.now(timezone.utc) + timedelta(days=10),
        protocol="TLSv1.3",
    )

    findings = analyze_tls(result)

    assert finding_by_id(findings, "TLS-002").status == Status.WARNING

def test_expired_certificate_fails():
    result = TLSResult(
        target="https://example.com",
        verified=True,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        protocol="TLSv1.3",
    )

    findings = analyze_tls(result)

    assert finding_by_id(findings, "TLS-002").status == Status.FAIL

def test_legacy_tls_version_warns():
    result = TLSResult(
        target="https://example.com",
        verified=True,
        protocol="TLSv1.0",
    )

    findings = analyze_tls(result)

    assert finding_by_id(findings, "TLS-003").status == Status.WARNING

def test_unknown_tls_version():
    result = TLSResult(
        target="https://example.com",
        verified=True,
        protocol=None,
    )

    findings = analyze_tls(result)

    assert finding_by_id(findings, "TLS-003").status == Status.UNKNOWN

def test_unverified_certificate_reports_error():
    result = TLSResult(
        target="https://example.com",
        error="Certificate verification failed",
    )

    findings = analyze_tls(result)

    assert len(findings) == 1
    assert findings[0].status == Status.ERROR

def test_http_url_is_not_applicable():
    result = collect_tls("http://example.com")

    findings = analyze_tls(result)

    assert result.verified is False
    assert findings[0].status == Status.UNKNOWN

@pytest.mark.parametrize(
    "url",
    [
        "https://",
        "https://example.com:8443",
        "https://user:pass@example.com",
        "not-a-url",
    ],
)

def test_invalid_tls_targets(url):
    result = collect_tls(url)

    assert result.verified is False
    assert result.error is not None

def test_successful_tls_collection(monkeypatch):
    fake_tls_socket = MagicMock()
    fake_tls_socket.getpeercert.return_value = {
        "notAfter": "Dec 31 23:59:59 2030 GMT"
    }
    fake_tls_socket.version.return_value = "TLSv1.3"
    fake_tls_socket.cipher.return_value = (
        "TLS_AES_256_GCM_SHA384",
        "TLSv1.3",
        256,
    )

    fake_tls_socket.__enter__.return_value = fake_tls_socket

    fake_connection = MagicMock()
    fake_connection.__enter__.return_value = fake_connection

    fake_context = MagicMock()
    fake_context.wrap_socket.return_value = fake_tls_socket

    monkeypatch.setattr(
        ssl,
        "create_default_context",
        lambda: fake_context,
    )

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: fake_connection,
    )

    result = collect_tls("https://example.com")

    assert result.verified is True
    assert result.protocol == "TLSv1.3"
    assert result.cipher_bits == 256
    assert result.expires_at is not None

    fake_context.wrap_socket.assert_called_once_with(
        fake_connection,
        server_hostname="example.com",
    )

def test_tls_network_failure(monkeypatch):
    def fail_connection(address, timeout):
        raise OSError("Connection refused")

    monkeypatch.setattr(
        socket,
        "create_connection",
        fail_connection,
    )

    result = collect_tls("https://example.com")

    assert result.verified is False
    assert "Connection refused" in result.error

def test_tls_certificate_verification_failure(monkeypatch):
    def fail_connection(address, timeout):
        raise ssl.SSLCertVerificationError(
            "certificate verify failed"
        )

    monkeypatch.setattr(
        socket,
        "create_connection",
        fail_connection,
    )

    result = collect_tls("https://example.com")

    assert result.verified is False
    assert "Certificate verification failed" in result.error