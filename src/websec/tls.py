import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from websec.models import Finding, Severity, Status

@dataclass
class TLSResult:
    target: str
    verified: bool = False
    expires_at: datetime | None = None
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    error: str | None = None

def collect_tls(url: str) -> TLSResult:
    """Collect verified TLS information from an HTTPS URL."""
    result = TLSResult(target=url)

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() != "https":
            result.error = "TLS analysis requires an HTTPS URL."
            return result

        if not parsed.hostname:
            result.error = "URL is missing a hostname."
            return result

        if parsed.username is not None or parsed.password is not None:
            result.error = "URLS containing credentials are not supported."
            return result

        port = parsed.port or 443

        if port != 443:
            result.error = "TLS analysis currently supports port 443 only."
            return result

        context = ssl.create_default_context()

        with socket.create_connection(
            (parsed.hostname, port),
            timeout=5,
        ) as connection:
            with context.wrap_socket(
                connection,
                server_hostname=parsed.hostname,
            ) as tls_socket:
                result.verified = True

                certificate = tls_socket.getpeercert()
                expiration = certificate.get("notAfter")

                if expiration:
                    timestamp = ssl.cert_time_to_seconds(expiration)
                    result.expires_at = datetime.fromtimestamp(
                        timestamp,
                        tz=timezone.utc
                    )

                result.protocol = tls_socket.version()

                cipher_info = tls_socket.cipher()

                if cipher_info:
                    result.cipher = cipher_info[0]
                    result.cipher_bits = cipher_info[2]

    except ssl.SSLCertVerificationError as exc:
        result.error = f"Certificate verification failed: {exc}"

    except (ssl.SSLError, OSError, ValueError) as exc:
        result.error = f"TLS connection failed: {exc}"

    return result

def analyze_tls(result: TLSResult) -> list[Finding]:
    """Convert TLS information into security findings."""
    findings = []

    if not result.verified:
        is_https = urlsplit(result.target).scheme.lower() == "https"

        findings.append(
            Finding(
                check_id="TLS-001",
                title="TLS Certificate Verification",
                severity=Severity.HIGH if is_https else Severity.INFO,
                status=Status.ERROR if is_https else Status.UNKNOWN,
                description=(
                    "The TLS certificate could not be verified."
                    if is_https
                    else "TLS analysis does not apply to HTTP URLs."
                ),
                evidence=result.error or "No verified TLS connection.",
                recommendation=(
                    "Check the certificate, hostname, trust chain, "
                    "and TLS configuration."
                    if is_https
                    else "Use an HTTPS URL to analyze TLS."
                ),
            )
        )

        return findings

    findings.append(
        Finding(
            check_id="TLS-001",
            title="TLS Certificate Verification",
            severity=Severity.INFO,
            status=Status.PASS,
            description=(
                "The TLS certificate passed certificate-chain "
                "and hostname verification."
            ),
            evidence="Verified TLS handshake completed successfully.",
            recommendation="Continue maintaining a valid TLS certificate."
        )
    )

    if result.expires_at is not None:
        now = datetime.now(timezone.utc)
        remaining = result.expires_at - now
        days_remaining = remaining.total_seconds() / 86400

        if days_remaining < 0:
            expiration_status = Status.FAIL
            expiration_severity = Severity.HIGH
        elif days_remaining < 30:
            expiration_status = Status.WARNING
            expiration_severity = Severity.MEDIUM
        else:
            expiration_status = Status.PASS
            expiration_severity = Severity.INFO

        findings.append(
            Finding(
                check_id="TLS-002",
                title="TLS Certificate Expiration",
                severity=expiration_severity,
                status=expiration_status,
                description="Checks when the TLS certificate expires.",
                evidence=(
                    f"Certificate expires at "
                    f"{result.expires_at.isoformat()} "
                    f"({days_remaining:.1f} days remaining)."
                ),
                recommendation=(
                    "Renew the certificate before it expires."
                ),
            )
        )

    else:
        findings.append(
            Finding(
                check_id="TLS-002",
                title="TLS Certificate Expiration",
                severity=Severity.INFO,
                status=Status.UNKNOWN,
                description="Certificate expiration could not be determined.",
                evidence="No expiration date was available.",
                recommendation="Inspect the certificate expiration manually.",
            )
        )

    if result.protocol is None:
        protocol_status = Status.UNKNOWN
        protocol_severity = Severity.INFO
    elif result.protocol in ("TLSv1.2", "TLSv1.3"):
        protocol_status = Status.PASS
        protocol_severity = Severity.INFO
    else:
        protocol_status = Status.WARNING
        protocol_severity = Severity.HIGH

    findings.append(
        Finding(
            check_id="TLS-003",
            title="Negotiated TLS Version",
            severity=protocol_severity,
            status=protocol_status,
            description="Checks the TLS version negotiated by this connection.",
            evidence=f"Negotiated protocol: {result.protocol or 'Unknown'}",
            recommendation=(
                "Prefer TLS 1.2 or TLS 1.3 and disable obsolete protocols."
            ),
        )
    )

    findings.append(
        Finding(
            check_id="TLS-004",
            title="Negotiated Cipher",
            severity=Severity.INFO,
            status=Status.UNKNOWN,
            description="Reports the cipher negotiated by this connection.",
            evidence=(
                f"Cipher: {result.cipher or 'Unknown'}; "
                f"secret bits: {result.cipher_bits}"
            ),
            recommendation=(
                "Review cipher configuration and prefer modern "
                "authenticated encryption suites."
            ),
        )
    )

    return findings
