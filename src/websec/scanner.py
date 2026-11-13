import httpx

from websec.models import Finding, ScanResult, Severity, Status
from websec.http import validate_url, collect_http, analyze_redirects
from websec.headers import analyze_headers
from websec.tls import collect_tls, analyze_tls

def scan(url: str) -> ScanResult:
    """Run HTTP, security header, and TLS analysis on a target."""

    result = ScanResult(target=url)

    try:
        validate_url(url)

    except ValueError as exc:
        result.findings.append(
            Finding(
                check_id="SCAN-001",
                title="Invalid Target URL",
                severity=Severity.INFO,
                status=Status.ERROR,
                description="The supplied URL is invalid or unsupported.",
                evidence=str(exc),
                recommendation="Provide a valid HTTP or HTTPS URL.",
            )
        )

        return result

    try:
        http_result = collect_http(url)

    except (httpx.HTTPError, ValueError) as exc:
        result.findings.append(
            Finding(
                check_id="SCAN-002",
                title="HTTP Collection Failed",
                severity=Severity.INFO,
                status=Status.ERROR,
                description="HTTP response information could not be collected.",
                evidence=str(exc),
                recommendation=(
                    "Check the target URL, network connection, "
                    "and website availability."
                ),
            )
        )

        return result

    result.findings.extend(
        analyze_redirects(http_result)
    )

    if http_result.responses:
        final_response = http_result.responses[-1]

        result.findings.extend(
            analyze_headers(
                final_response.headers,
                http_result.final_url,
            )
        )

    else:
        result.findings.append(
            Finding(
                check_id="SCAN-003",
                title="Security Header Analysis Unavailable",
                severity=Severity.INFO,
                status=Status.UNKNOWN,
                description="No HTTP response was available for header analysis.",
                evidence="The HTTP response list was empty.",
                recommendation="Retry the scan when the target is unavailable.",
            )
        )

    tls_result = collect_tls(http_result.final_url)

    result.findings.extend(
        analyze_tls(tls_result)
    )

    return result