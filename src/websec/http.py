from dataclasses import dataclass
from urllib.parse import urlsplit
from websec.models import Finding, Severity, Status

import httpx

@dataclass
class HTTPResponse:
    url: str
    status_code: int
    headers: dict[str, str]

@dataclass
class HTTPResult:
    target: str
    final_url: str
    responses: list[HTTPResponse]

def validate_url(target: str) -> str:
    target = target.strip()
    parsed = urlsplit(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must use HTTP or HTTPS")

    if not parsed.hostname:
        raise ValueError("URL must include a hostname")

    if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL containing credentials are not allowed")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc

    if port is not None and port not in (80, 443):
        raise ValueError("Only ports 80 and 443 are supported")

    return target

def collect_http(target: str) -> HTTPResult:
    target = validate_url(target)

    with httpx.Client(
        timeout=5.0,
        follow_redirects=True,
        max_redirects=5,
        trust_env=False,
    ) as client:
        response = client.get(target)

    chain = [*response.history, response]

    responses = [
        HTTPResponse(
            url=str(item.url),
            status_code=item.status_code,
            headers=dict(item.headers),
        )
        for item in chain
    ]

    return HTTPResult(
        target=target,
        final_url=str(response.url),
        responses=responses,
    )

def analyze_redirects(result: HTTPResult) -> list[Finding]:
    findings = []

    urls = [response.url for response in result.responses]
    schemes = [urlsplit(url).scheme.lower() for url in urls]

    for index in range(len(schemes) - 1):
        if schemes[index] == "https" and schemes[index + 1] == "http":
            findings.append(
                Finding(
                    check_id="HTTP-001",
                    title="HTTPS to HTTP downgrade",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description="A redirect moves traffic from HTTPS to HTTP.",
                    evidence=f"{urls[index]} -> {urls[index + 1]}",
                    recommendation=(
                        "Keep redirects and destination resources on HTTPS."
                    ),
                )
            )

    if schemes[0] == "http":
        if schemes[-1] == "https":
            findings.append(
                Finding(
                    check_id="HTTP-002",
                    title="HTTP upgraded to HTTPS",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    description="The request chain ends on HTTPS.",
                    evidence=" -> ".join(urls),
                    recommendation="Continue enforcing HTTPS.",
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="HTTP-003",
                    title="HTTP request did not reach HTTPS",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    description=(
                        "The HTTP request chain did not finish on HTTPS."
                    ),
                    evidence=" -> ".join(urls),
                    recommendation=(
                        "Configure HTTP requests to redirect to HTTPS."
                    ),
                )
            )

    return findings