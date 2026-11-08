from dataclasses import dataclass
from urllib.parse import urlsplit

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