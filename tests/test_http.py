import httpx
import pytest

from websec.http import collect_http, validate_url
from websec.http import HTTPResponse, HTTPResult, analyze_redirects
from websec.models import Status

@pytest.mark.parametrize(
    "target",
    [
        "file:///etc/passwd",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com:8080",
        "not-a-url",
    ],
)

def test_invalid_urls(target):
    with pytest.raises(ValueError):
        validate_url(target)

def test_collect_http(monkeypatch):
    original_client = httpx.Client
    def mock_client(*args, **kwargs):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"X-Content-Type-Options": "nosniff"},
                request=request,
            )
        )

        return original_client(
            transport=transport,
            **kwargs,
        )

    monkeypatch.setattr("websec.http.httpx.Client", mock_client)

    result = collect_http("https://example.com")

    assert result.target == "https://example.com"
    assert result.final_url == "https://example.com"
    assert len(result.responses) == 1
    assert result.responses[0].status_code == 200
    assert (
        result.responses[0].headers["x-content-type-options"] == "nosniff"
    )

def make_http_result(urls):
    responses = [
        HTTPResponse(url=url, status_code=301, headers={})
        for url in urls[:-1]
    ]

    responses.append(
        HTTPResponse(url=urls[-1], status_code=200, headers={})
    )

    return HTTPResult(
        target=urls[0],
        final_url=urls[-1],
        responses=responses,
    )

def test_https_downgrade():
    result = make_http_result([
        "https://example.com",
        "http://example.com",
    ])

    findings = analyze_redirects(result)

    assert any(
        finding.check_id == "HTTP-001"
        and finding.status == Status.FAIL
        for finding in findings
    )

def test_http_upgrade():
    result = make_http_result([
        "http://example.com",
        "https://example.com",
    ])

    findings = analyze_redirects(result)

    assert any(
        finding.check_id == "HTTP-002"
        and finding.status == Status.PASS
        for finding in findings
    )

def test_http_without_upgrade():
    result = make_http_result([
        "http://example.com",
    ])

    findings = analyze_redirects(result)

    assert any(
        finding.check_id == "HTTP-003"
        and finding.status == Status.WARNING
        for finding in findings
    )

def test_empty_http_response():
    result = HTTPResult(
        target="https://example.com",
        final_url="https://example.com",
        responses=[],
    )

    findings = analyze_redirects(result)

    assert len(findings) == 1
    assert findings[0].check_id == "HTTP-004"
    assert findings[0].status == Status.UNKNOWN

def test_http_without_redirects():
    result = make_http_result([
        "https://example.com",
    ])

    findings = analyze_redirects(result)

    assert findings == []