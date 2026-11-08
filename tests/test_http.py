import httpx
import pytest

from websec.http import collect_http, validate_url

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