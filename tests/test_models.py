from websec.models import Finding, ScanResult, Severity, Status

def test_scan_result_starts_empty():
    result = ScanResult(target="https://example.com")

    assert result.target == "https://example.com"
    assert result.findings == []

def test_scan_result_can_store_finding():
    finding = Finding(
        check_id="TEST-001",
        title="Example security check",
        severity=Severity.MEDIUM,
        status=Status.FAIL,
        description="A test security issue.",
        evidence="Example evidence",
        recommendation="Fix the configuration."
    )

    result = ScanResult(target="https://example.com")
    result.findings.append(finding)

    assert len(result.findings) == 1
    assert result.findings[0].check_id == "TEST-001"
    assert result.findings[0].severity == Severity.MEDIUM