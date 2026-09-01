from src import anonymize


def test_anonymize_removes_raw_tests_and_identifiers_without_mutating_input():
    source = {
        "meta": {
            "timestamp": "2026-09-01T12:34:56.789Z",
            "run_id": "private-run-id",
            "target": "203.0.113.4",
            "profile": "reality",
        },
        "tests": {
            "pcap": {"pcap_path": "private.pcapng", "capture": {"packets": 4}},
            "sni": [{"sni": "private.example"}],
        },
        "summary": {"assessment": "insufficient_evidence", "confidence": "low"},
    }
    result = anonymize.anonymize_report(source, isp="Example ISP", country="XX")
    assert result["meta"]["timestamp"] == "2026-09-01T12:34:00Z"
    assert result["meta"]["target"] == "redacted"
    assert result["meta"]["isp"] == "Example ISP"
    assert result["meta"]["country"] == "XX"
    assert "run_id" not in result["meta"]
    assert "tests" not in result
    assert source["meta"]["target"] == "203.0.113.4"


def test_anonymize_accepts_an_unparseable_legacy_timestamp():
    source = {
        "meta": {"timestamp": "unknown", "target": "203.0.113.4"},
        "summary": {"score": 0, "confidence": "unknown"},
    }
    result = anonymize.anonymize_report(source)
    assert result["meta"]["timestamp"] == "unknown"
    assert result["meta"]["target"] == "redacted"
