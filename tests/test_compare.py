from src import compare


def test_rst_comparison_keeps_zero_as_a_real_ratio():
    changes = compare.compare_rst(
        {"ratio": 0.0, "dominant_verdict": "no_reset"},
        {"ratio": 0.8, "dominant_verdict": "reset"},
    )
    assert any(row["signal"] == "rst_ratio" for row in changes)
    assert any(row["signal"] == "rst_verdict" for row in changes)


def test_content_comparisons_report_missing_and_changed_values():
    sni = compare.compare_sni(
        [{"sni": "a.example", "dominant_response": "timeout"}],
        [{"sni": "a.example", "dominant_response": "server_hello"}],
    )
    hosts = compare.compare_http_host(
        [{"host": "a.example", "classification": "closed"}],
        [{"host": "b.example", "classification": "data"}],
    )
    signals = compare.compare_signals(
        {"path": {"strength": "weak"}},
        {"path": {"strength": "strong"}},
    )
    assert sni[0]["before"] == "timeout"
    assert {row["domain"] for row in hosts} == {"a.example", "b.example"}
    assert signals[0]["after"] == "strong"
