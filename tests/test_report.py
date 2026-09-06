from src import report


def test_report_separates_observation_from_attribution():
    results = {
        "sni": [
            {
                "sni": "comparison.example",
                "category": "clean",
                "dominant_response": "tls_alert",
                "status_breakdown": {"tls_alert": 1.0},
            },
            {
                "sni": "suspect.example",
                "category": "blocked",
                "dominant_response": "no_response_before_timeout",
                "status_breakdown": {"no_response_before_timeout": 1.0},
            },
        ],
        "pcap_correlation": {
            "suspect.example": {"retransmissions": 4, "tls_alerts": 0},
        },
    }

    generated = report.generate("203.0.113.10", results, samples=3)

    assert generated["summary"]["assessment"] == "content_dependent_behavior_observed"
    assert generated["summary"]["confidence"] == "moderate"
    assert generated["summary"]["dpi_detected"] is None
    signal = generated["summary"]["signals"]["tls_sni_differential"]
    assert signal["attribution"] == "on-path_or_destination"
    assert signal["limitations"]


def test_report_does_not_call_timeout_a_proven_drop():
    generated = report.generate(
        "203.0.113.10",
        {"sni": [{
            "sni": "only.example",
            "category": "blocked",
            "dominant_response": "no_response_before_timeout",
            "status_breakdown": {"no_response_before_timeout": 1.0},
        }]},
    )
    signal = generated["summary"]["signals"]["tls_sni_differential"]
    assert signal["strength"] == "inconclusive"
