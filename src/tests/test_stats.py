import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from stats import summarize, summarize_status

def test_summarize_basic():
    result = summarize([10.0, 20.0, 30.0])
    assert result["median_ms"] == 20.0
    assert result["min_ms"] == 10.0
    assert result["max_ms"] == 30.0
    assert result["timeout_rate"] == 0.0
    assert result["samples"] == 3
    print("✓ test_summarize_basic")

def test_summarize_with_none():
    result = summarize([10.0, None, 30.0])
    assert result["timeout_rate"] == round(1/3, 2)
    assert result["samples"] == 3
    print("✓ test_summarize_with_none")

def test_summarize_all_none():
    result = summarize([None, None])
    assert result["median_ms"] is None
    assert result["timeout_rate"] == 1.0
    print("✓ test_summarize_all_none")

def test_summarize_status_basic():
    result = summarize_status(["tls_alert", "tls_alert", "silent_drop"])
    assert result["dominant"] == "tls_alert"
    assert result["total"] == 3
    print("✓ test_summarize_status_basic")

def test_summarize_status_empty():
    result = summarize_status([])
    assert result["dominant"] is None
    print("✓ test_summarize_status_empty")

if __name__ == "__main__":
    test_summarize_basic()
    test_summarize_with_none()
    test_summarize_all_none()
    test_summarize_status_basic()
    test_summarize_status_empty()
    print("\nAll tests passed.")