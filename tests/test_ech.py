from types import SimpleNamespace

from src.probes import ech_test


def test_record_summary_extracts_ech_bytes_and_alpn():
    record = SimpleNamespace(
        priority=1,
        target=".",
        params={
            1: SimpleNamespace(ids=(b"h2", b"h3")),
            5: SimpleNamespace(ech=b"public-ech-config"),
        },
    )

    result = ech_test._record_summary(record)

    assert result["ech_present"] is True
    assert result["ech_config_length"] == len(b"public-ech-config")
    assert result["alpn"] == ["h2", "h3"]


def test_runtime_capabilities_have_a_clear_boolean_verdict():
    result = ech_test.runtime_capabilities()
    assert isinstance(result["handshake_supported"], bool)
    assert result["python_openssl"]
