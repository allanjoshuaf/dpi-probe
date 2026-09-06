from types import SimpleNamespace
import subprocess

import pytest

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


@pytest.mark.parametrize('code,status,attempted', [
    (0, 'ech_required_request_succeeded', True),
    (4, 'unsupported_by_curl_build', False),
    (101, 'ech_required_not_satisfied', True),
    (28, 'request_failed_stage_unresolved', True),
])
def test_active_ech_never_accepts_opportunistic_fallback(monkeypatch, code, status, attempted):
    monkeypatch.setattr(ech_test.shutil, 'which', lambda name: 'curl')
    def execute(command, **kwargs):
        assert command[command.index('--ech') + 1] == 'hard'
        assert command[1] == '--disable'
        assert '--insecure' not in command
        assert command[-1] == 'https://example.com/'
        return subprocess.CompletedProcess(command, code, '200' if code == 0 else '', '')
    monkeypatch.setattr(ech_test.subprocess, 'run', execute)
    result = ech_test.curl_handshake('example.com')
    assert result['status'] == status
    assert result['attempted'] is attempted
