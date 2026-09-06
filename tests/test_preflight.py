from types import SimpleNamespace

import pytest

import bootstrap
from src import pcap, preflight
from src.probe import Probe


def test_missing_python_modules_are_reported(monkeypatch):
    def missing(module):
        raise ImportError(module)
    monkeypatch.setattr(preflight.importlib, 'import_module', missing)
    issues = preflight.python_issues()
    assert any('cryptography' in issue for issue in issues)
    assert any('dnspython' in issue for issue in issues)


def test_incompatible_dependency_is_reported(monkeypatch):
    monkeypatch.setattr(preflight.importlib, 'import_module', lambda name: None)
    monkeypatch.setattr(preflight.importlib.metadata, 'version', lambda name: '999.0')
    assert len(preflight.python_issues()) == 2


def test_empty_interface_output_is_unavailable(monkeypatch):
    monkeypatch.setattr(pcap, 'find_tshark', lambda: 'tshark')
    monkeypatch.setattr(pcap.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout='\n'))
    assert pcap.list_interfaces() == []


def test_doctor_does_not_claim_capture_when_interfaces_missing(monkeypatch, capsys):
    monkeypatch.setattr(preflight, 'python_issues', lambda: [])
    monkeypatch.setattr(pcap, 'find_tshark', lambda: 'tshark')
    monkeypatch.setattr(pcap, 'list_interfaces', lambda: [])
    assert not preflight.doctor()
    assert 'UNAVAILABLE' in capsys.readouterr().out


def test_declined_setup_does_not_create_environment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bootstrap, 'ROOT', tmp_path)
    monkeypatch.setattr(bootstrap, 'consent', lambda _: False)
    assert bootstrap.main() == 2
    assert not (tmp_path / '.venv').exists()


def test_requested_capture_without_tshark_sends_no_probes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pcap, 'find_tshark', lambda: None)
    probe = Probe('192.0.2.1', pcap=True, pcap_interface='1')
    monkeypatch.setattr(probe, 'test_tcp_rst', lambda: pytest.fail('Network probe started'))
    with pytest.raises(RuntimeError, match='TShark'):
        probe.run()
