import json
import sys
import subprocess
from pathlib import Path

import pytest

from src import cli_wizard


@pytest.fixture(autouse=True)
def french_language(monkeypatch):
    monkeypatch.setattr(cli_wizard.i18n, 'load_language', lambda: 'fr')
    cli_wizard.i18n.set_language('fr')
    yield
    cli_wizard.i18n.set_language('fr')


def answers(monkeypatch, values):
    iterator = iter(values)
    monkeypatch.setattr('builtins.input', lambda prompt='': next(iterator))


def test_menu_quit_never_runs_network(monkeypatch, capsys):
    answers(monkeypatch, ['bad', '0'])
    monkeypatch.setattr(cli_wizard, 'diagnose', lambda: pytest.fail('unexpected diagnosis'))
    cli_wizard.run()
    assert 'Choisis un numéro' in capsys.readouterr().out


def test_offline_menu_creates_real_reports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    log = tmp_path / 'box.log'
    log.write_text('ERROR reality handshake failed: EOF\n', encoding='utf-8')
    answers(monkeypatch, ['2', '', '', str(log), '3', '2', '0'])
    cli_wizard.run()
    outputs = list((tmp_path / 'reports').glob('*/diagnosis.json'))
    assert len(outputs) == 1
    result = json.loads(outputs[0].read_text(encoding='utf-8'))
    assert result['active_checks'] is None
    assert result['diagnosis']['findings'][0]['code'] == 'log_reality_or_tls_handshake'
    assert outputs[0].with_suffix('.md').exists()
    shared = outputs[0].with_name('diagnosis.shared.json')
    assert shared.exists()
    assert str(log) not in shared.read_text(encoding='utf-8')


def test_file_input_retries_missing_path(tmp_path, monkeypatch):
    file = tmp_path / 'space name.json'
    file.write_text('{}')
    answers(monkeypatch, [str(tmp_path / 'missing'), f'"{file}"'])
    assert cli_wizard.file_input('test') == str(file.resolve())


def test_integer_and_endpoint_validation(monkeypatch):
    answers(monkeypatch, ['x', '0', '8', 'wrong', '[::1]:443'])
    assert cli_wizard.integer_input('test', 3, 1, 10) == 8
    assert cli_wizard.endpoint_input(None) == '[::1]:443'


def test_missing_tshark_is_actionable(monkeypatch):
    answers(monkeypatch, ['', '203.0.113.1:443', '', '2'])
    monkeypatch.setattr(cli_wizard.pcap, 'find_tshark', lambda: None)
    with pytest.raises(RuntimeError, match='TShark absent'):
        cli_wizard.diagnose()


def test_live_capture_uses_selected_interface_and_port(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    answers(monkeypatch, ['', '203.0.113.1:8443', '', '2', '1', '3', '5', '', '1', '1'])
    monkeypatch.setattr(cli_wizard.pcap, 'find_tshark', lambda: 'tshark')
    monkeypatch.setattr(cli_wizard.pcap, 'list_interfaces', lambda: ['3. Ethernet'])
    monkeypatch.setattr(cli_wizard.flow_analysis, 'resolve_endpoint', lambda *a: ['203.0.113.1'])
    observed = {}
    def capture(address, path, **kwargs):
        observed.update(address=address, path=path, **kwargs)
        return {'status': 'ok'}
    monkeypatch.setattr(cli_wizard.pcap, 'capture', capture)
    monkeypatch.setattr(cli_wizard.tunnel_diagnose, 'run', lambda **kw: observed.update(diagnosis=kw) or {})
    cli_wizard.diagnose()
    assert observed['interface'] == '3'
    assert observed['port'] == 8443
    assert observed['duration'] == 5
    assert observed['diagnosis']['pcap_path'] == observed['path']
    assert observed['diagnosis']['active_checks'] is False


def test_failed_capture_does_not_get_reported_as_success(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    answers(monkeypatch, ['', '203.0.113.1:443', '', '2', '1', '3', '5'])
    monkeypatch.setattr(cli_wizard.pcap, 'find_tshark', lambda: 'tshark')
    monkeypatch.setattr(cli_wizard.pcap, 'list_interfaces', lambda: ['3. Ethernet'])
    monkeypatch.setattr(cli_wizard.flow_analysis, 'resolve_endpoint', lambda *a: ['203.0.113.1'])
    monkeypatch.setattr(cli_wizard.pcap, 'capture', lambda *a, **kw: {'status': 'error', 'stderr': 'Permission denied'})
    monkeypatch.setattr(cli_wizard.tunnel_diagnose, 'run', lambda **kw: pytest.fail('must not analyze'))
    with pytest.raises(RuntimeError, match='Permission denied'):
        cli_wizard.diagnose()


def test_menu_recovers_from_operation_error(monkeypatch, capsys):
    answers(monkeypatch, ['2', '0'])
    def fail():
        raise RuntimeError('missing tool')
    monkeypatch.setattr(cli_wizard, 'diagnose', fail)
    cli_wizard.run()
    assert 'missing tool' in capsys.readouterr().out


def test_full_test_dispatch(monkeypatch):
    from src.probe import Probe
    answers(monkeypatch, ['2', 'not an ip', '203.0.113.1', '2', '1'])
    called = []
    monkeypatch.setattr(Probe, 'run', lambda self: called.append((self.target, self.samples)))
    cli_wizard.network_tests()
    assert called == [('203.0.113.1', 2)]


def test_single_test_saves_report(tmp_path, monkeypatch):
    from src.probe import Probe
    monkeypatch.chdir(tmp_path)
    answers(monkeypatch, ['3', '203.0.113.1', '1', '1'])
    monkeypatch.setattr(Probe, 'test_tcp_rst', lambda self: self.results.update(tcp_443={'status': 'open'}))
    cli_wizard.network_tests()
    assert len(list((tmp_path / 'reports').glob('report_*.json'))) == 1


def test_headless_no_arguments_never_starts_probes():
    main = Path(__file__).resolve().parents[1] / 'main.py'
    result = subprocess.run([sys.executable, str(main)], input='', capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'interactive mode needs a terminal' in result.stderr


def test_capture_builds_endpoint_filter(tmp_path, monkeypatch):
    from src import pcap
    monkeypatch.setattr(pcap, 'find_tshark', lambda: 'tshark')
    observed = []
    def execute(command, **kwargs):
        observed.append(command)
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(pcap.subprocess, 'run', execute)
    pcap.capture('203.0.113.1', str(tmp_path / 'capture.pcap'), interface='3', duration=5, port=8443)
    assert 'host 203.0.113.1 and tcp port 8443' in observed[0]
