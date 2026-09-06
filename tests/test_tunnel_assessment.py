import json
import socket
import subprocess

import pytest

from src import anonymize, tunnel_assessment, tunnel_diagnose


def test_no_evidence_does_not_claim_a_working_tunnel():
    result = tunnel_assessment.assess({})
    assert result['status'] == 'insufficient_evidence'
    assert result['blocking_confirmed'] is None
    assert result['exact_hop'] is None


def test_verified_cover_is_not_reality_authentication():
    result = tunnel_assessment.assess({'active_checks': {'tls_cover': {'status': 'verified'}}})
    finding = result['findings'][0]
    assert finding['code'] == 'ordinary_tls_verified'
    assert 'does not authenticate' in finding['possible_causes'][0]
    assert result['blocking_confirmed'] is None


def test_empty_capture_is_a_collection_issue():
    result = tunnel_assessment.assess({'pcap': {'packet_count': 0, 'streams': []}})
    assert result['findings'][0]['code'] == 'empty_client_capture'


def test_dual_forward_path_has_bounded_attribution():
    result = tunnel_assessment.assess({'dual_pcap': {'assessment': 'forward_path_packet_divergence'}})
    assert 'between capture points' in result['findings'][0]['location']
    assert result['exact_hop'] is None


def test_report_is_written_with_parent_and_readable_companion(tmp_path):
    log = tmp_path / 'box.log'
    log.write_text('ERROR failed reality handshake: unexpected EOF\n', encoding='utf-8')
    output = tmp_path / 'nested' / 'diagnosis.json'
    result = tunnel_diagnose.run(log_path=str(log), output_path=str(output))
    assert result['diagnosis']['findings'][0]['code'] == 'log_reality_or_tls_handshake'
    assert json.loads(output.read_text(encoding='utf-8')) == result
    assert 'Pour trancher' in output.with_suffix('.md').read_text(encoding='utf-8')
    shared = anonymize.anonymize_report(result)
    assert str(tmp_path) not in json.dumps(shared)
    assert 'log_reality_or_tls_handshake' in shared['summary']['finding_codes']
    assert 'events' not in json.dumps(shared)


def test_no_input_is_rejected():
    with pytest.raises(ValueError, match='provide'):
        tunnel_diagnose.run()


@pytest.mark.parametrize('secret_line', [
    'ERROR tls invalid "password": "sensitive value"',
    'ERROR reality invalid short_id=deadbeef',
    'ERROR connection vless://secret@host:443?sid=deadbeef',
    'ERROR tls Authorization: Bearer sensitive-token',
    'ERROR uuid=00000000-0000-0000-0000-000000000000',
])
def test_secret_formats_are_redacted(secret_line):
    result = tunnel_diagnose._redact_log_line(secret_line)
    for forbidden in ('sensitive value', 'deadbeef', 'secret@', 'sensitive-token', '00000000-0000'):
        assert forbidden not in result


def test_dns_failure_is_evidence_not_a_crash(monkeypatch):
    def fail(*args):
        raise socket.gaierror('unresolved')
    monkeypatch.setattr(tunnel_diagnose.flow_analysis, 'resolve_endpoint', fail)
    tcp = tunnel_diagnose.tcp_connect_samples('invalid.test', 443)
    result = tunnel_assessment.assess({'active_checks': {'tcp': tcp}})
    assert result['findings'][0]['code'] == 'endpoint_dns_failed'


def test_traceroute_timeout_bytes_are_json_serializable(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.TimeoutExpired('tracert', 45, output=b'partial route')
    monkeypatch.setattr(tunnel_diagnose.subprocess, 'run', fail)
    assert 'partial route' in json.dumps(tunnel_diagnose.route_snapshot('203.0.113.1'))


@pytest.mark.parametrize('url', ['http://example.com', 'http://secret@127.0.0.1', 'http://127.0.0.1?token=secret'])
def test_api_rejects_nonlocal_or_credential_urls(url):
    with pytest.raises(ValueError, match='loopback'):
        tunnel_diagnose.clash_api_snapshot(url, 'secret')


def test_selected_outbound_supplies_sni_and_samples(tmp_path, monkeypatch):
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'outbounds': [
        {'type': 'vless', 'tag': tag, 'server': host, 'server_port': 443,
         'tls': {'server_name': sni}}
        for tag, host, sni in [('one', '203.0.113.1', 'one.example'), ('two', '203.0.113.2', 'two.example')]
    ]}), encoding='utf-8')
    observed = []
    monkeypatch.setattr(tunnel_diagnose, 'tcp_connect_samples', lambda *a, **kw: observed.append((a, kw)) or {})
    monkeypatch.setattr(tunnel_diagnose, 'route_snapshot', lambda *a: {})
    monkeypatch.setattr(tunnel_diagnose, 'tls_cover_check', lambda *a, **kw: {'server_name': a[2]})
    report = tunnel_diagnose.run(config_path=str(config), outbound_tag='two', active_checks=True,
                                 samples=4, output_path=str(tmp_path / 'result.json'))
    assert report['endpoint'] == '203.0.113.2:443'
    assert report['active_checks']['tls_cover']['server_name'] == 'two.example'
    assert observed[0][1]['samples'] == 4
    report = tunnel_diagnose.run(config_path=str(config), endpoint='203.0.113.3:443', active_checks=True,
                                 output_path=str(tmp_path / 'other.json'))
    assert report['active_checks']['tls_cover'] is None


def test_odd_short_id_is_invalid(tmp_path):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps({'outbounds': [{'type': 'vless', 'tls': {
        'reality': {'enabled': True, 'short_id': 'abc'}}}]}), encoding='utf-8')
    row = tunnel_diagnose.inspect_sing_box_config(str(path))['vless_outbounds'][0]
    assert 'reality_short_id_must_be_0_to_8_bytes_hex' in row['issues']
