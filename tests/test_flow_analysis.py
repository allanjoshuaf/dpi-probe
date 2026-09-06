from src import flow_analysis
import pytest


def packet(frame, direction, seq, payload=0, flags=0x10, stream="1", retransmission=False):
    return {
        "frame": frame,
        "time_epoch": float(frame),
        "time_relative": float(frame),
        "src": "a",
        "dst": "b",
        "src_port": 50000 if direction == "client_to_server" else 443,
        "dst_port": 443 if direction == "client_to_server" else 50000,
        "direction": direction,
        "seq": seq,
        "ack": 1,
        "payload_len": payload,
        "flags": flags,
        "stream": stream,
        "ttl": 64,
        "retransmission": retransmission,
        "lost_segment": False,
        "duplicate_ack": False,
        "syn": bool(flags & 0x02),
        "ack_flag": bool(flags & 0x10),
        "rst": bool(flags & 0x04),
        "fin": bool(flags & 0x01),
    }


def test_stream_phase_finds_unanswered_first_data():
    packets = [
        packet(1, "client_to_server", 100, flags=0x02),
        packet(2, "server_to_client", 200, flags=0x12),
        packet(3, "client_to_server", 101, flags=0x10),
        packet(4, "client_to_server", 101, payload=300),
        packet(5, "client_to_server", 101, payload=300, retransmission=True),
    ]
    summary = flow_analysis.summarize_streams(packets)[0]
    assert summary["phase"] == "client_data_unacknowledged_with_retransmissions"


def test_client_cleanup_reset_is_not_called_a_target_reset():
    packets = [
        packet(1, "client_to_server", 100, flags=0x02),
        packet(2, "server_to_client", 200, flags=0x12),
        packet(3, "client_to_server", 101, payload=300),
        packet(4, "client_to_server", 401, flags=0x14),
    ]
    summary = flow_analysis.summarize_streams(packets)[0]
    assert summary["phase"] == "client_cleanup_reset_after_unacknowledged_data"


def test_acknowledged_upload_is_not_called_unanswered():
    packets = [
        packet(1, "client_to_server", 100, flags=0x02),
        packet(2, "server_to_client", 200, flags=0x12),
        packet(3, "client_to_server", 101, payload=300),
        {**packet(4, "server_to_client", 201, flags=0x10), "ack": 401},
        packet(5, "client_to_server", 101, payload=300, retransmission=True),
    ]
    summary = flow_analysis.summarize_streams(packets)[0]
    assert summary["first_client_payload_acknowledged"] is True
    assert summary["phase"] == "client_data_acknowledged_no_return_payload_with_retransmissions"


def test_late_reset_after_two_sided_fin_is_orderly_close_context():
    packets = [
        packet(1, "client_to_server", 100, flags=0x02),
        packet(2, "server_to_client", 200, flags=0x12),
        packet(3, "client_to_server", 101, payload=71),
        packet(4, "server_to_client", 201, payload=7),
        packet(5, "server_to_client", 208, flags=0x11),
        packet(6, "client_to_server", 172, flags=0x11),
        packet(7, "server_to_client", 209, flags=0x04),
    ]
    summary = flow_analysis.summarize_streams(packets)[0]
    assert summary["phase"] == "late_target_direction_reset_after_orderly_close"


def test_midstream_bidirectional_flow_is_not_called_failed_handshake():
    packets = [
        packet(10, "client_to_server", 1000, payload=200),
        packet(11, "server_to_client", 2000, payload=300),
    ]
    summary = flow_analysis.summarize_streams(packets)[0]
    assert summary["phase"] == "bidirectional_data_observed_partial_capture"


def test_transport_summary_keeps_tls_and_loss_measures_bounded():
    hello = {
        **packet(1, "client_to_server", 100, payload=500),
        "tls_handshake_type": 1,
        "tls_sni": "cover.example",
        "ack_rtt_ms": None,
    }
    server_hello = {
        **packet(2, "server_to_client", 200, payload=700),
        "time_epoch": 1.25,
        "tls_handshake_type": 2,
        "tls_sni": None,
        "ack_rtt_ms": 230.0,
    }
    metrics = flow_analysis.summarize_transport([hello, server_hello])
    assert metrics["tls"]["client_hello_count"] == 1
    assert metrics["tls"]["server_hello_count"] == 1
    assert metrics["tls"]["sni_counts"] == {"cover.example": 1}
    assert metrics["target_ack_rtt_ms"]["median"] == 230.0


def test_exact_tshark_flag_counts_preserve_overlapping_flags(monkeypatch):
    monkeypatch.setattr(
        flow_analysis,
        "_run_tshark",
        lambda *args, **kwargs: ["50000\t443\t192.0.2.10\t203.0.113.1"],
    )
    counts = flow_analysis._exact_analysis_flag_counts(
        "capture.pcapng", ["203.0.113.1"], 443
    )
    assert counts["client_to_server"]["retransmissions"] == 1
    assert counts["client_to_server"]["fast_retransmissions"] == 1


def test_dual_vantage_finds_forward_divergence(monkeypatch):
    client = [packet(1, "client_to_server", 100, flags=0x02), packet(2, "client_to_server", 101, payload=500)]
    server = [packet(1, "client_to_server", 100, flags=0x02)]

    monkeypatch.setattr(flow_analysis, "resolve_endpoint", lambda host, port: ["203.0.113.1"])
    monkeypatch.setattr(
        flow_analysis,
        "extract_packets",
        lambda path, addresses, port: client if path == "client.pcap" else server,
    )
    result = flow_analysis.compare_vantages("client.pcap", "server.pcap", "203.0.113.1:443")
    assert result["assessment"] == "forward_path_packet_divergence"
    assert result["forward_payload_packets_missing_at_server"] == 1


def test_duplicate_from_any_capture_is_not_divergence(monkeypatch):
    one = packet(1, "server_to_client", 200, payload=50)
    duplicate = {**one, "frame": 2}
    client = [one]
    server = [one, duplicate]
    monkeypatch.setattr(flow_analysis, "resolve_endpoint", lambda host, port: ["203.0.113.1"])
    monkeypatch.setattr(
        flow_analysis,
        "extract_packets",
        lambda path, addresses, port: client if path == "client.pcap" else server,
    )
    result = flow_analysis.compare_vantages("client.pcap", "server.pcap", "203.0.113.1:443")
    assert result["assessment"] == "no_material_divergence_in_matched_packets"


def test_parse_ipv6_endpoint():
    assert flow_analysis.parse_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)


@pytest.mark.parametrize('endpoint', ['2001:db8::1:443', '-h:443', 'host name:443', 'example.test:0'])
def test_invalid_endpoint(endpoint):
    with pytest.raises(ValueError):
        flow_analysis.parse_endpoint(endpoint)


def test_one_way_payload_without_retransmission_is_not_no_payload():
    rows = [packet(1, 'server_to_client', 200, flags=0x12), packet(2, 'client_to_server', 101, payload=50)]
    assert flow_analysis.summarize_streams(rows)[0]['phase'] == 'client_data_unacknowledged'


def test_reset_before_fins_is_not_late_orderly_close():
    rows = [packet(1, 'server_to_client', 200, flags=0x14),
            packet(2, 'client_to_server', 100, flags=0x11), packet(3, 'server_to_client', 200, flags=0x11)]
    assert flow_analysis.summarize_streams(rows)[0]['phase'] == 'target_direction_reset_during_tcp_setup'


def test_ack_wrap_and_reset_ack():
    data = packet(1, 'client_to_server', 2**32 - 10, payload=20)
    ack = {**packet(2, 'server_to_client', 200), 'ack': 10}
    assert flow_analysis.summarize_streams([data, ack])[0]['first_client_payload_acknowledged']
    rst = {**ack, 'rst': True}
    assert not flow_analysis.summarize_streams([data, rst])[0]['first_client_payload_acknowledged']


def test_offload_byte_coverage_and_wrap():
    source = [packet(1, 'client_to_server', 2**32 - 100, payload=200)]
    other = [packet(1, 'client_to_server', 2**32 - 100, payload=100),
             packet(2, 'client_to_server', 0, payload=100)]
    assert flow_analysis._unmatched_ranges(source, other) == []
    assert flow_analysis._unmatched_ranges(other, source) == []
    assert flow_analysis._unmatched_ranges(source, other[:1]) == source


@pytest.mark.parametrize('client,server,expected', [
    ([], [], 'insufficient_capture_evidence'),
    ([packet(1, 'client_to_server', 100, payload=20)], [], 'insufficient_capture_evidence'),
    ([packet(1, 'client_to_server', 100, payload=20)], [packet(1, 'client_to_server', 900, payload=20)], 'no_unambiguous_common_flow'),
])
def test_missing_or_unrelated_captures_are_inconclusive(monkeypatch, client, server, expected):
    monkeypatch.setattr(flow_analysis, 'resolve_endpoint', lambda *a: ['203.0.113.1'])
    monkeypatch.setattr(flow_analysis, 'extract_packets', lambda path, *a: client if path == 'client' else server)
    result = flow_analysis.compare_vantages('client', 'server', '203.0.113.1:443')
    assert result['assessment'] == expected


def test_offload_comparison_pairs_streams_despite_nat(monkeypatch):
    syn = packet(1, 'client_to_server', 100, flags=0x02)
    client = [syn, packet(2, 'client_to_server', 101, payload=200)]
    server = [{**syn, 'stream': '99', 'src_port': 60000},
              packet(2, 'client_to_server', 101, payload=100, stream='99'),
              packet(3, 'client_to_server', 201, payload=100, stream='99')]
    monkeypatch.setattr(flow_analysis, 'resolve_endpoint', lambda *a: ['203.0.113.1'])
    monkeypatch.setattr(flow_analysis, 'extract_packets', lambda path, *a: client if path == 'client' else server)
    result = flow_analysis.compare_vantages('client', 'server', '203.0.113.1:443')
    assert result['assessment'] == 'no_material_divergence_in_matched_packets'
    assert result['matched_flow_count'] == 1
