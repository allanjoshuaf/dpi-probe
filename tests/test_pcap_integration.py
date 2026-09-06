"""Exercise real TShark field extraction on generated packets, without traffic."""
import socket
import struct

import pytest

from src import flow_analysis, pcap, tunnel_diagnose


def write_capture(path, packets):
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for index, (reverse, seq, ack, flags, payload) in enumerate(packets):
        src, dst = ('203.0.113.1', '192.0.2.10') if reverse else ('192.0.2.10', '203.0.113.1')
        ports = (443, 50000) if reverse else (50000, 443)
        tcp = struct.pack('!HHIIBBHHH', *ports, seq, ack, 0x50, flags, 65535, 0, 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), index, 0, 64, 6, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
        frame = b'\x00' * 12 + b'\x08\x00' + ip + tcp
        data += struct.pack('<IIII', 1700000000 + index, 0, len(frame), len(frame)) + frame
    path.write_bytes(data)


def test_real_tshark_end_to_end(tmp_path):
    if not pcap.find_tshark():
        pytest.skip('TShark is optional and unavailable')
    setup = [(False, 100, 0, 2, b''), (True, 200, 101, 0x12, b''), (False, 101, 201, 0x10, b'')]
    client, server = tmp_path / 'client.pcap', tmp_path / 'server.pcap'
    write_capture(client, setup + [(False, 101, 201, 0x18, b'abcde')])
    write_capture(server, setup)
    report = tunnel_diagnose.run(endpoint='203.0.113.1:443', pcap_path=str(client),
                                 server_pcap_path=str(server), output_path=str(tmp_path / 'diagnosis.json'))
    assert report['pcap']['packet_count'] == 4
    assert report['pcap']['streams'][0]['phase'] == 'client_data_unacknowledged'
    assert report['dual_pcap']['assessment'] == 'forward_path_packet_divergence'
    assert report['dual_pcap']['forward_payload_packets_missing_at_server'] == 1
    assert any(f['code'] == 'dual_forward_path_packet_divergence' for f in report['diagnosis']['findings'])
    write_capture(server, setup + [(False, 101, 201, 0x18, b'ab'), (False, 103, 201, 0x18, b'cde')])
    assert flow_analysis.compare_vantages(str(client), str(server), '203.0.113.1:443')['assessment'] == 'no_material_divergence_in_matched_packets'
