import json
import socket

from src import tunnel_diagnose


def test_config_inspection_redacts_credentials(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "log": {"level": "debug", "timestamp": True},
        "outbounds": [{
            "type": "vless",
            "tag": "reality",
            "server": "vpn.example",
            "server_port": 443,
            "uuid": "secret-uuid",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": "cover.example",
                "reality": {"enabled": True, "public_key": "secret-key", "short_id": "0123456789abcdef"},
            },
        }],
    }), encoding="utf-8")

    result = tunnel_diagnose.inspect_sing_box_config(str(path))
    serialized = json.dumps(result)
    assert "secret-uuid" not in serialized
    assert "secret-key" not in serialized
    assert result["vless_outbounds"][0]["reality_enabled"] is True
    assert result["vless_outbounds"][0]["issues"] == []


def test_log_classification_identifies_handshake_stage(tmp_path):
    path = tmp_path / "box.log"
    secret_uuid = "550e8400-e29b-41d4-a716-446655440000"
    path.write_text(
        f"2026-08-31 ERROR failed reality handshake uuid={secret_uuid}: unexpected EOF\n",
        encoding="utf-8",
    )
    result = tunnel_diagnose.analyze_log(str(path))
    assert result["dominant_failure_stage"] == "reality_or_tls_handshake"
    assert secret_uuid not in json.dumps(result)
    assert "<redacted>" in result["events"][0]["text"]


def test_windows_underlay_interface_is_applied(monkeypatch):
    class FakeSocket:
        def __init__(self, *args):
            self.options = []
        def settimeout(self, value):
            self.timeout = value
        def setsockopt(self, *args):
            self.options.append(args)
        def connect(self, address):
            self.address = address
        def close(self):
            pass

    fake = FakeSocket()
    monkeypatch.setattr(tunnel_diagnose.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        tunnel_diagnose.socket,
        "getaddrinfo",
        lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 443))],
    )
    monkeypatch.setattr(tunnel_diagnose.socket, "socket", lambda *args: fake)
    result = tunnel_diagnose._connect_with_optional_windows_interface(
        "example.test", 443, 4.0, 18
    )
    assert result is fake
    assert fake.address == ("203.0.113.1", 443)
    assert fake.options[-1] == (socket.IPPROTO_IP, 31, socket.htonl(18))


def test_tls_cover_check_reports_verified_certificate(monkeypatch):
    class Raw:
        def close(self):
            pass

    class TLS:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def getpeercert(self):
            return {
                "subject": ((('commonName', 'cover.example'),),),
                "issuer": ((('organizationName', 'Test CA'),),),
                "subjectAltName": (("DNS", "cover.example"),),
            }
        def version(self):
            return "TLSv1.3"
        def cipher(self):
            return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    class Context:
        def wrap_socket(self, raw, server_hostname):
            assert server_hostname == "cover.example"
            return TLS()

    monkeypatch.setattr(
        tunnel_diagnose,
        "_connect_with_optional_windows_interface",
        lambda *args: Raw(),
    )
    monkeypatch.setattr(tunnel_diagnose.ssl, "create_default_context", lambda: Context())
    result = tunnel_diagnose.tls_cover_check(
        "203.0.113.1", 443, "cover.example", interface_index=18
    )
    assert result["status"] == "verified"
    assert result["certificate_common_name"] == "cover.example"
