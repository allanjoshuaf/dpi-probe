import socket
import time
from src.tests.sni_test import build_tls_client_hello

def send_normal(s: socket.socket, payload: bytes) -> bytes:
    s.send(payload)
    return s.recv(4096)

def send_fragmented(s: socket.socket, payload: bytes, fragment_at: int = None) -> bytes:
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if fragment_at is None:
        fragment_at = len(payload) // 2
    s.sendall(payload[:fragment_at])
    time.sleep(0.05)
    s.sendall(payload[fragment_at:])
    return s.recv(4096)

def interpret(response: bytes) -> str:
    if not response:
        return "silent_drop"
    if response[0] == 0x15:
        return "tls_alert"
    if response[0] == 0x16:
        return "server_hello"
    return f"unknown_{hex(response[0])}"

def test_domain(target_ip: str, sni: str, timeout: float = 4.0) -> dict:
    payload = build_tls_client_hello(sni)
    result = {
        "sni": sni,
        "normal": None,
        "fragmented": None,
        "verdict": None,
    }

    # Normal
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, 443))
        try:
            r = send_normal(s, payload)
            result["normal"] = interpret(r)
        except socket.timeout:
            result["normal"] = "silent_drop"
        s.close()
    except Exception as e:
        result["normal"] = f"error: {e}"

    time.sleep(0.2)

    # Fragmented
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, 443))
        try:
            r = send_fragmented(s, payload)
            result["fragmented"] = interpret(r)
        except socket.timeout:
            result["fragmented"] = "silent_drop"
        s.close()
    except Exception as e:
        result["fragmented"] = f"error: {e}"

    # Verdict
    n = result["normal"]
    f = result["fragmented"]

    if n == "silent_drop" and f in ["tls_alert", "server_hello"]:
        result["verdict"] = "possible_fragmentation_bypass"
    elif n == "silent_drop" and f == "silent_drop":
        result["verdict"] = "fragmentation_no_effect"
    elif n in ["tls_alert", "server_hello"] and f in ["tls_alert", "server_hello"]:
        result["verdict"] = "no_blocking"
    else:
        result["verdict"] = "inconclusive"

    return result

def run(config: dict, target_ip: str = "1.1.1.1") -> list:
    blocked = config["domains"]["blocked"]
    clean = config["domains"]["clean"]

    print("\n[*] TLS ClientHello Fragmentation Test")
    print(f"    Target : {target_ip}:443\n")

    results = []

    for sni in clean + blocked:
        r = test_domain(target_ip, sni)

        indicator = "✓" if r["verdict"] == "no_blocking" else \
                    "!" if r["verdict"] == "possible_fragmentation_bypass" else "✗"

        print(f"    [{indicator}] {sni:<25} normal={r['normal']:<12} fragmented={r['fragmented']:<12} → {r['verdict']}")
        results.append(r)

    return results