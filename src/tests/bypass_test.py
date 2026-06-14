import socket
import time
from src.tests.sni_test import build_tls_client_hello

def split_clienthello_record(clienthello: bytes, split_at: int) -> tuple:
    if len(clienthello) < 6:
        raise ValueError("invalid TLS record")
    if clienthello[0] != 0x16:
        raise ValueError("not a TLS handshake record")
    record_header = clienthello[:3]
    payload = clienthello[5:]
    if split_at <= 0 or split_at >= len(payload):
        raise ValueError("invalid split position")
    part1 = payload[:split_at]
    part2 = payload[split_at:]
    record1 = record_header + len(part1).to_bytes(2, "big") + part1
    record2 = record_header + len(part2).to_bytes(2, "big") + part2
    return record1, record2

def interpret(data: bytes) -> str:
    if not data:
        return "silent_drop"
    if data[0] == 0x16:
        return "server_hello"
    if data[0] == 0x15:
        return "tls_alert"
    return f"unknown_{hex(data[0])}"

def connect(target_ip: str, timeout: float = 4.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(timeout)
    s.connect((target_ip, 443))
    return s

def test_normal(target_ip: str, sni: str, timeout: float = 4.0) -> str:
    try:
        s = connect(target_ip, timeout)
        s.sendall(build_tls_client_hello(sni))
        try:
            return interpret(s.recv(4096))
        except socket.timeout:
            return "silent_drop"
        finally:
            s.close()
    except Exception as e:
        return f"error: {e}"

def test_record_split(target_ip: str, sni: str, split_at: int, timeout: float = 4.0) -> str:
    try:
        hello = build_tls_client_hello(sni)
        r1, r2 = split_clienthello_record(hello, split_at)
        s = connect(target_ip, timeout)
        s.sendall(r1)
        time.sleep(0.05)
        s.sendall(r2)
        try:
            return interpret(s.recv(4096))
        except socket.timeout:
            return "silent_drop"
        finally:
            s.close()
    except Exception as e:
        return f"error: {e}"

def build_padded_hello(sni: str, padding_size: int) -> bytes:
    return build_tls_client_hello(sni, padding_size=padding_size)

def test_padding(target_ip: str, sni: str, padding_sizes: list, timeout: float = 4.0) -> dict:
    results = {}
    for size in padding_sizes:
        try:
            s = connect(target_ip, timeout)
            s.sendall(build_padded_hello(sni, size))
            try:
                results[size] = interpret(s.recv(4096))
            except socket.timeout:
                results[size] = "silent_drop"
            finally:
                s.close()
        except Exception as e:
            results[size] = f"error: {e}"
        time.sleep(0.1)
    return results        

def run(config: dict, target_ip: str = "1.1.1.1") -> list:
    blocked = config["domains"]["blocked"]
    clean = config["domains"]["clean"]

    split_positions = [32, 64, 80, 128]

    print("\n[*] DPI Bypass — TLS Record Fragmentation")
    print(f"    Target        : {target_ip}:443")
    print(f"    Split points  : {split_positions}\n")

    results = []

    for sni in clean + blocked:
        normal = test_normal(target_ip, sni)
        splits = {}

        for pos in split_positions:
            time.sleep(0.1)
            splits[pos] = test_record_split(target_ip, sni, pos)

        confirmed_bypass = [
            pos for pos, r in splits.items()
            if normal == "silent_drop" and r == "server_hello"
        ]

        possible_bypass = [
            pos for pos, r in splits.items()
            if normal == "silent_drop" and r == "tls_alert"
        ]

        if confirmed_bypass:
            verdict = "confirmed_bypass"
        elif possible_bypass:
            verdict = "possible_bypass"
        elif normal == "silent_drop":
            verdict = "bypass_ineffective"
        else:
            verdict = "no_blocking"

        indicator = (
            "!" if verdict == "confirmed_bypass"
            else "?" if verdict == "possible_bypass"
            else "+" if verdict == "no_blocking"
            else "x"
        )

        split_summary = " | ".join(f"@{p}={v}" for p, v in splits.items())
        print(f"    [{indicator}] {sni:<25} normal={normal:<12} {split_summary}")
        if confirmed_bypass:
            print(f"         CONFIRMED BYPASS: {confirmed_bypass}")

        if possible_bypass:
            print(f"         POSSIBLE BYPASS: {possible_bypass}")

        results.append({
            "sni": sni,
            "category": "clean" if sni in clean else "blocked",
            "normal": normal,
            "splits": splits,
            "confirmed_bypass": confirmed_bypass,
            "possible_bypass": possible_bypass,
            "verdict": verdict,
        })

    print("\n[*] DPI Bypass — Padding Extension\n")
    padding_sizes = [64, 128, 256, 512]

    for sni in clean + blocked:
        normal = next((r["normal"] for r in results if r["sni"] == sni), None)
        pad_results = test_padding(target_ip, sni, padding_sizes)

        confirmed = [s for s, r in pad_results.items()
                     if normal == "silent_drop" and r == "server_hello"]
        possible = [s for s, r in pad_results.items()
                    if normal == "silent_drop" and r == "tls_alert"]

        verdict = "confirmed_bypass" if confirmed else \
                  "possible_bypass" if possible else \
                  "bypass_ineffective" if normal == "silent_drop" else \
                  "no_blocking"

        indicator = "!" if verdict == "confirmed_bypass" else \
                    "?" if verdict == "possible_bypass" else \
                    "+" if verdict == "no_blocking" else "x"

        pad_summary = " | ".join(f"pad{s}={r}" for s, r in pad_results.items())
        print(f"    [{indicator}] {sni:<25} {pad_summary}")

        for r in results:
            if r["sni"] == sni:
                r["padding"] = pad_results
                r["padding_bypass"] = bool(confirmed or possible)
                r["padding_confirmed"] = confirmed
                r["padding_possible"] = possible

    return results