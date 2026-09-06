import socket
import time
from src.probes.sni_test import build_tls_client_hello

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
        return "connection_closed_no_data"
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
            return "no_response_before_timeout"
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
            return "no_response_before_timeout"
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
                results[size] = "no_response_before_timeout"
            finally:
                s.close()
        except Exception as e:
            results[size] = f"error: {e}"
        time.sleep(0.1)
    return results

def randomize_case(sni: str) -> str:
    import random
    letters = [index for index, char in enumerate(sni) if char.lower() != char.upper()]
    if not letters:
        return sni
    variant = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in sni)
    if variant == sni:
        index = random.choice(letters)
        variant = variant[:index] + variant[index].swapcase() + variant[index + 1:]
    return variant

def test_case_randomization(target_ip: str, sni: str, attempts: int = 3, timeout: float = 4.0) -> dict:
    results = []
    variants = []
    for _ in range(attempts):
        variant = randomize_case(sni)
        variants.append(variant)
        try:
            s = connect(target_ip, timeout)
            s.sendall(build_tls_client_hello(variant))
            try:
                results.append(interpret(s.recv(4096)))
            except socket.timeout:
                results.append("no_response_before_timeout")
            finally:
                s.close()
        except Exception as e:
            results.append(f"error: {e}")
        time.sleep(0.1)

    responses = [r for r in results if r in {"server_hello", "tls_alert"}]

    if len(responses) == attempts:
        verdict = "response_for_all_case_variants"
    elif len(responses) > 0:
        verdict = "response_for_some_case_variants"
    else:
        verdict = "no_response_for_case_variants"

    return {
        "sni": sni,
        "variants_tested": variants,
        "results": results,
        "response_count": len(responses),
        "verdict": verdict
    }

def run(config: dict, target_ip: str = "1.1.1.1") -> list:
    blocked = config["domains"]["blocked"]
    clean = config["domains"]["clean"]

    split_positions = [128]

    print("\n[*] TLS Record-Split Differential Test")
    print(f"    Target        : {target_ip}:443")
    print(f"    Split points  : {split_positions}\n")

    results = []

    for sni in clean + blocked:
        normal = test_normal(target_ip, sni)
        splits = {}

        hello = build_tls_client_hello(sni)

        needle = b"\x00\x17\x00\x18"
        pos = hello.find(needle)

        if pos == -1:
            print(f"[!] motif non trouvé pour {sni}")
            continue

        split_positions = [pos + 2]

        for split_at in split_positions:
            time.sleep(0.1)
            splits[split_at] = test_record_split(
                target_ip,
                sni,
                split_at
            )

        server_hello_changes = [
            pos for pos, r in splits.items()
            if normal in {"silent_drop", "no_response_before_timeout", "connection_closed_no_data"} and r == "server_hello"
        ]

        tls_alert_changes = [
            pos for pos, r in splits.items()
            if normal in {"silent_drop", "no_response_before_timeout", "connection_closed_no_data"} and r == "tls_alert"
        ]

        if server_hello_changes:
            verdict = "server_hello_only_after_record_split"
        elif tls_alert_changes:
            verdict = "tls_alert_only_after_record_split"
        elif normal in {"silent_drop", "no_response_before_timeout", "connection_closed_no_data"}:
            verdict = "no_response_with_or_without_record_split"
        else:
            verdict = "baseline_already_responded"

        indicator = (
            "!" if verdict == "server_hello_only_after_record_split"
            else "?" if verdict == "tls_alert_only_after_record_split"
            else "+" if verdict == "baseline_already_responded"
            else "x"
        )

        split_summary = " | ".join(f"@{p}={v}" for p, v in splits.items())
        print(f"    [{indicator}] {sni:<25} normal={normal:<12} {split_summary}")
        if server_hello_changes:
            print(f"         OUTCOME CHANGE (ServerHello): {server_hello_changes}")

        if tls_alert_changes:
            print(f"         OUTCOME CHANGE (TLS alert): {tls_alert_changes}")

        results.append({
            "sni": sni,
            "category": "clean" if sni in clean else "blocked",
            "normal": normal,
            "splits": splits,
            "server_hello_after_record_split": server_hello_changes,
            "tls_alert_after_record_split": tls_alert_changes,
            "verdict": verdict,
        })

    print("\n[*] TLS Padding Outcome Differential\n")
    padding_sizes = [64, 128, 256, 512]

    for sni in clean + blocked:
        normal = next((r["normal"] for r in results if r["sni"] == sni), None)
        pad_results = test_padding(target_ip, sni, padding_sizes)

        server_hello_changes = [s for s, r in pad_results.items()
                     if normal in {"silent_drop", "no_response_before_timeout", "connection_closed_no_data"} and r == "server_hello"]
        tls_alert_changes = [s for s, r in pad_results.items()
                    if normal in {"silent_drop", "no_response_before_timeout", "connection_closed_no_data"} and r == "tls_alert"]

        verdict = "server_hello_only_with_padding" if server_hello_changes else \
                  "tls_alert_only_with_padding" if tls_alert_changes else \
                  "no_response_with_or_without_padding" if normal in {"silent_drop", "no_response_before_timeout", "connection_closed_no_data"} else \
                  "baseline_already_responded"

        indicator = "!" if verdict == "server_hello_only_with_padding" else \
                    "?" if verdict == "tls_alert_only_with_padding" else \
                    "+" if verdict == "baseline_already_responded" else "x"

        pad_summary = " | ".join(f"pad{s}={r}" for s, r in pad_results.items())
        print(f"    [{indicator}] {sni:<25} {pad_summary}")

        for r in results:
            if r["sni"] == sni:
                r["padding"] = pad_results
                r["padding_outcome_changed"] = bool(server_hello_changes or tls_alert_changes)
                r["padding_server_hello_changes"] = server_hello_changes
                r["padding_tls_alert_changes"] = tls_alert_changes

    print("\n[*] SNI Case Outcome Differential\n")

    for sni in blocked:
        r = test_case_randomization(target_ip, sni)

        if r["verdict"] == "response_for_all_case_variants":
            indicator = "!"
        elif r["verdict"] == "response_for_some_case_variants":
            indicator = "?"
        else:
            indicator = "x"

        variants_str = " | ".join(
            f"{v}={res}"
            for v, res in zip(r["variants_tested"], r["results"])
        )

        print(f"    [{indicator}] {sni:<25} {variants_str}")

        for existing in results:
            if existing["sni"] == sni:
                existing["case_randomization"] = r

    return results
