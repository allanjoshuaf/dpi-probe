import socket
import time
from src.tests.sni_test import build_tls_client_hello

def send_normal(s: socket.socket, payload: bytes) -> bytes:
    s.sendall(payload)
    return s.recv(4096)


def send_fragmented(s: socket.socket, payload: bytes, fragment_at: int) -> bytes:
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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

    sni_pos = payload.find(sni.encode())

    result = {
        "sni": sni,
        "normal": None,
        "cuts": {},
        "verdict": None,
    }

    # Test normal — baseline
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, 443))
        try:
            result["normal"] = interpret(send_normal(s, payload))
        except socket.timeout:
            result["normal"] = "silent_drop"
        s.close()
    except Exception as e:
        result["normal"] = f"error: {e}"

    time.sleep(0.1)

    # Positions de coupure — à l'intérieur du SNI lui-même
    if sni_pos == -1:
        result["verdict"] = "sni_not_found_in_payload"
        return result

    candidates = {
        "before_sni": sni_pos - 1,
        "sni_start":  sni_pos,
        "byte_1":     sni_pos + 1,
        "byte_2":     sni_pos + 2,
        "middle":     sni_pos + len(sni) // 2,
        "last_byte":  sni_pos + len(sni) - 1,
        "after_sni":  sni_pos + len(sni),
    }

    # Filtrer positions invalides et doublons
    seen = set()
    cuts = {}
    for name, pos in candidates.items():
        if 0 < pos < len(payload) and pos not in seen:
            cuts[name] = pos
            seen.add(pos)

    # Tester chaque position
    for cut_name, cut_pos in cuts.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target_ip, 443))
            try:
                result["cuts"][cut_name] = interpret(send_fragmented(s, payload, cut_pos))
            except socket.timeout:
                result["cuts"][cut_name] = "silent_drop"
            s.close()
        except ConnectionResetError:
            result["cuts"][cut_name] = "rst"
        except Exception as e:
            result["cuts"][cut_name] = f"error: {e}"
        time.sleep(0.1)

    # Verdict
    cut_results = list(result["cuts"].values())

    if result["normal"] == "silent_drop" and any(
        v in ("server_hello", "tls_alert") for v in cut_results
    ):
        result["verdict"] = "possible_reassembly_gap"
    elif result["normal"] == "silent_drop" and all(
        v == "silent_drop" for v in cut_results
    ):
        result["verdict"] = "full_reassembly_confirmed"
    elif (
        result["normal"] in ("server_hello", "tls_alert")
        and all(
            v in ("server_hello", "tls_alert")
            for v in cut_results
        )
    ):
        result["verdict"] = "no_blocking"
    else:
        result["verdict"] = "inconclusive"

    return result


def run(config: dict, target_ip: str = "1.1.1.1") -> list:
    blocked = config["domains"]["blocked"]
    clean   = config["domains"]["clean"]

    print("\n[*] SNI Cut-Point Fragmentation Test")
    print(f"    Target : {target_ip}:443")
    print(f"    Coupe le payload TCP à l'intérieur du SNI lui-même\n")

    results = []

    for sni in clean + blocked:
        category = "clean" if sni in clean else "blocked"
        r = test_domain(target_ip, sni)
        r["category"] = category

        verdict  = r["verdict"]
        indicator = (
            "✓" if verdict == "no_blocking"             else
            "!" if verdict == "possible_reassembly_gap" else
            "✗" if verdict == "full_reassembly_confirmed" else
            "?"
        )

        print(f"    [{indicator}] {sni:<25} normal={r['normal']:<12} → {verdict}")

        for cut_name, cut_result in r["cuts"].items():
            marker = "  ← BYPASS" if cut_result in ("server_hello", "tls_alert") else ""
            print(f"         {cut_name:<12} → {cut_result}{marker}")

        results.append(r)

    # Résumé
    print(f"\n[*] Summary")
    gaps     = [r for r in results if r["verdict"] == "possible_reassembly_gap"]
    full_ra  = [r for r in results if r["verdict"] == "full_reassembly_confirmed"]
    no_block = [r for r in results if r["verdict"] == "no_blocking"]

    print(f"    no_blocking               : {len(no_block)}")
    print(f"    full_reassembly_confirmed : {len(full_ra)}")
    print(f"    possible_reassembly_gap   : {len(gaps)}")

    if gaps:
        print(f"\n    Gaps detected :")
        for r in gaps:
            bypass_cuts = [
                name for name, val in r["cuts"].items()
                if val in ("server_hello", "tls_alert")
            ]
            print(f"      {r['sni']:<25} → {', '.join(bypass_cuts)}")

    return results