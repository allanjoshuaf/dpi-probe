import socket
import time
from src.probes.sni_test import build_tls_client_hello

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
        return "connection_closed_no_data"
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
            result["normal"] = "no_response_before_timeout"
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
                result["cuts"][cut_name] = "no_response_before_timeout"
            s.close()
        except ConnectionResetError:
            result["cuts"][cut_name] = "rst"
        except Exception as e:
            result["cuts"][cut_name] = f"error: {e}"
        time.sleep(0.1)

    # Verdict
    cut_results = list(result["cuts"].values())

    no_response = {"no_response_before_timeout", "connection_closed_no_data", "silent_drop"}
    if result["normal"] in no_response and any(
        v in ("server_hello", "tls_alert") for v in cut_results
    ):
        result["verdict"] = "outcome_changed_after_tcp_segmentation"
    elif result["normal"] in no_response and all(
        v in no_response for v in cut_results
    ):
        result["verdict"] = "no_outcome_change_all_splits"
    elif (
        result["normal"] in ("server_hello", "tls_alert")
        and all(
            v in ("server_hello", "tls_alert")
            for v in cut_results
        )
    ):
        result["verdict"] = "response_for_all_segmentations"
    else:
        result["verdict"] = "inconclusive"

    return result


def run(config: dict, target_ip: str = "1.1.1.1") -> list:
    blocked = config["domains"]["blocked"]
    clean   = config["domains"]["clean"]

    print("\n[*] TCP Write-Segmentation Differential Test")
    print(f"    Target : {target_ip}:443")
    print("    This changes application write boundaries; it does not guarantee IP fragmentation.\n")

    results = []

    for sni in clean + blocked:
        category = "clean" if sni in clean else "blocked"
        r = test_domain(target_ip, sni)
        r["category"] = category

        verdict  = r["verdict"]
        indicator = (
            "✓" if verdict == "response_for_all_segmentations" else
            "!" if verdict == "outcome_changed_after_tcp_segmentation" else
            "?" if verdict == "no_outcome_change_all_splits" else
            "?"
        )

        print(f"    [{indicator}] {sni:<25} normal={r['normal']:<12} → {verdict}")

        for cut_name, cut_result in r["cuts"].items():
            marker = "  <- RESPONSE" if cut_result in ("server_hello", "tls_alert") else ""
            print(f"         {cut_name:<12} → {cut_result}{marker}")

        results.append(r)

    # Résumé
    print(f"\n[*] Summary")
    gaps = [r for r in results if r["verdict"] == "outcome_changed_after_tcp_segmentation"]
    full_ra = [r for r in results if r["verdict"] == "no_outcome_change_all_splits"]
    no_block = [r for r in results if r["verdict"] == "response_for_all_segmentations"]

    print(f"    response_for_all_segmentations      : {len(no_block)}")
    print(f"    no_outcome_change_all_splits        : {len(full_ra)}")
    print(f"    outcome_changed_after_segmentation  : {len(gaps)}")

    if gaps:
        print("\n    Outcome changes (attribution unresolved):")
        for r in gaps:
            changed_cuts = [
                name for name, val in r["cuts"].items()
                if val in ("server_hello", "tls_alert")
            ]
            print(f"      {r['sni']:<25} → {', '.join(changed_cuts)}")

    return results
