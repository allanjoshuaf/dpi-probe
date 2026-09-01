import socket
import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import dns.resolver
from src.probes.sni_test import build_tls_client_hello


def resolve_ip(sni: str, via: str = "1.1.1.1") -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [via]
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        answers = resolver.resolve(sni, "A")
        return str(answers[0])
    except Exception:
        return None


def validate_bypass(sni: str, split_pos: int, target_ip: str = None, timeout: float = 8.0) -> dict:
    """
    Observe la première réponse TLS après segmentation vers l'IP résolue.

    Cette fonction conserve son nom historique mais ne valide ni une session
    TLS complète, ni un contournement de DPI.
    """
    resolved_ip = target_ip or resolve_ip(sni)

    result = {
        "sni":                sni,
        "target_ip":          resolved_ip,
        "split_pos":          split_pos,
        "tcp_connected":      False,
        "first_record_sent":  False,
        "second_record_sent": False,
        "server_response":    None,
        "server_hello_observed": False,
        "application_session_validated": False,
        "status":             None,
    }

    if not resolved_ip:
        result["status"] = "dns_failed"
        return result

    payload = build_tls_client_hello(sni)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(timeout)
        s.connect((resolved_ip, 443))
        result["tcp_connected"] = True

        s.sendall(payload[:split_pos])
        result["first_record_sent"] = True

        time.sleep(0.05)

        s.sendall(payload[split_pos:])
        result["second_record_sent"] = True

        data = b""

        while True:
            try:
                chunk = s.recv(4096)

                if not chunk:
                    break

                data += chunk

            except socket.timeout:
                break

        s.close()

        if not data:
            result["status"] = "connection_closed_no_data"

        elif data[0] == 0x16:
            result["server_hello_observed"] = True
            result["server_response"] = "tls_handshake_record"
            result["status"] = "server_hello_observed"

        elif data[0] == 0x15:
            alert_level = data[5] if len(data) > 5 else None
            alert_desc = data[6] if len(data) > 6 else None
            result["server_response"] = "tls_alert"
            result["alert_level"]     = alert_level
            result["alert_desc"]      = hex(alert_desc) if alert_desc else None
            result["status"]          = "tls_rejected"
        else:
            result["server_response"] = f"unknown_{hex(data[0])}"
            result["status"]          = "unexpected"

    except socket.timeout:
        result["status"] = "timeout"
    except ConnectionResetError:
        result["status"] = "rst"
    except Exception as e:
        result["status"] = f"error: {e}"

    return result


def run() -> list:
    candidates = [
        {"sni": "instagram.com", "split": 128},
        {"sni": "facebook.com",  "split": 127},
        {"sni": "twitter.com",   "split": 126},
    ]

    print("\n[*] TLS Record-Split Follow-up — Resolved Destination")
    print("    Résolution DNS via 1.1.1.1 — IP réelle du domaine")
    print("    Observation de la première réponse; aucun bypass n'est présumé\n")

    results = []

    for c in candidates:
        r = validate_bypass(c["sni"], c["split"])

        status    = r["status"]
        indicator = "✓" if status == "server_hello_observed" else "✗"

        print(f"    [{indicator}] {c['sni']:<25} ip={r.get('target_ip') or 'dns_failed':<16} split={c['split']} → {status}")

        if status == "tls_rejected" and r.get("alert_desc"):
            print(f"         TLS alert: level={r['alert_level']} desc={r['alert_desc']}")

        if status == "server_hello_observed":
            print(f"         ServerHello reçu — handshake TLS initié")
            print(f"         Note: ServerHello ne garantit pas une session complète")
            print(f"               Les étapes suivantes (Certificate, Finished) peuvent échouer")

        results.append(r)

    print()
    validated = [r for r in results if r["status"] == "server_hello_observed"]
    rejected  = [r for r in results if r["status"] == "tls_rejected"]
    dropped   = [r for r in results if r["status"] in ("connection_closed_no_data", "timeout", "timeout_after_hello")]

    print(f"[*] Résumé")
    print(f"    server_hello_observed : {len(validated)}")
    print(f"    tls_rejected     : {len(rejected)}")
    print(f"    no_response_or_eof   : {len(dropped)}")

    if validated:
        print("\n    Un ServerHello a été observé après segmentation du ClientHello.")
        print("    Cela ne localise pas le traitement et ne valide pas une session applicative complète.")

    if rejected:
        print(f"\n    TLS alert reçu — le serveur a rejeté le ClientHello.")
        print("    L'origine exacte de l'alerte exige une capture serveur ou un endpoint contrôlé.")

    if dropped and not validated and not rejected:
        print("\n    Aucune réponse avant le délai, ou fermeture sans données, sur l'IP résolue.")
        print("    Cela ne permet pas d'attribuer la perte au réseau ou au serveur.")

    return results


if __name__ == "__main__":
    run()
