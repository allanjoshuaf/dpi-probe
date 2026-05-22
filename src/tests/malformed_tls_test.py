import socket
import time

def build_malformed_hello(variant: str, sni: str = "google.com") -> bytes:
    """
    Build intentionally malformed TLS ClientHello packets.
    Each variant targets a different parser weakness.
    """
    sni_bytes = sni.encode()
    sni_len = len(sni_bytes)

    sni_ext = (
        b'\x00\x00' +
        (sni_len + 5).to_bytes(2, 'big') +
        (sni_len + 3).to_bytes(2, 'big') +
        b'\x00' +
        sni_len.to_bytes(2, 'big') +
        sni_bytes
    )

    if variant == "wrong_version":
        # Claim TLS 9.9 - no such version
        hello_body = (
            b'\x09\x09' +       # fake version
            b'\x00' * 32 +
            b'\x00' +
            b'\x00\x02' +
            b'\x13\x01' +
            b'\x01\x00' +
            len(sni_ext).to_bytes(2, 'big') +
            sni_ext
        )

    elif variant == "empty_ciphers":
        # Zero cipher suites - invalid by spec
        hello_body = (
            b'\x03\x03' +
            b'\x00' * 32 +
            b'\x00' +
            b'\x00\x00' +       # 0 cipher suites
            b'\x01\x00' +
            len(sni_ext).to_bytes(2, 'big') +
            sni_ext
        )

    elif variant == "oversized_sni":
        # SNI longer than declared length
        fake_sni = b'\x00\x00' + b'\x00\x05' + b'\x00\x03' + b'\x00' + b'\x00\x01' + b'A' * 500
        hello_body = (
            b'\x03\x03' +
            b'\x00' * 32 +
            b'\x00' +
            b'\x00\x02' +
            b'\x13\x01' +
            b'\x01\x00' +
            len(fake_sni).to_bytes(2, 'big') +
            fake_sni
        )

    elif variant == "truncated":
        # Packet cut in the middle of extensions
        hello_body = (
            b'\x03\x03' +
            b'\x00' * 32 +
            b'\x00' +
            b'\x00\x02' +
            b'\x13\x01' +
            b'\x01\x00' +
            b'\x00\x10'         # claims 16 bytes of extensions but sends none
        )

    elif variant == "duplicate_sni":
        # Two SNI extensions - forbidden by RFC
        double_sni = sni_ext + sni_ext
        hello_body = (
            b'\x03\x03' +
            b'\x00' * 32 +
            b'\x00' +
            b'\x00\x02' +
            b'\x13\x01' +
            b'\x01\x00' +
            len(double_sni).to_bytes(2, 'big') +
            double_sni
        )

    else:
        raise ValueError(f"Unknown variant: {variant}")

    handshake = (
        b'\x01' +
        len(hello_body).to_bytes(3, 'big') +
        hello_body
    )

    return (
        b'\x16' +
        b'\x03\x01' +
        len(handshake).to_bytes(2, 'big') +
        handshake
    )


def probe_variant(target_ip: str, variant: str, port: int = 443, timeout: float = 4.0) -> dict:
    result = {
        "variant": variant,
        "status": None,
        "response_type": None,
        "rtt_ms": None,
        "raw_byte": None,
        "note": None,
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))

        payload = build_malformed_hello(variant)
        start = time.time()
        s.send(payload)

        try:
            response = s.recv(4096)
            rtt = round((time.time() - start) * 1000, 2)
            result["rtt_ms"] = rtt

            if len(response) == 0:
                result["status"] = "empty"
                result["response_type"] = "silent_drop"
                result["note"] = "No response - possible DPI drop"
            elif response[0] == 0x15:
                alert_desc = response[6] if len(response) > 6 else None
                result["status"] = "alert"
                result["response_type"] = "tls_alert"
                result["raw_byte"] = hex(alert_desc) if alert_desc else None
                result["note"] = f"TLS Alert code {hex(alert_desc)}" if alert_desc else "TLS Alert"
            elif response[0] == 0x16:
                result["status"] = "ok"
                result["response_type"] = "server_hello"
                result["note"] = "Server accepted malformed hello - suspicious"
            else:
                result["status"] = "unknown"
                result["raw_byte"] = hex(response[0])
                result["note"] = f"Unexpected first byte: {hex(response[0])}"

        except socket.timeout:
            result["status"] = "timeout"
            result["response_type"] = "silent_drop"
            result["note"] = "Timeout - silent drop"

        s.close()

    except ConnectionResetError:
        result["status"] = "rst"
        result["response_type"] = "tcp_reset"
        result["note"] = "TCP RST - connection killed"
    except Exception as e:
        result["status"] = "error"
        result["note"] = str(e)

    return result


def run(target_ip: str, samples: int = 1):
    from src.stats import summarize, summarize_status

    variants = [
        "wrong_version",
        "empty_ciphers",
        "oversized_sni",
        "truncated",
        "duplicate_sni",
    ]

    print("\n[*] Malformed TLS ClientHello Test")
    print(f"    Target  : {target_ip}:443")
    print(f"    Samples : {samples}\n")

    results = []

    for variant in variants:
        rtts = []
        statuses = []
        raw_bytes = []

        for _ in range(samples):
            r = probe_variant(target_ip, variant)
            rtts.append(r.get("rtt_ms"))
            statuses.append(r.get("response_type"))
            if r.get("raw_byte"):
                raw_bytes.append(r["raw_byte"])

        stats = summarize(rtts)
        status_summary = summarize_status(statuses)
        dominant = status_summary["dominant"]
        dominant_byte = max(set(raw_bytes), key=raw_bytes.count) if raw_bytes else None

        indicator = "✓" if dominant == "tls_alert" else "⚠" if dominant in ["server_hello", "unknown"] else "✗"

        if samples == 1:
            print(f"    [{indicator}] {variant:<20} → {dominant:<15} {dominant_byte or ''}")
        else:
            consistency = int(status_summary["breakdown"].get(dominant, 0) * 100)
            print(f"    [{indicator}] {variant:<20} → {dominant:<15} {stats['median_ms']}ms median  {consistency}% consistent")

        results.append({
            "variant": variant,
            "dominant_response": dominant,
            "dominant_alert_code": dominant_byte,
            "status_breakdown": status_summary["breakdown"],
            "rtt_stats": stats,
            "observation": "consistent_with_middlebox_tls_parser" if stats["median_ms"] and stats["median_ms"] < 15 else "inconclusive",
        })

    return results