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


def run(target_ip: str):
    variants = [
        "wrong_version",
        "empty_ciphers",
        "oversized_sni",
        "truncated",
        "duplicate_sni",
    ]

    print("\n[*] Malformed TLS ClientHello Test")
    print(f"    Target : {target_ip}:443\n")

    results = []
    for variant in variants:
        r = probe_variant(target_ip, variant)
        indicator = "✓" if r["status"] == "alert" else "⚠" if r["status"] in ["ok", "unknown"] else "✗"
        print(f"    [{indicator}] {variant:<20} → {r['response_type']:<15} {r['note']}")
        results.append(r)

    return results