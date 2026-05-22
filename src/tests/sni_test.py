import socket
import ssl
import time

KNOWN_BLOCKED = [
    "instagram.com",
    "facebook.com", 
    "twitter.com",
    "youtube.com",
]

KNOWN_CLEAN = [
    "google.com",
    "github.com",
    "cloudflare.com",
]

def build_tls_client_hello(sni: str) -> bytes:
    """Craft a realistic TLS ClientHello mimicking a real browser"""
    sni_bytes = sni.encode()
    sni_len = len(sni_bytes)

    # SNI extension
    sni_ext = (
        b'\x00\x00' +
        (sni_len + 5).to_bytes(2, 'big') +
        (sni_len + 3).to_bytes(2, 'big') +
        b'\x00' +
        sni_len.to_bytes(2, 'big') +
        sni_bytes
    )

    # Supported groups (elliptic curves)
    supported_groups = (
        b'\x00\x0a' +
        b'\x00\x08' +
        b'\x00\x06' +
        b'\x00\x1d' +   # x25519
        b'\x00\x17' +   # secp256r1
        b'\x00\x18'     # secp384r1
    )

    # EC point formats
    ec_point_formats = (
        b'\x00\x0b' +
        b'\x00\x02' +
        b'\x01' +
        b'\x00'
    )

    # Supported versions (TLS 1.3 + 1.2)
    supported_versions = (
        b'\x00\x2b' +
        b'\x00\x05' +
        b'\x04' +
        b'\x03\x04' +   # TLS 1.3
        b'\x03\x03'     # TLS 1.2
    )

    # Signature algorithms
    sig_algs = (
        b'\x00\x0d' +
        b'\x00\x0a' +
        b'\x00\x08' +
        b'\x04\x03' +   # ecdsa_secp256r1_sha256
        b'\x08\x07' +   # ed25519
        b'\x04\x01' +   # rsa_pkcs1_sha256
        b'\x05\x01'     # rsa_pkcs1_sha384
    )

    # Key share (x25519 public key placeholder)
    key_share = (
        b'\x00\x33' +
        b'\x00\x26' +
        b'\x00\x24' +
        b'\x00\x1d' +
        b'\x00\x20' +
        b'\x00' * 32   # fake x25519 key
    )

    extensions = sni_ext + supported_groups + ec_point_formats + supported_versions + sig_algs + key_share

    # Cipher suites (modern browser selection)
    cipher_suites = (
        b'\x13\x01' +   # TLS_AES_128_GCM_SHA256
        b'\x13\x02' +   # TLS_AES_256_GCM_SHA384
        b'\x13\x03' +   # TLS_CHACHA20_POLY1305_SHA256
        b'\xc0\x2b' +   # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        b'\xc0\x2f' +   # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        b'\xc0\x2c' +   # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        b'\xc0\x30'     # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    )

    import os
    random_bytes = os.urandom(32)

    hello_body = (
        b'\x03\x03' +                               # legacy version
        random_bytes +                              # real random
        b'\x00' +                                   # session ID length
        len(cipher_suites).to_bytes(2, 'big') +
        cipher_suites +
        b'\x01\x00' +                               # compression
        len(extensions).to_bytes(2, 'big') +
        extensions
    )

    handshake = (
        b'\x01' +
        len(hello_body).to_bytes(3, 'big') +
        hello_body
    )

    record = (
        b'\x16' +
        b'\x03\x01' +
        len(handshake).to_bytes(2, 'big') +
        handshake
    )

    return record
    
def test_sni(target_ip: str, sni: str, port: int = 443, timeout: float = 4.0) -> dict:
    result = {
        "sni": sni,
        "status": None,
        "rtt_ms": None,
        "response_type": None,
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        s.connect((target_ip, port))
        rtt = round((time.time() - start) * 1000, 2)
        result["rtt_ms"] = rtt

        s.send(build_tls_client_hello(sni))
        response = s.recv(4096)
        s.close()

        if len(response) == 0:
            result["status"] = "empty"
            result["response_type"] = "possible_block"
        elif response[0] == 0x15:
            result["status"] = "alert"
            result["response_type"] = "tls_alert"
        elif response[0] == 0x16:
            result["status"] = "ok"
            result["response_type"] = "server_hello"
        else:
            result["status"] = "unknown"
            result["response_type"] = f"byte_{hex(response[0])}"

    except socket.timeout:
        result["status"] = "timeout"
        result["response_type"] = "silent_drop"
    except ConnectionResetError:
        result["status"] = "rst"
        result["response_type"] = "tcp_reset"
    except Exception as e:
        result["status"] = "error"
        result["response_type"] = str(e)

    return result

def run(target_ip: str, samples: int = 1):
    from src.stats import summarize, summarize_status

    print("\n[*] SNI Fingerprinting Test")
    print(f"    Target IP : {target_ip}")
    print(f"    Testing {len(KNOWN_BLOCKED)} blocked + {len(KNOWN_CLEAN)} clean domains")
    print(f"    Samples   : {samples}\n")

    results = []

    for sni in KNOWN_CLEAN + KNOWN_BLOCKED:
        label = "CLEAN   " if sni in KNOWN_CLEAN else "BLOCKED?"
        
        rtts = []
        statuses = []

        for _ in range(samples):
            r = test_sni(target_ip, sni)
            rtts.append(r["rtt_ms"])
            statuses.append(r["response_type"])

        stats = summarize(rtts)
        status_summary = summarize_status(statuses)
        dominant = status_summary["dominant"]
        indicator = "✓" if dominant == "server_hello" or dominant == "tls_alert" else "✗"

        if samples == 1:
            print(f"    [{indicator}] {label} {sni:<25} → {dominant} ({rtts[0]}ms)")
        else:
            print(f"    [{indicator}] {label} {sni:<25} → {dominant} ({stats['median_ms']}ms median, {int(status_summary['breakdown'].get(dominant, 0) * 100)}% consistent)")

        results.append({
            "sni": sni,
            "category": "clean" if sni in KNOWN_CLEAN else "blocked",
            "dominant_response": dominant,
            "status_breakdown": status_summary["breakdown"],
            "rtt_stats": stats,
            "observation": "consistent_with_sni_filtering" if dominant == "silent_drop" else "no_filtering_observed",
        })

    return results