import socket
import hashlib
import time
import os
import random
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


GREASE_VALUES = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
    0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
    0xeaea, 0xfafa
]
GREASE_SET = set(GREASE_VALUES)

MUTATIONS = [
    "baseline",
    "cipher_order_reversed",
    "extension_order_changed",
    "no_alpn",
    "alpn_http1_only",
    "x25519_only",
    "tls12_only",
    "padding_256",
    "grease_cipher",
    "grease_extension",
    "grease_groups",
]


# Blocs modulaires

def _sni_ext(sni: str) -> bytes:
    b = sni.encode()
    n = len(b)
    return (
        b'\x00\x00' +
        (n + 5).to_bytes(2, 'big') +
        (n + 3).to_bytes(2, 'big') +
        b'\x00' +
        n.to_bytes(2, 'big') +
        b
    )

def _supported_groups(curves: list) -> bytes:
    body = b''.join(c.to_bytes(2, 'big') for c in curves)
    return (
        b'\x00\x0a' +
        (len(body) + 2).to_bytes(2, 'big') +
        len(body).to_bytes(2, 'big') +
        body
    )

def _ec_point_formats() -> bytes:
    return b'\x00\x0b\x00\x02\x01\x00'

def _supported_versions(versions: list) -> bytes:
    body = b''.join(v.to_bytes(2, 'big') for v in versions)
    return (
        b'\x00\x2b' +
        (len(body) + 1).to_bytes(2, 'big') +
        len(body).to_bytes(1, 'big') +
        body
    )

def _sig_algs() -> bytes:
    return b'\x00\x0d\x00\x0a\x00\x08\x04\x03\x08\x07\x04\x01\x05\x01'

def _key_share(pub: bytes) -> bytes:
    return b'\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20' + pub

def _psk_modes() -> bytes:
    return b'\x00\x2d\x00\x02\x01\x01'

def _alpn(protocols: list) -> bytes:
    proto_bytes = b''.join(
        len(p).to_bytes(1, 'big') + p.encode()
        for p in protocols
    )
    return (
        b'\x00\x10' +
        (len(proto_bytes) + 2).to_bytes(2, 'big') +
        len(proto_bytes).to_bytes(2, 'big') +
        proto_bytes
    )

def _padding(size: int) -> bytes:
    return b'\x00\x15' + size.to_bytes(2, 'big') + b'\x00' * size

def _grease_ext() -> bytes:
    return b'\x0a\x0a\x00\x00'

def _wrap(extensions: bytes, ciphers: bytes, pub: bytes) -> bytes:
    # Injecter la vraie clé publique dans key_share
    placeholder = b'\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20' + b'\x00' * 32
    real_ks     = _key_share(pub)
    if placeholder in extensions:
        extensions = extensions.replace(placeholder, real_ks)

    random_bytes = os.urandom(32)
    session_id   = os.urandom(32)

    hello_body = (
        b'\x03\x03' +
        random_bytes +
        len(session_id).to_bytes(1, 'big') +
        session_id +
        len(ciphers).to_bytes(2, 'big') +
        ciphers +
        b'\x01\x00' +
        len(extensions).to_bytes(2, 'big') +
        extensions
    )
    handshake = b'\x01' + len(hello_body).to_bytes(3, 'big') + hello_body
    return b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake


# Build hello

# Placeholder pour key_share - remplacé dans _wrap()
_KS_PLACEHOLDER = b'\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20' + b'\x00' * 32

CIPHERS_BASELINE = (
    b'\x13\x01\x13\x02\x13\x03'
    b'\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30'
)
CIPHERS_REVERSED = (
    b'\xc0\x30\xc0\x2c\xc0\x2f\xc0\x2b'
    b'\x13\x03\x13\x02\x13\x01'
)
CIPHERS_GREASE = (
    b'\x0a\x0a' +
    b'\x13\x01\x13\x02\x13\x03'
    b'\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30'
)
CIPHERS_12_ONLY = b'\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30'


def build_hello(sni: str, mutation: str) -> bytes:
    priv = x25519.X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    sni_b      = _sni_ext(sni)
    grp_full   = _supported_groups([0x001d, 0x0017, 0x0018])
    grp_x25519 = _supported_groups([0x001d])
    grp_grease = _supported_groups([0x0a0a, 0x001d, 0x0017, 0x0018])
    ec         = _ec_point_formats()
    ver_13_12  = _supported_versions([0x0304, 0x0303])
    ver_12     = _supported_versions([0x0303])
    sig        = _sig_algs()
    ks         = _KS_PLACEHOLDER
    psk        = _psk_modes()
    alp        = _alpn(["h2", "http/1.1"])
    alp_h1     = _alpn(["http/1.1"])
    pad        = _padding(256)
    grease_e   = _grease_ext()

    if mutation == "baseline":
        ext = sni_b + grp_full + ec + ver_13_12 + sig + ks + psk + alp

    elif mutation == "cipher_order_reversed":
        ext = sni_b + grp_full + ec + ver_13_12 + sig + ks + psk + alp
        return _wrap(ext, CIPHERS_REVERSED, pub)

    elif mutation == "extension_order_changed":
        ext = grp_full + ec + ver_13_12 + sig + ks + psk + alp + sni_b

    elif mutation == "no_alpn":
        ext = sni_b + grp_full + ec + ver_13_12 + sig + ks + psk

    elif mutation == "alpn_http1_only":
        ext = sni_b + grp_full + ec + ver_13_12 + sig + ks + psk + alp_h1

    elif mutation == "x25519_only":
        ext = sni_b + grp_x25519 + ec + ver_13_12 + sig + ks + psk + alp

    elif mutation == "tls12_only":
        ext = sni_b + grp_full + ec + ver_12 + sig + alp
        return _wrap(ext, CIPHERS_12_ONLY, pub)

    elif mutation == "padding_256":
        ext = sni_b + grp_full + ec + ver_13_12 + sig + ks + psk + alp + pad

    elif mutation == "grease_cipher":
        ext = sni_b + grp_full + ec + ver_13_12 + sig + ks + psk + alp
        return _wrap(ext, CIPHERS_GREASE, pub)

    elif mutation == "grease_extension":
        ext = grease_e + sni_b + grp_full + ec + ver_13_12 + sig + ks + psk + alp

    elif mutation == "grease_groups":
        ext = sni_b + grp_grease + ec + ver_13_12 + sig + ks + psk + alp

    else:
        raise ValueError(f"Unknown mutation: {mutation}")

    return _wrap(ext, CIPHERS_BASELINE, pub)


# JA3

def compute_ja3(payload: bytes) -> str:
    try:
        offset = 9
        offset += 2 + 32

        sid_len = payload[offset]
        offset += 1 + sid_len

        cs_len = (payload[offset] << 8) | payload[offset + 1]
        offset += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            cs = (payload[offset + i] << 8) | payload[offset + i + 1]
            if cs not in GREASE_SET:
                ciphers.append(cs)
        offset += cs_len

        comp_len = payload[offset]
        offset += 1 + comp_len

        ext_total = (payload[offset] << 8) | payload[offset + 1]
        offset += 2
        ext_end   = offset + ext_total

        extensions = []
        curves     = []
        ec_fmts    = []

        while offset + 4 <= ext_end:
            et = (payload[offset] << 8) | payload[offset + 1]
            el = (payload[offset + 2] << 8) | payload[offset + 3]
            offset += 4

            if et not in GREASE_SET:
                extensions.append(et)

            if et == 0x000a and el >= 2:
                cl = (payload[offset] << 8) | payload[offset + 1]
                for i in range(2, 2 + cl, 2):
                    c = (payload[offset + i] << 8) | payload[offset + i + 1]
                    if c not in GREASE_SET:
                        curves.append(c)

            if et == 0x000b and el >= 1:
                fl = payload[offset]
                for i in range(1, 1 + fl):
                    ec_fmts.append(payload[offset + i])

            offset += el

        tls_ver = (payload[9] << 8) | payload[10]
        s = (
            f"{tls_ver},"
            f"{'-'.join(str(c) for c in ciphers)},"
            f"{'-'.join(str(e) for e in extensions)},"
            f"{'-'.join(str(c) for c in curves)},"
            f"{'-'.join(str(f) for f in ec_fmts)}"
        )
        return hashlib.md5(s.encode()).hexdigest()
    except Exception:
        return "parse_error"


# Probe

def probe(target_ip: str, sni: str, mutation: str,
          samples: int = 1, timeout: float = 4.0) -> dict:
    payload     = build_hello(sni, mutation)
    ja3         = compute_ja3(payload)
    statuses    = []
    alert_codes = []

    for _ in range(samples):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(timeout)
            s.connect((target_ip, 443))
            s.sendall(payload)

            try:
                resp = s.recv(4096)
            except socket.timeout:
                statuses.append("no_response_before_timeout")
                s.close()
                time.sleep(0.1)
                continue

            s.close()

            if not resp:
                statuses.append("connection_closed_no_data")
            elif resp[0] == 0x16 and len(resp) > 5 and resp[5] == 0x02:
                statuses.append("server_hello")
            elif resp[0] == 0x15:
                code = resp[6] if len(resp) > 6 else None
                statuses.append("tls_alert")
                if code:
                    alert_codes.append(code)
            else:
                statuses.append(f"unknown_{hex(resp[0])}")

        except socket.timeout:
            statuses.append("timeout")
        except ConnectionResetError:
            statuses.append("rst")
        except Exception:
            statuses.append("error")

        time.sleep(0.1)

    dominant   = max(set(statuses), key=statuses.count) if statuses else "error"
    alert_desc = None
    if alert_codes:
        code = max(set(alert_codes), key=alert_codes.count)
        alert_desc = {
            0x28: "handshake_failure",
            0x2a: "bad_record_mac",
            0x32: "decode_error",
            0x46: "illegal_parameter",
            0x47: "unknown_ca",
            0x70: "protocol_version",
            0x71: "insufficient_security",
        }.get(code, f"0x{code:02x}")

    return {
        "mutation":   mutation,
        "sni":        sni,
        "ja3":        ja3,
        "status":     dominant,
        "samples":    statuses,
        "alert_desc": alert_desc,
    }


# Conclusion

def _conclude(clean: str, blocked_results: list) -> str:
    if clean not in ("server_hello",):
        return "hello_incompatible"
    if any(r == "server_hello" for r in blocked_results):
        return "outcome_changed_with_mutation"
    if all(r in {"no_response_before_timeout", "connection_closed_no_data", "silent_drop"} for r in blocked_results):
        return "no_effect"
    if all(r == "tls_alert" for r in blocked_results):
        return "no_effect"
    return "inconclusive"


# Run

def run(config: dict, target_ips: list = None, samples: int = 1) -> list:
    if target_ips is None:
        target_ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    blocked_domains = config["domains"]["blocked"][:3]
    clean_domain    = config["domains"]["clean"][0]
    domains         = [clean_domain] + blocked_domains

    # Ordre aléatoire des mutations à chaque run
    mutations = MUTATIONS.copy()
    random.shuffle(mutations)
    # Baseline toujours en premier pour référence
    mutations.remove("baseline")
    mutations.insert(0, "baseline")

    all_results = []

    for target_ip in target_ips:
        print(f"\n[*] TLS JA3 Mutation Test - {target_ip}:443")
        print(f"    Clean    : {clean_domain}")
        print(f"    Blocked  : {', '.join(blocked_domains)}")
        print(f"    Samples  : {samples} per mutation")
        print(f"    Mutations: {len(mutations)}\n")

        header = f"    {'Mutation':<26} {'JA3':<34}"
        for d in domains:
            header += f" {d.split('.')[0][:11]:<13}"
        header += " Conclusion"
        print(header)
        print("    " + "-" * 120)

        target_results = []

        for mutation in mutations:
            row_data   = {}
            alert_info = {}
            ja3_hash   = None

            for sni in domains:
                r = probe(target_ip, sni, mutation, samples=samples)
                row_data[sni]   = r["status"]
                alert_info[sni] = r["alert_desc"]
                if ja3_hash is None:
                    ja3_hash = r["ja3"]

            clean_status   = row_data[clean_domain]
            blocked_status = [row_data[d] for d in blocked_domains]
            conclusion     = _conclude(clean_status, blocked_status)

            row = f"    {mutation:<26} {ja3_hash:<34}"
            for d in domains:
                status = row_data[d]
                label  = {
                    "server_hello": "SH",
                    "no_response_before_timeout": "no_resp",
                    "connection_closed_no_data": "eof",
                    "silent_drop":  "legacy",
                    "tls_alert":    "alert",
                    "timeout":      "timeout",
                    "rst":          "rst",
                }.get(status, status[:8])
                if status == "tls_alert" and alert_info[d]:
                    label = f"alert({alert_info[d][:8]})"
                row += f" {label:<13}"
            row += f" {conclusion}"
            print(row)

            target_results.append({
                "target_ip":  target_ip,
                "mutation":   mutation,
                "ja3":        ja3_hash,
                "results":    row_data,
                "conclusion": conclusion,
            })

        # Résumé par target
        outcome_changes = [r for r in target_results if r["conclusion"] == "outcome_changed_with_mutation"]
        print(f"\n[*] Summary - {target_ip}")
        print(f"    Mutations tested : {len(mutations)}")
        print(f"    Outcome changes  : {len(outcome_changes)}")

        if outcome_changes:
            print(f"\n    TLS outcomes changed with ClientHello mutations on {target_ip}")
            for r in outcome_changes:
                print(f"    Mutation : {r['mutation']}  JA3 : {r['ja3']}")
            print("\n    This is a differential observation, not a confirmed JA3 bypass.")
            print("    Server compatibility and on-path handling must be separated with a controlled endpoint.")
        else:
            print(f"\n    No mutation-dependent outcome change observed on {target_ip}.")
            print("    This does not prove that filtering depends only on SNI.")

        all_results.extend(target_results)

    return all_results

if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from src import config as cfg
    config = cfg.load()
    run(config)
