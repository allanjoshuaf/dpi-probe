import socket
import hashlib
import time
from src.probes.sni_test import build_tls_client_hello


GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
          0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
          0xeaea, 0xfafa}


def parse_client_hello(data: bytes) -> dict | None:
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None

        offset = 5
        if data[offset] != 0x01:
            return None
        offset += 4

        tls_version = (data[offset] << 8) | data[offset + 1]
        offset += 2

        offset += 32  # random

        session_id_len = data[offset]
        offset += 1 + session_id_len

        cs_len = (data[offset] << 8) | data[offset + 1]
        offset += 2
        cipher_suites = []
        for i in range(0, cs_len, 2):
            cs = (data[offset + i] << 8) | data[offset + i + 1]
            if cs not in GREASE:
                cipher_suites.append(cs)
        offset += cs_len

        comp_len = data[offset]
        offset += 1 + comp_len

        extensions      = []
        elliptic_curves = []
        ec_point_formats = []
        has_sni         = False
        has_alpn        = False
        has_padding     = False
        alpn_protocols  = []

        if offset + 2 <= len(data):
            ext_total = (data[offset] << 8) | data[offset + 1]
            offset += 2
            ext_end = offset + ext_total

            while offset + 4 <= ext_end:
                ext_type = (data[offset] << 8) | data[offset + 1]
                ext_len  = (data[offset + 2] << 8) | data[offset + 3]
                offset += 4

                if ext_type not in GREASE:
                    extensions.append(ext_type)

                # SNI (0x0000)
                if ext_type == 0x0000:
                    has_sni = True

                # supported_groups (0x000a)
                if ext_type == 0x000a and ext_len >= 2:
                    curves_len = (data[offset] << 8) | data[offset + 1]
                    for i in range(2, 2 + curves_len, 2):
                        if offset + i + 1 < len(data):
                            curve = (data[offset + i] << 8) | data[offset + i + 1]
                            if curve not in GREASE:
                                elliptic_curves.append(curve)

                # ec_point_formats (0x000b)
                if ext_type == 0x000b and ext_len >= 1:
                    fmt_len = data[offset]
                    for i in range(1, 1 + fmt_len):
                        if offset + i < len(data):
                            ec_point_formats.append(data[offset + i])

                # ALPN (0x0010)
                if ext_type == 0x0010:
                    has_alpn = True
                    try:
                        proto_list_len = (data[offset] << 8) | data[offset + 1]
                        pos = offset + 2
                        while pos < offset + 2 + proto_list_len:
                            proto_len = data[pos]
                            proto = data[pos + 1: pos + 1 + proto_len].decode(errors="ignore")
                            alpn_protocols.append(proto)
                            pos += 1 + proto_len
                    except IndexError:
                        # A truncated extension is evidence of an incomplete
                        # capture, not a reason to discard the whole probe.
                        pass

                # Padding (0x0015)
                if ext_type == 0x0015:
                    has_padding = True

                offset += ext_len

        return {
            "tls_version":       tls_version,
            "cipher_suites":     cipher_suites,
            "cipher_count":      len(cipher_suites),
            "extensions":        extensions,
            "extension_count":   len(extensions),
            "elliptic_curves":   elliptic_curves,
            "ec_point_formats":  ec_point_formats,
            "has_sni":           has_sni,
            "has_alpn":          has_alpn,
            "has_padding":       has_padding,
            "alpn_protocols":    alpn_protocols,
        }

    except Exception:
        return None


def parse_server_hello(data: bytes) -> dict | None:
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None

        offset = 5
        if data[offset] != 0x02:
            return None
        offset += 4

        tls_version = (data[offset] << 8) | data[offset + 1]
        offset += 2

        offset += 32  # random

        session_id_len = data[offset]
        offset += 1 + session_id_len

        cipher_suite = (data[offset] << 8) | data[offset + 1]
        offset += 2

        offset += 1  # compression

        extensions = []

        if offset + 2 <= len(data):
            ext_total = (data[offset] << 8) | data[offset + 1]
            offset += 2
            ext_end = offset + ext_total

            while offset + 4 <= ext_end:
                ext_type = (data[offset] << 8) | data[offset + 1]
                ext_len  = (data[offset + 2] << 8) | data[offset + 3]
                offset += 4
                if ext_type not in GREASE:
                    extensions.append(ext_type)
                offset += ext_len

        return {
            "tls_version":  tls_version,
            "cipher_suite": cipher_suite,
            "extensions":   extensions,
        }

    except Exception:
        return None


def compute_ja3(parsed: dict) -> tuple[str, str]:
    fields = [
        str(parsed["tls_version"]),
        "-".join(str(c) for c in parsed["cipher_suites"]),
        "-".join(str(e) for e in parsed["extensions"]),
        "-".join(str(c) for c in parsed["elliptic_curves"]),
        "-".join(str(f) for f in parsed["ec_point_formats"]),
    ]
    ja3_string = ",".join(fields)
    ja3_hash   = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_hash, ja3_string


def compute_ja3s(parsed: dict) -> tuple[str, str]:
    fields = [
        str(parsed["tls_version"]),
        str(parsed["cipher_suite"]),
        "-".join(str(e) for e in parsed["extensions"]),
    ]
    ja3s_string = ",".join(fields)
    ja3s_hash   = hashlib.md5(ja3s_string.encode()).hexdigest()
    return ja3s_hash, ja3s_string


def probe(target_ip: str, sni: str, timeout: float = 4.0) -> dict:
    payload = build_tls_client_hello(sni)

    result = {
        "sni":              sni,
        "target_ip":        target_ip,
        "status":           None,
        "ja3":              None,
        "ja3_string":       None,
        "ja3s":             None,
        "ja3s_string":      None,
        "clienthello_size": len(payload),
        "cipher_count":     None,
        "extension_count":  None,
        "elliptic_curves":  None,
        "has_sni":          None,
        "has_alpn":         None,
        "has_padding":      None,
        "alpn_protocols":   None,
    }

    parsed_ch = parse_client_hello(payload)
    if parsed_ch:
        result["ja3"], result["ja3_string"] = compute_ja3(parsed_ch)
        result["cipher_count"]    = parsed_ch["cipher_count"]
        result["extension_count"] = parsed_ch["extension_count"]
        result["elliptic_curves"] = parsed_ch["elliptic_curves"]
        result["has_sni"]         = parsed_ch["has_sni"]
        result["has_alpn"]        = parsed_ch["has_alpn"]
        result["has_padding"]     = parsed_ch["has_padding"]
        result["alpn_protocols"]  = parsed_ch["alpn_protocols"]

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(timeout)
        s.connect((target_ip, 443))
        s.sendall(payload)

        try:
            response = s.recv(4096)
        except socket.timeout:
            result["status"] = "no_response_before_timeout"
            s.close()
            return result

        s.close()

        if not response:
            result["status"] = "connection_closed_no_data"
        elif response[0] == 0x16 and len(response) > 5 and response[5] == 0x02:
            result["status"] = "server_hello"
            parsed_sh = parse_server_hello(response)
            if parsed_sh:
                result["ja3s"], result["ja3s_string"] = compute_ja3s(parsed_sh)
        elif response[0] == 0x15:
            result["status"] = "tls_alert"
            parsed_sh = parse_server_hello(response)
            if parsed_sh:
                result["ja3s"], result["ja3s_string"] = compute_ja3s(parsed_sh)
        else:
            result["status"] = f"unknown_{hex(response[0])}"

    except socket.timeout:
        result["status"] = "timeout"
    except ConnectionResetError:
        result["status"] = "rst"
    except Exception as e:
        result["status"] = f"error: {e}"

    return result


def run(config: dict, target_ip: str = "1.1.1.1") -> list:
    blocked = config["domains"]["blocked"]
    clean   = config["domains"]["clean"]

    print("\n[*] TLS JA3 Baseline")
    print(f"    Target : {target_ip}:443\n")

    results   = []
    ja3_seen  = {}
    ja3s_seen = {}

    for sni in clean + blocked:
        category = "clean" if sni in clean else "blocked"
        r = probe(target_ip, sni)
        r["category"] = category

        indicator = (
            "✓" if r["status"] == "server_hello" else
            "⚠" if r["status"] == "tls_alert"    else
            "✗"
        )

        print(f"    [{indicator}] {sni:<25} → {r['status']}")
        print(f"         JA3          : {r['ja3'] or 'N/A'}")
        print(f"         JA3S         : {r['ja3s'] or 'N/A'}")
        print(f"         hello_size   : {r['clienthello_size']} bytes")
        print(f"         ciphers      : {r['cipher_count']}")
        print(f"         extensions   : {r['extension_count']}")
        print(f"         curves       : {r['elliptic_curves']}")
        print(f"         sni={r['has_sni']} alpn={r['has_alpn']} padding={r['has_padding']}")
        if r["alpn_protocols"]:
            print(f"         alpn         : {r['alpn_protocols']}")

        if r["ja3"]:
            ja3_seen.setdefault(r["ja3"], []).append(sni)
        if r["ja3s"]:
            ja3s_seen.setdefault(r["ja3s"], []).append(sni)

        results.append(r)
        time.sleep(0.1)

    print(f"\n[*] JA3 Baseline Summary")

    print(f"\n    Our ClientHello (JA3) :")
    for h, domains in ja3_seen.items():
        print(f"      {h} — {len(domains)} domain(s)")
        # JA3 identique pour tous — attendu

    print(f"\n    Server responses (JA3S) :")
    if ja3s_seen:
        for h, domains in ja3s_seen.items():
            print(f"      {h} — {', '.join(domains)}")
        if len(ja3s_seen) > 1:
            print(f"\n    Multiple JA3S signatures observed.")
            print(f"    This may indicate different TLS implementations,")
            print(f"    different servers, or an intermediary generating")
            print(f"    TLS responses on the path.")
        else:
            print(f"\n    Single JA3S signature — consistent responder.")
    else:
        print(f"      No ServerHello received on any domain.")
        print("      JA3S unavailable - no ServerHello was parsed from the responses.")

    return results
