"""Encrypted ClientHello (ECH) availability and runtime capability checks."""

from __future__ import annotations

import base64
import ssl
import time
from typing import Any

import dns.resolver


def runtime_capabilities() -> dict[str, Any]:
    """Report whether this Python TLS runtime can perform an ECH handshake."""
    api_names = ["set_ech_config_list", "set_ech_config"]
    detected = [name for name in api_names if hasattr(ssl.SSLContext, name)]
    return {
        "python_openssl": ssl.OPENSSL_VERSION,
        "detected_python_apis": detected,
        "handshake_supported": bool(detected),
        "capability_basis": "Python ssl.SSLContext API inspection; the OpenSSL version string alone is insufficient.",
    }


def _record_summary(record: Any) -> dict[str, Any]:
    params = getattr(record, "params", {})
    ech_param = params.get(5)
    ech_config = getattr(ech_param, "ech", None) if ech_param is not None else None

    alpn_param = params.get(1)
    alpn_ids = getattr(alpn_param, "ids", ()) if alpn_param is not None else ()
    alpn = [item.decode("ascii", errors="replace") for item in alpn_ids]

    return {
        "priority": getattr(record, "priority", None),
        "target": str(getattr(record, "target", "")),
        "alpn": alpn,
        "ech_present": ech_config is not None,
        "ech_config_length": len(ech_config) if ech_config is not None else 0,
        # The configuration is public DNS data; retaining it allows a capable
        # TLS implementation to use the exact published bytes later.
        "ech_config_base64": base64.b64encode(ech_config).decode("ascii") if ech_config else None,
    }


def query_https_records(hostname: str, timeout: float = 4.0) -> dict[str, Any]:
    """Fetch HTTPS/SVCB records and extract the ECH public configuration."""
    result: dict[str, Any] = {
        "hostname": hostname,
        "status": "unknown",
        "records": [],
        "rtt_ms": None,
        "error": None,
    }
    started = time.monotonic()
    try:
        answers = dns.resolver.resolve(hostname, "HTTPS", lifetime=timeout)
        result["rtt_ms"] = round((time.monotonic() - started) * 1000, 2)
        result["records"] = [_record_summary(record) for record in answers]
        result["status"] = "ok"
    except dns.resolver.NXDOMAIN:
        result["status"] = "nxdomain"
    except dns.resolver.NoAnswer:
        result["status"] = "no_https_record"
    except dns.exception.Timeout:
        result["status"] = "timeout"
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    return result


def run(hostname: str, timeout: float = 4.0) -> dict[str, Any]:
    """Run the non-invasive ECH test for one hostname."""
    hostname = hostname.rstrip(".")
    dns_result = query_https_records(hostname, timeout)
    capabilities = runtime_capabilities()
    ech_records = [record for record in dns_result["records"] if record["ech_present"]]

    result = {
        "hostname": hostname,
        "standards": ["RFC 9848 (DNS bootstrap)", "RFC 9849 (TLS ECH)"],
        "dns": dns_result,
        "runtime": capabilities,
        "ech_advertised": bool(ech_records),
        "handshake_attempted": False,
        "handshake_status": "not_supported_by_local_tls_runtime",
    }
    if capabilities["handshake_supported"]:
        # Python builds exposing this API can be wired here once their exact API
        # stabilises. Do not claim an ECH handshake from a plain TLS connection.
        result["handshake_status"] = "runtime_api_detected_not_implemented"

    print("\n[*] Encrypted ClientHello (ECH) Test")
    print(f"    Hostname          : {hostname}")
    print(f"    HTTPS DNS status  : {dns_result['status']}")
    print(f"    ECH advertised    : {'yes' if result['ech_advertised'] else 'no'}")
    if ech_records:
        print(f"    ECH config bytes  : {ech_records[0]['ech_config_length']}")
    print(f"    TLS runtime       : {capabilities['python_openssl']}")
    print(f"    ECH handshake     : {result['handshake_status']}")
    return result
