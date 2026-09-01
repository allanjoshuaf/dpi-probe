#!/usr/bin/env python3
"""dpi-probe: evidence collection for network interference and tunnel faults."""

import sys
import argparse
import ipaddress
import json
import os
from src.probe import Probe
from src import autodetect
from src import config as cfg

def configure_console_encoding():
    """Avoid Windows cp1252 crashes when printing Unicode status markers."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def main():
    configure_console_encoding()

    parser = argparse.ArgumentParser(
        description="dpi-probe - collect evidence about network interference and tunnel failures"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="dpi-probe 0.2.0-alpha"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target IP to probe (omit for auto-detection mode)"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="Number of repetitions for sampling-aware probes (default: 1)"
    )
    parser.add_argument(
        "--multi",
        action="store_true",
        help="Probe all targets from targets.json in one run"
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Network condition label e.g. no-vpn, adguard, reality, mobile"
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("REPORT_A", "REPORT_B"),
        help="Compare two report files"
    )
    parser.add_argument(
        "--pcap",
        action="store_true",
        help="Capture and analyze packets with tshark during probe"
    )
    parser.add_argument(
        "--pcap-interface",
        type=str,
        default=None,
        help="Verified tshark interface used for packet capture"
    )
    parser.add_argument(
        "--anonymize",
        type=str,
        default=None,
        metavar="REPORT",
        help="Anonymize a report for voluntary sharing"
    )
    parser.add_argument(
        "--isp",
        type=str,
        default=None,
        help="Optional ISP label to include in an anonymized report"
    )
    parser.add_argument(
        "--country",
        type=str,
        default=None,
        help="Optional two-letter country code to include in an anonymized report"
    )
    parser.add_argument(
        "--ech",
        metavar="HOSTNAME",
        help="Inspect HTTPS DNS records and local ECH handshake support for one hostname"
    )
    parser.add_argument(
        "--reverse-trace",
        metavar="PUBLIC_IP",
        help="Run a traceroute from a controlled remote SSH agent back to this public IP"
    )
    parser.add_argument(
        "--reverse-agent",
        metavar="USER_AT_HOST",
        help="SSH destination for --reverse-trace (for example probe@198.51.100.10)"
    )
    parser.add_argument(
        "--reverse-agent-os",
        choices=("linux", "windows"),
        default="linux",
        help="Operating system of --reverse-agent (default: linux)"
    )
    parser.add_argument(
        "--reverse-max-hops",
        type=int,
        default=30,
        help="Maximum reverse-traceroute hops, 1-64 (default: 30)"
    )
    parser.add_argument(
        "--reverse-timeout-ms",
        type=int,
        default=2000,
        help="Per-hop reverse-traceroute timeout, 100-10000 ms (default: 2000)"
    )
    parser.add_argument(
        "--diagnose-tunnel",
        action="store_true",
        help="Diagnose a sing-box VLESS/REALITY endpoint from config, log and/or PCAP evidence"
    )
    parser.add_argument("--tunnel-endpoint", metavar="HOST:PORT", help="REALITY server endpoint")
    parser.add_argument("--sing-box-config", metavar="FILE", help="sing-box JSON config (secrets are not copied to reports)")
    parser.add_argument("--sing-box-log", metavar="FILE", help="timestamped sing-box log covering the failure")
    parser.add_argument("--tunnel-pcap", metavar="FILE", help="client-side PCAP of the REALITY endpoint")
    parser.add_argument("--sing-box-api", metavar="URL", help="local Clash API, usually http://127.0.0.1:9090")
    parser.add_argument(
        "--sing-box-secret-env",
        metavar="ENV_NAME",
        help="environment variable containing the Clash API secret (avoids command-history leakage)"
    )
    parser.add_argument("--active-tunnel-checks", action="store_true", help="run TCP and traceroute checks to the tunnel endpoint")
    parser.add_argument(
        "--underlay-interface-index",
        type=int,
        help="force active endpoint TCP checks onto this physical Windows interface index",
    )
    parser.add_argument("--diagnosis-output", metavar="FILE", help="path for the tunnel diagnosis JSON")
    parser.add_argument(
        "--dual-pcap",
        nargs=2,
        metavar=("CLIENT_PCAP", "SERVER_PCAP"),
        help="compare client and server captures using absolute TCP sequence numbers"
    )
    parser.add_argument("--flow-output", metavar="FILE", help="output JSON path for --dual-pcap")

    args = parser.parse_args()

    if args.samples < 1:
        parser.error("--samples must be at least 1")
    exclusive_modes = [
        bool(args.multi), bool(args.compare), bool(args.anonymize), bool(args.ech),
        bool(args.reverse_trace), bool(args.diagnose_tunnel), bool(args.dual_pcap),
    ]
    if sum(exclusive_modes) > 1:
        parser.error("choose only one operation mode: --multi, --compare, --anonymize, --ech, --reverse-trace, --diagnose-tunnel, or --dual-pcap")
    if args.target and any(exclusive_modes):
        parser.error("the positional target cannot be combined with another operation mode")
    if args.pcap and not args.pcap_interface:
        parser.error("--pcap requires --pcap-interface N; list interfaces with: py -c \"from src import pcap; [print(i) for i in pcap.list_interfaces()]\"")

    if args.dual_pcap:
        if not args.tunnel_endpoint:
            parser.error("--dual-pcap requires --tunnel-endpoint HOST:PORT")
        from src import flow_analysis
        try:
            analysis = flow_analysis.compare_vantages(
                args.dual_pcap[0], args.dual_pcap[1], args.tunnel_endpoint
            )
        except (ValueError, OSError, RuntimeError) as exc:
            parser.error(str(exc))
        output = args.flow_output or "reports/dual_pcap_analysis.json"
        flow_analysis.save_analysis(analysis, output)
        print(f"[*] Dual-vantage assessment : {analysis['assessment']}")
        print(f"    Forward missing payload : {analysis['forward_payload_packets_missing_at_server']}")
        print(f"    Reverse missing payload : {analysis['reverse_payload_packets_missing_at_client']}")
        print(f"    Client-only server RST  : {analysis['server_to_client_resets_seen_only_at_client']}")
        print(f"    Report                  : {output}")
        sys.exit(0)

    if args.diagnose_tunnel:
        from src import tunnel_diagnose
        secret = None
        if args.sing_box_secret_env:
            secret = os.environ.get(args.sing_box_secret_env)
            if secret is None:
                parser.error(f"environment variable {args.sing_box_secret_env!r} is not set")
        try:
            tunnel_diagnose.run(
                endpoint=args.tunnel_endpoint,
                config_path=args.sing_box_config,
                log_path=args.sing_box_log,
                pcap_path=args.tunnel_pcap,
                clash_api=args.sing_box_api,
                clash_secret=secret,
                active_checks=args.active_tunnel_checks,
                underlay_interface_index=args.underlay_interface_index,
                output_path=args.diagnosis_output,
            )
        except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        sys.exit(0)

    if args.ech:
        from src.probes import ech_test
        ech_test.run(args.ech)
        sys.exit(0)

    if args.reverse_trace:
        if not args.reverse_agent:
            parser.error("--reverse-trace requires --reverse-agent USER_AT_HOST")
        from src import reverse_traceroute
        try:
            reverse_traceroute.run(
                args.reverse_agent,
                args.reverse_trace,
                agent_os=args.reverse_agent_os,
                max_hops=args.reverse_max_hops,
                timeout_ms=args.reverse_timeout_ms,
            )
        except ValueError as exc:
            parser.error(str(exc))
        sys.exit(0)

    if args.anonymize:
        from src import anonymize
        anonymize.run(args.anonymize, isp=args.isp, country=args.country)
        sys.exit(0)

    if args.compare:
        from src import compare
        compare.run(args.compare[0], args.compare[1])
        sys.exit(0)

    try:
        config = cfg.load()
    except ValueError as exc:
        parser.error(str(exc))

    if args.multi:
        targets = config.get("targets", [])
        print(f"[*] Multi-target mode - {len(targets)} targets")
        if args.samples > 1:
            print(f"[*] Samples per test : {args.samples}\n")
        for t in targets:
            print(f"\n{'='*50}")
            print(f"  Target : {t['name']} - {t['ip']}")
            print(f"{'='*50}")
            pcap_enabled = args.pcap or (args.pcap_interface is not None)
            probe = Probe(t["ip"], samples=args.samples, config=config, profile=args.profile, pcap=pcap_enabled, pcap_interface=args.pcap_interface)
            probe.run()
        sys.exit(0)

    if not args.target:
        print("[*] No target specified - running auto-detection mode")
        autodetect.run()
        sys.exit(0)

    try:
        target_address = ipaddress.ip_address(args.target)
        if target_address.version != 4:
            parser.error("only IPv4 targets are currently supported")
    except ValueError:
        parser.error("target must be a valid IPv4 address")

    print(f"[*] Starting DPI probe against {args.target}")
    if args.samples > 1:
        print(f"[*] Samples per test : {args.samples}")

    pcap_enabled = args.pcap or (args.pcap_interface is not None)
    probe = Probe(args.target, samples=args.samples, config=config, profile=args.profile, pcap=pcap_enabled, pcap_interface=args.pcap_interface)
    probe.run()

if __name__ == "__main__":
    main()
