#!/usr/bin/env python3
"""
dpi-probe - DPI detection and fingerprinting tool
"""

import sys
import argparse
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
        description="dpi-probe - detect and fingerprint DPI middleboxes"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="dpi-probe 0.1.0-alpha"
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
        help="Number of times to repeat each probe (default: 1)"
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
        help="Network interface for pcap capture (default: auto)"
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
        help="ISP name to include in anonymized report e.g. Tele2, Beeline"
    )
    parser.add_argument(
        "--country",
        type=str,
        default=None,
        help="Country code to include in anonymized report e.g. RU, IR, CN"
    )

    args = parser.parse_args()
    config = cfg.load()

    if args.anonymize:
        from src import anonymize
        anonymize.run(args.anonymize, isp=args.isp, country=args.country)
        sys.exit(0)

    if args.compare:
        from src import compare
        compare.run(args.compare[0], args.compare[1])
        sys.exit(0)

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

    print(f"[*] Starting DPI probe against {args.target}")
    if args.samples > 1:
        print(f"[*] Samples per test : {args.samples}")

    pcap_enabled = args.pcap or (args.pcap_interface is not None)
    probe = Probe(args.target, samples=args.samples, config=config, profile=args.profile, pcap=pcap_enabled, pcap_interface=args.pcap_interface)
    probe.run()

if __name__ == "__main__":
    main()