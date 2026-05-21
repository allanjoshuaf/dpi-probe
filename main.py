#!/usr/bin/env python3
"""
dpi-probe - DPI detection and fingerprinting tool
"""

import sys
from src.probe import Probe
from src import autodetect

def main():
    if len(sys.argv) < 2:
        print("[*] No target specified; running auto-detection mode")
        result = autodetect.run()
        sys.exit(0)

    target = sys.argv[1]
    print(f"[*] Starting DPI probe against {target}")

    probe = Probe(target)
    probe.run()

if __name__ == "__main__":
    main()