#!/usr/bin/env python3
"""
dpi-probe — DPI detection and fingerprinting tool
"""

import sys
from src.probe import Probe

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(f"[*] Starting DPI probe against {target}")
    
    probe = Probe(target)
    probe.run()

if __name__ == "__main__":
    main()