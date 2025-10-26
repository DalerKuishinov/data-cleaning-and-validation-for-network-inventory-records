#!/usr/bin/env python3
# Simple runner to produce baseline outputs.
# Extend this to call your own normalization/classification steps.

import subprocess, sys
from pathlib import Path

HERE = Path(__file__).parent

def main():
    # Step 1: IPv4 normalization (example starter)
    subprocess.check_call([sys.executable, str(HERE / "datargent.py"), str(HERE / "inventory_raw.csv")])

if __name__ == "__main__":
    main()
