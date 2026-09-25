#!/usr/bin/env python3
"""
ReconShot — Automated Web Application Screenshot Reconnaissance
Author  : Mr Dinesh Pathro
Support : https://buymeacoffee.com/mrdineshpathro

Usage:
    python3 reconshot.py -u https://example.com
    python3 reconshot.py -l urls.txt --workers 5 --report
    cat urls.txt | python3 reconshot.py
"""

import sys
from reconshot.cli import main

if __name__ == "__main__":
    main()
