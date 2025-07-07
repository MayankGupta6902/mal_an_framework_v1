#!/usr/bin/env python3

import pefile
import sys
import os

def calculate_imphash(filepath):
    if not os.path.isfile(filepath):
        print(f"[!] File not found: {filepath}")
        return
    try:
        pe = pefile.PE(filepath)
        print(f"[+] File: {filepath}")
        print(f"[+] Imphash: {pe.get_imphash()}")
    except Exception as e:
        print(f"[!] Error processing {filepath}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python imphash_calc.py <path_to_pe_file>")
    else:
        calculate_imphash(sys.argv[1])
