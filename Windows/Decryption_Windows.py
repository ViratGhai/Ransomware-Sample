#!/usr/bin/env python3
"""
decryption_win.py
Decrypts files previously encrypted with encryption_win.py.

Usage:
    python decryption_win.py "C:\restore\home" "C:\restore\root" "C:\keys\ransom.key"
"""

import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


def load_key(key_path: Path) -> bytes:
    if not key_path.is_file():
        print(f"[-] Key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)
    return key_path.read_bytes()


def decrypt_file(file_path: Path, fernet: Fernet) -> None:
    try:
        data = file_path.read_bytes()
        decrypted = fernet.decrypt(data)
        file_path.write_bytes(decrypted)
        print(f"[+] Decrypted: {file_path}")
    except InvalidToken:
        print(f"[-] Not encrypted or wrong key: {file_path}", file=sys.stderr)
    except Exception as e:
        print(f"[-] Failed to decrypt {file_path}: {e}", file=sys.stderr)


def decrypt_directory(root_dir: Path, fernet: Fernet) -> None:
    for dirpath, _, filenames in os.walk(root_dir):
        for name in filenames:
            file_path = Path(dirpath) / name
            if file_path.is_file():
                decrypt_file(file_path, fernet)


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__.strip())
        sys.exit(1)

    key_path = Path(sys.argv[-1]).resolve()
    directories = [Path(p).resolve() for p in sys.argv[1:-1]]

    for d in directories:
        if not d.is_dir():
            print(f"[-] Not a directory: {d}", file=sys.stderr)
            sys.exit(1)

    key = load_key(key_path)
    fernet = Fernet(key)
    print(f"[+] Using key: {key_path}")

    print("[*] Starting decryption...")
    for d in directories:
        print(f"[*] Decrypting: {d}")
        decrypt_directory(d, fernet)

    print("[+] Decryption complete!")


if __name__ == "__main__":
    main()