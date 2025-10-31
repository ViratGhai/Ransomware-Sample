#!/usr/bin/env python3
"""
encryption_win.py
Windows-compatible encryptor.
"""

import os
import sys
import getpass
import shutil
from pathlib import Path
from cryptography.fernet import Fernet
import zipfile
from zipfile import ZipFile, ZIP_DEFLATED


def generate_key(key_path: Path) -> bytes:
    key = Fernet.generate_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    print(f"[+] New encryption key saved: {key_path}")
    return key


def load_key(key_path: Path) -> bytes:
    if not key_path.is_file():
        print(f"[-] Key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)
    return key_path.read_bytes()


def encrypt_file(file_path: Path, fernet: Fernet) -> None:
    try:
        data = file_path.read_bytes()
        encrypted = fernet.encrypt(data)
        file_path.write_bytes(encrypted)
        print(f"[+] Encrypted: {file_path}")
    except Exception as e:
        print(f"[-] Failed to encrypt {file_path}: {e}", file=sys.stderr)


def encrypt_directory(root_dir: Path, fernet: Fernet) -> None:
    for dirpath, _, filenames in os.walk(root_dir):
        for name in filenames:
            file_path = Path(dirpath) / name
            if file_path.is_file():
                if file_path.suffix.lower() == '.zip' and file_path.name == root_dir.name + '.zip':
                    continue
                encrypt_file(file_path, fernet)


def create_password_protected_zip(dir_path: Path, password: str) -> Path:
    zip_path = dir_path.with_suffix(".zip")
    print(f"[*] Creating password-protected ZIP: {zip_path}")

    with ZipFile(zip_path, 'w', ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(dir_path)  # <-- CORRECT
                zipf.write(file_path, arcname)
        zipf.setpassword(password.encode('utf-8'))

    print(f"[+] ZIP created: {zip_path}")
    return zip_path


def delete_directory_contents(dir_path: Path) -> None:
    for item in dir_path.iterdir():
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
            print(f"[-] Deleted: {item}")
        except Exception as e:
            print(f"[-] Failed to delete {item}: {e}", file=sys.stderr)


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

    if key_path.exists():
        key = load_key(key_path)
        print(f"[+] Loaded key: {key_path}")
    else:
        key = generate_key(key_path)

    fernet = Fernet(key)

    print("\n[*] Set password for the ZIP archive:")
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm:  ")
    if password != confirm:
        print("[-] Passwords do not match!", file=sys.stderr)
        sys.exit(1)
    if not password:
        print("[-] Password cannot be empty!", file=sys.stderr)
        sys.exit(1)

    print("\n[*] Starting encryption...")
    for d in directories:
        print(f"\n[*] Encrypting directory: {d}")
        encrypt_directory(d, fernet)

    print("\n[*] Creating ZIP archives and cleaning up...")
    for d in directories:
        zip_path = create_password_protected_zip(d, password)
        delete_directory_contents(d)
        print(f"[*] Directory cleaned. Only ZIP remains: {zip_path.name}")

    print("\n[+] ENCRYPTION COMPLETE")
    print(f"[*] Decrypt with: python Decryption_Windows.py {' '.join([f'\"{d}\"' for d in directories])} \"{key_path}\"")
    print(f"[*] Extract .zip files with password to restore folders first.")


if __name__ == "__main__":
    main()