# Ransomware Simulator (Educational / Red Team Use Only)

> **WARNING: THIS TOOL IS FOR EDUCATIONAL, SECURITY TESTING, AND AUTHORIZED RED TEAM PURPOSES ONLY.**

---

## Overview

This repository contains **two Python scripts** simulating ransomware behavior:

1. `encryption_win.py` – Encrypts files, creates password-protected ZIP archives, and deletes originals.
2. `decryption_win.py` – Restores encrypted files using the correct key.

**Purpose**:  
Demonstrate how symmetric encryption (Fernet), file archiving, and cleanup work — **for learning, penetration testing, or backup validation**.

---

## Features

- Cross-platform (Windows/Linux/macOS via `pathlib`)
- Uses **AES-128 in CBC mode with HMAC** via `cryptography.Fernet`
- Password-protected ZIP archives (ZipCrypto)
- In-place encryption & secure cleanup
- Hidden password input
- Full error handling

---

## Installation

```bash
pip install cryptography
