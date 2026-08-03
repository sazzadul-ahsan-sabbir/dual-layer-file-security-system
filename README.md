# Dual-Layer File Security System

A desktop GUI application for encrypting and decrypting files using symmetric cryptography, with a password-protected secret key.

## Features

- **Password-protected key generation** — the secret key is never stored in plaintext; it is wrapped using a password-derived key (PBKDF2-HMAC-SHA256, 390,000 iterations)
- **Batch file encryption/decryption** — select and process multiple files at once
- **Tamper detection** — Fernet's built-in HMAC authentication detects if an encrypted file has been modified or if the wrong key/password is used
- **Simple Tkinter GUI** — no command-line usage required

## How It Works

1. **Layer 1 (Password → Wrapping Key):** Your password + a random salt are run through PBKDF2-HMAC-SHA256 to derive a wrapping key.
2. **Layer 2 (Wrapping Key → Secret Key):** The wrapping key encrypts the real Fernet secret key before it's saved to the `.key` file.
3. **File Encryption:** The real secret key encrypts/decrypts your chosen files using Fernet (AES-128-CBC + HMAC-SHA256).

## Requirements

- Python 3.x
- `cryptography` package

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python file_security_app.py
```

1. Click **Generate Key** → choose where to save the `.key` file → set a password (min. 6 characters, entered twice to confirm)
2. Click **Add File(s)** → select one or more files to encrypt/decrypt
3. Click **Encrypt All** or **Decrypt All** → enter your password when prompted

## ⚠️ Important

- If you lose either the `.key` file **or** the password, encrypted files **cannot be recovered**. There is no backdoor or recovery option.
- Keep your `.key` file and password stored separately for better security.

## Author

Sazzadul Ahsan Sabbir
