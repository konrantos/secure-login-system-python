# Secure Login System — Python Implementation

> Course project for **System Security** (6th semester) — Department of Informatics and Telecommunications of the University of Ioannina.

## Overview

This project implements a secure login system that combines:

- 🔐 **AES encryption** (symmetric, OFB mode)
- 🔏 **ECDSA digital signatures** (SECP256R1 + SHA-256)
- 🧂 **Password hashing** using MD5 and random salt
- 🔐 **Key generation and storage** in `.pem` files
- 🧪 **Signature verification** for file integrity
- 🧾 CLI-based user menu for account creation and login

---

## Features

1. **User Account Creation**
   - Prompts for 3 users
   - Hashes passwords with unique 128-bit salt using MD5
   - Stores records in `data.txt`

2. **Digital Signature**
   - Signs `data.txt` using ECDSA
   - Signature saved as `data.txt.signature`

3. **Encryption**
   - AES (256-bit key, OFB mode)
   - Stores encrypted file with random IV in `encrypted_data.txt`

4. **Login System**
   - Decrypts and verifies signature before authenticating user
   - Matches username and password (hashed+salted)

5. **Key Management**
   - Generates public/private ECDSA keys
   - Stores them in `.pem` files
   - Stores AES key in `aes_key.txt`

---

## Files

| File                    | Description                        |
|-------------------------|------------------------------------|
| `secure_login.py`       | Main program logic (menu + crypto) |
| `data.txt`              | Plaintext user records             |
| `data.txt.signature`    | Digital signature for verification |
| `encrypted_data.txt`    | AES-encrypted version of `data.txt`|
| `aes_key.txt`           | AES key used for encryption        |
| `private_key.pem`       | ECDSA private key                  |
| `public_key.pem`        | ECDSA public key                   |

---

## How to Run

### Requirements

Install the cryptography package:

```bash
pip install cryptography
```

### Run

```bash
python secure_login.py
```

Follow the prompts in the terminal to create users or log in.

---

## Security Notes

- MD5 is insecure for production use, but included here as part of academic study.
- AES in OFB mode ensures that plaintext blocks are not repeated in ciphertext.
- All secrets (keys, plaintext files) should be securely erased after use in real systems.

---

## License

This project is licensed under the MIT License.

---

## Acknowledgements

- University of Ioannina — course project for *System Security*
- Uses [cryptography](https://cryptography.io/) Python library
