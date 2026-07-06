# text-encryption-algo
CRYPTOGRAPHY algorithms like AES, DES, and RSA..

# Text Encryption (AES, DES, RSA)

A compact cybersecurity project that demonstrates text encryption & decryption using **AES**, **DES**, and **RSA**.
It includes a clean Python API and a friendly CLI.

> ⚠️ Education-first. AES-GCM here is strong; DES-CBC is **legacy** and provided for comparison only. Use AES or RSA in real systems.

---

## Quick Start

```bash
# 1) Create a fresh virtual environment (recommended)
python -m venv .venv
# (Linux/macOS) activate
source .venv/bin/activate
# (Windows) activate
.venv\Scripts\activate

# 2) Install dependency
pip install -r requirements.txt

# 3) Use the CLI
python -m src.cli --help
```

### AES (GCM)

```bash
# Encrypt
python -m src.cli aes-encrypt --text "hello world" --passphrase "My$tr0ngPass" -o out_aes.json

# Decrypt
python -m src.cli aes-decrypt --infile out_aes.json --passphrase "My$tr0ngPass"
```

### DES (CBC - legacy, for learning)

```bash
# Encrypt
python -m src.cli des-encrypt --text "legacy demo" --passphrase "weakpass" -o out_des.json

# Decrypt
python -m src.cli des-decrypt --infile out_des.json --passphrase "weakpass"
```

### RSA (OAEP)

```bash
# Generate keypair (PEM files)
python -m src.cli rsa-genkeys --outdir keys

# Encrypt using public key
python -m src.cli rsa-encrypt --text "hello rsa" --pubkey keys/public.pem -o out_rsa.txt

# Decrypt using private key
python -m src.cli rsa-decrypt --infile out_rsa.txt --privkey keys/private.pem
```

---

## Project Layout

```
text_encryption_project/
├── requirements.txt
├── README.md
├── src/
│   ├── utils.py
│   ├── aes_tool.py
│   ├── des_tool.py
│   ├── rsa_tool.py
│   └── cli.py
└── tests/
    └── test_roundtrip.py
```

---

## Security Notes

- **AES-GCM** provides confidentiality + integrity (includes a tag). Use it in real apps.
- **DES-CBC** is **not secure** by modern standards; included for historical comparison only.
- Use **PBKDF2** (200k iters) to derive keys from passphrases. Always randomize **salt** and **nonce/IV**.
- Never reuse nonces/IVs with the same key.
- RSA here uses **OAEP** (with SHA-256) which is the modern, safe padding for RSA encryption.

---

## License

MIT — do whatever you want, but please don't use DES in production 🙂
