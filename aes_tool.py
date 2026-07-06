\
from typing import Dict, Any
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from .utils import rand_bytes, b64e, b64d, derive_key

def encrypt_aes_gcm(plaintext: str, passphrase: str) -> Dict[str, Any]:
    """
    AES-256-GCM encryption with PBKDF2-derived key.
    Returns a JSON-serializable dict with base64-encoded fields.
    """
    salt = rand_bytes(16)
    key = derive_key(passphrase, salt, 32)  # 256-bit key
    cipher = AES.new(key, AES.MODE_GCM)  # random 96-bit nonce inside
    nonce = cipher.nonce
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return {
        "alg": "AES",
        "mode": "GCM",
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
        "tag": b64e(tag),
        "kdf": "PBKDF2-SHA256-200k"
    }

def decrypt_aes_gcm(obj: Dict[str, Any], passphrase: str) -> str:
    salt = b64d(obj["salt"])
    nonce = b64d(obj["nonce"])
    ct = b64d(obj["ciphertext"])
    tag = b64d(obj["tag"])
    key = derive_key(passphrase, salt, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode("utf-8")
