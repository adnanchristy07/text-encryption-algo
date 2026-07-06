\
from typing import Dict, Any
from Crypto.Cipher import DES

from .utils import rand_bytes, b64e, b64d, derive_key, pkcs7_pad, pkcs7_unpad

def encrypt_des_cbc(plaintext: str, passphrase: str) -> Dict[str, Any]:
    """
    DES-CBC (legacy!). PBKDF2-derived 8-byte key, PKCS7 padding.
    """
    salt = rand_bytes(16)
    key = derive_key(passphrase, salt, 8)  # 64-bit DES key (56 effective bits)
    iv = rand_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext.encode("utf-8"), 8))
    return {
        "alg": "DES",
        "mode": "CBC",
        "salt": b64e(salt),
        "iv": b64e(iv),
        "ciphertext": b64e(ct),
        "kdf": "PBKDF2-SHA256-200k",
        "padding": "PKCS7"
    }

def decrypt_des_cbc(obj: Dict[str, Any], passphrase: str) -> str:
    salt = b64d(obj["salt"])
    iv = b64d(obj["iv"])
    ct = b64d(obj["ciphertext"])
    key = derive_key(passphrase, salt, 8)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    pt = pkcs7_unpad(cipher.decrypt(ct))
    return pt.decode("utf-8")
