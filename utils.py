\
import os, base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

PBKDF2_ITERS = 200_000

def rand_bytes(n: int) -> bytes:
    return os.urandom(n)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def derive_key(passphrase: str, salt: bytes, key_len: int) -> bytes:
    """
    Derive a binary key from a UTF-8 passphrase using PBKDF2-HMAC-SHA256.
    """
    return PBKDF2(passphrase.encode("utf-8"), salt, dkLen=key_len, count=PBKDF2_ITERS, hmac_hash_module=SHA256)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes) -> bytes:
    if not padded:
        raise ValueError("Invalid padding")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16 or pad_len > len(padded):
        raise ValueError("Invalid padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return padded[:-pad_len]
