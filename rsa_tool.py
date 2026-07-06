\
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64, os, json

def generate_keypair(bits: int = 2048, outdir: str = "keys") -> Tuple[str, str]:
    """
    Generate RSA keypair and save to PEM files. Returns (private_path, public_path).
    """
    os.makedirs(outdir, exist_ok=True)
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()

    priv_path = os.path.join(outdir, "private.pem")
    pub_path = os.path.join(outdir, "public.pem")
    with open(priv_path, "wb") as f:
        f.write(private_pem)
    with open(pub_path, "wb") as f:
        f.write(public_pem)
    return priv_path, pub_path

def encrypt_with_public(plaintext: str, public_key_path: str) -> str:
    with open(public_key_path, "rb") as f:
        pub = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    ct = cipher.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(ct).decode("utf-8")

def decrypt_with_private(ciphertext_b64: str, private_key_path: str) -> str:
    with open(private_key_path, "rb") as f:
        priv = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    pt = cipher.decrypt(base64.b64decode(ciphertext_b64.encode("utf-8")))
    return pt.decode("utf-8")
