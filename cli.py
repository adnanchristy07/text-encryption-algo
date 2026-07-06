\
import argparse, json, sys, os
from .aes_tool import encrypt_aes_gcm, decrypt_aes_gcm
from .des_tool import encrypt_des_cbc, decrypt_des_cbc
from .rsa_tool import generate_keypair, encrypt_with_public, decrypt_with_private

def read_text(args):
    if args.text is not None:
        return args.text
    if args.infile:
        with open(args.infile, "r", encoding="utf-8") as f:
            return f.read()
    raise SystemExit("Provide --text or --infile")

def write_out(obj, outfile):
    if outfile:
        with open(outfile, "w", encoding="utf-8") as f:
            if isinstance(obj, (dict, list)):
                json.dump(obj, f, indent=2)
            else:
                f.write(str(obj))
        print(f"Written to {outfile}")
    else:
        if isinstance(obj, (dict, list)):
            print(json.dumps(obj, indent=2))
        else:
            print(obj)

def main():
    p = argparse.ArgumentParser(description="Text Encryption CLI (AES, DES, RSA)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # AES
    paes_e = sub.add_parser("aes-encrypt", help="Encrypt text with AES-GCM")
    paes_e.add_argument("--text", help="Plain text to encrypt")
    paes_e.add_argument("--infile", help="File containing plain text")
    paes_e.add_argument("--passphrase", required=True)
    paes_e.add_argument("-o", "--outfile", help="Output JSON file")

    paes_d = sub.add_parser("aes-decrypt", help="Decrypt AES-GCM JSON")
    paes_d.add_argument("--infile", required=True, help="JSON produced by aes-encrypt")
    paes_d.add_argument("--passphrase", required=True)

    # DES
    pdes_e = sub.add_parser("des-encrypt", help="Encrypt text with DES-CBC (legacy)")
    pdes_e.add_argument("--text", help="Plain text to encrypt")
    pdes_e.add_argument("--infile", help="File containing plain text")
    pdes_e.add_argument("--passphrase", required=True)
    pdes_e.add_argument("-o", "--outfile", help="Output JSON file")

    pdes_d = sub.add_parser("des-decrypt", help="Decrypt DES-CBC JSON")
    pdes_d.add_argument("--infile", required=True, help="JSON produced by des-encrypt")
    pdes_d.add_argument("--passphrase", required=True)

    # RSA
    prsa_g = sub.add_parser("rsa-genkeys", help="Generate RSA keypair")
    prsa_g.add_argument("--outdir", default="keys", help="Directory to place PEM files")

    prsa_e = sub.add_parser("rsa-encrypt", help="Encrypt with RSA (OAEP) using public key")
    prsa_e.add_argument("--text", help="Plain text to encrypt")
    prsa_e.add_argument("--infile", help="File containing plain text")
    prsa_e.add_argument("--pubkey", required=True, help="Path to public.pem")
    prsa_e.add_argument("-o", "--outfile", help="Where to write base64 ciphertext")

    prsa_d = sub.add_parser("rsa-decrypt", help="Decrypt RSA (OAEP) using private key")
    prsa_d.add_argument("--infile", required=True, help="File containing base64 ciphertext")
    prsa_d.add_argument("--privkey", required=True, help="Path to private.pem")

    args = p.parse_args()

    if args.cmd == "aes-encrypt":
        pt = read_text(args)
        obj = encrypt_aes_gcm(pt, args.passphrase)
        write_out(obj, args.outfile)

    elif args.cmd == "aes-decrypt":
        with open(args.infile, "r", encoding="utf-8") as f:
            obj = json.load(f)
        pt = decrypt_aes_gcm(obj, args.passphrase)
        write_out(pt, None)

    elif args.cmd == "des-encrypt":
        pt = read_text(args)
        obj = encrypt_des_cbc(pt, args.passphrase)
        write_out(obj, args.outfile)

    elif args.cmd == "des-decrypt":
        with open(args.infile, "r", encoding="utf-8") as f:
            obj = json.load(f)
        pt = decrypt_des_cbc(obj, args.passphrase)
        write_out(pt, None)

    elif args.cmd == "rsa-genkeys":
        priv, pub = generate_keypair(outdir=args.outdir)
        print(f"Generated:\n  {priv}\n  {pub}")

    elif args.cmd == "rsa-encrypt":
        pt = read_text(args)
        ct_b64 = encrypt_with_public(pt, args.pubkey)
        write_out(ct_b64, args.outfile)

    elif args.cmd == "rsa-decrypt":
        with open(args.infile, "r", encoding="utf-8") as f:
            ct_b64 = f.read().strip()
        pt = decrypt_with_private(ct_b64, args.privkey)
        write_out(pt, None)

if __name__ == "__main__":
    main()
