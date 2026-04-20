#!/usr/bin/env python3
"""
Encrypt/decrypt files using:
  - YubiKey HMAC challenge-response (via ykman otp calculate)
  - + a user-entered password (PBKDF2-HMAC-SHA256)
  - Final key derived with HKDF-SHA256 -> AES-256-GCM

File format (v2):
  MAGIC(4) | ver(1) | slot(1) | hkdf_salt(16) | nonce(12) |
  pw_salt(16) | pbkdf2_iters(4) | chall_len(2) | challenge(chall_len) | ciphertext...
"""

import argparse
import getpass
import os
import struct
import subprocess
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"YKAE"
VERSION = 2

HKDF_SALT_LEN = 16
PW_SALT_LEN = 16
NONCE_LEN = 12
DEFAULT_CHALLENGE_LEN = 64
DEFAULT_PBKDF2_ITERS = 250_000

INFO = b"yubikey-aes256-file-v2"
MAX_CHALLENGE_LEN = 1024


@dataclass
class HeaderV2:
    version: int
    slot: int
    hkdf_salt: bytes
    nonce: bytes
    pw_salt: bytes
    pbkdf2_iters: int
    challenge: bytes

    def pack(self) -> bytes:
        if self.version != VERSION:
            raise ValueError("Bad header version")
        if len(self.hkdf_salt) != HKDF_SALT_LEN:
            raise ValueError("Bad hkdf_salt length")
        if len(self.nonce) != NONCE_LEN:
            raise ValueError("Bad nonce length")
        if len(self.pw_salt) != PW_SALT_LEN:
            raise ValueError("Bad pw_salt length")
        if not (1 <= len(self.challenge) <= MAX_CHALLENGE_LEN):
            raise ValueError("Bad challenge length")
        if not (1 <= self.pbkdf2_iters <= 2_000_000):
            raise ValueError("Unreasonable PBKDF2 iterations")

        # Format:
        # MAGIC(4) | ver(1) | slot(1) | hkdf_salt(16) | nonce(12) |
        # pw_salt(16) | iters(4) | chall_len(2) | challenge(variable)
        return b"".join([
            MAGIC,
            struct.pack("!B", self.version),
            struct.pack("!B", self.slot),
            self.hkdf_salt,
            self.nonce,
            self.pw_salt,
            struct.pack("!I", self.pbkdf2_iters),
            struct.pack("!H", len(self.challenge)),
            self.challenge,
        ])

    @staticmethod
    def unpack(blob: bytes) -> tuple["HeaderV2", int]:
        min_len = 4 + 1 + 1 + HKDF_SALT_LEN + NONCE_LEN + PW_SALT_LEN + 4 + 2
        if len(blob) < min_len:
            raise ValueError("File too short / invalid header")

        if blob[:4] != MAGIC:
            raise ValueError("Bad magic (not a YKAE file)")

        ver = blob[4]
        if ver != VERSION:
            raise ValueError(f"Unsupported version: {ver}")

        slot = blob[5]
        if slot not in (1, 2):
            raise ValueError(f"Invalid slot in header: {slot}")

        off = 6
        hkdf_salt = blob[off:off + HKDF_SALT_LEN]; off += HKDF_SALT_LEN
        nonce = blob[off:off + NONCE_LEN]; off += NONCE_LEN
        pw_salt = blob[off:off + PW_SALT_LEN]; off += PW_SALT_LEN

        (iters,) = struct.unpack("!I", blob[off:off + 4]); off += 4
        if not (1 <= iters <= 2_000_000):
            raise ValueError("Unreasonable PBKDF2 iterations in header")

        (clen,) = struct.unpack("!H", blob[off:off + 2]); off += 2
        if clen <= 0 or clen > MAX_CHALLENGE_LEN:
            raise ValueError("Invalid challenge length")

        if len(blob) < off + clen:
            raise ValueError("Truncated header (challenge missing)")

        challenge = blob[off:off + clen]
        return HeaderV2(
            version=ver,
            slot=slot,
            hkdf_salt=hkdf_salt,
            nonce=nonce,
            pw_salt=pw_salt,
            pbkdf2_iters=iters,
            challenge=challenge,
        ), off + clen


def run_ykman_calculate(slot: int, challenge: bytes, access_code_hex: str | None = None) -> bytes:
    """
    Calls:
      ykman otp calculate [--access-code HEX] {1|2} CHALLENGE_HEX
    Expects stdout: hex string of response.
    """
    if slot not in (1, 2):
        raise ValueError("slot must be 1 or 2")

    challenge_hex = challenge.hex()
    cmd = ["ykman", "otp", "calculate"]
    if access_code_hex:
        cmd += ["--access-code", access_code_hex]
    cmd += [str(slot), challenge_hex]

    try:
        r = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        raise RuntimeError("ykman not found. Install yubikey-manager (ykman).")
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or "").strip()
        raise RuntimeError(f"ykman failed: {msg}") from e

    out = (r.stdout or "").strip().replace(" ", "").replace("\n", "")
    try:
        return bytes.fromhex(out)
    except ValueError as e:
        raise RuntimeError(f"Unexpected ykman output (not hex): {out!r}") from e


def derive_pw_key(password_bytes: bytes, pw_salt: bytes, iters: int) -> bytes:
    """
    PBKDF2-HMAC-SHA256 -> 32 bytes
    (Use per-file pw_salt stored in header to make precomputation harder.)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pw_salt,
        iterations=iters,
    )
    return kdf.derive(password_bytes)


def derive_aes256_key(yk_response: bytes, pw_key: bytes, hkdf_salt: bytes) -> bytes:
    """
    Final AES-256 key = HKDF-SHA256( yk_response || pw_key, salt=hkdf_salt, info=INFO )
    """
    ikm = yk_response + pw_key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=INFO,
    )
    return hkdf.derive(ikm)


def read_password(confirm: bool) -> bytes:
    p1 = getpass.getpass("Password: ").encode("utf-8")
    if not p1:
        raise ValueError("Empty password is not allowed")
    if confirm:
        p2 = getpass.getpass("Confirm password: ").encode("utf-8")
        if p1 != p2:
            raise ValueError("Passwords do not match")
    return p1


def encrypt_file(in_path: str, out_path: str, slot: int, access_code_hex: str | None,
                 pbkdf2_iters: int, challenge_len: int):
    password = read_password(confirm=True)
    plaintext = open(in_path, "rb").read()

    challenge = os.urandom(challenge_len)
    hkdf_salt = os.urandom(HKDF_SALT_LEN)
    pw_salt = os.urandom(PW_SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    yk_resp = run_ykman_calculate(slot=slot, challenge=challenge, access_code_hex=access_code_hex)
    pw_key = derive_pw_key(password, pw_salt=pw_salt, iters=pbkdf2_iters)
    key = derive_aes256_key(yk_resp, pw_key, hkdf_salt=hkdf_salt)

    hdr = HeaderV2(
        version=VERSION,
        slot=slot,
        hkdf_salt=hkdf_salt,
        nonce=nonce,
        pw_salt=pw_salt,
        pbkdf2_iters=pbkdf2_iters,
        challenge=challenge,
    )
    header_bytes = hdr.pack()

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, header_bytes)

    with open(out_path, "wb") as f:
        f.write(header_bytes)
        f.write(ciphertext)


def decrypt_file(in_path: str, out_path: str, access_code_hex: str | None):
    password = read_password(confirm=False)
    blob = open(in_path, "rb").read()

    hdr, header_len = HeaderV2.unpack(blob)
    ciphertext = blob[header_len:]
    if not ciphertext:
        raise ValueError("No ciphertext")

    yk_resp = run_ykman_calculate(slot=hdr.slot, challenge=hdr.challenge, access_code_hex=access_code_hex)
    pw_key = derive_pw_key(password, pw_salt=hdr.pw_salt, iters=hdr.pbkdf2_iters)
    key = derive_aes256_key(yk_resp, pw_key, hkdf_salt=hdr.hkdf_salt)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(hdr.nonce, ciphertext, blob[:header_len])

    with open(out_path, "wb") as f:
        f.write(plaintext)


def main():
    p = argparse.ArgumentParser(
        description="Encrypt/decrypt files with AES-256-GCM using YubiKey HMAC challenge-response + password."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("enc", help="Encrypt")
    pe.add_argument("-i", "--in", dest="inp", required=True, help="Input file")
    pe.add_argument("-o", "--out", dest="out", required=True, help="Output file")
    pe.add_argument("--slot", type=int, choices=[1, 2], default=2, help="YubiKey slot (1 or 2). Default: 2")
    pe.add_argument("--access-code", dest="access_code", default=None,
                    help="Optional 6-byte access code in hex (12 hex chars).")
    pe.add_argument("--pbkdf2-iters", type=int, default=DEFAULT_PBKDF2_ITERS,
                    help=f"PBKDF2 iterations (default: {DEFAULT_PBKDF2_ITERS})")
    pe.add_argument("--challenge-len", type=int, default=DEFAULT_CHALLENGE_LEN,
                    help=f"Challenge length in bytes (default: {DEFAULT_CHALLENGE_LEN})")

    pd = sub.add_parser("dec", help="Decrypt")
    pd.add_argument("-i", "--in", dest="inp", required=True, help="Input file")
    pd.add_argument("-o", "--out", dest="out", required=True, help="Output file")
    pd.add_argument("--access-code", dest="access_code", default=None,
                    help="Optional 6-byte access code in hex (12 hex chars).")

    args = p.parse_args()

    if args.cmd == "enc":
        if args.challenge_len < 16 or args.challenge_len > MAX_CHALLENGE_LEN:
            raise SystemExit(f"--challenge-len must be between 16 and {MAX_CHALLENGE_LEN}")
        if args.pbkdf2_iters < 50_000 or args.pbkdf2_iters > 2_000_000:
            raise SystemExit("--pbkdf2-iters must be between 50000 and 2000000")

        encrypt_file(
            in_path=args.inp,
            out_path=args.out,
            slot=args.slot,
            access_code_hex=args.access_code,
            pbkdf2_iters=args.pbkdf2_iters,
            challenge_len=args.challenge_len,
        )

    elif args.cmd == "dec":
        decrypt_file(
            in_path=args.inp,
            out_path=args.out,
            access_code_hex=args.access_code,
        )
    else:
        raise SystemExit("Unknown command")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AES-256-GCM file encryption using:
  - YubiKey HMAC challenge-response (ykman otp calculate)
  - Optional password (PBKDF2-HMAC-SHA256)
  - Final key derived with HKDF-SHA256

File format (v3):
MAGIC(4) | ver(1) | flags(1) | slot(1) |
hkdf_salt(16) | nonce(12) |
pw_salt(16) | pbkdf2_iters(4) |
chall_len(2) | challenge(chall_len) | ciphertext...
"""

import argparse
import getpass
import os
import struct
import subprocess
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ===== constants =====

MAGIC = b"YKAE"
VERSION = 3

FLAG_USES_PASSWORD = 0x01

HKDF_SALT_LEN = 16
PW_SALT_LEN = 16
NONCE_LEN = 12

DEFAULT_CHALLENGE_LEN = 64
DEFAULT_PBKDF2_ITERS = 250_000
MAX_CHALLENGE_LEN = 1024

INFO = b"yk-aes256-file-v3"


# ===== header =====

@dataclass
class HeaderV3:
    version: int
    flags: int
    slot: int
    hkdf_salt: bytes
    nonce: bytes
    pw_salt: bytes
    pbkdf2_iters: int
    challenge: bytes

    def pack(self) -> bytes:
        return b"".join([
            MAGIC,
            struct.pack("!B", self.version),
            struct.pack("!B", self.flags),
            struct.pack("!B", self.slot),
            self.hkdf_salt,
            self.nonce,
            self.pw_salt,
            struct.pack("!I", self.pbkdf2_iters),
            struct.pack("!H", len(self.challenge)),
            self.challenge,
        ])

    @staticmethod
    def unpack(blob: bytes) -> tuple["HeaderV3", int]:
        min_len = 4 + 1 + 1 + 1 + HKDF_SALT_LEN + NONCE_LEN + PW_SALT_LEN + 4 + 2
        if len(blob) < min_len:
            raise ValueError("Invalid file (too short)")

        if blob[:4] != MAGIC:
            raise ValueError("Bad magic")

        ver, flags, slot = struct.unpack("!BBB", blob[4:7])
        if ver != VERSION:
            raise ValueError(f"Unsupported version {ver}")
        if slot not in (1, 2):
            raise ValueError("Invalid slot")

        off = 7
        hkdf_salt = blob[off:off + HKDF_SALT_LEN]; off += HKDF_SALT_LEN
        nonce = blob[off:off + NONCE_LEN]; off += NONCE_LEN
        pw_salt = blob[off:off + PW_SALT_LEN]; off += PW_SALT_LEN
        (iters,) = struct.unpack("!I", blob[off:off + 4]); off += 4
        (clen,) = struct.unpack("!H", blob[off:off + 2]); off += 2

        if clen <= 0 or clen > MAX_CHALLENGE_LEN:
            raise ValueError("Invalid challenge length")

        challenge = blob[off:off + clen]
        return HeaderV3(
            version=ver,
            flags=flags,
            slot=slot,
            hkdf_salt=hkdf_salt,
            nonce=nonce,
            pw_salt=pw_salt,
            pbkdf2_iters=iters,
            challenge=challenge,
        ), off + clen


# ===== yubikey =====

def run_ykman(slot: int, challenge: bytes, access_code: str | None) -> bytes:
    cmd = ["ykman", "otp", "calculate"]
    if access_code:
        cmd += ["--access-code", access_code]
    cmd += [str(slot), challenge.hex()]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        raise RuntimeError("ykman not found")
    except subprocess.CalledProcessError as e:
        raise RuntimeError((e.stderr or e.stdout).strip())

    return bytes.fromhex(r.stdout.strip())


# ===== KDFs =====

def derive_pw_key(password: bytes, salt: bytes, iters: int) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iters,
    ).derive(password)


def derive_final_key(yk_resp: bytes, pw_key: bytes, hkdf_salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=INFO,
    ).derive(yk_resp + pw_key)


# ===== utils =====

def read_password(confirm: bool) -> bytes:
    p1 = getpass.getpass("Password: ").encode()
    if not p1:
        raise ValueError("Empty password not allowed")
    if confirm:
        p2 = getpass.getpass("Confirm password: ").encode()
        if p1 != p2:
            raise ValueError("Passwords do not match")
    return p1


# ===== encrypt / decrypt =====

def encrypt(inp, out, slot, access_code, use_password, pbkdf2_iters, chall_len):
    plaintext = open(inp, "rb").read()

    challenge = os.urandom(chall_len)
    hkdf_salt = os.urandom(HKDF_SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    flags = 0
    if use_password:
        flags |= FLAG_USES_PASSWORD
        password = read_password(confirm=True)
        pw_salt = os.urandom(PW_SALT_LEN)
        pw_key = derive_pw_key(password, pw_salt, pbkdf2_iters)
    else:
        pw_salt = b"\x00" * PW_SALT_LEN
        pw_key = b""

    yk_resp = run_ykman(slot, challenge, access_code)
    key = derive_final_key(yk_resp, pw_key, hkdf_salt)

    hdr = HeaderV3(
        version=VERSION,
        flags=flags,
        slot=slot,
        hkdf_salt=hkdf_salt,
        nonce=nonce,
        pw_salt=pw_salt,
        pbkdf2_iters=pbkdf2_iters,
        challenge=challenge,
    )
    header_bytes = hdr.pack()

    ct = AESGCM(key).encrypt(nonce, plaintext, header_bytes)

    with open(out, "wb") as f:
        f.write(header_bytes)
        f.write(ct)


def decrypt(inp, out, access_code, no_password):
    blob = open(inp, "rb").read()
    hdr, hlen = HeaderV3.unpack(blob)

    uses_pw = bool(hdr.flags & FLAG_USES_PASSWORD)
    if uses_pw and no_password:
        raise RuntimeError("File requires password")
    if (not uses_pw) and (not no_password):
        print("Note: file does NOT use password")

    if uses_pw:
        password = read_password(confirm=False)
        pw_key = derive_pw_key(password, hdr.pw_salt, hdr.pbkdf2_iters)
    else:
        pw_key = b""

    yk_resp = run_ykman(hdr.slot, hdr.challenge, access_code)
    key = derive_final_key(yk_resp, pw_key, hdr.hkdf_salt)

    pt = AESGCM(key).decrypt(hdr.nonce, blob[hlen:], blob[:hlen])

    with open(out, "wb") as f:
        f.write(pt)


# ===== CLI =====

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("enc")
    pe.add_argument("-i", "--in", dest="inp", required=True)
    pe.add_argument("-o", "--out", required=True)
    pe.add_argument("--slot", type=int, choices=[1, 2], default=2)
    pe.add_argument("--access-code")
    pe.add_argument("--no-password", action="store_true")
    pe.add_argument("--pbkdf2-iters", type=int, default=DEFAULT_PBKDF2_ITERS)
    pe.add_argument("--challenge-len", type=int, default=DEFAULT_CHALLENGE_LEN)

    pd = sub.add_parser("dec")
    pd.add_argument("-i", "--in", dest="inp", required=True)
    pd.add_argument("-o", "--out", required=True)
    pd.add_argument("--access-code")
    pd.add_argument("--no-password", action="store_true")

    a = p.parse_args()

    if a.cmd == "enc":
        encrypt(
            a.inp, a.out, a.slot, a.access_code,
            not a.no_password,
            a.pbkdf2_iters,
            a.challenge_len,
        )
    else:
        decrypt(a.inp, a.out, a.access_code, a.no_password)


if __name__ == "__main__":
    main()

