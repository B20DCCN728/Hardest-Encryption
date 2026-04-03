"""
_crypto_engine.py — Lõi mã hóa AES (thuật toán, KDF, định dạng header)
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from enum import IntEnum
from typing import NamedTuple

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ─── Hằng số ──────────────────────────────────────────────────────────────────

MAGIC       = b"CRYPTOOL"   # 8 bytes — định danh file
VERSION     = 0x02
SALT_SIZE   = 32
GCM_NONCE   = 12
CBC_IV_SIZE = 16
TAG_SIZE    = 16
KEY_SIZE    = 32            # AES-256

# Flag byte trong header
FLAG_STREAMING = 0x01       # bit 0: file dùng streaming mode

# ─── Enums ────────────────────────────────────────────────────────────────────

class Algorithm(IntEnum):
    AES_GCM = 0
    AES_CBC = 1
    AES_SIV = 2

class KDF(IntEnum):
    ARGON2ID = 0
    PBKDF2   = 1

ALG_LABEL = {
    Algorithm.AES_GCM: "AES-256-GCM",
    Algorithm.AES_CBC: "AES-256-CBC+HMAC",
    Algorithm.AES_SIV: "AES-256-SIV",
}
KDF_LABEL = {
    KDF.ARGON2ID: "Argon2id",
    KDF.PBKDF2:   "PBKDF2-SHA256",
}

# ─── Global Header (80 bytes) ─────────────────────────────────────────────────
#
#  Offset  Size  Field
#  ──────  ────  ─────────────────────────────────────
#     0      8   Magic "CRYPTOOL"
#     8      1   Version
#     9      1   Algorithm  (0=GCM, 1=CBC, 2=SIV)
#    10      1   KDF        (0=Argon2id, 1=PBKDF2)
#    11      1   Flags      (bit0=streaming)
#    12     32   Salt
#    44     16   Nonce/IV   (12B GCM zero-padded to 16)
#    60     16   Auth Tag   (GCM/SIV) hoặc HMAC[:16] (CBC)
#    76      4   Orig size  (uint32 LE, 0 nếu stream)

HEADER_FMT  = "<8sBBBB32s16s16sI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # = 80

assert HEADER_SIZE == 80, f"Header size phải 80, got {HEADER_SIZE}"


class HeaderInfo(NamedTuple):
    algorithm:  Algorithm
    kdf:        KDF
    flags:      int
    salt:       bytes
    nonce:      bytes
    tag:        bytes
    orig_size:  int


# ─── Key Derivation ───────────────────────────────────────────────────────────

def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    """Argon2id: memory-hard, chống GPU/ASIC brute force."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=65_536,   # 64 MB
        parallelism=4,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )

def derive_key_pbkdf2(password: bytes, salt: bytes) -> bytes:
    """PBKDF2-SHA256: 600 000 iter, FIPS 140-2 compatible."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=600_000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def derive_key(password: bytes, salt: bytes, kdf: KDF) -> bytes:
    if kdf == KDF.ARGON2ID:
        return derive_key_argon2(password, salt)
    return derive_key_pbkdf2(password, salt)


# ─── AES Algorithms ──────────────────────────────────────────────────────────

def encrypt_gcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """AES-256-GCM → (nonce12, tag16, ciphertext)."""
    nonce = secrets.token_bytes(GCM_NONCE)
    out   = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, out[-16:], out[:-16]

def decrypt_gcm(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce[:12], ciphertext + tag, None)


def encrypt_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)."""
    iv = secrets.token_bytes(CBC_IV_SIZE)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc    = cipher.encryptor()
    ct     = enc.update(padded) + enc.finalize()
    mac    = hmac.new(key, iv + ct, hashlib.sha256).digest()
    nonce_padded = iv + b"\x00" * (16 - CBC_IV_SIZE)
    return nonce_padded, mac[:16], ct

def decrypt_cbc(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    iv = nonce[:CBC_IV_SIZE]
    expected_mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac[:16], tag):
        raise ValueError("HMAC xác thực thất bại — sai mật khẩu hoặc dữ liệu bị giả mạo")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec    = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_siv(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """AES-256-SIV: nonce-misuse resistant."""
    ct_full = AESSIV(key * 2).encrypt(plaintext, [b"cryptool-siv"])
    return b"\x00" * 16, ct_full[:16], ct_full[16:]

def decrypt_siv(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    return AESSIV(key * 2).decrypt(tag + ciphertext, [b"cryptool-siv"])


# ─── Header Packing ──────────────────────────────────────────────────────────

def pack_header(
    alg: Algorithm, kdf: KDF, flags: int,
    salt: bytes, nonce: bytes, tag: bytes, orig_size: int,
) -> bytes:
    nonce_pad = (nonce + b"\x00" * 16)[:16]
    return struct.pack(
        HEADER_FMT,
        MAGIC, VERSION, int(alg), int(kdf), flags,
        salt, nonce_pad, tag, orig_size & 0xFFFF_FFFF,
    )

def unpack_header(data: bytes) -> HeaderInfo:
    if len(data) < HEADER_SIZE:
        raise ValueError("Dữ liệu quá ngắn — không phải định dạng CrypTool")
    magic, ver, alg_id, kdf_id, flags, salt, nonce, tag, orig_size = struct.unpack(
        HEADER_FMT, data[:HEADER_SIZE]
    )
    if magic != MAGIC:
        raise ValueError(f"Magic bytes không đúng: {magic!r}")
    if ver not in (0x01, 0x02):
        raise ValueError(f"Phiên bản không hỗ trợ: {ver:#04x}")
    return HeaderInfo(Algorithm(alg_id), KDF(kdf_id), flags, salt, nonce, tag, orig_size)


# ─── Small-data encrypt/decrypt (text & files < threshold) ──────────────────

def encrypt_data(
    plaintext: bytes,
    password: str,
    alg: Algorithm = Algorithm.AES_GCM,
    kdf: KDF       = KDF.ARGON2ID,
) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key  = derive_key(password.encode(), salt, kdf)

    if alg == Algorithm.AES_GCM:
        nonce, tag, ct = encrypt_gcm(plaintext, key)
    elif alg == Algorithm.AES_CBC:
        nonce, tag, ct = encrypt_cbc(plaintext, key)
    elif alg == Algorithm.AES_SIV:
        nonce, tag, ct = encrypt_siv(plaintext, key)
    else:
        raise ValueError(f"Algorithm không hỗ trợ: {alg}")

    header = pack_header(alg, kdf, 0, salt, nonce, tag, len(plaintext))
    return header + ct

def decrypt_data(blob: bytes, password: str) -> bytes:
    info = unpack_header(blob)
    if info.flags & FLAG_STREAMING:
        raise ValueError("Đây là file streaming, dùng _file_streamer.decrypt_file()")
    key = derive_key(password.encode(), info.salt, info.kdf)
    ct  = blob[HEADER_SIZE:]

    if info.algorithm == Algorithm.AES_GCM:
        return decrypt_gcm(key, info.nonce, info.tag, ct)
    elif info.algorithm == Algorithm.AES_CBC:
        return decrypt_cbc(key, info.nonce, info.tag, ct)
    elif info.algorithm == Algorithm.AES_SIV:
        return decrypt_siv(key, info.nonce, info.tag, ct)
    raise ValueError(f"Algorithm không xác định: {info.algorithm}")

def get_blob_info(blob: bytes) -> dict:
    info = unpack_header(blob)
    return {
        "algorithm":   ALG_LABEL[info.algorithm],
        "kdf":         KDF_LABEL[info.kdf],
        "key_size":    "256-bit",
        "flags":       info.flags,
        "streaming":   bool(info.flags & FLAG_STREAMING),
        "orig_size":   info.orig_size,
        "cipher_size": len(blob) - HEADER_SIZE,
        "salt_hex":    info.salt.hex()[:20] + "...",
        "tag_hex":     info.tag.hex(),
        "header_size": HEADER_SIZE,
    }


# ─── Password Strength ───────────────────────────────────────────────────────

def password_strength(pwd: str) -> tuple[str, str]:
    """(label, rich_color)."""
    s = 0
    if len(pwd) >= 12: s += 1
    if len(pwd) >= 20: s += 1
    if any(c.isupper() for c in pwd): s += 1
    if any(c.islower() for c in pwd): s += 1
    if any(c.isdigit() for c in pwd): s += 1
    if any(c in r"!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd): s += 1
    table = [
        (1, "Rất yếu",   "red"),
        (2, "Yếu",       "orange1"),
        (3, "Trung bình","yellow"),
        (4, "Khá",       "cyan"),
        (5, "Mạnh",      "green"),
        (6, "Rất mạnh",  "bright_green"),
    ]
    for threshold, label, color in table:
        if s <= threshold:
            return label, color
    return "Rất mạnh", "bright_green"
