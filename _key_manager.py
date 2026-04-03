"""
_key_manager.py — Quản lý file khóa nhị phân (.ckey)

Định dạng CKEYFILE:
  [0:8]   Magic "CKEYFILE"
  [8]     Version 0x01
  [9]     Protection  (0=none, 1=password)
  [10]    Default algorithm
  [11]    Default KDF
  [12:20] Created timestamp (int64 LE, unix seconds)
  [20:52] Salt (32B, zeros nếu không bảo vệ)
  [52:64] Nonce (12B, zeros nếu không bảo vệ)
  [64:80] GCM Tag (16B, zeros nếu không bảo vệ)
  [80:84] Metadata JSON length (uint32 LE)
  [84:116] Key data (32B — raw hoặc AES-GCM encrypted)
  [116:]  Metadata JSON (UTF-8)
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from _crypto_engine import Algorithm, KDF, KEY_SIZE, ALG_LABEL, KDF_LABEL

# ─── Binary format ────────────────────────────────────────────────────────────

KEY_MAGIC    = b"CKEYFILE"
KEY_VERSION  = 0x01

PROTECT_NONE = 0x00
PROTECT_PWD  = 0x01

KEY_HDR_FMT  = "<8sBBBBq32s12s16sI"
KEY_HDR_SIZE = struct.calcsize(KEY_HDR_FMT)   # = 84
KEY_DATA_OFFSET = KEY_HDR_SIZE                 # key 32B ngay sau header
META_OFFSET     = KEY_DATA_OFFSET + KEY_SIZE   # = 116

assert KEY_HDR_SIZE == 84
assert META_OFFSET == 116


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class KeyMeta:
    description: str       = ""
    fingerprint: str       = ""
    created_at:  str       = ""
    algorithm:   str       = "AES-256-GCM"
    kdf:         str       = "Argon2id"
    version:     str       = "1.0"
    tags:        list[str] = field(default_factory=list)

@dataclass
class KeyFile:
    """Đại diện cho một file khóa .ckey đã được tải."""
    raw_key:    bytes        # 32-byte AES-256 key
    protection: int          # PROTECT_NONE hoặc PROTECT_PWD
    default_alg: Algorithm
    default_kdf: KDF
    meta: KeyMeta


# ─── Helpers ──────────────────────────────────────────────────────────────────

def key_fingerprint(raw_key: bytes) -> str:
    """Tạo fingerprint ngắn gọn từ raw key."""
    digest = hashlib.sha256(b"fingerprint:" + raw_key).hexdigest()
    parts  = [digest[i:i+4] for i in range(0, 20, 4)]
    return ":".join(parts)

def _derive_key_protection(password: str, salt: bytes) -> bytes:
    """KDF để mã hóa khóa trong file (Argon2id nhẹ hơn để mở file nhanh)."""
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=32_768,   # 32 MB (nhẹ hơn data encryption)
        parallelism=2,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )

def _encrypt_key(raw_key: bytes, password: str) -> tuple[bytes, bytes, bytes]:
    """Mã hóa raw key bằng AES-GCM với password. → (salt, nonce, encrypted_key+tag)."""
    salt  = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    pkey  = _derive_key_protection(password, salt)
    ct    = AESGCM(pkey).encrypt(nonce, raw_key, b"ckeyfile-v1")
    return salt, nonce, ct   # ct = 32B key + 16B tag = 48B

def _decrypt_key(encrypted: bytes, salt: bytes, nonce: bytes, password: str) -> bytes:
    """Giải mã key từ file."""
    pkey = _derive_key_protection(password, salt)
    try:
        return AESGCM(pkey).decrypt(nonce, encrypted, b"ckeyfile-v1")
    except Exception:
        raise ValueError("Mật khẩu key file sai hoặc file bị hỏng")


# ─── Save ─────────────────────────────────────────────────────────────────────

def save_key(
    path:        Path,
    raw_key:     bytes,
    *,
    password:    Optional[str]   = None,
    default_alg: Algorithm       = Algorithm.AES_GCM,
    default_kdf: KDF             = KDF.ARGON2ID,
    description: str             = "",
    tags:        list[str]       = (),
) -> KeyFile:
    """
    Lưu AES key ra file nhị phân .ckey.
    Nếu password=None → key lưu raw (không bảo vệ).
    Nếu password=str  → key được mã hóa AES-GCM.
    """
    if len(raw_key) != KEY_SIZE:
        raise ValueError(f"raw_key phải đúng {KEY_SIZE} bytes, got {len(raw_key)}")

    now = int(time.time())
    fp  = key_fingerprint(raw_key)

    meta = KeyMeta(
        description=description,
        fingerprint=fp,
        created_at=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        algorithm=ALG_LABEL[default_alg],
        kdf=KDF_LABEL[default_kdf],
        tags=list(tags),
    )
    meta_bytes = json.dumps(asdict(meta), ensure_ascii=False).encode()

    if password is not None:
        protection = PROTECT_PWD
        salt, nonce, key_data = _encrypt_key(raw_key, password)
        # key_data = 48B (32B key + 16B GCM tag)
        # Pad/trim to KEY_SIZE for the fixed slot — store full 48B
        # → Adjust: we store 48B in key slot; let's make key slot 48B
        # Actually simplest: always store 48B in key slot (accommodate tag)
    else:
        protection = PROTECT_NONE
        salt   = b"\x00" * 32
        nonce  = b"\x00" * 12
        key_data = raw_key   # 32B

    # Fixed key slot: always 48 bytes (32B raw key padded, or 48B encrypted)
    if protection == PROTECT_NONE:
        key_slot = raw_key + b"\x00" * 16    # 48B = key + zero padding
        tag_bytes = b"\x00" * 16
    else:
        key_slot  = key_data    # 48B = encrypted key + GCM tag
        tag_bytes = b"\x00" * 16   # not used (GCM tag embedded in key_slot)

    header = struct.pack(
        KEY_HDR_FMT,
        KEY_MAGIC, KEY_VERSION, protection, int(default_alg), int(default_kdf),
        now, salt, nonce, tag_bytes, len(meta_bytes),
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + key_slot + meta_bytes)

    # Set restrictive permissions (Unix only)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

    return KeyFile(raw_key=raw_key, protection=protection,
                   default_alg=default_alg, default_kdf=default_kdf, meta=meta)


# ─── Load ─────────────────────────────────────────────────────────────────────

def load_key(path: Path, password: Optional[str] = None) -> KeyFile:
    """
    Tải key từ file .ckey.
    password cần thiết nếu file được bảo vệ.
    """
    if not path.exists():
        raise FileNotFoundError(f"Key file không tồn tại: {path}")

    data = path.read_bytes()
    if len(data) < META_OFFSET + 48:
        raise ValueError("File key quá nhỏ hoặc bị hỏng")

    (
        magic, version, protection, alg_id, kdf_id,
        created_ts, salt, nonce, tag_bytes, meta_len,
    ) = struct.unpack(KEY_HDR_FMT, data[:KEY_HDR_SIZE])

    if magic != KEY_MAGIC:
        raise ValueError(f"Không phải CKEYFILE: magic={magic!r}")
    if version != KEY_VERSION:
        raise ValueError(f"Key file version không hỗ trợ: {version}")

    key_slot   = data[KEY_DATA_OFFSET : KEY_DATA_OFFSET + 48]
    meta_bytes = data[KEY_DATA_OFFSET + 48 : KEY_DATA_OFFSET + 48 + meta_len]

    if protection == PROTECT_NONE:
        raw_key = key_slot[:KEY_SIZE]
    elif protection == PROTECT_PWD:
        if password is None:
            raise ValueError("Key file được bảo vệ bằng mật khẩu — cần nhập password")
        raw_key = _decrypt_key(key_slot, salt, nonce, password)
    else:
        raise ValueError(f"Protection mode không xác định: {protection}")

    try:
        meta_dict = json.loads(meta_bytes.decode())
        meta = KeyMeta(**{k: meta_dict.get(k, v)
                         for k, v in asdict(KeyMeta()).items()})
    except Exception:
        meta = KeyMeta(fingerprint=key_fingerprint(raw_key))

    return KeyFile(
        raw_key=raw_key,
        protection=protection,
        default_alg=Algorithm(alg_id),
        default_kdf=KDF(kdf_id),
        meta=meta,
    )


# ─── List Keys ───────────────────────────────────────────────────────────────

def list_keys(directory: Path) -> list[dict]:
    """Liệt kê tất cả file .ckey trong thư mục."""
    results = []
    for p in sorted(directory.glob("**/*.ckey")):
        try:
            data = p.read_bytes()
            (_, _, protection, alg_id, kdf_id,
             created_ts, _, _, _, meta_len) = struct.unpack(KEY_HDR_FMT, data[:KEY_HDR_SIZE])
            meta_bytes = data[KEY_DATA_OFFSET + 48 : KEY_DATA_OFFSET + 48 + meta_len]
            try:
                meta_dict = json.loads(meta_bytes.decode())
            except Exception:
                meta_dict = {}
            results.append({
                "path":        str(p),
                "name":        p.stem,
                "size":        p.stat().st_size,
                "protection":  "🔒 Password" if protection == PROTECT_PWD else "🔓 None",
                "algorithm":   ALG_LABEL.get(alg_id, f"algo:{alg_id}"),
                "kdf":         KDF_LABEL.get(kdf_id, f"kdf:{kdf_id}"),
                "fingerprint": meta_dict.get("fingerprint", "?"),
                "description": meta_dict.get("description", ""),
                "created_at":  meta_dict.get("created_at", "?"),
            })
        except Exception as e:
            results.append({"path": str(p), "error": str(e)})
    return results


# ─── Key Generation ──────────────────────────────────────────────────────────

def generate_key() -> bytes:
    """Tạo AES-256 key ngẫu nhiên an toàn."""
    return secrets.token_bytes(KEY_SIZE)
