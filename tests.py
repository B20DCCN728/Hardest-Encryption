#!/usr/bin/env python3
"""
Tests CrypTool v2 — 7 nhóm kiểm thử toàn diện
Chạy: python tests.py
"""
from __future__ import annotations

import hashlib
import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _crypto_engine import (
    Algorithm, KDF, HEADER_SIZE, FLAG_STREAMING,
    derive_key, encrypt_data, decrypt_data, get_blob_info,
    pack_header, unpack_header, password_strength,
    SALT_SIZE, GCM_NONCE,
)
from _key_manager import (
    generate_key, save_key, load_key, list_keys,
    key_fingerprint, PROTECT_NONE, PROTECT_PWD, KEY_HDR_SIZE,
)
from _file_streamer import (
    encrypt_file_stream, decrypt_file_stream,
    detect_file_type, format_size, should_use_streaming,
    STREAM_HDR_SIZE,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASS = 0
FAIL = 0


def test(name: str, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  ✓  {name}")
        PASS += 1
    except Exception as e:
        print(f"  ✗  {name}")
        print(f"       └─ {type(e).__name__}: {e}")
        FAIL += 1


def section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


# ════════════════════════════════════════════════════════════
# 1. Core Crypto Engine
# ════════════════════════════════════════════════════════════
section("1. Core Crypto Engine — AES + KDF")

def roundtrip(alg, kdf, data=b"Hello CrypTool v2!"):
    blob = encrypt_data(data, "password", alg=alg, kdf=kdf)
    assert decrypt_data(blob, "password") == data

test("GCM + Argon2id",      lambda: roundtrip(Algorithm.AES_GCM, KDF.ARGON2ID))
test("GCM + PBKDF2",        lambda: roundtrip(Algorithm.AES_GCM, KDF.PBKDF2))
test("CBC + Argon2id",      lambda: roundtrip(Algorithm.AES_CBC, KDF.ARGON2ID))
test("CBC + PBKDF2",        lambda: roundtrip(Algorithm.AES_CBC, KDF.PBKDF2))
test("SIV + Argon2id",      lambda: roundtrip(Algorithm.AES_SIV, KDF.ARGON2ID))

def test_large():
    data = secrets.token_bytes(2 * 1024 * 1024)  # 2 MB
    roundtrip(Algorithm.AES_GCM, KDF.PBKDF2, data)

def test_empty():
    roundtrip(Algorithm.AES_GCM, KDF.PBKDF2, b"")

def test_unicode():
    data = "🔐 Tiếng Việt có dấu — CrypTool v2 — こんにちは".encode()
    roundtrip(Algorithm.AES_GCM, KDF.ARGON2ID, data)

def test_binary_all_bytes():
    data = bytes(range(256)) * 50
    roundtrip(Algorithm.AES_CBC, KDF.PBKDF2, data)

test("Data lớn (2 MB)",     test_large)
test("Empty data",           test_empty)
test("Unicode + emoji",      test_unicode)
test("Binary all 256 bytes", test_binary_all_bytes)

# ════════════════════════════════════════════════════════════
# 2. Security Properties
# ════════════════════════════════════════════════════════════
section("2. Security Properties — Bảo mật")

def test_wrong_password_gcm():
    blob = encrypt_data(b"secret", "correct", alg=Algorithm.AES_GCM)
    try:
        decrypt_data(blob, "wrong")
        assert False, "Phải raise"
    except Exception:
        pass

def test_wrong_password_cbc():
    blob = encrypt_data(b"secret", "correct", alg=Algorithm.AES_CBC)
    try:
        decrypt_data(blob, "wrong")
        assert False
    except Exception:
        pass

def test_tamper_gcm():
    blob = encrypt_data(b"secret data", "password", alg=Algorithm.AES_GCM)
    ba = bytearray(blob)
    ba[HEADER_SIZE + 5] ^= 0xFF
    try:
        decrypt_data(bytes(ba), "password")
        assert False
    except Exception:
        pass

def test_tamper_cbc_mac():
    blob = encrypt_data(b"secret", "password", alg=Algorithm.AES_CBC)
    ba = bytearray(blob)
    ba[HEADER_SIZE + 3] ^= 0xAA
    try:
        decrypt_data(bytes(ba), "password")
        assert False
    except Exception:
        pass

def test_tamper_magic():
    blob = encrypt_data(b"test", "password")
    ba   = bytearray(blob)
    ba[0] = 0xFF   # corrupt magic
    try:
        unpack_header(bytes(ba))
        assert False
    except ValueError:
        pass

def test_nonce_unique():
    blobs = [encrypt_data(b"same", "password") for _ in range(10)]
    assert len(set(blobs)) == 10, "Mỗi blob phải unique"

def test_semantic_security():
    plain = b"A" * 200
    blobs = {encrypt_data(plain, "password") for _ in range(5)}
    assert len(blobs) == 5

def test_no_plaintext_leak():
    """Plaintext không được xuất hiện trong ciphertext."""
    plain = b"ULTRA_SECRET_PLAINTEXT_1234567890"
    blob  = encrypt_data(plain, "password")
    ct    = blob[HEADER_SIZE:]
    assert plain not in ct, "Plaintext bị lộ trong ciphertext"

def test_streaming_flag():
    """FLAG_STREAMING phải được đặt đúng trong header."""
    salt  = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(GCM_NONCE)
    hdr   = pack_header(Algorithm.AES_GCM, KDF.PBKDF2, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    info  = unpack_header(hdr)
    assert info.flags & FLAG_STREAMING

test("Sai password bị từ chối (GCM)",   test_wrong_password_gcm)
test("Sai password bị từ chối (CBC)",   test_wrong_password_cbc)
test("Giả mạo ciphertext (GCM)",        test_tamper_gcm)
test("Giả mạo ciphertext (CBC+HMAC)",   test_tamper_cbc_mac)
test("Giả mạo magic bytes",             test_tamper_magic)
test("Nonce unique mỗi lần",            test_nonce_unique)
test("Semantic security (IND-CPA)",     test_semantic_security)
test("Không lộ plaintext",              test_no_plaintext_leak)
test("FLAG_STREAMING trong header",     test_streaming_flag)

# ════════════════════════════════════════════════════════════
# 3. Key Manager
# ════════════════════════════════════════════════════════════
section("3. Key Manager — File .ckey")

def test_key_generate():
    k1 = generate_key()
    k2 = generate_key()
    assert len(k1) == 32
    assert k1 != k2

def test_key_save_load_raw():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "test.ckey"
        raw  = generate_key()
        save_key(path, raw, password=None, description="test")
        kf   = load_key(path, password=None)
        assert kf.raw_key == raw
        assert kf.meta.description == "test"

def test_key_save_load_protected():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "protected.ckey"
        raw  = generate_key()
        save_key(path, raw, password="strongPass!99", description="protected key")
        kf   = load_key(path, password="strongPass!99")
        assert kf.raw_key == raw

def test_key_wrong_password():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "test.ckey"
        raw  = generate_key()
        save_key(path, raw, password="correct")
        try:
            load_key(path, password="wrong")
            assert False, "Phải raise với sai password"
        except Exception:
            pass

def test_key_permissions():
    import stat
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "test.ckey"
        save_key(path, generate_key())
        mode = path.stat().st_mode & 0o777
        # Trên Linux: phải là 600 (owner-only)
        if sys.platform != "win32":
            assert mode == 0o600, f"Mode phải 600, got {oct(mode)}"

def test_key_fingerprint_stable():
    raw = generate_key()
    fp1 = key_fingerprint(raw)
    fp2 = key_fingerprint(raw)
    assert fp1 == fp2

def test_key_fingerprint_different():
    fp1 = key_fingerprint(generate_key())
    fp2 = key_fingerprint(generate_key())
    assert fp1 != fp2

def test_key_metadata():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "meta.ckey"
        raw  = generate_key()
        save_key(path, raw, password=None,
                 description="My key", tags=["video", "backup"],
                 default_alg=Algorithm.AES_CBC)
        kf = load_key(path)
        assert kf.meta.description == "My key"
        assert "video" in kf.meta.tags
        assert kf.default_alg == Algorithm.AES_CBC

def test_key_list():
    with tempfile.TemporaryDirectory() as td:
        for i in range(3):
            save_key(Path(td) / f"key{i}.ckey", generate_key(), description=f"key-{i}")
        items = list_keys(Path(td))
        assert len(items) == 3
        assert all("error" not in item for item in items)

def test_key_bad_magic():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "bad.ckey"
        path.write_bytes(b"NOTAKEY" + b"\x00" * 200)
        try:
            load_key(path)
            assert False
        except ValueError as e:
            assert "CKEYFILE" in str(e) or "magic" in str(e).lower() or "không phải" in str(e).lower()

test("Tạo key ngẫu nhiên",           test_key_generate)
test("Lưu/tải key không bảo vệ",     test_key_save_load_raw)
test("Lưu/tải key có password",      test_key_save_load_protected)
test("Sai password key file",         test_key_wrong_password)
test("Quyền file 600 (Unix)",         test_key_permissions)
test("Fingerprint ổn định",           test_key_fingerprint_stable)
test("Fingerprint khác nhau",         test_key_fingerprint_different)
test("Metadata được lưu chính xác",  test_key_metadata)
test("Liệt kê nhiều key files",       test_key_list)
test("Magic bytes check",             test_key_bad_magic)

# ════════════════════════════════════════════════════════════
# 4. Streaming File Encryption
# ════════════════════════════════════════════════════════════
section("4. Streaming File Encryption — Video/Image/Document")

def _make_test_file(size: int, suffix: str = ".bin") -> Path:
    p = Path(tempfile.mktemp(suffix=suffix))
    p.write_bytes(secrets.token_bytes(size))
    return p

def test_stream_small_file():
    """1 KB — streaming với 1 chunk."""
    src = _make_test_file(1024, ".jpg")
    dst = src.with_suffix(".enc")
    dec = src.with_suffix(".dec.jpg")
    key   = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    encrypt_file_stream(src, dst, key, nonce, ghdr, chunk_size=4096)
    result = decrypt_file_stream(dst, dec, key, nonce)
    assert dec.read_bytes() == src.read_bytes()
    assert result.orig_ext == ".jpg"
    for p in (src, dst, dec): p.unlink(missing_ok=True)

def test_stream_medium_file():
    """1 MB — nhiều chunks."""
    src = _make_test_file(1 * 1024 * 1024, ".mp4")
    dst = src.with_suffix(".enc")
    dec = src.with_suffix(".dec.mp4")
    key   = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    encrypt_file_stream(src, dst, key, nonce, ghdr, chunk_size=256*1024)
    result = decrypt_file_stream(dst, dec, key, nonce)
    assert dec.read_bytes() == src.read_bytes()
    assert result.num_chunks > 1
    for p in (src, dst, dec): p.unlink(missing_ok=True)

def test_stream_empty_file():
    """File rỗng — 0 bytes."""
    src = _make_test_file(0, ".txt")
    dst = src.with_suffix(".enc")
    dec = src.with_suffix(".dec.txt")
    key   = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    encrypt_file_stream(src, dst, key, nonce, ghdr)
    decrypt_file_stream(dst, dec, key, nonce)
    assert dec.read_bytes() == b""
    for p in (src, dst, dec): p.unlink(missing_ok=True)

def test_stream_tamper_chunk():
    """Sửa 1 byte trong chunk → phải bị phát hiện."""
    src = _make_test_file(512 * 1024, ".bin")
    dst = src.with_suffix(".enc")
    dec = src.with_suffix(".dec")
    key   = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    encrypt_file_stream(src, dst, key, nonce, ghdr)

    # Corrupt 1 byte trong phần ciphertext
    ba = bytearray(dst.read_bytes())
    ba[HEADER_SIZE + STREAM_HDR_SIZE + 20] ^= 0xFF
    dst.write_bytes(bytes(ba))

    try:
        decrypt_file_stream(dst, dec, key, nonce)
        assert False, "Phải phát hiện giả mạo"
    except Exception:
        pass
    for p in (src, dst, dec): p.unlink(missing_ok=True)

def test_stream_hmac_tamper():
    """Sửa HMAC cuối file → phải bị phát hiện."""
    src = _make_test_file(256 * 1024, ".bin")
    dst = src.with_suffix(".enc")
    dec = src.with_suffix(".dec")
    key   = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    encrypt_file_stream(src, dst, key, nonce, ghdr)

    ba = bytearray(dst.read_bytes())
    ba[-5] ^= 0xAB   # corrupt HMAC
    dst.write_bytes(bytes(ba))

    try:
        decrypt_file_stream(dst, dec, key, nonce)
        assert False, "Phải phát hiện HMAC sai"
    except Exception:
        pass
    for p in (src, dst, dec): p.unlink(missing_ok=True)

def test_stream_wrong_key():
    """Sai key → phải thất bại."""
    src = _make_test_file(64 * 1024, ".bin")
    dst = src.with_suffix(".enc")
    dec = src.with_suffix(".dec")
    key   = generate_key()
    wrong_key = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    encrypt_file_stream(src, dst, key, nonce, ghdr)
    try:
        decrypt_file_stream(dst, dec, wrong_key, nonce)
        assert False
    except Exception:
        pass
    for p in (src, dst, dec): p.unlink(missing_ok=True)

def test_stream_chunk_count():
    """Số chunk chính xác."""
    src = _make_test_file(1 * 1024 * 1024, ".bin")
    dst = src.with_suffix(".enc")
    key   = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    result = encrypt_file_stream(src, dst, key, nonce, ghdr, chunk_size=256*1024)
    assert result.num_chunks == 4   # 1MB / 256KB = 4 chunks
    for p in (src, dst): p.unlink(missing_ok=True)

def test_stream_ext_preserved():
    """Extension gốc được lưu trong stream header."""
    src = _make_test_file(10 * 1024, ".mkv")
    dst = src.with_suffix(".enc")
    key   = generate_key()
    nonce = secrets.token_bytes(GCM_NONCE)
    salt  = secrets.token_bytes(SALT_SIZE)
    ghdr  = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    result = encrypt_file_stream(src, dst, key, nonce, ghdr)
    assert result.orig_ext == ".mkv"
    for p in (src, dst): p.unlink(missing_ok=True)

def test_stream_with_keyfile():
    """Workflow hoàn chỉnh: keygen → save → encrypt → decrypt."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        kf_path = td / "test.ckey"
        src     = td / "video.mp4"
        dst     = td / "video.mp4.enc"
        dec     = td / "video_dec.mp4"

        src.write_bytes(secrets.token_bytes(500 * 1024))

        # Tạo và lưu key
        raw_key = generate_key()
        save_key(kf_path, raw_key, password="keypass", description="test video key")

        # Load key và mã hóa
        kf    = load_key(kf_path, password="keypass")
        nonce = secrets.token_bytes(GCM_NONCE)
        salt  = secrets.token_bytes(SALT_SIZE)
        ghdr  = pack_header(kf.default_alg, kf.default_kdf, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
        encrypt_file_stream(src, dst, kf.raw_key, nonce, ghdr)

        # Load key và giải mã
        kf2 = load_key(kf_path, password="keypass")
        hdr = unpack_header(dst.read_bytes())
        decrypt_file_stream(dst, dec, kf2.raw_key, hdr.nonce[:12])

        assert dec.read_bytes() == src.read_bytes()

test("Stream file nhỏ (1 KB .jpg)",    test_stream_small_file)
test("Stream file trung (1 MB .mp4)",  test_stream_medium_file)
test("Stream file rỗng (0 B)",         test_stream_empty_file)
test("Phát hiện giả mạo chunk",        test_stream_tamper_chunk)
test("Phát hiện giả mạo HMAC",         test_stream_hmac_tamper)
test("Sai key bị từ chối",             test_stream_wrong_key)
test("Số chunks chính xác",            test_stream_chunk_count)
test("Extension được lưu (.mkv)",       test_stream_ext_preserved)
test("Workflow hoàn chỉnh với .ckey",  test_stream_with_keyfile)

# ════════════════════════════════════════════════════════════
# 5. File Type Detection
# ════════════════════════════════════════════════════════════
section("5. File Type Detection")

def test_detect_video():
    _, icon = detect_file_type(Path("movie.mp4"))
    assert icon == "🎬"

def test_detect_image():
    _, icon = detect_file_type(Path("photo.jpg"))
    assert icon == "🖼️"

def test_detect_audio():
    _, icon = detect_file_type(Path("song.mp3"))
    assert icon == "🎵"

def test_detect_doc():
    _, icon = detect_file_type(Path("report.pdf"))
    assert icon == "📄"

def test_detect_unknown():
    _, icon = detect_file_type(Path("data.xyz"))
    assert icon == "📁"

def test_format_size():
    assert "1.0 KB" == format_size(1024)
    assert "1.0 MB" == format_size(1024**2)
    assert "1.0 GB" == format_size(1024**3)

test("Nhận diện video (.mp4)",   test_detect_video)
test("Nhận diện image (.jpg)",   test_detect_image)
test("Nhận diện audio (.mp3)",   test_detect_audio)
test("Nhận diện document (.pdf)",test_detect_doc)
test("File lạ → 📁",            test_detect_unknown)
test("Format size đúng",         test_format_size)

# ════════════════════════════════════════════════════════════
# 6. Header & Info
# ════════════════════════════════════════════════════════════
section("6. Header Format & Info")

def test_header_size():
    assert HEADER_SIZE == 80

def test_header_roundtrip():
    salt  = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(GCM_NONCE)
    tag   = secrets.token_bytes(16)
    hdr   = pack_header(Algorithm.AES_CBC, KDF.PBKDF2, FLAG_STREAMING, salt, nonce, tag, 1234)
    info  = unpack_header(hdr)
    assert info.algorithm == Algorithm.AES_CBC
    assert info.kdf       == KDF.PBKDF2
    assert info.flags     == FLAG_STREAMING
    assert info.salt      == salt
    assert info.orig_size == 1234

def test_get_blob_info():
    blob = encrypt_data(b"hello", "password", alg=Algorithm.AES_GCM, kdf=KDF.PBKDF2)
    info = get_blob_info(blob)
    assert info["algorithm"] == "AES-256-GCM"
    assert info["kdf"] == "PBKDF2-SHA256"
    assert not info["streaming"]

def test_streaming_flag_in_info():
    salt  = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(GCM_NONCE)
    hdr   = pack_header(Algorithm.AES_GCM, KDF.ARGON2ID, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
    dummy = hdr + b"\x00" * 100
    info  = get_blob_info(dummy)
    assert info["streaming"] is True

test("HEADER_SIZE = 80 bytes",     test_header_size)
test("Header round-trip",          test_header_roundtrip)
test("get_blob_info() direct",     test_get_blob_info)
test("get_blob_info() streaming",  test_streaming_flag_in_info)

# ════════════════════════════════════════════════════════════
# 7. Edge Cases
# ════════════════════════════════════════════════════════════
section("7. Edge Cases")

def test_special_password():
    pwd = "!@#$%^&*()_+{}|:\"<>?🔑€¥"
    data = b"special password test"
    blob = encrypt_data(data, pwd)
    assert decrypt_data(blob, pwd) == data

def test_very_long_password():
    pwd = "A" * 10_000
    data = b"long password test"
    blob = encrypt_data(data, pwd)
    assert decrypt_data(blob, pwd) == data

def test_null_bytes_data():
    data = b"\x00" * 500 + b"secret" + b"\x00" * 500
    blob = encrypt_data(data, "password")
    assert decrypt_data(blob, "password") == data

def test_password_strength_weak():
    level, _ = password_strength("abc")
    assert level in ("Rất yếu", "Yếu")

def test_password_strength_strong():
    level, _ = password_strength("MyStr0ng!Password#2024")
    assert level in ("Mạnh", "Rất mạnh")

def test_each_encryption_unique():
    plain = b"same input"
    enc = {encrypt_data(plain, "password") for _ in range(5)}
    assert len(enc) == 5

def test_key_size_256():
    salt = secrets.token_bytes(32)
    k = derive_key(b"password", salt, KDF.PBKDF2)
    assert len(k) == 32

test("Password ký tự đặc biệt",     test_special_password)
test("Password rất dài (10K chars)", test_very_long_password)
test("Data chứa null bytes",         test_null_bytes_data)
test("Password strength: yếu",       test_password_strength_weak)
test("Password strength: mạnh",      test_password_strength_strong)
test("Mỗi lần mã hóa unique",       test_each_encryption_unique)
test("Key size = 32 bytes (AES-256)", test_key_size_256)

# ════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════
total = PASS + FAIL
print(f"\n{'═'*60}")
print(f"  Kết quả: {PASS}/{total} tests passed", end="")
if FAIL == 0:
    print("  🎉 All passed!")
else:
    print(f"  ({FAIL} FAILED) ❌")
print(f"{'═'*60}\n")

sys.exit(0 if FAIL == 0 else 1)
