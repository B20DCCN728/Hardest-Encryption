"""
_file_streamer.py — Mã hóa file streaming (video, ảnh, tài liệu lớn)

Định dạng file .enc (streaming):
  [Global Header  80B ]  ← pack_header(flags=FLAG_STREAMING)
  [Stream Header  56B ]  ← STRM magic + metadata
  [Chunk 0            ]  ← nonce(12) + ct_len(4) + ciphertext+tag
  [Chunk 1            ]
  ...
  [Stream HMAC    32B ]  ← HMAC-SHA256 toàn bộ chunk tags (integrity)

Mỗi chunk được mã hóa AES-256-GCM độc lập với:
  • Nonce riêng: SHA256(master_nonce + chunk_index)[:12]
  • AAD: "ch:" + chunk_index(8B LE) + master_nonce  → chống reorder

Chunk size mặc định: 4 MB (điều chỉnh được)
"""
from __future__ import annotations

import hashlib
import hmac
import mimetypes
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from _crypto_engine import HEADER_SIZE

# ─── Hằng số ──────────────────────────────────────────────────────────────────

STREAM_MAGIC     = b"STRM"
DEFAULT_CHUNK    = 4 * 1024 * 1024     # 4 MB
GCM_TAG_SIZE     = 16
STREAM_HMAC_SIZE = 32

# Stream Header format (56 bytes):
#   [0:4]   Magic "STRM"
#   [4:8]   Chunk size (uint32)
#   [8:16]  Original file size (uint64)
#   [16:24] Number of chunks (uint64)
#   [24:25] Extension length (uint8)
#   [25:41] Extension string (16B, null-padded)
#   [41:49] MIME type (8B, null-padded preview)
#   [49:56] Reserved (7B)

STREAM_HDR_FMT  = "<4sIQQB16s8s7s"
STREAM_HDR_SIZE = struct.calcsize(STREAM_HDR_FMT)
assert STREAM_HDR_SIZE == 56, f"Got {STREAM_HDR_SIZE}"

# ─── Callbacks ────────────────────────────────────────────────────────────────

ProgressCallback = Callable[[int, int, float], None]   # (bytes_done, total, speed_bps)


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class StreamResult:
    orig_size:   int
    enc_size:    int
    num_chunks:  int
    chunk_size:  int
    orig_ext:    str
    mime_type:   str
    elapsed_sec: float

    @property
    def speed_mbps(self) -> float:
        if self.elapsed_sec <= 0:
            return 0.0
        return (self.orig_size / self.elapsed_sec) / (1024 * 1024)

    @property
    def overhead_bytes(self) -> int:
        return self.enc_size - self.orig_size


# ─── Nonce & AAD derivation ──────────────────────────────────────────────────

def _chunk_nonce(master_nonce: bytes, chunk_idx: int) -> bytes:
    """Nonce duy nhất cho mỗi chunk, dẫn xuất từ master nonce."""
    return hashlib.sha256(
        b"nonce:" + master_nonce + struct.pack("<Q", chunk_idx)
    ).digest()[:12]

def _chunk_aad(master_nonce: bytes, chunk_idx: int) -> bytes:
    """AAD gắn chunk vào vị trí — chống chunk reordering attack."""
    return b"ch:" + struct.pack("<Q", chunk_idx) + master_nonce


# ─── File Type Detection ─────────────────────────────────────────────────────

def detect_file_type(path: Path) -> tuple[str, str]:
    """Trả về (mime_type, icon) dựa trên extension."""
    ext  = path.suffix.lower()
    mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"

    VIDEO_EXT = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".ts", ".mpg", ".mpeg"}
    IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg", ".heic", ".raw", ".cr2"}
    AUDIO_EXT = {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma", ".opus"}
    DOC_EXT   = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt"}
    ARCH_EXT  = {".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz", ".zst"}
    CODE_EXT  = {".py", ".js", ".ts", ".go", ".rs", ".cpp", ".c", ".java", ".rb", ".php"}
    DB_EXT    = {".db", ".sqlite", ".sqlite3", ".sql"}

    if ext in VIDEO_EXT: return mime, "🎬"
    if ext in IMAGE_EXT: return mime, "🖼️"
    if ext in AUDIO_EXT: return mime, "🎵"
    if ext in DOC_EXT:   return mime, "📄"
    if ext in ARCH_EXT:  return mime, "📦"
    if ext in CODE_EXT:  return mime, "💻"
    if ext in DB_EXT:    return mime, "🗄️"
    return mime, "📁"


# ─── Stream Header Packing ───────────────────────────────────────────────────

def _pack_stream_header(
    chunk_size: int, orig_size: int, num_chunks: int,
    orig_ext: str, mime_type: str,
) -> bytes:
    ext_b    = orig_ext.encode()[:16]
    ext_pad  = ext_b + b"\x00" * (16 - len(ext_b))
    mime_b   = mime_type.encode()[:8]
    mime_pad = mime_b + b"\x00" * (8 - len(mime_b))
    return struct.pack(
        STREAM_HDR_FMT,
        STREAM_MAGIC, chunk_size, orig_size, num_chunks,
        len(ext_b), ext_pad, mime_pad, b"\x00" * 7,
    )

def _unpack_stream_header(data: bytes, offset: int) -> tuple:
    raw = data[offset : offset + STREAM_HDR_SIZE]
    if len(raw) < STREAM_HDR_SIZE:
        raise ValueError("Stream header bị cắt cụt")
    (magic, chunk_size, orig_size, num_chunks,
     ext_len, ext_pad, mime_pad, _) = struct.unpack(STREAM_HDR_FMT, raw)
    if magic != STREAM_MAGIC:
        raise ValueError(f"Stream magic không khớp: {magic!r}")
    orig_ext  = ext_pad[:ext_len].decode(errors="replace")
    mime_type = mime_pad.rstrip(b"\x00").decode(errors="replace")
    return chunk_size, orig_size, num_chunks, orig_ext, mime_type


# ─── Encrypt File (streaming) ────────────────────────────────────────────────

def encrypt_file_stream(
    src:          Path,
    dst:          Path,
    key:          bytes,
    master_nonce: bytes,
    global_header: bytes,
    chunk_size:   int = DEFAULT_CHUNK,
    on_progress:  Optional[ProgressCallback] = None,
) -> StreamResult:
    """
    Mã hóa file theo từng chunk bằng AES-256-GCM.
    global_header: 80-byte header đã được tạo sẵn, ghi trước stream data.
    """
    orig_size = src.stat().st_size
    mime_type, _ = detect_file_type(src)
    orig_ext  = src.suffix

    num_chunks = max(1, (orig_size + chunk_size - 1) // chunk_size) if orig_size > 0 else 1
    stream_hdr = _pack_stream_header(chunk_size, orig_size, num_chunks, orig_ext, mime_type)

    aesgcm      = AESGCM(key)
    hmac_ctx    = hmac.new(key, b"stream-integrity:", hashlib.sha256)
    enc_size    = len(global_header) + STREAM_HDR_SIZE
    chunk_idx   = 0
    bytes_done  = 0
    t_start     = time.perf_counter()
    t_last      = t_start
    bytes_last  = 0

    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(global_header)
        fout.write(stream_hdr)

        while True:
            chunk = fin.read(chunk_size)
            if not chunk and chunk_idx > 0:
                break                           # EOF
            if not chunk:
                chunk = b""                     # empty file: 1 empty chunk

            nonce     = _chunk_nonce(master_nonce, chunk_idx)
            aad       = _chunk_aad(master_nonce, chunk_idx)
            ct_and_tag = aesgcm.encrypt(nonce, chunk, aad)
            ct_len    = len(ct_and_tag)

            fout.write(nonce)                                  # 12B
            fout.write(struct.pack("<I", ct_len))              # 4B
            fout.write(ct_and_tag)                             # ct + 16B tag

            # HMAC feeds on tag bytes của mỗi chunk (16B cuối ct_and_tag)
            hmac_ctx.update(ct_and_tag[-GCM_TAG_SIZE:])

            enc_size  += 12 + 4 + ct_len
            bytes_done += len(chunk)
            chunk_idx  += 1

            if on_progress and orig_size > 0:
                now = time.perf_counter()
                if now - t_last >= 0.15 or bytes_done >= orig_size:
                    dt    = now - t_last
                    speed = (bytes_done - bytes_last) / max(dt, 1e-9)
                    on_progress(bytes_done, orig_size, speed)
                    t_last    = now
                    bytes_last = bytes_done

            if not chunk:   # empty file: thoát sau 1 chunk
                break

        # Ghi HMAC toàn cục ở cuối
        fout.write(hmac_ctx.digest())
        enc_size += STREAM_HMAC_SIZE

    elapsed = time.perf_counter() - t_start
    return StreamResult(
        orig_size=orig_size, enc_size=enc_size,
        num_chunks=chunk_idx, chunk_size=chunk_size,
        orig_ext=orig_ext, mime_type=mime_type,
        elapsed_sec=elapsed,
    )


# ─── Decrypt File (streaming) ────────────────────────────────────────────────

def decrypt_file_stream(
    src:          Path,
    dst:          Path,
    key:          bytes,
    master_nonce: bytes,
    on_progress:  Optional[ProgressCallback] = None,
) -> StreamResult:
    """
    Giải mã file streaming .enc.
    Đọc stream header tại HEADER_SIZE, sau đó giải mã từng chunk.
    """
    t_start   = time.perf_counter()
    file_data  = src.read_bytes()                # dùng mmap nếu file rất lớn
    stream_off = HEADER_SIZE

    chunk_size, orig_size, num_chunks, orig_ext, mime_type = _unpack_stream_header(
        file_data, stream_off
    )

    aesgcm    = AESGCM(key)
    hmac_ctx  = hmac.new(key, b"stream-integrity:", hashlib.sha256)
    cursor    = stream_off + STREAM_HDR_SIZE
    bytes_done = 0
    t_last    = t_start
    bytes_last = 0

    # Vị trí HMAC = cuối file - 32B
    expected_hmac = file_data[-STREAM_HMAC_SIZE:]
    payload_end   = len(file_data) - STREAM_HMAC_SIZE

    with open(dst, "wb") as fout:
        for chunk_idx in range(num_chunks):
            if cursor + 12 + 4 > payload_end:
                raise ValueError(f"File bị cắt cụt tại chunk {chunk_idx}")

            nonce      = file_data[cursor : cursor + 12]
            ct_len     = struct.unpack("<I", file_data[cursor+12 : cursor+16])[0]
            ct_and_tag = file_data[cursor+16 : cursor+16+ct_len]
            cursor    += 12 + 4 + ct_len

            if len(ct_and_tag) < ct_len:
                raise ValueError(f"Chunk {chunk_idx}: dữ liệu không đủ")

            aad = _chunk_aad(master_nonce, chunk_idx)
            try:
                plaintext = aesgcm.decrypt(nonce, ct_and_tag, aad)
            except Exception:
                raise ValueError(
                    f"Chunk {chunk_idx}: xác thực thất bại — "
                    "sai key hoặc dữ liệu bị giả mạo/sắp xếp lại"
                )

            hmac_ctx.update(ct_and_tag[-GCM_TAG_SIZE:])
            fout.write(plaintext)

            bytes_done += len(plaintext)
            if on_progress and orig_size > 0:
                now = time.perf_counter()
                if now - t_last >= 0.15 or chunk_idx == num_chunks - 1:
                    dt    = now - t_last
                    speed = (bytes_done - bytes_last) / max(dt, 1e-9)
                    on_progress(bytes_done, orig_size, speed)
                    t_last    = now
                    bytes_last = bytes_done

    # Xác minh HMAC toàn stream
    computed_hmac = hmac_ctx.digest()
    if not hmac.compare_digest(computed_hmac, expected_hmac):
        # Xóa file output không hợp lệ
        try:
            dst.unlink()
        except Exception:
            pass
        raise ValueError(
            "Stream HMAC không khớp — file bị giả mạo, chunk bị xóa/đảo thứ tự"
        )

    elapsed = time.perf_counter() - t_start
    enc_size = src.stat().st_size
    return StreamResult(
        orig_size=orig_size, enc_size=enc_size,
        num_chunks=num_chunks, chunk_size=chunk_size,
        orig_ext=orig_ext, mime_type=mime_type,
        elapsed_sec=elapsed,
    )


# ─── Large file helper (mmap for very large files) ───────────────────────────

def should_use_streaming(path: Path, threshold_mb: int = 8) -> bool:
    """File >= threshold_mb MB → dùng streaming."""
    try:
        return path.stat().st_size >= threshold_mb * 1024 * 1024
    except Exception:
        return False

def format_size(n: int) -> str:
    """Hiển thị kích thước file thân thiện."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"
