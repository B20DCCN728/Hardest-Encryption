#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              CrypTool v2 — AES Encryption CLI               ║
║                                                              ║
║  Mã hóa:  AES-256-GCM · AES-256-CBC · AES-256-SIV           ║
║  KDF:     Argon2id · PBKDF2-SHA256                           ║
║  File:    Streaming chunked (video, ảnh, document, ...)      ║
║  Key:     Binary .ckey (có/không password protect)           ║
║  CLI:     Thông tin chi tiết, progress bar, benchmark         ║
╚══════════════════════════════════════════════════════════════╝

Sử dụng:
  python cryptool.py encrypt -f video.mp4 -p "pass"
  python cryptool.py encrypt -f video.mp4 --key-file my.ckey --key-pass "kpass"
  python cryptool.py decrypt -f video.mp4.enc --key-file my.ckey --key-pass "kpass"
  python cryptool.py key generate --save my.ckey --protect
  python cryptool.py key info my.ckey
  python cryptool.py key list .
  python cryptool.py benchmark
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn, DownloadColumn, Progress, SpinnerColumn,
    TaskProgressColumn, TextColumn, TimeElapsedColumn, TransferSpeedColumn,
)
from rich.table import Table
from rich.text import Text

# ─── Imports từ modules ───────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent))

from _crypto_engine import (
    Algorithm, KDF, HEADER_SIZE, FLAG_STREAMING,
    ALG_LABEL, KDF_LABEL,
    derive_key, encrypt_data, decrypt_data, get_blob_info,
    pack_header, unpack_header, password_strength,
    GCM_NONCE, SALT_SIZE,
)
from _key_manager import (
    KeyFile, KeyMeta, generate_key, save_key, load_key,
    list_keys, key_fingerprint, PROTECT_NONE, PROTECT_PWD,
)
from _file_streamer import (
    StreamResult, detect_file_type, format_size,
    encrypt_file_stream, decrypt_file_stream,
    should_use_streaming, STREAM_HDR_SIZE,
    DEFAULT_CHUNK,
)

# ─── App & Console ────────────────────────────────────────────────────────────

app     = typer.Typer(
    name="cryptool",
    help="🔐 [bold]CrypTool v2[/bold] — Mã hóa AES chuyên nghiệp",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)
key_app = typer.Typer(help="🗝️  Quản lý file khóa (.ckey)", no_args_is_help=True)
app.add_typer(key_app, name="key")

console = Console()
err     = Console(stderr=True)

# ─── Shared helpers ───────────────────────────────────────────────────────────

ALG_MAP = {"gcm": Algorithm.AES_GCM, "cbc": Algorithm.AES_CBC, "siv": Algorithm.AES_SIV}
KDF_MAP = {"argon2": KDF.ARGON2ID, "pbkdf2": KDF.PBKDF2}

def _resolve_alg(s: str) -> Algorithm:
    s = s.lower()
    if s not in ALG_MAP:
        err.print(f"[red]✗ Algorithm không hợp lệ: {s}. Chọn: gcm, cbc, siv[/red]")
        raise typer.Exit(1)
    return ALG_MAP[s]

def _resolve_kdf(s: str) -> KDF:
    s = s.lower()
    if s not in KDF_MAP:
        err.print(f"[red]✗ KDF không hợp lệ: {s}. Chọn: argon2, pbkdf2[/red]")
        raise typer.Exit(1)
    return KDF_MAP[s]

def _ask_password(confirm: bool = False) -> str:
    pwd = typer.prompt("🔑 Mật khẩu mã hóa", hide_input=True)
    if confirm:
        pwd2 = typer.prompt("🔑 Xác nhận mật khẩu", hide_input=True)
        if pwd != pwd2:
            err.print("[red]✗ Mật khẩu không khớp[/red]")
            raise typer.Exit(1)
    return pwd

def _load_key_source(
    key_file: Optional[Path],
    key_pass: Optional[str],
    password: Optional[str],
    alg: Algorithm,
    kdf: KDF,
    for_encrypt: bool = True,
) -> tuple[Optional[bytes], Algorithm, KDF, str]:
    """
    Giải quyết nguồn key: key file hoặc password.
    Returns (raw_key_or_None, alg, kdf, source_label).
    raw_key=None nghĩa là dùng password-based KDF (gọi encrypt_data/decrypt_data).
    """
    if key_file is not None:
        if not key_file.exists():
            err.print(f"[red]✗ Key file không tồn tại: {key_file}[/red]")
            raise typer.Exit(1)
        kp = key_pass or (typer.prompt(f"🔑 Mật khẩu key file [{key_file.name}]", hide_input=True)
                          if _is_key_protected(key_file) else None)
        try:
            kf = load_key(key_file, kp)
        except Exception as e:
            err.print(f"[red]✗ Không tải được key file: {e}[/red]")
            raise typer.Exit(1)
        return kf.raw_key, kf.default_alg, kf.default_kdf, f"🗝️ {key_file.name}"
    else:
        if password is None:
            password = _ask_password(confirm=for_encrypt)
        return None, alg, kdf, "🔑 Password"

def _is_key_protected(path: Path) -> bool:
    """Kiểm tra nhanh xem key file có password không."""
    try:
        from _key_manager import KEY_HDR_FMT, KEY_HDR_SIZE, PROTECT_PWD
        import struct as _s
        data = path.read_bytes()
        _, _, protection, *_ = _s.unpack(KEY_HDR_FMT, data[:KEY_HDR_SIZE])
        return protection == PROTECT_PWD
    except Exception:
        return False

def _make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def _wait_for_back() -> None:
    console.print("\n[dim]Nhấn Enter để quay lại menu...[/dim]")
    input()


def _prompt_optional_text(label: str) -> Optional[str]:
    value = typer.prompt(label, default="").strip()
    return value or None


def _prompt_optional_path(label: str) -> Optional[Path]:
    value = typer.prompt(label, default="").strip()
    return Path(value) if value else None


def _prompt_menu_alg(default: str = "gcm") -> str:
    while True:
        value = typer.prompt("Thuật toán [gcm/cbc/siv]", default=default).strip().lower()
        if value in ALG_MAP:
            return value
        err.print("[red]✗ Chọn một trong: gcm, cbc, siv[/red]")


def _prompt_menu_kdf(default: str = "argon2") -> str:
    while True:
        value = typer.prompt("KDF [argon2/pbkdf2]", default=default).strip().lower()
        if value in KDF_MAP:
            return value
        err.print("[red]✗ Chọn một trong: argon2, pbkdf2[/red]")


def _prompt_menu_mode(default: str = "file") -> str:
    while True:
        value = typer.prompt("Chế độ [text/file]", default=default).strip().lower()
        if value in {"text", "file"}:
            return value
        err.print("[red]✗ Chọn một trong: text, file[/red]")


def _menu_encrypt() -> None:
    console.print("\n[bold cyan]🔒 Mã hóa[/bold cyan]")
    mode = _prompt_menu_mode()
    if mode == "text":
        text = typer.prompt("Văn bản cần mã hóa")
        file = None
        output = None
        chunk_mb = 4
        stream_th = 8
        delete_src = False
    else:
        file = Path(typer.prompt("File cần mã hóa"))
        text = None
        output = _prompt_optional_path("Output file [Enter để mặc định]")
        chunk_mb = typer.prompt("Chunk size cho streaming (MB)", type=int, default=4)
        stream_th = typer.prompt("Streaming khi file >= X MB", type=int, default=8)
        delete_src = typer.confirm("Xóa file gốc sau khi mã hóa?", default=False)

    use_key_file = typer.confirm("Dùng file .ckey?", default=False)
    if use_key_file:
        key_file = Path(typer.prompt("Đường dẫn file .ckey"))
        key_pass = _prompt_optional_text("Mật khẩu mở key file [Enter nếu không có]")
        password = None
    else:
        key_file = None
        key_pass = None
        password = _prompt_optional_text("Mật khẩu [Enter để nhập ẩn sau]")

    cmd_encrypt(
        text=text,
        file=file,
        output=output,
        password=password,
        key_file=key_file,
        key_pass=key_pass,
        algorithm=_prompt_menu_alg(),
        kdf=_prompt_menu_kdf(),
        chunk_mb=chunk_mb,
        stream_th=stream_th,
        delete_src=delete_src,
    )


def _menu_decrypt() -> None:
    console.print("\n[bold cyan]🔓 Giải mã[/bold cyan]")
    mode = _prompt_menu_mode()
    if mode == "text":
        text = typer.prompt("Ciphertext Base64")
        file = None
        output = None
    else:
        file = Path(typer.prompt("File .enc"))
        text = None
        output = _prompt_optional_path("Output file [Enter để mặc định]")

    use_key_file = typer.confirm("Dùng file .ckey?", default=False)
    if use_key_file:
        key_file = Path(typer.prompt("Đường dẫn file .ckey"))
        key_pass = _prompt_optional_text("Mật khẩu mở key file [Enter nếu không có]")
        password = None
    else:
        key_file = None
        key_pass = None
        password = _prompt_optional_text("Mật khẩu [Enter để nhập ẩn sau]")

    cmd_decrypt(
        text=text,
        file=file,
        output=output,
        password=password,
        key_file=key_file,
        key_pass=key_pass,
    )


def _menu_key_generate() -> None:
    console.print("\n[bold yellow]🗝️  Tạo key file[/bold yellow]")
    save = Path(typer.prompt("Lưu key vào", default="key.ckey"))
    protect = typer.confirm("Bảo vệ key file bằng mật khẩu?", default=False)
    if protect:
        key_pass = _prompt_optional_text("Mật khẩu bảo vệ [Enter để nhập ẩn sau]")
    else:
        key_pass = None

    cmd_key_generate(
        save=save,
        protect=protect,
        key_pass=key_pass,
        description=typer.prompt("Mô tả", default=""),
        algorithm=_prompt_menu_alg(),
        kdf=_prompt_menu_kdf(),
        tags=typer.prompt("Tags (phân tách bằng dấu phẩy)", default=""),
    )


def _menu_key_info() -> None:
    console.print("\n[bold yellow]📋 Thông tin key file[/bold yellow]")
    cmd_key_info(
        key_path=Path(typer.prompt("Đường dẫn file .ckey")),
        key_pass=_prompt_optional_text("Mật khẩu key file [Enter nếu không có]"),
        show_fp=typer.confirm("Hiển thị fingerprint đầy đủ?", default=False),
    )


def _menu_key_list() -> None:
    console.print("\n[bold yellow]📂 Liệt kê key file[/bold yellow]")
    cmd_key_list(
        directory=Path(typer.prompt("Thư mục tìm kiếm", default=".")),
    )


def _menu_info() -> None:
    console.print("\n[bold blue]📋 Xem thông tin ciphertext[/bold blue]")
    mode = _prompt_menu_mode()
    if mode == "text":
        cmd_info(text=typer.prompt("Ciphertext Base64"), file=None)
    else:
        cmd_info(file=Path(typer.prompt("File .enc")), text=None)


def _menu_benchmark() -> None:
    console.print("\n[bold magenta]⚡ Benchmark[/bold magenta]")
    cmd_benchmark(size_mb=typer.prompt("Kích thước test (MB)", type=int, default=64))


def _run_menu_action(label: str, action) -> None:
    try:
        action()
    except typer.Exit:
        pass
    except Exception as e:
        err.print(f"\n[bold red]✗ Lỗi không mong muốn trong {label}:[/bold red] {e}")
    _wait_for_back()


def _render_interactive_menu() -> None:
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), border_style="cyan")
    table.add_column("", style="bold cyan", width=3)
    table.add_column("")
    table.add_row("1", "🔒 Mã hóa")
    table.add_row("2", "🔓 Giải mã")
    table.add_row("3", "🗝️  Tạo key file")
    table.add_row("4", "📋 Thông tin key file")
    table.add_row("5", "📂 Liệt kê key file")
    table.add_row("6", "📋 Thông tin ciphertext")
    table.add_row("7", "⚡ Benchmark")
    table.add_row("0", "Thoát")
    console.print(Panel(table, title="[bold]CrypTool Interactive Menu[/bold]", border_style="cyan"))


def _run_interactive_menu() -> None:
    actions = {
        "1": ("Mã hóa", _menu_encrypt),
        "2": ("Giải mã", _menu_decrypt),
        "3": ("Tạo key file", _menu_key_generate),
        "4": ("Thông tin key file", _menu_key_info),
        "5": ("Liệt kê key file", _menu_key_list),
        "6": ("Thông tin ciphertext", _menu_info),
        "7": ("Benchmark", _menu_benchmark),
    }

    while True:
        console.print()
        _render_interactive_menu()
        choice = typer.prompt("Chọn chức năng", default="1").strip()
        if choice == "0":
            console.print("\n[bold green]Tạm biệt.[/bold green]\n")
            return
        if choice not in actions:
            err.print("[red]✗ Lựa chọn không hợp lệ. Vui lòng chọn lại.[/red]")
            continue
        label, action = actions[choice]
        _run_menu_action(label, action)


# ─── encrypt ─────────────────────────────────────────────────────────────────

@app.command("encrypt", help="🔒 Mã hóa file (video, ảnh, tài liệu...) hoặc văn bản")
def cmd_encrypt(
    text:       Annotated[Optional[str],  typer.Option("-t","--text",     help="Văn bản cần mã hóa")] = None,
    file:       Annotated[Optional[Path], typer.Option("-f","--file",     help="File cần mã hóa")] = None,
    output:     Annotated[Optional[Path], typer.Option("-o","--output",   help="File output")] = None,
    password:   Annotated[Optional[str],  typer.Option("-p","--password", help="Mật khẩu")] = None,
    key_file:   Annotated[Optional[Path], typer.Option("--key-file",      help="File .ckey thay cho password")] = None,
    key_pass:   Annotated[Optional[str],  typer.Option("--key-pass",      help="Mật khẩu mở key file")] = None,
    algorithm:  Annotated[str,            typer.Option("-a","--algo",     help="gcm | cbc | siv")] = "gcm",
    kdf:        Annotated[str,            typer.Option("-k","--kdf",      help="argon2 | pbkdf2")] = "argon2",
    chunk_mb:   Annotated[int,            typer.Option("--chunk-mb",      help="Chunk size cho streaming (MB)")] = 4,
    stream_th:  Annotated[int,            typer.Option("--stream-from",   help="Dùng streaming khi file >= X MB")] = 8,
    delete_src: Annotated[bool,           typer.Option("--delete-src",    help="Xóa file gốc sau khi mã hóa")] = False,
):
    if text is None and file is None:
        err.print("[red]✗ Cần chỉ định [bold]--text[/bold] hoặc [bold]--file[/bold][/red]")
        raise typer.Exit(1)

    alg_choice = _resolve_alg(algorithm)
    kdf_choice = _resolve_kdf(kdf)

    raw_key, alg_choice, kdf_choice, key_source = _load_key_source(
        key_file, key_pass, password, alg_choice, kdf_choice, for_encrypt=True
    )

    # ── Mã hóa văn bản ───────────────────────────────────────────────────────
    if file is None:
        plaintext = text.encode("utf-8")
        strength, scolor = password_strength(password or "")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("[cyan]Đang mã hóa...", total=None)
            t0   = time.perf_counter()
            if raw_key is not None:
                # Dùng raw key: tự tạo salt + derive nonce
                import secrets as _s
                salt  = _s.token_bytes(SALT_SIZE)
                nonce = _s.token_bytes(GCM_NONCE)
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                ct_tag = AESGCM(raw_key).encrypt(nonce, plaintext, None)
                hdr    = pack_header(alg_choice, kdf_choice, 0, salt, nonce, ct_tag[-16:], len(plaintext))
                blob   = hdr + ct_tag[:-16]
            else:
                blob = encrypt_data(plaintext, password, alg=alg_choice, kdf=kdf_choice)
            elapsed = time.perf_counter() - t0
            prog.update(task, description="[green]✓ Hoàn tất")

        encoded = base64.b64encode(blob).decode()

        table = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        table.add_column("", style="dim", width=22)
        table.add_column("")
        table.add_row("Nguồn",         f"📝 Văn bản ({len(plaintext)} bytes)")
        table.add_row("Thuật toán",    f"[cyan]{ALG_LABEL[alg_choice]}[/cyan]")
        table.add_row("KDF",           f"[cyan]{KDF_LABEL[kdf_choice]}[/cyan]")
        table.add_row("Nguồn khóa",   key_source)
        if password:
            table.add_row("Độ mạnh MK", f"[{scolor}]{strength}[/{scolor}]")
        table.add_row("Kích thước",    f"{len(plaintext)} → {len(blob)} bytes (+{len(blob)-len(plaintext)} overhead)")
        table.add_row("Thời gian",     f"{elapsed*1000:.0f} ms")

        console.print(Panel(table, title="[bold green]🔒 Mã Hóa Thành Công[/bold green]", border_style="green"))
        console.print(Panel(encoded, title="[bold]Ciphertext (Base64)[/bold]", border_style="cyan"))
        return

    # ── Mã hóa file ──────────────────────────────────────────────────────────
    if not file.exists():
        err.print(f"[red]✗ File không tồn tại: {file}[/red]")
        raise typer.Exit(1)

    out_path = output or file.with_suffix(file.suffix + ".enc")
    if out_path == file:
        err.print("[red]✗ Output không được trùng với input[/red]")
        raise typer.Exit(1)

    mime_type, icon = detect_file_type(file)
    file_size       = file.stat().st_size
    use_streaming   = should_use_streaming(file, threshold_mb=stream_th) or raw_key is not None

    console.print(
        f"\n  {icon} [bold]{file.name}[/bold]  "
        f"[dim]{format_size(file_size)} · {mime_type}[/dim]"
    )
    console.print(
        f"  Mode: [cyan]{'Streaming' if use_streaming else 'Direct'}[/cyan]  "
        f"Algo: [cyan]{ALG_LABEL[alg_choice]}[/cyan]  "
        f"Key: {key_source}\n"
    )

    if use_streaming:
        # Tạo key nếu dùng password
        if raw_key is None:
            salt    = secrets.token_bytes(SALT_SIZE)
            raw_key = derive_key(password.encode(), salt, kdf_choice)
        else:
            salt = secrets.token_bytes(SALT_SIZE)

        master_nonce = secrets.token_bytes(GCM_NONCE)
        global_hdr   = pack_header(
            alg_choice, kdf_choice, FLAG_STREAMING,
            salt, master_nonce, b"\x00" * 16, 0
        )

        with _make_progress() as prog:
            task = prog.add_task(
                f"[cyan]Mã hóa {file.name}[/cyan]",
                total=file_size,
            )

            def on_progress(done: int, total: int, speed: float) -> None:
                prog.update(task, completed=done)

            t0 = time.perf_counter()
            result = encrypt_file_stream(
                src=file, dst=out_path,
                key=raw_key, master_nonce=master_nonce,
                global_header=global_hdr,
                chunk_size=chunk_mb * 1024 * 1024,
                on_progress=on_progress,
            )
            prog.update(task, completed=file_size,
                        description=f"[green]✓ {file.name}")

        _print_file_result(
            file, out_path, result, alg_choice, kdf_choice, key_source, streaming=True
        )

    else:
        # Direct encryption (file nhỏ)
        plaintext = file.read_bytes()

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task(f"[cyan]Mã hóa {file.name}...", total=None)
            t0   = time.perf_counter()
            if raw_key is not None:
                salt  = secrets.token_bytes(SALT_SIZE)
                nonce = secrets.token_bytes(GCM_NONCE)
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                ct_tag = AESGCM(raw_key).encrypt(nonce, plaintext, None)
                hdr    = pack_header(alg_choice, kdf_choice, 0, salt, nonce, ct_tag[-16:], len(plaintext))
                blob   = hdr + ct_tag[:-16]
            else:
                blob = encrypt_data(plaintext, password, alg=alg_choice, kdf=kdf_choice)
            elapsed = time.perf_counter() - t0
            out_path.write_bytes(blob)
            prog.update(task, description=f"[green]✓ {file.name}")

        result = StreamResult(
            orig_size=len(plaintext), enc_size=len(blob),
            num_chunks=1, chunk_size=len(plaintext),
            orig_ext=file.suffix, mime_type=mime_type,
            elapsed_sec=elapsed,
        )
        _print_file_result(file, out_path, result, alg_choice, kdf_choice, key_source, streaming=False)

    if delete_src:
        file.unlink()
        console.print(f"  [dim]🗑️  Đã xóa file gốc: {file}[/dim]")


# ─── decrypt ─────────────────────────────────────────────────────────────────

@app.command("decrypt", help="🔓 Giải mã file hoặc văn bản")
def cmd_decrypt(
    text:     Annotated[Optional[str],  typer.Option("-t","--text",     help="Ciphertext Base64")] = None,
    file:     Annotated[Optional[Path], typer.Option("-f","--file",     help="File .enc")] = None,
    output:   Annotated[Optional[Path], typer.Option("-o","--output",   help="File output")] = None,
    password: Annotated[Optional[str],  typer.Option("-p","--password", help="Mật khẩu")] = None,
    key_file: Annotated[Optional[Path], typer.Option("--key-file",      help="File .ckey")] = None,
    key_pass: Annotated[Optional[str],  typer.Option("--key-pass",      help="Mật khẩu key file")] = None,
):
    if text is None and file is None:
        err.print("[red]✗ Cần [bold]--text[/bold] hoặc [bold]--file[/bold][/red]")
        raise typer.Exit(1)

    raw_key, _, _, key_source = _load_key_source(
        key_file, key_pass, password,
        Algorithm.AES_GCM, KDF.ARGON2ID, for_encrypt=False
    )
    if raw_key is None and password is None:
        password = _ask_password(confirm=False)

    # ── Giải mã văn bản ──────────────────────────────────────────────────────
    if file is None:
        try:
            blob = base64.b64decode(text.strip())
        except Exception:
            err.print("[red]✗ Base64 không hợp lệ[/red]")
            raise typer.Exit(1)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("[cyan]Đang giải mã...", total=None)
            t0   = time.perf_counter()
            try:
                info = get_blob_info(blob)
                if raw_key is not None:
                    hdr = unpack_header(blob)
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    ct  = blob[HEADER_SIZE:]
                    plaintext = AESGCM(raw_key).decrypt(hdr.nonce[:12], ct + hdr.tag, None)
                else:
                    plaintext = decrypt_data(blob, password)
                elapsed = time.perf_counter() - t0
                prog.update(task, description="[green]✓ Hoàn tất")
            except Exception as e:
                prog.update(task, description="[red]✗ Thất bại")
                err.print(f"\n[bold red]✗ Giải mã thất bại:[/bold red] {e}")
                raise typer.Exit(1)

        table = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        table.add_column("", style="dim", width=22)
        table.add_column("")
        table.add_row("Thuật toán", f"[cyan]{info['algorithm']}[/cyan]")
        table.add_row("KDF",        f"[cyan]{info['kdf']}[/cyan]")
        table.add_row("Kích thước", f"{len(plaintext)} bytes")
        table.add_row("Thời gian",  f"{elapsed*1000:.0f} ms")
        console.print(Panel(table, title="[bold green]🔓 Giải Mã Thành Công[/bold green]", border_style="green"))

        try:
            console.print(Panel(plaintext.decode("utf-8"), title="[bold]Plaintext[/bold]", border_style="cyan"))
        except UnicodeDecodeError:
            console.print(Panel(
                f"[yellow]Dữ liệu nhị phân ({len(plaintext)} bytes)[/yellow]\n" +
                plaintext[:64].hex(),
                title="[bold]Kết quả (hex)[/bold]",
            ))
        return

    # ── Giải mã file ──────────────────────────────────────────────────────────
    if not file.exists():
        err.print(f"[red]✗ File không tồn tại: {file}[/red]")
        raise typer.Exit(1)

    # Đọc header để biết mode
    file_bytes = file.read_bytes()
    try:
        hdr_info = unpack_header(file_bytes)
    except Exception as e:
        err.print(f"[red]✗ Không đọc được header: {e}[/red]")
        raise typer.Exit(1)

    is_streaming = bool(hdr_info.flags & FLAG_STREAMING)

    # Tên output
    if output:
        out_path = output
    elif file.suffix == ".enc":
        out_path = file.with_suffix("")
    else:
        out_path = file.with_suffix(".dec")

    # Lấy raw_key
    if raw_key is None:
        raw_key = derive_key(password.encode(), hdr_info.salt, hdr_info.kdf)

    console.print(
        f"\n  🔓 [bold]{file.name}[/bold]  "
        f"[dim]{format_size(file.stat().st_size)}[/dim]  "
        f"Mode: [cyan]{'Streaming' if is_streaming else 'Direct'}[/cyan]\n"
    )

    if is_streaming:
        with _make_progress() as prog:
            # Lấy orig_size từ stream header
            from _file_streamer import _unpack_stream_header
            chunk_size_v, orig_size, num_chunks, orig_ext, _ = _unpack_stream_header(
                file_bytes, HEADER_SIZE
            )
            task = prog.add_task(
                f"[cyan]Giải mã {file.name}[/cyan]",
                total=orig_size,
            )

            def on_progress(done: int, total: int, speed: float) -> None:
                prog.update(task, completed=done)

            try:
                result = decrypt_file_stream(
                    src=file, dst=out_path,
                    key=raw_key,
                    master_nonce=hdr_info.nonce[:12],
                    on_progress=on_progress,
                )
                prog.update(task, completed=orig_size,
                            description=f"[green]✓ {file.name}")
            except Exception as e:
                prog.update(task, description="[red]✗ Thất bại")
                err.print(f"\n[bold red]✗ Giải mã thất bại:[/bold red] {e}")
                raise typer.Exit(1)

        _print_decrypt_result(file, out_path, result, hdr_info)

    else:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task(f"[cyan]Giải mã {file.name}...", total=None)
            t0   = time.perf_counter()
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                ct        = file_bytes[HEADER_SIZE:]
                plaintext = AESGCM(raw_key).decrypt(hdr_info.nonce[:12], ct + hdr_info.tag, None)
                elapsed   = time.perf_counter() - t0
                out_path.write_bytes(plaintext)
                prog.update(task, description=f"[green]✓ {file.name}")
            except Exception as e:
                prog.update(task, description="[red]✗ Thất bại")
                err.print(f"\n[bold red]✗ Giải mã thất bại:[/bold red] {e}")
                raise typer.Exit(1)

        _, icon = detect_file_type(out_path)
        table = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        table.add_column("", style="dim", width=22)
        table.add_column("")
        table.add_row("Thuật toán", f"[cyan]{ALG_LABEL[hdr_info.algorithm]}[/cyan]")
        table.add_row("Kích thước", f"{format_size(len(plaintext))}")
        table.add_row("Thời gian",  f"{elapsed*1000:.0f} ms")
        table.add_row("Output",     f"[green]{icon} {out_path}[/green]")
        console.print(Panel(table, title="[bold green]🔓 Giải Mã Thành Công[/bold green]", border_style="green"))


# ─── key generate ─────────────────────────────────────────────────────────────

@key_app.command("generate", help="✨ Tạo AES-256 key mới và lưu vào file .ckey")
def cmd_key_generate(
    save:        Annotated[Path,         typer.Option("--save",        help="Đường dẫn file .ckey")] = Path("key.ckey"),
    protect:     Annotated[bool,         typer.Option("--protect",     help="Bảo vệ key file bằng mật khẩu")] = False,
    key_pass:    Annotated[Optional[str],typer.Option("--key-pass",    help="Mật khẩu bảo vệ")] = None,
    description: Annotated[str,          typer.Option("--desc",        help="Mô tả ngắn về key")] = "",
    algorithm:   Annotated[str,          typer.Option("-a","--algo",   help="gcm | cbc | siv")] = "gcm",
    kdf:         Annotated[str,          typer.Option("-k","--kdf",    help="argon2 | pbkdf2")] = "argon2",
    tags:        Annotated[str,          typer.Option("--tags",        help="Tags, ngăn cách bằng dấu phẩy")] = "",
):
    alg_choice = _resolve_alg(algorithm)
    kdf_choice = _resolve_kdf(kdf)
    tag_list   = [t.strip() for t in tags.split(",") if t.strip()]

    pwd = None
    if protect:
        if key_pass:
            pwd = key_pass
        else:
            pwd = typer.prompt("🔒 Mật khẩu bảo vệ key file", hide_input=True)
            pwd2 = typer.prompt("🔒 Xác nhận", hide_input=True)
            if pwd != pwd2:
                err.print("[red]✗ Mật khẩu không khớp[/red]")
                raise typer.Exit(1)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task("[cyan]Đang tạo key ngẫu nhiên...", total=None)
        raw_key = generate_key()
        fp = key_fingerprint(raw_key)

        if protect:
            prog.update(task, description="[cyan]Đang mã hóa key file (Argon2id)...")

        kf = save_key(
            save, raw_key,
            password=pwd,
            default_alg=alg_choice,
            default_kdf=kdf_choice,
            description=description,
            tags=tag_list,
        )
        prog.update(task, description="[green]✓ Key đã được lưu")

    table = Table(box=box.ROUNDED, show_header=False, padding=(0,2), border_style="yellow")
    table.add_column("", style="dim", width=20)
    table.add_column("")
    table.add_row("File",        f"[yellow]{save}[/yellow]")
    table.add_row("Kích thước", f"{save.stat().st_size} bytes")
    table.add_row("Bảo vệ",    f"{'[green]🔒 Password protected[/green]' if protect else '[dim]🔓 Không bảo vệ[/dim]'}")
    table.add_row("Thuật toán", f"[cyan]{ALG_LABEL[alg_choice]}[/cyan]")
    table.add_row("KDF",        f"[cyan]{KDF_LABEL[kdf_choice]}[/cyan]")
    table.add_row("Fingerprint", f"[dim]{fp}[/dim]")
    if description:
        table.add_row("Mô tả",  description)
    if tag_list:
        table.add_row("Tags",   ", ".join(tag_list))
    table.add_row("Entropy",    f"256 bits (CSPRNG)")
    table.add_row("Quyền file", "600 (chỉ owner đọc được)")

    console.print(Panel(table, title="[bold yellow]🗝️  Key Đã Tạo Thành Công[/bold yellow]", border_style="yellow"))
    console.print(
        f"\n  [bold]Sử dụng:[/bold]\n"
        f"  [dim]python cryptool.py encrypt -f file.mp4 --key-file {save}[/dim]\n"
        f"  [dim]python cryptool.py decrypt -f file.mp4.enc --key-file {save}[/dim]\n"
    )


# ─── key info ────────────────────────────────────────────────────────────────

@key_app.command("info", help="📋 Xem thông tin file khóa .ckey")
def cmd_key_info(
    key_path: Annotated[Path,         typer.Argument(help="Đường dẫn file .ckey")],
    key_pass: Annotated[Optional[str],typer.Option("--key-pass", help="Mật khẩu (để xác minh)")] = None,
    show_fp:  Annotated[bool,         typer.Option("--fingerprint", help="Hiển thị fingerprint đầy đủ")] = False,
):
    if not key_path.exists():
        err.print(f"[red]✗ Không tìm thấy: {key_path}[/red]")
        raise typer.Exit(1)

    items = list_keys(key_path.parent)
    item  = next((i for i in items if Path(i["path"]) == key_path.resolve() or
                  Path(i["path"]).name == key_path.name), None)

    if not item or "error" in item:
        err.print(f"[red]✗ Không đọc được key file: {item.get('error', '?')}[/red]")
        raise typer.Exit(1)

    table = Table(box=box.ROUNDED, show_header=False, padding=(0,2), border_style="yellow")
    table.add_column("", style="dim bold", width=20)
    table.add_column("")
    table.add_row("File",       f"[yellow]{key_path}[/yellow]")
    table.add_row("Kích thước", f"{key_path.stat().st_size} bytes")
    table.add_row("Bảo vệ",    item["protection"])
    table.add_row("Thuật toán", f"[cyan]{item['algorithm']}[/cyan]")
    table.add_row("KDF",        f"[cyan]{item['kdf']}[/cyan]")
    table.add_row("Fingerprint", f"[dim]{item['fingerprint']}[/dim]")
    table.add_row("Tạo lúc",   item["created_at"])
    if item["description"]:
        table.add_row("Mô tả", item["description"])

    # Xác minh nếu có password
    if key_pass or (item["protection"] == "🔒 Password" and
                    typer.confirm("Xác minh mật khẩu?")):
        try:
            kp = key_pass or typer.prompt("🔑 Mật khẩu", hide_input=True)
            load_key(key_path, kp)
            table.add_row("Xác minh", "[green]✓ Key hợp lệ[/green]")
        except Exception as e:
            table.add_row("Xác minh", f"[red]✗ {e}[/red]")

    console.print(Panel(table, title="[bold yellow]🗝️  Key File Info[/bold yellow]", border_style="yellow"))


# ─── key list ────────────────────────────────────────────────────────────────

@key_app.command("list", help="📂 Liệt kê tất cả file .ckey trong thư mục")
def cmd_key_list(
    directory: Annotated[Path, typer.Argument(help="Thư mục tìm kiếm")] = Path("."),
):
    items = list_keys(directory)
    if not items:
        console.print(f"[dim]Không tìm thấy file .ckey trong {directory}[/dim]")
        return

    table = Table(
        "File", "Bảo vệ", "Thuật toán", "Fingerprint", "Mô tả", "Tạo lúc",
        title=f"[bold yellow]🗝️  Key Files trong {directory}[/bold yellow]",
        box=box.ROUNDED, border_style="yellow",
    )
    for item in items:
        if "error" in item:
            table.add_row(item["path"], "[red]Lỗi[/red]", "", item["error"], "", "")
            continue
        table.add_row(
            Path(item["path"]).name,
            item["protection"],
            f"[cyan]{item['algorithm']}[/cyan]",
            f"[dim]{item['fingerprint'][:19]}...[/dim]",
            item["description"][:30] or "[dim]—[/dim]",
            item["created_at"],
        )
    console.print(table)
    console.print(f"\n  [dim]Tổng: {len(items)} key file(s)[/dim]\n")


# ─── info ─────────────────────────────────────────────────────────────────────

@app.command("info", help="📋 Kiểm tra thông tin file đã mã hóa")
def cmd_info(
    file: Annotated[Optional[Path], typer.Option("-f","--file", help="File .enc")] = None,
    text: Annotated[Optional[str],  typer.Option("-t","--text", help="Base64 ciphertext")] = None,
):
    if file is None and text is None:
        err.print("[red]✗ Cần --file hoặc --text[/red]")
        raise typer.Exit(1)

    blob = file.read_bytes() if file else base64.b64decode(text.strip())
    try:
        info = get_blob_info(blob)
    except Exception as e:
        err.print(f"[red]✗ {e}[/red]")
        raise typer.Exit(1)

    is_streaming = info.get("streaming", False)
    extra_rows = []

    if is_streaming:
        from _file_streamer import _unpack_stream_header, format_size as _fs
        try:
            cs, os_, nc, ext, mime = _unpack_stream_header(blob, HEADER_SIZE)
            extra_rows = [
                ("Mode",         "🔄 Streaming (chunked)"),
                ("Chunk size",   f"{cs // (1024*1024)} MB ({cs:,} bytes)"),
                ("Số chunks",    str(nc)),
                ("Extension",    ext or "—"),
                ("MIME type",    mime or "—"),
                ("Kích thước gốc", _fs(os_) if os_ else "—"),
            ]
        except Exception:
            extra_rows = [("Mode", "🔄 Streaming")]
    else:
        extra_rows = [("Mode", "📦 Direct (in-memory)")]

    table = Table(box=box.ROUNDED, show_header=False, padding=(0,2), border_style="blue")
    table.add_column("", style="dim bold", width=22)
    table.add_column("")
    table.add_row("Định dạng",    "[bold]CrypTool v2[/bold]")
    table.add_row("Thuật toán",   f"[cyan]{info['algorithm']}[/cyan]")
    table.add_row("KDF",          f"[cyan]{info['kdf']}[/cyan]")
    table.add_row("Kích thước key", info["key_size"])
    for k, v in extra_rows:
        table.add_row(k, v)
    table.add_row("Header size",  f"{info['header_size']} bytes")
    table.add_row("Auth Tag",     f"[dim]{info['tag_hex']}[/dim]")
    table.add_row("Salt",         f"[dim]{info['salt_hex']}[/dim]")
    if file:
        table.add_row("File",     str(file))
        table.add_row("Tổng kích thước", format_size(len(blob)))

    console.print(Panel(table, title="[bold blue]📋 Thông Tin Ciphertext[/bold blue]", border_style="blue"))


# ─── benchmark ───────────────────────────────────────────────────────────────

@app.command("benchmark", help="⚡ Đo hiệu năng mã hóa")
def cmd_benchmark(
    size_mb: Annotated[int, typer.Option("-s","--size", help="Kích thước test (MB)")] = 64,
):
    import tempfile
    password = "bench_password_2024"
    raw_data = secrets.token_bytes(size_mb * 1024 * 1024)

    console.print(f"\n[bold]⚡ Benchmark — {size_mb} MB dữ liệu ngẫu nhiên[/bold]\n")

    combos = [
        (Algorithm.AES_GCM, KDF.ARGON2ID, "Streaming GCM", "Argon2id", True),
        (Algorithm.AES_GCM, KDF.PBKDF2,   "Streaming GCM", "PBKDF2",   True),
        (Algorithm.AES_CBC, KDF.PBKDF2,   "Direct CBC",    "PBKDF2",   False),
        (Algorithm.AES_GCM, KDF.PBKDF2,   "Direct GCM",    "PBKDF2",   False),
    ]

    results = []
    with _make_progress() as prog:
        for alg, kdf_c, alg_name, kdf_name, streaming in combos:
            label = f"[cyan]{alg_name}[/cyan] + [yellow]{kdf_name}[/yellow]"
            task  = prog.add_task(label, total=size_mb * 1024 * 1024)

            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
                src = Path(tf.name)
                src.write_bytes(raw_data)

            dst = src.with_suffix(".enc")
            dec = src.with_suffix(".dec")

            key  = secrets.token_bytes(32)
            salt = secrets.token_bytes(SALT_SIZE)
            nonce = secrets.token_bytes(GCM_NONCE)

            if streaming:
                ghdr = pack_header(alg, kdf_c, FLAG_STREAMING, salt, nonce, b"\x00"*16, 0)
                t0 = time.perf_counter()
                encrypt_file_stream(src, dst, key, nonce, ghdr,
                                    on_progress=lambda d,t,s: prog.update(task, completed=d))
                enc_t = time.perf_counter() - t0
                prog.update(task, completed=size_mb * 1024 * 1024)

                t0 = time.perf_counter()
                dec_info = unpack_header(dst.read_bytes())
                decrypt_file_stream(dst, dec, key, dec_info.nonce[:12])
                dec_t = time.perf_counter() - t0
            else:
                t0   = time.perf_counter()
                blob = encrypt_data(raw_data, password, alg=alg, kdf=kdf_c)
                enc_t = time.perf_counter() - t0
                prog.update(task, completed=size_mb * 1024 * 1024)
                t0   = time.perf_counter()
                decrypt_data(blob, password)
                dec_t = time.perf_counter() - t0

            for p in (src, dst, dec):
                try: p.unlink()
                except Exception: pass

            tp_enc = size_mb / enc_t
            tp_dec = size_mb / dec_t
            results.append((alg_name, kdf_name, streaming, enc_t*1000, dec_t*1000, tp_enc, tp_dec))
            prog.update(task, description=f"[green]✓ {alg_name} + {kdf_name}")

    table = Table(
        "Thuật toán", "KDF", "Mode",
        "Mã hóa (ms)", "Giải mã (ms)",
        "Enc speed", "Dec speed",
        title="[bold]📊 Kết Quả Benchmark[/bold]",
        box=box.ROUNDED, border_style="cyan",
    )
    best_enc = min(r[3] for r in results)
    for alg_name, kdf_name, streaming, enc_ms, dec_ms, tp_enc, tp_dec in results:
        hi  = "[bold green]" if enc_ms == best_enc else ""
        end = "[/bold green]" if enc_ms == best_enc else ""
        table.add_row(
            f"{hi}{alg_name}{end}",
            kdf_name,
            "Stream" if streaming else "Direct",
            f"{hi}{enc_ms:.0f} ms{end}",
            f"{dec_ms:.0f} ms",
            f"{tp_enc:.1f} MB/s",
            f"{tp_dec:.1f} MB/s",
        )
    console.print(table)
    console.print("\n[dim]💡 KDF chiếm phần lớn thời gian 'Direct' — thiết kế để chống brute force[/dim]")
    console.print("[dim]💡 Streaming dùng raw key nên tốc độ phụ thuộc thuần vào AES-GCM[/dim]\n")


@app.command("menu", help="🧭 Chạy chế độ menu tương tác có thể quay lại")
def cmd_menu():
    _run_interactive_menu()


# ─── pipe ─────────────────────────────────────────────────────────────────────

@app.command("pipe", help="🔄 Đọc stdin, ghi stdout — dùng với Unix pipe")
def cmd_pipe(
    mode:     Annotated[str,          typer.Argument(help="encrypt | decrypt")],
    password: Annotated[str,          typer.Option("-p","--password")],
    algo:     Annotated[str,          typer.Option("-a","--algo")] = "gcm",
):
    """
    echo 'secret' | python cryptool.py pipe encrypt -p pass \\
                  | python cryptool.py pipe decrypt -p pass
    """
    if mode not in ("encrypt", "decrypt"):
        err.print("[red]✗ Mode: encrypt | decrypt[/red]")
        raise typer.Exit(1)
    alg = _resolve_alg(algo)
    data = sys.stdin.buffer.read()
    if mode == "encrypt":
        blob = encrypt_data(data, password, alg=alg)
        sys.stdout.buffer.write(base64.b64encode(blob))
    else:
        blob = base64.b64decode(data.strip())
        sys.stdout.buffer.write(decrypt_data(blob, password))


# ─── Print helpers ────────────────────────────────────────────────────────────

def _print_file_result(
    src: Path, dst: Path,
    result: StreamResult,
    alg: Algorithm, kdf: KDF,
    key_source: str,
    streaming: bool,
) -> None:
    _, icon = detect_file_type(src)
    table = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    table.add_column("", style="dim", width=24)
    table.add_column("")
    table.add_row("Nguồn",          f"{icon} {src.name}")
    table.add_row("Thuật toán",     f"[cyan]{ALG_LABEL[alg]}[/cyan]")
    table.add_row("KDF",            f"[cyan]{KDF_LABEL[kdf]}[/cyan]")
    table.add_row("Nguồn khóa",    key_source)
    table.add_row("Mode",           f"{'🔄 Streaming (' + str(result.num_chunks) + ' chunks)' if streaming else '📦 Direct'}")
    table.add_row("MIME type",      result.mime_type)
    table.add_row("Kích thước gốc", format_size(result.orig_size))
    table.add_row("Kích thước enc", format_size(result.enc_size))
    table.add_row("Overhead",       f"+{format_size(result.overhead_bytes)}")
    table.add_row("Tốc độ",        f"{result.speed_mbps:.1f} MB/s")
    table.add_row("Thời gian",      f"{result.elapsed_sec*1000:.0f} ms")
    table.add_row("Output",         f"[green]🔒 {dst}[/green]")
    console.print(Panel(table, title="[bold green]🔒 Mã Hóa Thành Công[/bold green]", border_style="green"))

def _print_decrypt_result(src: Path, dst: Path, result: StreamResult, hdr) -> None:
    _, icon = detect_file_type(dst)
    table = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    table.add_column("", style="dim", width=24)
    table.add_column("")
    table.add_row("Thuật toán",     f"[cyan]{ALG_LABEL[hdr.algorithm]}[/cyan]")
    table.add_row("KDF",            f"[cyan]{KDF_LABEL[hdr.kdf]}[/cyan]")
    table.add_row("Kích thước gốc", format_size(result.orig_size))
    table.add_row("Số chunks",      str(result.num_chunks))
    table.add_row("Tốc độ",        f"{result.speed_mbps:.1f} MB/s")
    table.add_row("Thời gian",      f"{result.elapsed_sec*1000:.0f} ms")
    table.add_row("Output",         f"[green]{icon} {dst}[/green]")
    console.print(Panel(table, title="[bold green]🔓 Giải Mã Thành Công[/bold green]", border_style="green"))


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) == 1:
        _run_interactive_menu()
    else:
        app()
