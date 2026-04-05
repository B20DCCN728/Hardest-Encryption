# Hardest-Encryption

`Hardest-Encryption` is a Python CLI project for encrypting text and files with AES-256. It supports password-based encryption, reusable `.ckey` key files, and chunked streaming encryption for large files such as videos, images, archives, and documents.

## Features

- AES-256-GCM, AES-256-CBC + HMAC, and AES-256-SIV
- Argon2id and PBKDF2-SHA256 key derivation
- Password-based or key-file-based workflows
- Streaming encryption for large files
- Binary `.ckey` key file format with optional password protection
- Interactive menu loop with `BACK` to the main menu
- Rich terminal UI with tables, panels, progress bars, and benchmark output
- Built-in test suite in `tests.py`

## Project Structure

```text
Hardest-Encryption/
|-- cryptool.py         # Main Typer CLI entrypoint
|-- _crypto_engine.py   # Core crypto primitives, header format, KDF logic
|-- _file_streamer.py   # Chunked file encryption/decryption for large files
|-- _key_manager.py     # .ckey key file format, save/load/list helpers
|-- tests.py            # Standalone test runner
|-- requirements.txt    # Python dependencies
|-- README.md           # Project documentation
|-- AGENTS.md           # Guidance for coding agents/contributors
`-- .idea/              # IDE metadata
```

## Requirements

- Python 3.10+
- Pip

Dependencies from `requirements.txt`:

- `cryptography>=41.0.0`
- `rich>=13.0.0`
- `typer>=0.9.0`
- `argon2-cffi>=23.0.0`

## Installation

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

Run the interactive menu:

```bash
python cryptool.py
```

Or open it explicitly:

```bash
python cryptool.py menu
```

Encrypt text with a password:

```bash
python cryptool.py encrypt --text "hello world" --password "StrongPass!123"
```

Decrypt Base64 ciphertext:

```bash
python cryptool.py decrypt --text "<base64-ciphertext>" --password "StrongPass!123"
```

Encrypt a file:

```bash
python cryptool.py encrypt --file secret.pdf --password "StrongPass!123"
```

Decrypt a file:

```bash
python cryptool.py decrypt --file secret.pdf.enc --password "StrongPass!123"
```

Create a reusable key file:

```bash
python cryptool.py key generate --save mykey.ckey --protect --desc "Primary backup key"
```

Encrypt with a key file:

```bash
python cryptool.py encrypt --file video.mp4 --key-file mykey.ckey --key-pass "KeyPass!123"
```

## CLI Commands

### `menu`

Runs the interactive menu loop. After each action, the program waits for Enter and returns to the main menu.

```bash
python cryptool.py menu
```

### `encrypt`

Encrypts plaintext or a file.

Common options:

- `-t, --text` plaintext input
- `-f, --file` file input
- `-o, --output` output file path
- `-p, --password` password input
- `--key-file` use a `.ckey` file instead of a password
- `--key-pass` password for protected `.ckey` files
- `-a, --algo` `gcm | cbc | siv`
- `-k, --kdf` `argon2 | pbkdf2`
- `--chunk-mb` streaming chunk size in MB
- `--stream-from` use streaming when file size is at least this many MB
- `--delete-src` delete original file after encryption

Examples:

```bash
python cryptool.py encrypt -f archive.zip -p "StrongPass!123" -a gcm -k argon2
python cryptool.py encrypt -t "confidential note" -p "StrongPass!123" -a siv
python cryptool.py encrypt -f movie.mkv --key-file media.ckey --key-pass "KeyPass!123"
```

### `decrypt`

Decrypts Base64 ciphertext or `.enc` files.

Common options:

- `-t, --text` Base64 ciphertext
- `-f, --file` encrypted file input
- `-o, --output` output file path
- `-p, --password` password input
- `--key-file` use a `.ckey` file
- `--key-pass` password for protected `.ckey` files

Examples:

```bash
python cryptool.py decrypt -f archive.zip.enc -p "StrongPass!123"
python cryptool.py decrypt -f movie.mkv.enc --key-file media.ckey --key-pass "KeyPass!123"
```

### `key generate`

Creates a new AES-256 key and saves it as a `.ckey` file.

Options:

- `--save` output path
- `--protect` password-protect the key file
- `--key-pass` password for protection
- `--desc` description
- `-a, --algo` default algorithm
- `-k, --kdf` default KDF
- `--tags` comma-separated metadata tags

Example:

```bash
python cryptool.py key generate --save backup.ckey --protect --desc "Backup vault key" --tags backup,archive
```

### `key info`

Displays metadata about a `.ckey` file.

```bash
python cryptool.py key info backup.ckey
python cryptool.py key info backup.ckey --key-pass "KeyPass!123" --fingerprint
```

### `key list`

Recursively lists `.ckey` files in a directory.

```bash
python cryptool.py key list .
```

### `info`

Inspects encrypted file or Base64 ciphertext metadata without decrypting it.

```bash
python cryptool.py info --file archive.zip.enc
python cryptool.py info --text "<base64-ciphertext>"
```

### `benchmark`

Runs a local encryption benchmark.

```bash
python cryptool.py benchmark
python cryptool.py benchmark --size 128
```

### `pipe`

Reads from `stdin` and writes to `stdout`.

```bash
echo secret | python cryptool.py pipe encrypt -p pass | python cryptool.py pipe decrypt -p pass
```

## Architecture

### 1. CLI Layer

`cryptool.py` exposes the Typer application and user-facing commands. It orchestrates password prompts, key loading, output naming, and Rich progress display.

### 2. Crypto Engine

`_crypto_engine.py` defines:

- AES algorithm enum and labels
- KDF enum and labels
- 80-byte global ciphertext header
- password derivation helpers
- text/small-data encryption and decryption
- ciphertext metadata inspection helpers

### 3. Streaming Layer

`_file_streamer.py` handles large-file workflows:

- chunk-based AES-GCM encryption
- per-chunk nonce derivation
- per-chunk AAD binding to prevent reordering
- trailing stream HMAC for integrity
- file-type detection and size formatting

### 4. Key Management

`_key_manager.py` implements the `.ckey` binary format, optional password protection for key files, and metadata such as fingerprint, description, tags, and default algorithm/KDF.

## File Formats

### Ciphertext Header

The encrypted blob begins with a fixed 80-byte header containing:

- magic bytes `CRYPTOOL`
- version
- algorithm id
- KDF id
- flags
- salt
- nonce or IV
- authentication tag
- original size

### Streaming Encrypted Files

Streaming `.enc` files contain:

1. Global 80-byte header
2. 56-byte stream header
3. Repeated encrypted chunks
4. Final stream HMAC

### `.ckey` Files

Key files use the `CKEYFILE` magic header and store:

- version and protection mode
- default algorithm and KDF
- creation timestamp
- protection salt and nonce when enabled
- encrypted or raw key slot
- metadata JSON

## Testing

Run the included test suite:

```bash
python tests.py
```

The current tests cover:

- crypto round-trips across algorithms and KDFs
- wrong-password and tamper rejection
- streaming flag/header behavior
- key generation, save/load, fingerprinting, and metadata
- file workflow helpers

## Notes

- Password-based encryption derives a fresh key from a random salt for each encryption.
- Streaming mode is used for larger files and when raw key files are supplied.
- The CLI currently mixes English identifiers with Vietnamese user-facing text.
- The repository does not currently include packaging metadata such as `pyproject.toml` or `setup.py`.

## License

No license file is present in the repository yet. Add one before publishing or reusing the project externally.
