# AGENTS.md

This file gives future coding agents a working map of the repository and the constraints that matter when changing it.

## Repository Purpose

This project is a standalone Python CLI for AES-based encryption and decryption of:

- text payloads
- small files handled in memory
- large files handled in streaming mode
- reusable `.ckey` key files with optional password protection

The main entrypoint is `cryptool.py`.

## Canonical Structure

```text
Hardest-Encryption/
|-- cryptool.py
|-- _crypto_engine.py
|-- _file_streamer.py
|-- _key_manager.py
|-- tests.py
|-- requirements.txt
|-- README.md
`-- AGENTS.md
```

## Module Responsibilities

### `cryptool.py`

- Owns the Typer CLI
- Connects user input to lower-level modules
- Handles Rich console output and progress
- Decides whether file encryption is direct or streaming
- Defines command surface:
  - `encrypt` — password or key-file based encryption
  - `decrypt` — with automatic streaming/direct detection
  - `key generate` — create and save `.ckey` files
  - `key info` — inspect key metadata and verify passwords
  - `key list` — recursively find `.ckey` files in a directory
  - `info` — inspect encrypted blob metadata without decrypting
  - `benchmark` — measure encryption/decryption performance
  - `menu` — interactive loop with Back option (default when no args)
  - `pipe` — stdin/stdout support for Unix pipes

### `_crypto_engine.py`

- Defines crypto enums and labels
- Implements Argon2id and PBKDF2 key derivation
- Implements AES-GCM, AES-CBC+HMAC, AES-SIV
- Owns the global 80-byte ciphertext header format
- Handles in-memory encryption/decryption flows
- Provides password strength indicator
- Supports both raw keys and password-derived keys

Do not casually change:

- `HEADER_FMT`
- `HEADER_SIZE`
- enum numeric values
- `MAGIC`, `VERSION`, flag semantics

Those are wire-format compatibility points.

### `_file_streamer.py`

- Owns large-file streaming format
- Uses chunked AES-GCM
- Derives chunk nonces from the master nonce
- Uses AAD to bind chunk order
- Appends a final HMAC for stream integrity

Do not casually change:

- `STREAM_HDR_FMT`
- `STREAM_HDR_SIZE`
- chunk framing layout
- HMAC coverage rules

These are also compatibility-sensitive.

### `_key_manager.py`

- Owns `.ckey` binary format
- Saves and loads key files
- Supports password-protected key files
- Stores metadata JSON

Do not casually change:

- `KEY_HDR_FMT`
- `KEY_HDR_SIZE`
- `KEY_MAGIC`
- `KEY_VERSION`
- protection mode ids
- fixed key slot assumptions

### `tests.py`

- Standalone regression suite
- Not pytest-based
- Run with `python tests.py`

Keep it updated whenever behavior or formats change.

## Important Behavioral Notes

- Password-based text encryption and direct file encryption depend on the header from `_crypto_engine.py`.
- Streaming encryption uses a separate stream header after the global header.
- When a raw key is supplied through `.ckey`, file encryption is forced toward a raw-key path and may bypass password-derived flows.
- Direct decryption in `cryptool.py` currently assumes an AES-GCM raw-key path for some file cases. Any change here should be verified carefully against CBC and SIV behavior.
- User-facing output is mostly Vietnamese. Preserve the current language style unless the task explicitly asks for localization cleanup.
- The `_load_key_source()` helper in `cryptool.py` resolves the key source (raw key from `.ckey` or password) and returns `(raw_key_or_None, alg, kdf, label)`. When `raw_key is None`, callers must provide a password for password-based KDF.
- Password confirmation prompts are only shown during encryption (`confirm=True` flag); decryption always prompts without confirmation.
- When decrypting, if both raw key and password are None, a single password prompt is issued automatically.

## Critical Patterns in cryptool.py

- **Default menu mode**: When `cryptool.py` is run with no arguments, it launches `_run_interactive_menu()` directly from `__main__`.
- **Key resolution flow**: All encrypt/decrypt commands use `_load_key_source()` to unify password vs. key-file handling. This centralizes authentication logic.
- **Streaming decision**: File encryption automatically uses streaming if either `should_use_streaming()` returns true OR a raw key is supplied.
- **Progress reporting**: Use `_make_progress()` to create Rich progress bars with standardized columns (spinner, bar, speed, elapsed time).
- **Rich output panels**: Use `Panel()` with border styles ("green" for success, "red" for error, "cyan" for info) and table layouts for all output.

## Change Guidelines

- Prefer small, format-preserving edits.
- Treat file format constants as public interfaces.
- If you change encryption or decryption logic, run `python tests.py`.
- If you add commands or flags, update both `README.md` and the CLI help text in `cryptool.py`.
- If you change `.ckey` metadata fields or semantics, update both `_key_manager.py` and documentation.
- Keep new dependencies out unless they are necessary.

## Recommended Workflow For Agents

1. Read `cryptool.py` to identify the user-facing path through CLI commands and helper functions like `_load_key_source()` and `_make_progress()`.
2. Trace key flows such as password prompting (`_ask_password()`) and streaming detection (`should_use_streaming()`).
3. Read the module that owns the relevant behavior (crypto engine, streaming, key management).
4. Check `tests.py` for current expectations on behavior, formats, and error conditions.
5. Make minimal edits; preserve format constants and enum values.
6. Run `python tests.py` when encryption/decryption logic changes.
7. Update `README.md` and CLI help text (`help=` in `@app.command()`) if command surface changes.
8. For file format changes, update both the implementation module and `tests.py`.

## Known Gaps

- No packaging metadata such as `pyproject.toml`
- No dedicated `tests/` directory or pytest suite
- No explicit license file
- Some console text shows encoding artifacts depending on terminal/code page

## Safe Assumptions

- The repo is meant to be used as a local CLI tool rather than an importable library package.
- The binary file formats are intentional and should be treated as stable unless the task explicitly requests a migration.
- Backward compatibility is more important than stylistic refactors in crypto-sensitive code.
