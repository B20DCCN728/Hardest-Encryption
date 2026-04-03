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
  - `encrypt`
  - `decrypt`
  - `key generate`
  - `key info`
  - `key list`
  - `info`
  - `benchmark`
  - `pipe`

### `_crypto_engine.py`

- Defines crypto enums and labels
- Implements Argon2id and PBKDF2 key derivation
- Implements AES-GCM, AES-CBC+HMAC, AES-SIV
- Owns the global 80-byte ciphertext header format
- Handles in-memory encryption/decryption flows

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

## Change Guidelines

- Prefer small, format-preserving edits.
- Treat file format constants as public interfaces.
- If you change encryption or decryption logic, run `python tests.py`.
- If you add commands or flags, update both `README.md` and the CLI help text in `cryptool.py`.
- If you change `.ckey` metadata fields or semantics, update both `_key_manager.py` and documentation.
- Keep new dependencies out unless they are necessary.

## Recommended Workflow For Agents

1. Read `cryptool.py` to identify the user-facing path.
2. Read the module that owns the relevant behavior.
3. Check `tests.py` for current expectations.
4. Make minimal edits.
5. Run `python tests.py` when behavior changes.
6. Update docs if command surface, formats, or setup changes.

## Known Gaps

- No packaging metadata such as `pyproject.toml`
- No dedicated `tests/` directory or pytest suite
- No explicit license file
- Some console text shows encoding artifacts depending on terminal/code page

## Safe Assumptions

- The repo is meant to be used as a local CLI tool rather than an importable library package.
- The binary file formats are intentional and should be treated as stable unless the task explicitly requests a migration.
- Backward compatibility is more important than stylistic refactors in crypto-sensitive code.
