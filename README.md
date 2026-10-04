# 📡 nostr-poster

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#-license)
[![Nostr](https://img.shields.io/badge/protocol-Nostr-purple.svg)](https://github.com/nostr-protocol/nips)
[![NIPs](https://img.shields.io/badge/NIPs-01%20%7C%2009%20%7C%2019%20%7C%2023-orange.svg)](https://github.com/nostr-protocol/nips)

> ⚡ A minimal, single-file Nostr publishing library — no `pynostr` dependency.
> Keys, events, signatures, relays, deletion: everything in one importable module.

---

## 📑 Table of Contents

- [✨ Features](#-features)
- [📦 Requirements & Installation](#-requirements--installation)
- [🚀 Quick Start](#-quick-start)
- [🔌 Relay Customization](#-relay-customization)
- [🧅 Tor / SOCKS5 Proxy](#-tor--socks5-proxy)
- [🛠️ API Reference](#️-api-reference)
- [📐 NIP Standards Used](#-nip-standards-used)
- [🗂️ Event Kinds](#️-event-kinds)
- [🔒 Security Notes](#-security-notes)
- [🧪 Development](#-development)
- [📄 License](#-license)

---

## ✨ Features

- 🔑 **Key generation** — fresh `nsec`/`npub` pairs, auto-backed up in plaintext to `keys_backup.txt`
- 📝 **Short notes** — publish kind `1` notes (NIP-01)
- 📄 **Long-form articles** — publish kind `30023` articles with `title`/`summary`/`image`/`t` tags (NIP-23)
- 🗑️ **Deletion** — request deletion of events (kind `5`, NIP-09), including addressable articles
- 🌐 **Custom relays** — edit the global `RELAYS` list or pass `relays=` per call
- 🧅 **Tor / SOCKS5 proxy** — optional proxy support for the built-in WebSocket transport
- ✍️ **BIP-340 Schnorr signatures** — via [`coincurve`](https://github.com/ofek/coincurve)
- 🔡 **Bech32 NIP-19 helpers** — encode/decode `nsec`/`npub` without extra deps
- 🕸️ **Zero-dependency transport** — hand-rolled minimal WebSocket client (RFC 6455), just `coincurve` + optional `PySocks`

---

## 📦 Requirements & Installation

| Dependency | Required? | Purpose |
| --- | --- | --- |
| Python 3.8+ | ✅ | Runtime |
| [`coincurve`](https://github.com/ofek/coincurve) | ✅ | secp256k1 / BIP-340 Schnorr signing |
| [`PySocks`](https://github.com/Anorov/PySocks) | ⚠️ optional | SOCKS5 proxy (e.g. Tor) |

```bash
pip install coincurve PySocks
```

Clone and use:

```bash
git clone https://github.com/wangyifan349/nostr-poster.git
cd nostr-poster
```

---

## 🚀 Quick Start

```python
import nostr_poster as nostr

# 1) 🔑 Generate a new key pair (auto plaintext backup to keys_backup.txt)
keys = nostr.create_keys()
print(keys["nsec"], keys["npub"])

# 2) 🌐 Customize relays
nostr.RELAYS = ["wss://relay.damus.io", "wss://nos.lol"]

# 3) 📝 Publish a short note (kind 1)
r = nostr.publish_note(keys["nsec"], "hello nostr")
print(r["event_id"], r["results"])

# 4) 📄 Publish a long-form article (kind 30023, NIP-23)
r = nostr.publish_article(
    keys["nsec"],
    title="Title",
    content="# markdown body",
    summary="Summary",
    topics=["bitcoin"],
)
print(r["event_id"], r["identifier"])

# 5) 🗑️ Delete a short note (kind 5, NIP-09)
nostr.delete_event(keys["nsec"], r["event_id"], target_kind=1, reason="no longer needed")

# 6) 🗑️ Delete a long-form article (with proper "a" address tag)
nostr.delete_article(keys["nsec"], r["event_id"], r["identifier"])

# Publish directly with an existing nsec (or 64-char hex key):
nostr.publish_note("nsec1...", "hello", relays=["wss://nos.lol"])
```

▶️ See [`example.py`](example.py) for a runnable demo that is **safe to run without secrets** (dry-run generates keys only).

---

## 🔌 Relay Customization

```python
# Globally
nostr.RELAYS = ["wss://relay.damus.io", "wss://nos.lol"]

# Or per call
nostr.publish_note(key, "hi", relays=["wss://nos.lol"])
```

A few popular relays to get started:

- 🟣 `wss://relay.damus.io`
- 🟢 `wss://nos.lol`
- 🔵 `wss://relay.primal.net`
- 🟠 `wss://nostr.mom`

---

## 🧅 Tor / SOCKS5 Proxy

Every publish/delete helper accepts `proxy=(host, port)`:

```python
nostr.publish_note(key, "hello over Tor", proxy=("127.0.0.1", 9050))
```

Typical Tor ports: `9050` (system daemon) or `9150` (Tor Browser). Requires `PySocks`.

---

## 🛠️ API Reference

### 🔑 Keys & backup

| Function | Description |
| --- | --- |
| `create_keys(backup_file=...)` | Generate a key pair and append a plaintext backup |
| `backup_keys(keys, backup_file=...)` | Append a key backup to a local file |
| `parse_key(value)` | Accept `nsec1...` or 64-char hex → 32-byte secret |
| `generate_secret_key()` | Raw 32-byte secret key |
| `secret_to_nsec()` / `nsec_to_secret()` | nsec ↔ raw bytes (NIP-19) |
| `pubkey_hex_from_secret()` / `pubkey_to_npub()` | x-only pubkey hex / npub encoding |

### ✍️ Events & signing

| Function | Description |
| --- | --- |
| `build_event(sk, kind, content, tags=None, ...)` | Build + sign a generic event |
| `build_note(sk, content, tags=None)` | Build a kind 1 note |
| `build_article(sk, title, content, ...)` | Build a kind 30023 article (NIP-23) |
| `build_deletion(sk, event_id, target_kind, ...)` | Build a kind 5 deletion (NIP-09) |
| `compute_event_id(...)` | NIP-01 event id (SHA-256 of serialized header) |
| `schnorr_sign(message_32, sk)` | BIP-340 Schnorr signature |

### 📤 Publishing & deletion

| Function | Description |
| --- | --- |
| `publish_note(nsec_or_hex, content, ...)` | Publish a kind 1 note |
| `publish_article(nsec_or_hex, title, content, ...)` | Publish a kind 30023 article |
| `publish_event(event, relays=..., ...)` | Publish a raw signed event dict |
| `delete_event(nsec_or_hex, event_id, target_kind=1, ...)` | Publish a kind 5 deletion |
| `delete_article(nsec_or_hex, event_id, identifier, ...)` | Delete an article with the `a` tag |

All publish/delete helpers accept optional `relays`, `timeout`, and `proxy`.
Return shape: `{"event_id": ..., "results": {relay_url: {"ok": bool, "msg": str}}}`.

### 🔡 Bech32 helpers

| Function | Description |
| --- | --- |
| `bech32_encode(hrp, data_bytes)` / `bech32_decode(bech)` | NIP-19 bech32 coding |

---

## 📐 NIP Standards Used

| NIP | Title | Where used |
| --- | --- | --- |
| [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol — event format, `EVENT`/`OK` messages | every published event |
| [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion | `delete_event`, `delete_article` (kind 5, `e`/`k`/`a` tags) |
| [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) | Bech32-encoded entities (`npub`, `nsec`) | `secret_to_nsec`, `nsec_to_secret`, `pubkey_to_npub` |
| [NIP-23](https://github.com/nostr-protocol/nips/blob/master/23.md) | Long-form content | `publish_article` (kind 30023, `d`/`title`/`published_at`/`t` tags) |

Signing follows [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) (Schnorr over secp256k1).
Transport is a minimal [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) WebSocket client.

---

## 🗂️ Event Kinds

| Kind | Name | Producer |
| --- | --- | --- |
| `1` | Short text note | `publish_note` |
| `30023` | Long-form article | `publish_article` |
| `5` | Deletion request | `delete_event`, `delete_article` |

---

## 🔒 Security Notes

- ⚠️ `create_keys()` writes your private key as **plaintext** to `keys_backup.txt` next to the library file. Treat it as a secret, restrict permissions, and **never commit it** (add it to `.gitignore`).
- 🚫 Anyone with the `nsec` or `sk_hex` fully controls the account.
- 🧅 Using Tor (`proxy=("127.0.0.1", 9050)`) helps hide your IP when publishing.
- 🗑️ Deletion is a *request*: relays are not strictly required to honor NIP-09.

---

## 🧪 Development

```bash
# Syntax / import check
python -c "import nostr_poster"

# Safe demo (no network)
python example.py
```

---

## 📄 License

MIT
