#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nostr_poster.py - Minimal Nostr publishing library (no pynostr dependency)

Features:
  - Generate secret/public keys (nsec/npub), automatically back up keys in
    plaintext to a local keys_backup.txt file
  - Publish short notes (kind 1) and long-form articles (kind 30023, NIP-23)
  - Customizable relay list RELAYS
  - Event construction, BIP-340 Schnorr signing (requires coincurve)
  - Minimal built-in WebSocket client (optional SOCKS5/Tor proxy)

Usage:
    import nostr_poster as nostr

    # 1) Generate a new key pair (auto plaintext backup to keys_backup.txt)
    keys = nostr.create_keys()
    print(keys["nsec"], keys["npub"])

    # 2) Customize relays
    nostr.RELAYS = ["wss://relay.damus.io", "wss://nos.lol"]

    # 3) Publish a short note (kind 1)
    r = nostr.publish_note(keys["nsec"], "hello nostr")
    print(r["event_id"], r["results"])

    # 4) Publish a long-form article (kind 30023, NIP-23)
    r = nostr.publish_article(
        keys["nsec"],
        title="Title",
        content="# markdown body",
        summary="Summary",
        topics=["bitcoin"],
    )
    print(r["event_id"], r["identifier"])

    # 5) Delete a short note
    nostr.delete_event(keys["nsec"], r["event_id"], target_kind=1, reason="no longer needed")

    # 6) Delete a long-form article
    nostr.delete_article(keys["nsec"], r["event_id"], r["identifier"])

    # Publish directly with an existing key (nsec or 64-char hex):
    nostr.publish_note("nsec1...", "hello", relays=["wss://nos.lol"])
"""

import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
import time

try:
    import socks
except Exception:
    socks = None

try:
    import coincurve
except Exception:
    coincurve = None

# ---------- Customizable relay list ----------
RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
]

BACKUP_FILE_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys_backup.txt")

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]


# ---------- bech32 (NIP-19) ----------
def _bech32_polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= _BECH32_GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    values = _hrp_expand(hrp) + data
    pm = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(pm >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_verify(hrp, data):
    return _bech32_polymod(_hrp_expand(hrp) + data) == 1


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid bit group")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp, data_bytes):
    data = _convertbits(data_bytes, 8, 5)
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


def bech32_decode(bech):
    bech = bech.lower()
    if bech.rfind("1") < 1 or bech.rfind("1") + 7 > len(bech):
        raise ValueError("invalid bech32 string")
    hrp = bech[: bech.rfind("1")]
    data = [_BECH32_CHARSET.index(c) for c in bech[bech.rfind("1") + 1 :]]
    if not _bech32_verify(hrp, data):
        raise ValueError("invalid bech32 checksum")
    return hrp, bytes(_convertbits(data[:-6], 5, 8, False))


# ---------- Keys ----------
def generate_secret_key():
    """Return a 32-byte secret key"""
    while True:
        sk = secrets.token_bytes(32)
        n = int.from_bytes(sk, "big")
        if 1 <= n < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            return sk


def secret_to_nsec(sk: bytes) -> str:
    return bech32_encode("nsec", sk)


def nsec_to_secret(nsec: str) -> bytes:
    hrp, data = bech32_decode(nsec)
    if hrp != "nsec":
        raise ValueError("not an nsec")
    return data


def pubkey_hex_from_secret(sk: bytes) -> str:
    if coincurve is None:
        raise RuntimeError("coincurve required: pip install coincurve")
    pk = coincurve.PrivateKey(sk)
    # x-only public key (32 bytes)
    return pk.public_key.format(compressed=True)[1:33].hex()


def pubkey_to_npub(pubkey_hex: str) -> str:
    return bech32_encode("npub", bytes.fromhex(pubkey_hex))


def parse_key(value: str) -> bytes:
    """Accept an nsec1... or 64-char hex secret key, return 32-byte secret key"""
    value = value.strip()
    if value.lower().startswith("nsec1"):
        return nsec_to_secret(value)
    if len(value) == 64:
        return bytes.fromhex(value)
    raise ValueError("an nsec1 or 64-char hex secret key is required")


def create_keys(backup_file: str = BACKUP_FILE_DEFAULT) -> dict:
    """Generate a new key pair and automatically append a plaintext backup to a local file"""
    sk = generate_secret_key()
    nsec = secret_to_nsec(sk)
    sk_hex = sk.hex()
    pub_hex = pubkey_hex_from_secret(sk)
    npub = pubkey_to_npub(pub_hex)
    keys = {"nsec": nsec, "npub": npub, "sk_hex": sk_hex, "pub_hex": pub_hex}
    backup_keys(keys, backup_file)
    return keys


def backup_keys(keys: dict, backup_file: str = BACKUP_FILE_DEFAULT):
    """Append plaintext key backup to a local file"""
    line = (
        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]\n"
        f"nsec: {keys['nsec']}\n"
        f"npub: {keys['npub']}\n"
        f"sk_hex: {keys['sk_hex']}\n"
        f"pub_hex: {keys['pub_hex']}\n\n"
    )
    os.makedirs(os.path.dirname(os.path.abspath(backup_file)) or ".", exist_ok=True)
    with open(backup_file, "a", encoding="utf-8") as f:
        f.write(line)
    return backup_file


# ---------- Events ----------
def _compact_json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def compute_event_id(pubkey_hex, created_at, kind, tags, content) -> str:
    serialized = _compact_json([0, pubkey_hex, created_at, kind, tags, content])
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def schnorr_sign(message_32: bytes, sk: bytes) -> str:
    if coincurve is None:
        raise RuntimeError("coincurve required")
    pk = coincurve.PrivateKey(sk)
    aux = secrets.token_bytes(32)
    try:
        sig = pk.sign_schnorr(message_32, aux_rand=aux)
    except TypeError:
        sig = pk.sign_schnorr(message_32, aux)
    return sig.hex()


def build_event(sk: bytes, kind: int, content: str, tags=None, created_at=None) -> dict:
    pub_hex = pubkey_hex_from_secret(sk)
    created_at = created_at or int(time.time())
    tags = tags or []
    eid = compute_event_id(pub_hex, created_at, kind, tags, content)
    sig = schnorr_sign(bytes.fromhex(eid), sk)
    return {
        "id": eid,
        "pubkey": pub_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


def build_note(sk: bytes, content: str, tags=None) -> dict:
    """kind 1 short note"""
    return build_event(sk, 1, content, tags or [])


def build_article(
    sk: bytes,
    title: str,
    content: str,
    summary: str = "",
    image: str = "",
    topics=None,
    identifier: str = "",
    published_at: int = None,
) -> dict:
    """kind 30023 long-form article (NIP-23)"""
    identifier = identifier or hashlib.sha1((title + str(time.time())).encode()).hexdigest()[:16]
    published_at = published_at or int(time.time())
    tags = [["d", identifier], ["title", title], ["published_at", str(published_at)]]
    if summary:
        tags.append(["summary", summary])
    if image:
        tags.append(["image", image])
    for t in topics or []:
        tags.append(["t", t])
    return build_event(sk, 30023, content, tags)


# ---------- WebSocket client ----------
class WsError(Exception):
    pass


_WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _WebSocket:
    def __init__(self, url: str, timeout=12.0, proxy=None):
        self.url = url
        self.timeout = timeout
        self.proxy = proxy
        self.sock = None

    def _connect(self):
        url = self.url
        assert url.startswith("wss://") or url.startswith("ws://")
        secure = url.startswith("wss://")
        rest = url[6:] if secure else url[5:]
        host, _, path = rest.partition("/")
        path = "/" + path
        port = 443 if secure else 80
        if ":" in host:
            host, p = host.rsplit(":", 1)
            port = int(p)

        if self.proxy:
            if socks is None:
                raise WsError("PySocks required: pip install PySocks")
            phost, pport = self.proxy
            self.sock = socks.create_connection(
                (host, port),
                proxy_type=socks.SOCKS5,
                proxy_addr=phost,
                proxy_port=pport,
                timeout=self.timeout,
            )
        else:
            self.sock = socket.create_connection((host, port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        if secure:
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)

        key = base64.b64encode(secrets.token_bytes(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WsError("handshake failed")
            resp += chunk
        head = resp.split(b"\r\n\r\n")[0].decode("latin-1")
        if "101" not in head.split("\r\n")[0]:
            raise WsError(f"handshake failed: {head.splitlines()[0] if head else ''}")
        expect = base64.b64encode(hashlib.sha1(key.encode() + _WS_GUID).digest())
        if b"Sec-WebSocket-Accept: " + expect not in resp:
            raise WsError("bad accept key")

    def _send(self, opcode: int, payload: bytes):
        mask = secrets.token_bytes(4)
        header = bytearray([0x80 | opcode])
        ln = len(payload)
        if ln < 126:
            header.append(0x80 | ln)
        elif ln < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", ln)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", ln)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + mask + masked)

    def send_text(self, text: str):
        self._send(0x1, text.encode("utf-8"))

    def _recv_frame(self):
        def read_exact(n):
            buf = b""
            while len(buf) < n:
                chunk = self.sock.recv(n - len(buf))
                if not chunk:
                    raise WsError("closed")
                buf += chunk
            return buf

        b1, b2 = read_exact(2)
        fin = b1 & 0x80
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack("!H", read_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack("!Q", read_exact(8))[0]
        mask = read_exact(4) if masked else None
        payload = read_exact(ln) if ln else b""
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload

    def recv_message(self) -> str:
        data = b""
        while True:
            fin, opcode, payload = self._recv_frame()
            if opcode == 0x8:
                raise WsError("closed by server")
            if opcode == 0x9:  # ping
                self._send(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode in (0x1, 0x0):
                data += payload
                if fin:
                    return data.decode("utf-8", errors="replace")

    def close(self):
        try:
            self._send(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def publish_event(event: dict, relays=None, timeout=12.0, proxy=None) -> dict:
    """Publish an event to the relay list, return {relay: ok/msg}"""
    relays = relays or RELAYS
    results = {}
    for url in relays:
        try:
            ws = _WebSocket(url, timeout=timeout, proxy=proxy)
            ws._connect()
            ws.send_text(json.dumps(["EVENT", event], ensure_ascii=False))
            deadline = time.time() + timeout
            ok = False
            msg = ""
            while time.time() < deadline:
                text = ws.recv_message()
                try:
                    arr = json.loads(text)
                except Exception:
                    continue
                if arr and arr[0] == "OK" and len(arr) >= 3 and arr[1] == event["id"]:
                    ok = bool(arr[2])
                    msg = arr[3] if len(arr) > 3 else ""
                    break
                if arr and arr[0] == "NOTICE":
                    msg = arr[1] if len(arr) > 1 else ""
            ws.close()
            results[url] = {"ok": ok, "msg": msg}
        except Exception as e:
            results[url] = {"ok": False, "msg": f"{type(e).__name__}: {e}"}
    return results


# ---------- Deletion (NIP-09, kind 5) ----------
def build_deletion(sk: bytes, event_id: str, target_kind: int, reason: str = "", address: str = "") -> dict:
    """Build a deletion event:
    - Regular event: tags = [["e", event_id], ["k", str(target_kind)]]
    - Long-form article (30023): additionally [["a", "30023:pubkey:identifier"]]
    """
    tags = [["e", event_id], ["k", str(target_kind)]]
    if address:
        tags.append(["a", address])
    return build_event(sk, 5, reason, tags)


def delete_event(
    nsec_or_hex: str,
    event_id: str,
    target_kind: int = 1,
    reason: str = "",
    address: str = "",
    relays=None,
    timeout=12.0,
    proxy=None,
) -> dict:
    """Publish a deletion request (kind 5). target_kind: 1=note, 30023=article"""
    sk = parse_key(nsec_or_hex)
    event = build_deletion(sk, event_id, target_kind, reason, address)
    results = publish_event(event, relays=relays, timeout=timeout, proxy=proxy)
    return {"event_id": event["id"], "results": results}


def delete_article(nsec_or_hex: str, event_id: str, identifier: str, reason: str = "", relays=None, timeout=12.0, proxy=None) -> dict:
    """Delete a long-form article: automatically adds the a tag 30023:pubkey:identifier"""
    sk = parse_key(nsec_or_hex)
    pub_hex = pubkey_hex_from_secret(sk)
    address = f"30023:{pub_hex}:{identifier}"
    event = build_deletion(sk, event_id, 30023, reason, address)
    results = publish_event(event, relays=relays, timeout=timeout, proxy=proxy)
    return {"event_id": event["id"], "results": results}


# ---------- High-level helpers ----------
def publish_note(nsec_or_hex: str, content: str, relays=None, tags=None, timeout=12.0, proxy=None) -> dict:
    sk = parse_key(nsec_or_hex)
    event = build_note(sk, content, tags)
    results = publish_event(event, relays=relays, timeout=timeout, proxy=proxy)
    return {"event_id": event["id"], "results": results}


def publish_article(
    nsec_or_hex: str,
    title: str,
    content: str,
    summary: str = "",
    image: str = "",
    topics=None,
    identifier: str = "",
    relays=None,
    timeout=12.0,
    proxy=None,
) -> dict:
    sk = parse_key(nsec_or_hex)
    event = build_article(sk, title, content, summary, image, topics, identifier)
    results = publish_event(event, relays=relays, timeout=timeout, proxy=proxy)
    return {"event_id": event["id"], "identifier": event["tags"][0][1], "results": results}


if __name__ == "__main__":
    keys = create_keys()
    print("New key pair generated and backed up:")
    print("nsec:", keys["nsec"])
    print("npub:", keys["npub"])
    print("Backup file:", BACKUP_FILE_DEFAULT)
