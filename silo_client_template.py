# **********************************************
# Copyright 2026 by Silo Client
# https://github.com/pabqp/silo-client
# **********************************************

from __future__ import annotations
# Importing standart modules
import asyncio
import base64
from collections import OrderedDict
import hashlib
import hmac
import io
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

def _load_dependencies():
    # Install dependencies only when they are missing
    required = {
        "aiohttp": "aiohttp>=3.10,<4",
        "discord": "discord.py>=2.4,<3",
        "cryptography": "cryptography>=44,<47",
        "psutil": "psutil>=6,<8",
        "qrcode": "qrcode[pil]>=7.4,<9",
        "pynput": "pynput>=1.7,<2",
    }
    missing = []
    for module, package in required.items():
        try: __import__(module)
        except ImportError: missing.append(package)
    if missing:
        print("[Silo Client] Installing required dependencies…")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "--disable-pip-version-check"])
        except Exception as exc:
            raise SystemExit(
                "Dependencies could not be installed. Check your Internet connection and permissions.\n"
                f'Run manually: "{sys.executable}" -m pip install ' + " ".join(missing) + f"\n\n{exc}"
            ) from exc

_load_dependencies()

# Importing more modules, cryptography and Discord related + psutil and qrcode
import aiohttpººº
from aiohttp import web
import discord
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:
    Argon2id = None

import psutil
import qrcode
try:
    from pynput import keyboard
except Exception:
    keyboard = None

# Configurating the defaults
CONFIG = __CONFIG_JSON__
PROTOCOL = "silo-v2"
PROTOCOL_V3 = "silo-v3"
TEMPLATE_VERSION = "2.0.2-configurable-dual-aead"
PREFIX = "SILO2:"
PREFIX_V3 = "SILO3:"
ROOM = f'{CONFIG["server_id"]}:{CONFIG["channel_id"]}'
MAX_TEXT = 900
MAX_ATTACHMENT_SIZE = 1_500_000
ATTACHMENT_CHUNK_SIZE = 224 * 1024
MAX_ATTACHMENT_CHUNKS = (MAX_ATTACHMENT_SIZE + ATTACHMENT_CHUNK_SIZE - 1) // ATTACHMENT_CHUNK_SIZE
MAX_MESSAGES = 5000
MAX_ATTACHMENTS = 100
MAX_REVISIONS = 20
KEY_EPOCH_SECONDS = 3600
TYPING_TTL = 3.0
TYPING_RATE_LIMIT = 2.25
DEFAULT_TOPIC = "lobby"
CONTROL_TOPIC = "_control"
ROTATION_INTERVAL = max(1, min(10000, int(CONFIG.get("key_rotation_interval", 50))))
PANIC_HOTKEY = str(CONFIG.get("panic_hotkey", "<ctrl>+<shift>+<alt>+k")).strip()
PAD_BUCKET = 64
AUTO_LOCK_SECONDS = max(30, min(3600, int(CONFIG.get("auto_lock_seconds", 300))))
DUAL_LAYER = bool(CONFIG.get("dual_layer_encryption", True))
ENCRYPT_LOCAL_HISTORY = bool(CONFIG.get("encrypted_local_history", True))
FEATURES = {
    "security_panel": bool(CONFIG.get("show_security_panel", True)),
    "statistics": bool(CONFIG.get("show_statistics", True)),
    "topics": bool(CONFIG.get("enable_topics", True)),
    "search": bool(CONFIG.get("enable_search", True)),
    "presence": bool(CONFIG.get("enable_presence", True)),
    "attachments": bool(CONFIG.get("enable_attachments", True)),
    "voice_notes": bool(CONFIG.get("enable_voice_notes", True)),
    "polls": bool(CONFIG.get("enable_polls", True)),
    "view_once": bool(CONFIG.get("enable_view_once", True)),
    "disappearing": bool(CONFIG.get("enable_disappearing", True)),
    "wallpapers": bool(CONFIG.get("enable_wallpapers", True)),
    "mobile_access": bool(CONFIG.get("enable_mobile_access", True)),
    "panic": bool(CONFIG.get("enable_panic", True)),
}

# Setup topic identifier standarts and verification
def normalize_topic_id(value: object) -> str:
    topic = str(value or "")
    if not topic or len(topic) > 48 or not all(char.isascii() and (char.isalnum() or char in "_-") for char in topic):
        raise ValueError("invalid topic identifier")
    return topic

def local_ip() -> str:
    # Best-effort LAN address used by phones on the same network (getting local IP)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        address = probe.getsockname()[0]
    except OSError:
        try: address = socket.gethostbyname(socket.gethostname())
        except OSError: address = "127.0.0.1"
    finally:
        probe.close()
    return address

LAN_IP = local_ip()

# Generates the url for mobile devices
def mobile_url() -> str:
    return f'http://{LAN_IP}:{CONFIG["port"]}/?access={CONFIG.get("web_access_token", "")}'

# Gets datetime
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

# Validate username
def clean_name(value: str) -> str:
    value = "".join(c for c in str(value).strip() if c.isprintable() and c not in "\r\n\t")
    return value[:40] or "User"

# Fast online AEAD backed by a one-time memory-hard password derivation
class CryptoBox:
    def __init__(self, passphrase: str):
        if len(passphrase) < 16:
            raise ValueError("The shared key must contain at least 16 characters")
        configured_salt = CONFIG.get("kdf_salt", "")
        try: salt = base64.urlsafe_b64decode(configured_salt + "===") if configured_salt else b""
        except Exception: salt = b""
        if len(salt) < 16:
            salt = hashlib.sha256(("SiloClient/v2/fallback/" + ROOM).encode()).digest()
        if Argon2id is not None:
            key = Argon2id(salt=salt[:32], length=32, iterations=3, lanes=4, memory_cost=131072).derive(passphrase.encode())
            self.kdf = "Argon2id · 128 MiB · t=3 · p=4"
        else:
            key = Scrypt(salt=salt[:32], length=32, n=2**17, r=8, p=1).derive(passphrase.encode())
            self.kdf = "Scrypt · N=131072 · r=8 · p=1"
        secondary_passphrase = str(CONFIG.get("secondary_key", ""))
        if DUAL_LAYER and len(secondary_passphrase) < 16:
            raise ValueError("Dual-layer encryption requires a different secondary key with at least 16 characters")
        if secondary_passphrase and hmac.compare_digest(secondary_passphrase.encode(), passphrase.encode()):
            raise ValueError("The primary and secondary encryption keys must be different")
        secondary_salt = hashlib.sha256(salt[:32] + b"SiloClient/secondary-kdf/v1").digest()
        if secondary_passphrase:
            if Argon2id is not None:
                secondary_key = Argon2id(salt=secondary_salt, length=32, iterations=3, lanes=4, memory_cost=131072).derive(secondary_passphrase.encode())
            else:
                secondary_key = Scrypt(salt=secondary_salt, length=32, n=2**17, r=8, p=1).derive(secondary_passphrase.encode())
        else:
            secondary_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=secondary_salt,
                info=b"SiloClient/compatibility-secondary/v1").derive(key)
        self.master_key = bytearray(key)
        self.secondary_master_key = bytearray(secondary_key)
        self.topic_ciphers: dict[tuple[str, str], AESGCM] = {}
        self.topic_chacha_ciphers: dict[tuple[str, str], ChaCha20Poly1305] = {}
        self.nonce_prefix = secrets.token_bytes(4)
        self.nonce_counter = secrets.randbelow(1 << 32)
        self.nonce_lock = threading.Lock()
        self.replay_cache: OrderedDict[bytes, None] = OrderedDict()
        self.replay_limit = 20000
        self.fingerprint = hashlib.sha256(key).hexdigest()[:12].upper()
        self.key_id_bytes = hmac.new(key, b"SiloClient/v3.2/key-commitment/" + ROOM.encode(), hashlib.sha256).digest()[:8]
        self.secondary_key_id_bytes = hmac.new(secondary_key, b"SiloClient/v5/secondary-commitment/" + ROOM.encode(), hashlib.sha256).digest()[:8]
        self.key_id = self.key_id_bytes.hex().upper()
        self.encrypted = 0
        self.decrypted = 0

    # Setup of the topic sha256 cipher system
    def topic_cipher(self, topic_id: str, purpose: str = "event") -> AESGCM:
        topic_id = normalize_topic_id(topic_id)
        cache_key = (topic_id, purpose)
        cipher = self.topic_ciphers.get(cache_key)
        if cipher is None:
            salt = hashlib.sha256(b"SiloClient/v3.2/HKDF/salt/" + ROOM.encode()).digest()
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=(b"SiloClient/v3.2/key/" + purpose.encode() + b"/" + topic_id.encode())).derive(bytes(self.master_key))
            cipher = AESGCM(key)
            self.topic_ciphers[cache_key] = cipher
            while len(self.topic_ciphers) > 128:
                self.topic_ciphers.pop(next(iter(self.topic_ciphers)))
        return cipher

    # Setup of the topic chacha cypher
    def topic_chacha_cipher(self, topic_id: str, purpose: str) -> ChaCha20Poly1305:
        topic_id = normalize_topic_id(topic_id)
        cache_key = (topic_id, purpose)
        cipher = self.topic_chacha_ciphers.get(cache_key)
        if cipher is None:
            salt = hashlib.sha256(b"SiloClient/v5/ChaCha/HKDF/salt/" + ROOM.encode()).digest()
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=(b"SiloClient/v5/ChaCha/key/" + purpose.encode() + b"/" + topic_id.encode())).derive(bytes(self.secondary_master_key))
            cipher = ChaCha20Poly1305(key)
            self.topic_chacha_ciphers[cache_key] = cipher
            while len(self.topic_chacha_ciphers) > 128:
                self.topic_chacha_ciphers.pop(next(iter(self.topic_chacha_ciphers)))
        return cipher

    # Read-only v3.1 compatibility during rolling upgrades
    def legacy_topic_cipher(self, topic_id: str) -> AESGCM:
        cache_key = (normalize_topic_id(topic_id), "legacy-event")
        cipher = self.topic_ciphers.get(cache_key)
        if cipher is None:
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=(b"SiloClient/v2/HKDF/topic/" + ROOM.encode() + b"/" + cache_key[0].encode())).derive(bytes(self.master_key))
            cipher = AESGCM(key); self.topic_ciphers[cache_key] = cipher
        return cipher

    # Nonce limits config
    def next_nonce(self) -> bytes:
        with self.nonce_lock:
            if self.nonce_counter >= (1 << 64) - 1:
                raise RuntimeError("nonce space exhausted; restart the client")
            self.nonce_counter += 1
            return self.nonce_prefix + self.nonce_counter.to_bytes(8, "big")

    @staticmethod
    def replay_token(scope: bytes, nonce: bytes) -> bytes:
        return hashlib.blake2s(scope + nonce, digest_size=16, person=b"SiloRply").digest()

    def reject_replay(self, scope: bytes, nonce: bytes):
        if self.replay_token(scope, nonce) in self.replay_cache:
            raise ValueError("replayed packet")

    def remember_nonce(self, scope: bytes, nonce: bytes):
        token = self.replay_token(scope, nonce)
        self.replay_cache[token] = None
        if len(self.replay_cache) > self.replay_limit:
            self.replay_cache.popitem(last=False)

    def aad(self, topic_id: str, purpose: str = "event") -> bytes:
        return (PROTOCOL + "|AES-256-GCM|" + ROOM + "|" + topic_id + "|" + purpose).encode()

    # Encryption layers
    def encrypt(self, value: dict) -> str:
        topic_id = normalize_topic_id(value.get("topic_id", CONTROL_TOPIC))
        nonce = self.next_nonce()
        clear = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        # Authenticated length hiding. Random slack avoids exposing exact message length while keeping the Discord payload comfortably below its limit
        target = ((len(clear) + 2 + PAD_BUCKET - 1) // PAD_BUCKET) * PAD_BUCKET
        target += secrets.randbelow(2) * PAD_BUCKET
        raw = len(clear).to_bytes(2, "big") + clear + secrets.token_bytes(target - len(clear) - 2)
        self.encrypted += 1
        epoch = int(time.time() // KEY_EPOCH_SECONDS)
        if DUAL_LAYER:
            outer_nonce = self.next_nonce()
            header = bytes((6, 2)) + self.key_id_bytes + self.secondary_key_id_bytes + epoch.to_bytes(4, "big")
            inner = self.topic_cipher(topic_id, f"event:{epoch}").encrypt(nonce, raw, self.aad(topic_id, "event-v6-inner") + header)
            encrypted = self.topic_chacha_cipher(topic_id, f"event:{epoch}").encrypt(
                outer_nonce, nonce + inner, self.aad(topic_id, "event-v6-outer") + header)
            blob = header + outer_nonce + encrypted
        else:
            header = bytes((5, 2)) + self.key_id_bytes + epoch.to_bytes(4, "big")
            encrypted = self.topic_cipher(topic_id, f"event:{epoch}").encrypt(nonce, raw, self.aad(topic_id, "event-v5") + header)
            blob = header + nonce + encrypted
        return PREFIX + topic_id + ":" + base64.urlsafe_b64encode(blob).decode()

    # Decryption method
    def decrypt(self, value: str) -> dict:
        if not value.startswith(PREFIX):
            raise ValueError("unknown protocol")
        try:
            topic_id, encoded = value[len(PREFIX):].split(":", 1)
            topic_id = normalize_topic_id(topic_id)
            blob = base64.urlsafe_b64decode(encoded)
        except (ValueError, TypeError):
            raise ValueError("invalid topic header") from None
        if len(blob) < 31:
            raise ValueError("truncated packet")
        if blob[:2] == bytes((6, 2)):
            if len(blob) < 63 or not hmac.compare_digest(blob[2:10], self.key_id_bytes) or not hmac.compare_digest(blob[10:18], self.secondary_key_id_bytes):
                raise ValueError("incorrect dual-layer room keys")
            header, epoch, outer_nonce, ciphertext = blob[:22], int.from_bytes(blob[18:22], "big"), blob[22:34], blob[34:]
            if abs(epoch - int(time.time() // KEY_EPOCH_SECONDS)) > 48: raise ValueError("key epoch is outside the acceptance window")
            self.reject_replay(b"event6/" + topic_id.encode(), outer_nonce)
            inner_blob = self.topic_chacha_cipher(topic_id, f"event:{epoch}").decrypt(
                outer_nonce, ciphertext, self.aad(topic_id, "event-v6-outer") + header)
            if len(inner_blob) < 29: raise ValueError("truncated inner encryption layer")
            nonce, inner = inner_blob[:12], inner_blob[12:]
            padded = self.topic_cipher(topic_id, f"event:{epoch}").decrypt(
                nonce, inner, self.aad(topic_id, "event-v6-inner") + header)
            clear_len = int.from_bytes(padded[:2], "big")
            if clear_len < 2 or clear_len > len(padded) - 2: raise ValueError("invalid authenticated padding")
            decoded = json.loads(padded[2:2 + clear_len])
            self.remember_nonce(b"event6/" + topic_id.encode(), outer_nonce)
        elif blob[:2] == bytes((5, 2)):
            if len(blob) < 43 or not hmac.compare_digest(blob[2:10], self.key_id_bytes):
                raise ValueError("incorrect room key")
            header, epoch, nonce, ciphertext = blob[:14], int.from_bytes(blob[10:14], "big"), blob[14:26], blob[26:]
            if abs(epoch - int(time.time() // KEY_EPOCH_SECONDS)) > 48: raise ValueError("key epoch is outside the acceptance window")
            self.reject_replay(b"event5/" + topic_id.encode(), nonce)
            padded = self.topic_cipher(topic_id, f"event:{epoch}").decrypt(nonce, ciphertext, self.aad(topic_id, "event-v5") + header)
            clear_len = int.from_bytes(padded[:2], "big")
            if clear_len < 2 or clear_len > len(padded) - 2: raise ValueError("invalid authenticated padding")
            decoded = json.loads(padded[2:2 + clear_len])
            self.remember_nonce(b"event5/" + topic_id.encode(), nonce)
        elif blob[:2] == bytes((4, 2)):
            if len(blob) < 43 or not hmac.compare_digest(blob[2:10], self.key_id_bytes): raise ValueError("incorrect room key")
            header, epoch, nonce, ciphertext = blob[:14], int.from_bytes(blob[10:14], "big"), blob[14:26], blob[26:]
            if abs(epoch - int(time.time() // KEY_EPOCH_SECONDS)) > 48: raise ValueError("key epoch is outside the acceptance window")
            self.reject_replay(b"event4/" + topic_id.encode(), nonce)
            decoded = json.loads(self.topic_cipher(topic_id, f"event:{epoch}").decrypt(nonce, ciphertext, self.aad(topic_id, "event-v4") + header))
            self.remember_nonce(b"event4/" + topic_id.encode(), nonce)
        elif blob[:2] == bytes((3, 2)):
            if len(blob) < 39 or not hmac.compare_digest(blob[2:10], self.key_id_bytes):
                raise ValueError("incorrect room key")
            header, nonce, ciphertext = blob[:10], blob[10:22], blob[22:]
            self.reject_replay(b"event/" + topic_id.encode(), nonce)
            decoded = json.loads(self.topic_cipher(topic_id, "event").decrypt(nonce, ciphertext, self.aad(topic_id, "event-v3") + header))
            self.remember_nonce(b"event/" + topic_id.encode(), nonce)
        elif blob[:2] == bytes((2, 2)):
            nonce = blob[2:14]
            self.reject_replay(b"legacy/" + topic_id.encode(), nonce)
            decoded = json.loads(self.legacy_topic_cipher(topic_id).decrypt(nonce, blob[14:], self.aad(topic_id)))
            self.remember_nonce(b"legacy/" + topic_id.encode(), nonce)
        else:
            raise ValueError("incompatible cryptographic version")
        self.decrypted += 1
        if decoded.get("topic_id") != topic_id:
            raise ValueError("authenticated topic does not match the header")
        return decoded

    # Encrypt attachement method
    def encrypt_attachment_chunk(self, topic_id: str, transfer_id: str, index: int, chunk: bytes) -> bytes:
        topic_id = normalize_topic_id(topic_id)
        nonce = self.next_nonce()
        epoch = int(time.time() // KEY_EPOCH_SECONDS)
        if DUAL_LAYER:
            outer_nonce = self.next_nonce()
            header = bytes((6, 3)) + self.key_id_bytes + self.secondary_key_id_bytes + epoch.to_bytes(4, "big")
            inner_aad = self.aad(topic_id, f"file-v6-inner:{transfer_id}:{index}") + header
            outer_aad = self.aad(topic_id, f"file-v6-outer:{transfer_id}:{index}") + header
            inner = self.topic_cipher(topic_id, f"attachment:{epoch}").encrypt(nonce, chunk, inner_aad)
            return header + outer_nonce + self.topic_chacha_cipher(topic_id, f"attachment:{epoch}").encrypt(outer_nonce, nonce + inner, outer_aad)
        header = bytes((4, 2)) + self.key_id_bytes + epoch.to_bytes(4, "big")
        aad = self.aad(topic_id, f"file-v4:{transfer_id}:{index}") + header
        return header + nonce + self.topic_cipher(topic_id, f"attachment:{epoch}").encrypt(nonce, chunk, aad)

    # Decrypt attachement mehtod
    def decrypt_attachment_chunk(self, topic_id: str, transfer_id: str, index: int, payload: bytes) -> bytes:
        topic_id = normalize_topic_id(topic_id)
        if len(payload) < 29:
            raise ValueError("truncated attachment chunk")
        if payload[:2] == bytes((6, 3)):
            if len(payload) < 63 or not hmac.compare_digest(payload[2:10], self.key_id_bytes) or not hmac.compare_digest(payload[10:18], self.secondary_key_id_bytes):
                raise ValueError("incorrect dual-layer attachment keys")
            header, epoch, outer_nonce = payload[:22], int.from_bytes(payload[18:22], "big"), payload[22:34]
            if abs(epoch - int(time.time() // KEY_EPOCH_SECONDS)) > 48: raise ValueError("attachment key epoch is outside the acceptance window")
            scope = f"file6/{topic_id}/{transfer_id}/{index}/".encode(); self.reject_replay(scope, outer_nonce)
            outer_aad = self.aad(topic_id, f"file-v6-outer:{transfer_id}:{index}") + header
            inner_blob = self.topic_chacha_cipher(topic_id, f"attachment:{epoch}").decrypt(outer_nonce, payload[34:], outer_aad)
            if len(inner_blob) < 29: raise ValueError("truncated inner attachment layer")
            nonce, inner = inner_blob[:12], inner_blob[12:]
            inner_aad = self.aad(topic_id, f"file-v6-inner:{transfer_id}:{index}") + header
            plain = self.topic_cipher(topic_id, f"attachment:{epoch}").decrypt(nonce, inner, inner_aad)
            self.remember_nonce(scope, outer_nonce); return plain
        if payload[:2] == bytes((4, 2)):
            if len(payload) < 43 or not hmac.compare_digest(payload[2:10], self.key_id_bytes): raise ValueError("incorrect attachment key")
            header, epoch, nonce = payload[:14], int.from_bytes(payload[10:14], "big"), payload[14:26]
            if abs(epoch - int(time.time() // KEY_EPOCH_SECONDS)) > 48: raise ValueError("attachment key epoch is outside the acceptance window")
            scope = f"file4/{topic_id}/{transfer_id}/{index}/".encode(); self.reject_replay(scope, nonce)
            aad = self.aad(topic_id, f"file-v4:{transfer_id}:{index}") + header
            plain = self.topic_cipher(topic_id, f"attachment:{epoch}").decrypt(nonce, payload[26:], aad)
            self.remember_nonce(scope, nonce); return plain
        if payload[:2] == bytes((3, 2)):
            if len(payload) < 39 or not hmac.compare_digest(payload[2:10], self.key_id_bytes):
                raise ValueError("incorrect attachment key")
            header, nonce = payload[:10], payload[10:22]
            self.reject_replay(f"file/{topic_id}/{transfer_id}/{index}/".encode(), nonce)
            aad = self.aad(topic_id, f"file-v3:{transfer_id}:{index}") + header
            plain = self.topic_cipher(topic_id, "attachment").decrypt(nonce, payload[22:], aad)
            self.remember_nonce(f"file/{topic_id}/{transfer_id}/{index}/".encode(), nonce)
            return plain
        nonce = payload[:12]
        self.reject_replay(f"legacy-file/{topic_id}/{transfer_id}/{index}/".encode(), nonce)
        aad = self.aad(topic_id, f"file:{transfer_id}:{index}")
        plain = self.legacy_topic_cipher(topic_id).decrypt(nonce, payload[12:], aad)
        self.remember_nonce(f"legacy-file/{topic_id}/{transfer_id}/{index}/".encode(), nonce)
        return plain

    # Encrypt local history method
    def encrypt_local_history(self, clear: bytes) -> bytes:
        """Layered authenticated encryption for data at rest."""
        magic = b"SILOHIST2\x00"
        inner_nonce, outer_nonce = secrets.token_bytes(12), secrets.token_bytes(12)
        identity = f"{ROOM}|{CONFIG['user_id']}".encode()
        key1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(identity).digest(),
            info=b"SiloClient/history/AES-256-GCM/v2").derive(bytes(self.master_key))
        key2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(identity + b"/secondary").digest(),
            info=b"SiloClient/history/ChaCha20-Poly1305/v2").derive(bytes(self.secondary_master_key))
        inner = AESGCM(key1).encrypt(inner_nonce, clear, magic + identity + b"/inner")
        outer = ChaCha20Poly1305(key2).encrypt(outer_nonce, inner_nonce + inner, magic + identity + b"/outer")
        return magic + outer_nonce + outer

    # Decrypt local history method
    def decrypt_local_history(self, payload: bytes) -> bytes:
        magic = b"SILOHIST2\x00"
        if len(payload) < len(magic) + 12 + 16 or not payload.startswith(magic):
            raise ValueError("invalid encrypted history container")
        identity = f"{ROOM}|{CONFIG['user_id']}".encode()
        key1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(identity).digest(),
            info=b"SiloClient/history/AES-256-GCM/v2").derive(bytes(self.master_key))
        key2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(identity + b"/secondary").digest(),
            info=b"SiloClient/history/ChaCha20-Poly1305/v2").derive(bytes(self.secondary_master_key))
        outer_nonce = payload[len(magic):len(magic) + 12]
        inner_blob = ChaCha20Poly1305(key2).decrypt(outer_nonce, payload[len(magic) + 12:], magic + identity + b"/outer")
        if len(inner_blob) < 28: raise ValueError("truncated encrypted history")
        return AESGCM(key1).decrypt(inner_blob[:12], inner_blob[12:], magic + identity + b"/inner")

    def invalidate(self):
        # Best-effort invalidation; Python and crypto backends may retain copies
        for index in range(len(self.master_key)):
            self.master_key[index] = secrets.randbits(8)
        for index in range(len(self.secondary_master_key)):
            self.secondary_master_key[index] = secrets.randbits(8)
        self.topic_ciphers.clear()
        self.topic_chacha_ciphers.clear()
        self.replay_cache.clear()
        self.nonce_prefix = secrets.token_bytes(4)

"""
Asynchronous group envelope using per-client X25519 session keys.
This is a bounded session ratchet, not Signal's Double Ratchet. A content key is
encrypted once with AES-256-GCM and wrapped independently for every known peer.
"""
class SessionRatchet:
    def __init__(self, master_key: bytearray):
        self.master_key = master_key
        self.private_keys: list[X25519PrivateKey] = []
        self.public_bytes = b""
        self.peers: dict[str, X25519PublicKey] = {}
        self.session_id = ""
        self.content_key = bytearray()
        self.sent_in_session = 0
        self.received_keys: dict[tuple[str, str], bytearray] = {}
        self.rotate_identity()
        self.rotate_content()

    def rotate_identity(self):
        private = X25519PrivateKey.generate()
        self.private_keys.insert(0, private)
        # One previous private key is retained only as a short grace window for in-flight Discord messages addressed to the prior announcement
        del self.private_keys[2:]
        self.public_bytes = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def rotate_content(self):
        self._scrub(self.content_key)
        # Independent AES and ChaCha session keys
        self.content_key = bytearray(secrets.token_bytes(64))
        self.session_id = secrets.token_hex(12)
        self.sent_in_session = 0

    def announcement(self) -> dict:
        return {"protocol": PROTOCOL_V3, "public_key": _b64(self.public_bytes),
                "rotation_interval": ROTATION_INTERVAL}

    def remember_peer(self, sender_id: str, encoded_key: str):
        raw = _unb64(encoded_key)
        if len(raw) != 32:
            raise ValueError("invalid X25519 public key")
        self.peers[str(sender_id)] = X25519PublicKey.from_public_bytes(raw)

    def due(self) -> bool:
        return self.sent_in_session >= ROTATION_INTERVAL

    def _kek(self, private: X25519PrivateKey, public: X25519PublicKey,
             sender_id: str, recipient_id: str, session_id: str) -> bytes:
        shared = private.exchange(public)
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=bytes(self.master_key),
                    info=(f"SiloClient/v3/X25519/{ROOM}/{sender_id}/{recipient_id}/{session_id}").encode()).derive(shared)

    @staticmethod
    def envelope_aad(topic_id: str, sender_id: str, session_id: str, public_key: str) -> bytes:
        return f"{PROTOCOL_V3}|AES-256-GCM|{ROOM}|{topic_id}|{sender_id}|{session_id}|{public_key}".encode()

    def encrypt(self, value: dict) -> str | None:
        recipients = {uid: key for uid, key in self.peers.items()
                      if uid != str(CONFIG["user_id"])}
        if not recipients:
            return None
        topic_id = normalize_topic_id(value.get("topic_id", CONTROL_TOPIC))
        sender_id = str(CONFIG["user_id"])
        public_key = _b64(self.public_bytes)
        aad = self.envelope_aad(topic_id, sender_id, self.session_id, public_key)
        nonce = secrets.token_bytes(12)
        clear = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        target = ((len(clear) + 2 + PAD_BUCKET - 1) // PAD_BUCKET) * PAD_BUCKET + secrets.randbelow(2) * PAD_BUCKET
        plaintext = len(clear).to_bytes(2, "big") + clear + secrets.token_bytes(target - len(clear) - 2)
        outer_nonce = secrets.token_bytes(12)
        inner = AESGCM(bytes(self.content_key[:32])).encrypt(nonce, plaintext, aad + b"|inner")
        ciphertext = ChaCha20Poly1305(bytes(self.content_key[32:])).encrypt(outer_nonce, nonce + inner, aad + b"|outer")
        wraps = {}
        for recipient_id, peer_key in recipients.items():
            wrap_nonce = secrets.token_bytes(12)
            wrap_aad = aad + b"|wrap|" + recipient_id.encode()
            kek = self._kek(self.private_keys[0], peer_key, sender_id, recipient_id, self.session_id)
            wraps[recipient_id] = {"n": _b64(wrap_nonce),
                                   "c": _b64(AESGCM(kek).encrypt(wrap_nonce, bytes(self.content_key), wrap_aad))}
        packet = {"v": 4, "a": "X25519-HKDF-SHA256+A256GCM+CHACHA20POLY1305", "t": topic_id,
                  "s": sender_id, "sid": self.session_id, "epk": public_key,
                  "n": _b64(outer_nonce), "c": _b64(ciphertext), "w": wraps}
        self.sent_in_session += 1
        return PREFIX_V3 + _b64(json.dumps(packet, separators=(",", ":"), sort_keys=True).encode())

    def decrypt(self, value: str) -> dict:
        try:
            packet = json.loads(_unb64(value[len(PREFIX_V3):]))
            dual_packet = packet.get("v") == 4 and packet.get("a") == "X25519-HKDF-SHA256+A256GCM+CHACHA20POLY1305"
            legacy_packet = packet.get("v") == 3 and packet.get("a") == "X25519-HKDF-SHA256+A256GCM"
            if not dual_packet and not legacy_packet:
                raise ValueError("incompatible session envelope")
            topic_id = normalize_topic_id(packet["t"])
            sender_id, session_id, public_key = str(packet["s"]), str(packet["sid"]), str(packet["epk"])
            message_nonce = _unb64(packet["n"])
            if len(message_nonce) != 12: raise ValueError("invalid session nonce")
            replay_scope = f"ratchet/{sender_id}/{session_id}/".encode()
            crypto.reject_replay(replay_scope, message_nonce)
            cache_id = (sender_id, session_id)
            key = self.received_keys.get(cache_id)
            if key is None:
                recipient_id = str(CONFIG["user_id"])
                wrapped = packet["w"].get(recipient_id)
                if not wrapped:
                    raise ValueError("v3 message is not addressed to this participant")
                sender_public = X25519PublicKey.from_public_bytes(_unb64(public_key))
                aad = self.envelope_aad(topic_id, sender_id, session_id, public_key)
                for private in self.private_keys:
                    try:
                        kek = self._kek(private, sender_public, sender_id, recipient_id, session_id)
                        raw = AESGCM(kek).decrypt(_unb64(wrapped["n"]), _unb64(wrapped["c"]),
                                                  aad + b"|wrap|" + recipient_id.encode())
                        key = bytearray(raw)
                        break
                    except InvalidTag:
                        continue
                if key is None:
                    raise InvalidTag
                self.received_keys[cache_id] = key
                while len(self.received_keys) > 32:
                    _, old_key = self.received_keys.popitem()
                    self._scrub(old_key)
            aad = self.envelope_aad(topic_id, sender_id, session_id, public_key)
            if dual_packet:
                inner_blob = ChaCha20Poly1305(bytes(key[32:])).decrypt(message_nonce, _unb64(packet["c"]), aad + b"|outer")
                if len(inner_blob) < 29: raise ValueError("truncated ratchet inner layer")
                padded = AESGCM(bytes(key[:32])).decrypt(inner_blob[:12], inner_blob[12:], aad + b"|inner")
            else:
                padded = AESGCM(bytes(key)).decrypt(message_nonce, _unb64(packet["c"]), aad)
            clear_len = int.from_bytes(padded[:2], "big")
            if clear_len < 2 or clear_len > len(padded) - 2: raise ValueError("invalid ratchet padding")
            decoded = json.loads(padded[2:2 + clear_len])
            if decoded.get("topic_id") != topic_id or str(decoded.get("sender_id")) != sender_id:
                raise ValueError("authenticated v3 metadata does not match")
            crypto.remember_nonce(replay_scope, message_nonce)
            return decoded
        except (KeyError, TypeError, json.JSONDecodeError):
            raise ValueError("malformed v3 packet") from None

    @staticmethod
    def _scrub(value: bytearray):
        for index in range(len(value)):
            value[index] = secrets.randbits(8)

    def invalidate(self):
        self._scrub(self.content_key)
        for key in self.received_keys.values():
            self._scrub(key)
        self.received_keys.clear()
        self.private_keys.clear()
        self.peers.clear()
        self.public_bytes = b""


crypto = CryptoBox(CONFIG["shared_key"])
ratchet = SessionRatchet(crypto.master_key)
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
channel: discord.TextChannel | None = None
ws_clients: set[web.WebSocketResponse] = set()
messages: dict[str, dict] = {}
topics: dict[str, dict] = {DEFAULT_TOPIC: {"id": DEFAULT_TOPIC, "name": "General", "created_at": now_iso(), "created_by": str(CONFIG["user_id"])}}
attachments: dict[str, dict] = {}
typing_state: dict[str, dict] = {}
typing_last_sent: dict[str, float] = {}
seen_events: set[str] = set()
event_log: dict[str, dict] = {}
clear_proposals: dict[str, dict] = {}
clear_epoch = ""
clear_commit_inflight: set[str] = set()
participants: dict[str, dict] = {}
local_presence_status = "online"
polls: dict[str, dict] = {}
activity_log: list[dict] = []
security_alerts: list[dict] = []
READ_RECEIPTS_ENABLED = bool(CONFIG.get("read_receipts", True))
MEMORY_ONLY = bool(CONFIG.get("memory_only", False))
username = clean_name(CONFIG["username"])
bad_packets = 0
delivery_ms = 0.0
started_at = time.time()
events_sent = 0
events_received = 0
bytes_sent = 0
bytes_received = 0
last_visible_ids: set[str] = set()
main_loop: asyncio.AbstractEventLoop | None = None
web_runner: web.AppRunner | None = None
panic_started = False
hotkey_listener = None

storage_root = Path.home() / ".silo_client"
room_storage_id = hashlib.sha256(ROOM.encode()).hexdigest()[:16]
# Include the authenticated key identity as well as the participant identity.
# Regenerated rooms with different keys can therefore never attempt to open
# one another's encrypted histories, even on the same computer.
client_storage_id = hashlib.sha256(
    f'{CONFIG["user_id"]}|{crypto.key_id}|{crypto.secondary_key_id_bytes.hex()}|{int(CONFIG["port"])}'.encode()
).hexdigest()[:24]
data_dir = storage_root / room_storage_id / client_storage_id
data_dir.mkdir(parents=True, exist_ok=True)
history_path = data_dir / (f'history_{CONFIG["user_id"]}.silo.enc' if ENCRYPT_LOCAL_HISTORY else f'history_{CONFIG["user_id"]}.json')
legacy_history_path = data_dir / f'history_{CONFIG["user_id"]}.json'
mobile_auth_path = data_dir / f'mobile_access_{CONFIG["user_id"]}.json'


def best_effort_remove_local_data():
    """Overwrite and remove only this client's isolated local storage.

    This reduces casual recovery risk but is not a forensic-erasure guarantee on
    SSDs, copy-on-write filesystems, snapshots, backups, journals or cloud sync.
    """
    root = data_dir
    if not root.exists() or root.is_symlink():
        return
    for path in list(root.rglob("*")):
        try:
            if path.is_file() and not path.is_symlink():
                size = path.stat().st_size
                with path.open("r+b", buffering=0) as handle:
                    remaining = size
                    while remaining:
                        block = secrets.token_bytes(min(1024 * 1024, remaining))
                        handle.write(block)
                        remaining -= len(block)
                    handle.flush()
                    os.fsync(handle.fileno())
        except OSError:
            pass
    shutil.rmtree(root, ignore_errors=True)


async def panic_shutdown():
    """Local-only emergency stop. It is intentionally not exposed over chat/web."""
    global panic_started
    if panic_started:
        return
    panic_started = True
    print("[PANIC] Closing connections and invalidating local state…", file=sys.stderr)
    for ws in tuple(ws_clients):
        try:
            await ws.close(code=1001, message=b"local panic shutdown")
        except Exception:
            pass
    ws_clients.clear()
    if web_runner is not None:
        try:
            await web_runner.cleanup()
        except Exception:
            pass
    try:
        if not client.is_closed():
            await client.close()
    except Exception:
        pass
    ratchet.invalidate()
    crypto.invalidate()
    CONFIG["shared_key"] = ""
    CONFIG["bot_token"] = ""
    best_effort_remove_local_data()
    await asyncio.sleep(0)
    os._exit(0)


def start_panic_hotkey(loop: asyncio.AbstractEventLoop):
    global hotkey_listener
    if not PANIC_HOTKEY:
        print("[WARN] Local kill switch disabled (empty hotkey)")
        return
    if keyboard is None:
        print("[WARN] The global panic hotkey could not be registered")
        return
    try:
        hotkey_listener = keyboard.GlobalHotKeys({
            PANIC_HOTKEY: lambda: asyncio.run_coroutine_threadsafe(panic_shutdown(), loop)
        })
        hotkey_listener.daemon = True
        hotkey_listener.start()
        print(f"[OK] Kill switch local preparado: {PANIC_HOTKEY}")
    except Exception as exc:
        print(f"[WARN] Global hotkey unavailable: {exc}")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def load_mobile_auth() -> dict:
    """Load only a password verifier and session key; never a plaintext password."""
    try:
        value = json.loads(mobile_auth_path.read_text(encoding="utf-8"))
        required = {"salt", "verifier", "session_key"}
        return value if isinstance(value, dict) and required.issubset(value) else {}
    except (FileNotFoundError, OSError, ValueError):
        return {}


mobile_auth = load_mobile_auth()


def mobile_password_configured() -> bool:
    return bool(mobile_auth.get("salt") and mobile_auth.get("verifier") and mobile_auth.get("session_key"))


def password_verifier(password: str, salt: bytes) -> bytes:
    # 64 MiB memory cost: appropriate for an interactive local access password.
    return Scrypt(salt=salt, length=32, n=2**16, r=8, p=1).derive(password.encode("utf-8"))


def encrypted_export(password: str, payload: dict) -> str:
    if len(password) < 12: raise ValueError("export password must contain at least 12 characters")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    ciphertext = AESGCM(key).encrypt(nonce, raw, b"SiloClient/encrypted-export/v1")
    return json.dumps({"format": "silo-encrypted-v1", "kdf": "scrypt-32768", "salt": _b64(salt),
        "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}, separators=(",", ":"))


def set_mobile_password(password: str):
    global mobile_auth
    salt = secrets.token_bytes(16)
    mobile_auth = {
        "version": 1,
        "salt": _b64(salt),
        "verifier": _b64(password_verifier(password, salt)),
        # Rotated on every password change to invalidate prior phone sessions.
        "session_key": _b64(secrets.token_bytes(32)),
        "changed_at": now_iso(),
    }
    temporary = mobile_auth_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(mobile_auth, separators=(",", ":")), encoding="utf-8")
    temporary.replace(mobile_auth_path)


def verify_mobile_password(password: str) -> bool:
    if not mobile_password_configured() or not isinstance(password, str):
        return False
    try:
        expected = _unb64(mobile_auth["verifier"])
        candidate = password_verifier(password, _unb64(mobile_auth["salt"]))
        return hmac.compare_digest(candidate, expected)
    except (KeyError, ValueError):
        return False


def load_history():
    global messages, topics, attachments, seen_events, event_log, clear_proposals, clear_epoch, polls, activity_log
    try:
        migrated_plaintext = False
        if history_path.exists():
            raw = history_path.read_bytes()
            clear = crypto.decrypt_local_history(raw) if ENCRYPT_LOCAL_HISTORY else raw
        elif legacy_history_path.exists():
            clear = legacy_history_path.read_bytes()
            migrated_plaintext = True
        else:
            raise FileNotFoundError
        data = json.loads(clear.decode("utf-8"))
        messages = data.get("messages", {})
        stored_topics = data.get("topics", {})
        topics = stored_topics if isinstance(stored_topics, dict) and DEFAULT_TOPIC in stored_topics else {
            DEFAULT_TOPIC: {"id": DEFAULT_TOPIC, "name": "General", "created_at": now_iso(), "created_by": str(CONFIG["user_id"])}}
        attachments = {}
        seen_events = set(data.get("seen_events", []))
        event_log = {item["event_id"]: item for item in data.get("events", []) if isinstance(item, dict) and item.get("event_id")}
        clear_proposals = {item["id"]: item for item in data.get("clear_proposals", [])
                           if isinstance(item, dict) and isinstance(item.get("id"), str)}
        clear_epoch = str(data.get("clear_epoch", ""))
        # A committed full-room deletion is an irreversible local boundary.
        # Never restore older messages or deletion tombstones from a stale cache.
        if clear_epoch:
            messages = {mid: message for mid, message in messages.items()
                        if str(message.get("timestamp", "")) > clear_epoch}
        polls = data.get("polls", {}) if isinstance(data.get("polls", {}), dict) else {}
        activity_log = data.get("activity", [])[-100:] if isinstance(data.get("activity", []), list) else []
        if migrated_plaintext and ENCRYPT_LOCAL_HISTORY and not MEMORY_ONLY:
            save_history()
            try: legacy_history_path.unlink()
            except OSError: pass
    except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if history_path.exists() and ENCRYPT_LOCAL_HISTORY:
            quarantine = history_path.with_name(
                f"{history_path.name}.quarantine-{int(time.time())}"
            )
            try:
                history_path.replace(quarantine)
                print(f"[WARN] An unreadable encrypted history was preserved as {quarantine.name}; starting this client with an empty history")
            except OSError:
                print("[WARN] Encrypted history authentication failed; starting this isolated client with an empty history")
        messages, topics, attachments, seen_events, event_log, clear_proposals, clear_epoch, polls, activity_log = {}, {DEFAULT_TOPIC: {"id": DEFAULT_TOPIC, "name": "General", "created_at": now_iso(), "created_by": str(CONFIG["user_id"])}}, {}, set(), {}, {}, "", {}, []
    except (FileNotFoundError, OSError):
        messages, topics, attachments, seen_events, event_log, clear_proposals, clear_epoch, polls, activity_log = {}, {DEFAULT_TOPIC: {"id": DEFAULT_TOPIC, "name": "General", "created_at": now_iso(), "created_by": str(CONFIG["user_id"])}}, {}, set(), {}, {}, "", {}, []


def save_history():
    if MEMORY_ONLY:
        return
    temporary = history_path.with_name(f".{history_path.name}.{os.getpid()}.tmp")
    clear = json.dumps({"messages": messages, "topics": topics, "seen_events": list(seen_events)[-10000:],
        "events": list(event_log.values())[-10000:], "clear_proposals": list(clear_proposals.values())[-50:],
        "clear_epoch": clear_epoch, "polls": polls, "activity": activity_log[-100:]}, ensure_ascii=False,
        separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload = crypto.encrypt_local_history(clear) if ENCRYPT_LOCAL_HISTORY else clear
    temporary.write_bytes(payload)
    try: os.chmod(temporary, 0o600)
    except OSError: pass
    temporary.replace(history_path)


def event(kind: str, data: dict, topic_id: str | None = None) -> dict:
    if topic_id is None:
        topic_id = data.get("topic_id") if kind in {"message", "edit", "delete", "pin", "highlight", "view_once_open", "file_start", "file_chunk", "file_complete", "typing", "topic_create", "topic_rename", "topic_delete", "reaction", "receipt", "poll_create", "poll_vote", "role_set"} else CONTROL_TOPIC
    topic_id = normalize_topic_id(topic_id)
    return {"v": 2, "room": ROOM, "topic_id": topic_id, "event_id": str(uuid.uuid4()), "kind": kind,
            "sender_id": str(CONFIG["user_id"]), "sender_name": username, "ts": now_iso(), "data": data}


def validate_event(item: dict):
    if not isinstance(item, dict) or not isinstance(item.get("data"), dict):
        raise ValueError("invalid event structure")
    if item.get("v") != 2 or item.get("room") != ROOM:
        raise ValueError("incompatible room or version")
    if item.get("kind") not in {"message", "edit", "delete", "pin", "highlight", "profile", "presence", "import",
                                "clear_request", "clear_vote", "clear_cancel", "clear_commit", "topic_create", "topic_rename", "topic_delete", "typing", "session_key",
                                "file_start", "file_chunk", "file_complete", "reaction", "receipt", "poll_create", "poll_vote", "view_once_open", "role_set"}:
        raise ValueError("unknown event")
    topic_id = normalize_topic_id(item.get("topic_id", ""))
    if item["kind"] in {"message", "edit", "delete", "pin", "highlight", "file_start", "file_chunk", "file_complete", "typing", "topic_create", "topic_rename", "topic_delete", "reaction", "receipt", "poll_create", "poll_vote", "view_once_open", "role_set"}:
        if topic_id == CONTROL_TOPIC:
            raise ValueError("content event without a topic")
    elif topic_id != CONTROL_TOPIC:
        raise ValueError("control event outside the control topic")
    uuid.UUID(item["event_id"])
    datetime.fromisoformat(item["ts"])
    if not str(item.get("sender_id", "")).isdigit():
        raise ValueError("invalid sender")
    data = item["data"]
    kind = item["kind"]
    if kind == "message":
        if not isinstance(data.get("id"), str) or not 1 <= len(str(data.get("content", ""))) <= MAX_TEXT:
            raise ValueError("invalid message")
        uuid.UUID(data["id"])
        if not isinstance(data.get("view_once", False), bool): raise ValueError("invalid view-once flag")
    elif kind == "view_once_open":
        uuid.UUID(str(data.get("id", "")))
    elif kind == "role_set":
        if data.get("role") not in {"admin", "member", "read_only"} or not str(data.get("user_id", "")).isdigit():
            raise ValueError("invalid topic role")
    elif kind in {"topic_create", "topic_rename"}:
        if not isinstance(data.get("name"), str) or not data["name"].strip() or len(data["name"]) > 40:
            raise ValueError("invalid topic")
    elif kind in {"file_start", "file_chunk", "file_complete"}:
        transfer_id = str(data.get("transfer_id", ""))
        uuid.UUID(transfer_id)
        if kind == "file_start":
            size, total = int(data.get("size", -1)), int(data.get("total", 0))
            digest = str(data.get("sha256", ""))
            expected_total = max(1, (size + ATTACHMENT_CHUNK_SIZE - 1) // ATTACHMENT_CHUNK_SIZE)
            if (not 0 <= size <= MAX_ATTACHMENT_SIZE or total != expected_total or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)):
                raise ValueError("invalid attachment metadata")
        elif kind == "file_chunk":
            if int(data.get("total", 0)) not in range(1, MAX_ATTACHMENT_CHUNKS + 1) or int(data.get("index", -1)) not in range(int(data["total"])):
                raise ValueError("invalid chunk index")
        elif len(str(data.get("sha256", ""))) != 64:
            raise ValueError("invalid final hash")
    elif kind == "typing":
        expires_at = float(data.get("expires_at", 0))
        if expires_at <= time.time() - 1 or expires_at > time.time() + 5:
            raise ValueError("invalid typing indicator")
    elif kind == "presence" and data.get("status", "online") not in {"online", "idle", "away", "offline"}:
        raise ValueError("invalid presence state")
    elif kind == "session_key":
        raw = _unb64(str(data.get("public_key", "")))
        if len(raw) != 32 or int(data.get("rotation_interval", 0)) not in range(1, 10001): raise ValueError("invalid session announcement")
    elif kind == "reaction":
        if str(data.get("emoji", "")) not in {"👍", "❤️", "😂", "🔥", "✅", "👀"}: raise ValueError("invalid reaction")
    elif kind == "receipt" and data.get("state") not in {"delivered", "read"}:
        raise ValueError("invalid receipt")
    elif kind == "poll_create":
        options = data.get("options", [])
        if not isinstance(options, list) or not 2 <= len(options) <= 8: raise ValueError("a poll needs 2 to 8 options")
    elif kind == "poll_vote" and not isinstance(data.get("option"), int):
        raise ValueError("invalid poll vote")


def proposal_is_valid(proposal: dict) -> bool:
    try:
        uuid.UUID(str(proposal["id"]))
        targets = proposal["target_ids"]
        return (isinstance(targets, list) and bool(targets) and len(targets) == len(set(targets))
                and all(str(target).isdigit() for target in targets)
                and str(proposal["initiator_id"]).isdigit() and float(proposal["expires_at"]) > 0)
    except (KeyError, TypeError, ValueError):
        return False


def clear_status(proposal: dict) -> str:
    if proposal.get("status") in {"rejected", "cancelled", "committed"}:
        return proposal["status"]
    if float(proposal.get("expires_at", 0)) <= time.time():
        return "expired"
    votes = proposal.get("votes", {})
    if any(not bool(vote.get("accept")) for vote in votes.values() if isinstance(vote, dict)):
        return "rejected"
    if all(str(target) in votes and bool(votes[str(target)].get("accept")) for target in proposal.get("target_ids", [])):
        return "approved"
    return "pending"


def clear_chat_history(commit_event: dict):
    """Erase all local chat content, including deleted-message tombstones."""
    global messages, attachments, polls, activity_log, event_log, seen_events, clear_epoch, clear_proposals
    clear_epoch = commit_event["ts"]
    messages.clear()
    attachments.clear()
    polls.clear()
    activity_log.clear()
    event_log.clear()
    event_log[commit_event["event_id"]] = commit_event
    seen_events.clear()
    seen_events.add(commit_event["event_id"])
    clear_proposals = {key: value for key, value in clear_proposals.items()
                       if value.get("status") not in {"committed", "rejected", "cancelled", "expired"}}


def topic_role(topic_id: str, user_id: str) -> str:
    topic = topics.get(topic_id, {})
    if str(topic.get("created_by")) == str(user_id):
        return "owner"
    return str(topic.get("roles", {}).get(str(user_id), "member"))


def apply_event(item: dict) -> bool:
    global clear_proposals, topics, attachments, messages, polls, activity_log
    eid = item["event_id"]
    if eid in seen_events:
        return False
    kind, data = item["kind"], item.get("data", {})
    # Delayed pre-clear events must never resurrect erased chat content.
    if clear_epoch and item["ts"] <= clear_epoch and kind not in {"clear_commit", "clear_cancel"}:
        seen_events.add(eid)
        save_history()
        return False
    seen_events.add(eid)
    if kind != "typing" and kind != "file_chunk":
        event_log[eid] = item
    sender_id = str(item["sender_id"])
    sender_name = clean_name(item.get("sender_name", "User"))
    previous_participant = participants.get(sender_id, {})
    participants[sender_id] = {"name": sender_name, "seen": time.time(),
        "status": previous_participant.get("status", "online")}

    if kind in {"message", "edit", "delete", "reaction", "file_start", "file_chunk", "file_complete", "poll_create", "poll_vote"}:
        if topic_role(item["topic_id"], sender_id) == "read_only":
            raise ValueError("read-only participant attempted to modify the topic")

    if kind == "message":
        mid = str(data["id"])
        topic_id = item["topic_id"]
        if topic_id not in topics:
            raise ValueError("message belongs to a missing topic")
        messages.setdefault(mid, {"id": mid, "content": str(data.get("content", ""))[:MAX_TEXT],
            "sender_id": sender_id, "username": sender_name, "timestamp": item["ts"],
            "topic_id": topic_id, "reply_to": data.get("reply_to"), "edited": False, "deleted": False,
            "pinned": False, "highlighted": False, "expires_at": data.get("expires_at"),
            "reactions": {}, "receipts": {}, "revisions": [], "mentions": list(data.get("mentions", []))[:20],
            "view_once": bool(data.get("view_once", False)), "opened_by": None})
        while len(messages) > MAX_MESSAGES:
            messages.pop(next(iter(messages)))
    elif kind in {"edit", "delete", "pin", "highlight"}:
        mid = str(data.get("id", ""))
        msg = messages.get(mid)
        if msg and msg.get("topic_id") == item["topic_id"]:
            if kind == "edit" and sender_id == msg["sender_id"]:
                msg.setdefault("revisions", []).append({"content": msg.get("content", ""), "at": item["ts"]})
                del msg["revisions"][:-MAX_REVISIONS]
                msg["content"], msg["edited"] = str(data.get("content", ""))[:MAX_TEXT], True
            elif kind == "delete" and sender_id == msg["sender_id"]:
                msg["content"], msg["deleted"] = "", True
            elif kind == "pin": msg["pinned"] = bool(data.get("state"))
            elif kind == "highlight": msg["highlighted"] = bool(data.get("state"))
    elif kind == "view_once_open":
        msg = messages.get(str(data.get("id", "")))
        if msg and msg.get("topic_id") == item["topic_id"] and msg.get("view_once") and not msg.get("opened_by") and sender_id != msg.get("sender_id"):
            msg["opened_by"], msg["content"], msg["deleted"] = sender_id, "", True
    elif kind == "role_set":
        topic = topics.get(item["topic_id"])
        if not topic or item["topic_id"] == DEFAULT_TOPIC or str(topic.get("created_by")) != sender_id:
            raise ValueError("only the topic creator can change permissions")
        if str(data["user_id"]) == str(topic.get("created_by")):
            raise ValueError("the topic owner role cannot be changed")
        topic.setdefault("roles", {})[str(data["user_id"])] = data["role"]
    elif kind == "profile":
        participants[sender_id] = {"name": clean_name(data.get("name", sender_name)), "seen": time.time(),
            "status": participants.get(sender_id, {}).get("status", "online")}
    elif kind == "presence":
        participants[sender_id]["status"] = data.get("status", "online")
    elif kind == "session_key":
        ratchet.remember_peer(sender_id, str(data["public_key"]))
    elif kind == "topic_create":
        topic_id = item["topic_id"]
        name = clean_name(str(data.get("name", "")))
        if not name:
            raise ValueError("empty topic name")
        if topic_id not in topics and len(topics) >= 20:
            raise ValueError("a room can contain at most 20 topics")
        topics.setdefault(topic_id, {"id": topic_id, "name": name, "created_at": item["ts"], "created_by": sender_id})
    elif kind == "topic_rename":
        topic_id = item["topic_id"]
        topic = topics.get(topic_id)
        if not topic or topic_id == DEFAULT_TOPIC or str(topic.get("created_by")) != sender_id:
            raise ValueError("only the topic creator can rename it")
        name = clean_name(str(data.get("name", "")))
        if not name:
            raise ValueError("empty topic name")
        topic["name"] = name
    elif kind == "topic_delete":
        topic_id = item["topic_id"]
        if topic_id == DEFAULT_TOPIC:
            raise ValueError("the default topic cannot be deleted")
        topic = topics.get(topic_id)
        if not topic or str(topic.get("created_by")) != sender_id:
            raise ValueError("only the topic creator can delete it")
        topics.pop(topic_id, None)
        messages = {key: value for key, value in messages.items() if value.get("topic_id") != topic_id}
        attachments = {key: value for key, value in attachments.items() if value.get("topic_id") != topic_id}
        polls = {key: value for key, value in polls.items() if value.get("topic_id") != topic_id}
        for key in [key for key, value in typing_state.items() if value.get("topic_id") == topic_id]:
            typing_state.pop(key, None)
    elif kind == "reaction":
        msg = messages.get(str(data.get("id", "")))
        if msg and msg.get("topic_id") == item["topic_id"]:
            emoji = str(data["emoji"]); users = msg.setdefault("reactions", {}).setdefault(emoji, [])
            if sender_id in users: users.remove(sender_id)
            else: users.append(sender_id)
    elif kind == "receipt":
        msg = messages.get(str(data.get("id", "")))
        if msg and msg.get("topic_id") == item["topic_id"] and sender_id != msg.get("sender_id"):
            msg.setdefault("receipts", {})[sender_id] = {"state": data["state"], "at": item["ts"]}
    elif kind == "poll_create":
        poll_id = str(data.get("id", "")); uuid.UUID(poll_id)
        polls.setdefault(poll_id, {"id": poll_id, "topic_id": item["topic_id"], "question": str(data.get("question", ""))[:240],
            "options": [str(value)[:100] for value in data["options"]], "votes": {}, "sender_id": sender_id,
            "username": sender_name, "timestamp": item["ts"]})
    elif kind == "poll_vote":
        poll = polls.get(str(data.get("id", ""))); option = int(data["option"])
        if not poll or poll["topic_id"] != item["topic_id"] or option not in range(len(poll["options"])):
            raise ValueError("invalid poll vote")
        poll["votes"][sender_id] = option
    elif kind == "typing":
        topic_id = item["topic_id"]
        expires_at = float(data.get("expires_at", 0))
        if expires_at <= time.time() or expires_at > time.time() + 5:
            raise ValueError("expired or invalid typing indicator")
        typing_state[f"{sender_id}:{topic_id}"] = {"name": sender_name, "sender_id": sender_id,
            "topic_id": topic_id, "expires_at": expires_at}
    elif kind == "file_start":
        transfer_id = str(data["transfer_id"])
        attachments.setdefault(transfer_id, {"transfer_id": transfer_id, "topic_id": item["topic_id"],
            "name": clean_name(str(data.get("name", "file")))[:120], "mime": str(data.get("mime", "application/octet-stream"))[:100],
            "size": int(data["size"]), "total": int(data["total"]), "sha256": str(data["sha256"]),
            "sender_id": sender_id, "username": sender_name, "timestamp": item["ts"], "chunks": {},
            "status": "receiving", "error": ""})
    elif kind == "file_chunk":
        transfer = attachments.get(str(data["transfer_id"]))
        chunk = data.get("_chunk")
        if not transfer or transfer["topic_id"] != item["topic_id"] or int(data["total"]) != transfer["total"]:
            raise ValueError("chunk without a valid transfer")
        if not isinstance(chunk, bytes) or len(chunk) > ATTACHMENT_CHUNK_SIZE:
            raise ValueError("invalid chunk contents")
        transfer["chunks"].setdefault(int(data["index"]), chunk)
    elif kind == "file_complete":
        transfer = attachments.get(str(data["transfer_id"]))
        if not transfer or transfer["topic_id"] != item["topic_id"] or data["sha256"] != transfer["sha256"]:
            raise ValueError("invalid transfer completion")
        if len(transfer["chunks"]) != transfer["total"]:
            transfer["status"], transfer["error"] = "failed", "Missing chunks"
        else:
            payload = b"".join(transfer["chunks"][index] for index in range(transfer["total"]))
            if len(payload) != transfer["size"] or not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), transfer["sha256"]):
                transfer["status"], transfer["error"] = "failed", "SHA-256 mismatch"
                transfer["chunks"].clear()
            else:
                transfer["bytes"], transfer["status"] = payload, "ready"
                transfer["chunks"].clear()
                while len(attachments) > MAX_ATTACHMENTS:
                    attachments.pop(next(iter(attachments)))
    elif kind == "clear_request":
        proposal = {
            "id": str(data.get("proposal_id", "")), "initiator_id": sender_id, "initiator_name": sender_name,
            "target_ids": [str(value) for value in data.get("target_ids", [])], "created_at": item["ts"],
            "expires_at": float(data.get("expires_at", 0)), "votes": {}, "status": "pending",
        }
        if not proposal_is_valid(proposal) or sender_id not in proposal["target_ids"]:
            raise ValueError("invalid deletion proposal")
        if proposal["expires_at"] > time.time() + 5 * 60 or proposal["expires_at"] <= time.time() - 5:
            raise ValueError("invalid proposal expiration")
        clear_proposals.setdefault(proposal["id"], proposal)
    elif kind == "clear_vote":
        proposal = clear_proposals.get(str(data.get("proposal_id", "")))
        if not proposal or sender_id not in proposal["target_ids"]:
            raise ValueError("deletion vote is not associated with a valid proposal")
        if clear_status(proposal) not in {"pending", "approved"}:
            raise ValueError("the deletion proposal has already ended")
        if sender_id in proposal["votes"]:
            raise ValueError("this participant has already voted")
        proposal["votes"][sender_id] = {"accept": bool(data.get("accept")), "name": sender_name, "at": item["ts"]}
        proposal["status"] = clear_status(proposal)
    elif kind == "clear_cancel":
        proposal = clear_proposals.get(str(data.get("proposal_id", "")))
        if proposal and sender_id == proposal["initiator_id"]:
            proposal["status"] = "cancelled"
            proposal["reason"] = clean_name(str(data.get("reason", "No confirmation")))[:80]
    elif kind == "clear_commit":
        proposal = clear_proposals.get(str(data.get("proposal_id", "")))
        if not proposal or sender_id != proposal["initiator_id"] or clear_status(proposal) != "approved":
            raise ValueError("global deletion without valid consensus")
        proposal["status"] = "committed"
        clear_chat_history(item)
    if kind not in {"typing", "presence", "receipt"}:
        activity_log.append({"kind": kind, "topic_id": item["topic_id"], "sender": sender_name, "at": item["ts"]})
        del activity_log[:-100]
    save_history()
    return True


def public_state() -> dict:
    now = time.time()
    public_participants = {}
    for uid, participant in participants.items():
        age = max(0, now - float(participant.get("seen", 0)))
        declared = participant.get("status", "online")
        status = "offline" if age >= 300 else ("away" if age >= 95 else declared)
        if any(value["sender_id"] == uid and value["expires_at"] > now for value in typing_state.values()):
            status = "typing"
        public_participants[uid] = {"name": participant.get("name", "User"), "status": status,
            "last_seen": datetime.fromtimestamp(float(participant.get("seen", now)), timezone.utc).isoformat(timespec="seconds")}
    active = {uid: p for uid, p in public_participants.items() if p["status"] != "offline"}
    visible = [m for m in messages.values()
               if (not clear_epoch or str(m.get("timestamp", "")) > clear_epoch)
               and (not m.get("expires_at") or float(m["expires_at"]) > now)]
    visible.sort(key=lambda m: (m.get("timestamp", ""), m["id"]))
    cpu = psutil.cpu_percent() if psutil else None
    ram = psutil.virtual_memory().percent if psutil else None
    disk = psutil.disk_usage(str(Path.home())).percent if psutil else None
    process = psutil.Process() if psutil else None
    net = psutil.net_io_counters() if psutil else None
    disk_info = psutil.disk_usage(str(Path.home())) if psutil else None
    pinned = sum(bool(m.get("pinned")) for m in visible)
    highlighted = sum(bool(m.get("highlighted")) for m in visible)
    edited = sum(bool(m.get("edited")) for m in visible)
    deleted = sum(bool(m.get("deleted")) for m in visible)
    mine = sum(m.get("sender_id") == str(CONFIG["user_id"]) for m in visible)
    characters = sum(len(m.get("content", "")) for m in visible)
    public_files = [{key: value for key, value in transfer.items() if key not in {"bytes", "chunks"}}
                    for transfer in attachments.values()]
    active_typing = [value for value in typing_state.values() if value["expires_at"] > now and value["sender_id"] != str(CONFIG["user_id"])]
    return {"type": "state", "messages": visible, "attachments": public_files, "topics": list(topics.values()),
        "polls": list(polls.values()), "activity": activity_log[-30:], "security_alerts": security_alerts[-20:],
        "settings": {"read_receipts": READ_RECEIPTS_ENABLED, "memory_only": MEMORY_ONLY,
                     "features": FEATURES, "dual_layer": DUAL_LAYER, "encrypted_local_history": ENCRYPT_LOCAL_HISTORY},
        "typing": active_typing, "participants": public_participants, "clear_proposals": visible_clear_proposals(), "self_id": str(CONFIG["user_id"]),
        "username": username, "stats": {"hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(), "processor": platform.processor() or "n/d", "python": platform.python_version(),
        "cpu": cpu, "cpu_count": psutil.cpu_count(logical=True) if psutil else os.cpu_count(), "ram": ram, "disk": disk,
        "ram_used": round(psutil.virtual_memory().used / 1073741824, 2) if psutil else None,
        "ram_total": round(psutil.virtual_memory().total / 1073741824, 2) if psutil else None,
        "disk_free": round(disk_info.free / 1073741824, 1) if disk_info else None,
        "process_ram": round(process.memory_info().rss / 1048576, 1) if process else None,
        "threads": process.num_threads() if process else None, "pid": os.getpid(),
        "net_sent": round(net.bytes_sent / 1048576, 1) if net else None, "net_received": round(net.bytes_recv / 1048576, 1) if net else None,
        "discord_latency": round(client.latency * 1000, 1) if client.is_ready() else None,
        "delivery_latency": round(delivery_ms, 1),
        "encryption": "AES-256-GCM + ChaCha20-Poly1305 · independent keys" if DUAL_LAYER else "AES-256-GCM · compatibility mode",
        "kdf": crypto.kdf + (" · dual independent derivation" if DUAL_LAYER else " · single-layer compatibility"),
        "fingerprint": crypto.fingerprint, "key_id": crypto.key_id,
        "nonce": "96-bit · CSPRNG prefix + monotonic counter", "replay_cache": len(crypto.replay_cache),
        "messages": len(visible), "mine": mine, "others": len(visible)-mine, "characters": characters,
        "pinned": pinned, "highlighted": highlighted, "edited": edited, "deleted": deleted,
        "events": len(seen_events), "events_sent": events_sent, "events_received": events_received,
        "bytes_sent": bytes_sent, "bytes_received": bytes_received,
        "encrypted": crypto.encrypted, "decrypted": crypto.decrypted,
        "participants_total": len(participants), "participants_active": len(active), "topics": len(topics),
        "attachments": len(public_files), "attachment_bytes": sum(int(item.get("size", 0)) for item in public_files),
        "websockets": len(ws_clients), "rejected": bad_packets, "uptime": int(now - started_at),
        "pending_transfers": sum(item.get("status") == "receiving" for item in attachments.values()),
        "cache_messages": len(messages), "cache_limit": MAX_MESSAGES,
        "port": int(CONFIG["port"]), "lan_ip": LAN_IP, "mobile_ready": LAN_IP != "127.0.0.1"}}


def public_telemetry() -> dict:
    """Realtime information that must never trigger a chat-feed render."""
    state = public_state()
    return {"type": "telemetry", "participants": state["participants"], "typing": state["typing"], "clear_proposals": state["clear_proposals"], "self_id": state["self_id"],
            "username": state["username"], "stats": state["stats"]}


def current_visible_ids() -> set[str]:
    now = time.time()
    return {mid for mid, message in messages.items()
            if not message.get("expires_at") or float(message["expires_at"]) > now}


def visible_clear_proposals() -> list[dict]:
    proposals = []
    for proposal in clear_proposals.values():
        status = clear_status(proposal)
        if status in {"pending", "approved", "rejected", "cancelled", "expired"}:
            copy = dict(proposal)
            copy["status"] = status
            proposals.append(copy)
    return sorted(proposals, key=lambda item: item.get("created_at", ""), reverse=True)[:5]


async def broadcast(payload: dict | None = None):
    raw = json.dumps(payload or public_state(), ensure_ascii=False)
    dead = set()
    for ws in ws_clients:
        try: await ws.send_str(raw)
        except Exception: dead.add(ws)
    ws_clients.difference_update(dead)


async def broadcast_telemetry():
    await broadcast(public_telemetry())


async def send_event(item: dict, apply_local: bool = True):
    global events_sent, bytes_sent, last_visible_ids
    if channel is None:
        raise RuntimeError("The bot is not connected to the channel yet")
    # Use an ephemeral group content key when peer identities are known. The
    # master-key envelope remains the rolling-upgrade and discovery fallback.
    if item.get("kind") != "session_key" and ratchet.due():
        ratchet.rotate_content()
    payload = ratchet.encrypt(item) if item.get("kind") != "session_key" else None
    if payload is None or len(payload) > 1950:
        payload = crypto.encrypt(item)
    if len(payload) > 1950:
        raise ValueError("Event is too large for Discord")
    if apply_local:
        apply_event(item)
    await channel.send(payload, allowed_mentions=discord.AllowedMentions.none())
    events_sent += 1
    bytes_sent += len(payload.encode())
    if item.get("kind") in {"presence", "profile"}:
        await broadcast_telemetry()
    else:
        await broadcast()
        last_visible_ids = current_visible_ids()
    if item.get("kind") == "clear_vote":
        await maybe_finalize_clear(str(item.get("data", {}).get("proposal_id", "")))


async def send_attachment(topic_id: str, name: str, mime: str, payload: bytes):
    """Encrypt each block independently and send it as a Discord attachment."""
    global events_sent, bytes_sent
    topic_id = normalize_topic_id(topic_id)
    if topic_id not in topics or len(payload) > MAX_ATTACHMENT_SIZE:
        raise ValueError("Topic not found or file exceeds 1.5 MB")
    transfer_id = str(uuid.uuid4())
    total = max(1, (len(payload) + ATTACHMENT_CHUNK_SIZE - 1) // ATTACHMENT_CHUNK_SIZE)
    digest = hashlib.sha256(payload).hexdigest()
    await send_event(event("file_start", {"transfer_id": transfer_id, "name": clean_name(name)[:120],
        "mime": mime[:100] or "application/octet-stream", "size": len(payload), "total": total, "sha256": digest}, topic_id))
    for index in range(total):
        chunk = payload[index * ATTACHMENT_CHUNK_SIZE:(index + 1) * ATTACHMENT_CHUNK_SIZE]
        encrypted = crypto.encrypt_attachment_chunk(topic_id, transfer_id, index, chunk)
        item = event("file_chunk", {"transfer_id": transfer_id, "index": index, "total": total}, topic_id)
        wire = crypto.encrypt(item)
        local_item = json.loads(json.dumps(item)); local_item["data"]["_chunk"] = chunk
        apply_event(local_item)
        await channel.send(wire, file=discord.File(io.BytesIO(encrypted), filename=f"{transfer_id}.{index}.silo"),
                           allowed_mentions=discord.AllowedMentions.none())
        events_sent += 1
        bytes_sent += len(wire.encode()) + len(encrypted)
    await send_event(event("file_complete", {"transfer_id": transfer_id, "sha256": digest}, topic_id))


async def maybe_finalize_clear(proposal_id: str):
    """Only the requester may emit the final signed global-clear event."""
    proposal = clear_proposals.get(proposal_id)
    if (not proposal or clear_status(proposal) != "approved"
            or proposal.get("initiator_id") != str(CONFIG["user_id"])
            or proposal_id in clear_commit_inflight):
        return
    clear_commit_inflight.add(proposal_id)
    try:
        await send_event(event("clear_commit", {"proposal_id": proposal_id}))
    finally:
        clear_commit_inflight.discard(proposal_id)


@client.event
async def on_ready():
    global channel
    guild = client.get_guild(int(CONFIG["server_id"]))
    channel = guild.get_channel(int(CONFIG["channel_id"])) if guild else None
    if channel is None:
        channel = client.get_channel(int(CONFIG["channel_id"]))
    if channel is None:
        print("[ERROR] The bot cannot access SERVER_ID/CHANNEL_ID")
        return
    participants[str(CONFIG["user_id"])] = {"name": username, "seen": time.time(), "status": local_presence_status}
    await send_event(event("presence", {"status": local_presence_status}), apply_local=False)
    await send_event(event("session_key", ratchet.announcement()), apply_local=True)
    await send_event(event("profile", {"name": username}), apply_local=True)
    print(f"[OK] Discord conectado como {client.user}")


@client.event
async def on_message(discord_message: discord.Message):
    global bad_packets, delivery_ms, events_received, bytes_received, last_visible_ids
    if client.user and discord_message.author.id == client.user.id:
        return
    if discord_message.channel.id != int(CONFIG["channel_id"]):
        return
    try:
        bytes_received += len(discord_message.content.encode())
        item = ratchet.decrypt(discord_message.content) if discord_message.content.startswith(PREFIX_V3) else crypto.decrypt(discord_message.content)
        validate_event(item)
        if item["kind"] == "file_chunk":
            if len(discord_message.attachments) != 1:
                raise ValueError("chunk without an encrypted attachment")
            encrypted_chunk = await discord_message.attachments[0].read(use_cached=True)
            data = item["data"]
            item["data"]["_chunk"] = crypto.decrypt_attachment_chunk(item["topic_id"], data["transfer_id"], int(data["index"]), encrypted_chunk)
        delivery_ms = max(0, (time.time() - datetime.fromisoformat(item["ts"]).timestamp()) * 1000)
        events_received += 1
        processed_kind = item["kind"]
        if item["kind"] == "import":
            nested = item.get("data", {}).get("event")
            validate_event(nested)
            changed = apply_event(nested)
            apply_event(item)
            processed_kind = nested["kind"]
        else:
            changed = apply_event(item)
        if changed:
            if processed_kind in {"presence", "profile"}:
                await broadcast_telemetry()
            else:
                await broadcast()
                last_visible_ids = current_visible_ids()
            if processed_kind == "clear_vote":
                proposal_id = (nested if item["kind"] == "import" else item).get("data", {}).get("proposal_id", "")
                await maybe_finalize_clear(str(proposal_id))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, InvalidTag):
        bad_packets += 1
        if bad_packets in {1, 5, 10, 25, 50}:
            security_alerts.append({"level": "warning", "message": f"{bad_packets} encrypted packets were rejected", "at": now_iso()})
            del security_alerts[:-20]


async def maintenance_loop():
    global last_visible_ids
    while True:
        await asyncio.sleep(1)
        participants[str(CONFIG["user_id"])] = {"name": username, "seen": time.time(), "status": local_presence_status}
        if channel and int(time.time()) % 10 == 0:
            try: await send_event(event("presence", {"status": local_presence_status}), apply_local=False)
            except Exception: pass
        visible_ids = current_visible_ids()
        expired_typing = [key for key, value in typing_state.items() if value["expires_at"] <= time.time()]
        for key in expired_typing:
            typing_state.pop(key, None)
        if visible_ids != last_visible_ids:
            last_visible_ids = visible_ids
            await broadcast()
        else:
            await broadcast_telemetry()
        for proposal in list(clear_proposals.values()):
            if (clear_status(proposal) == "expired" and proposal.get("initiator_id") == str(CONFIG["user_id"])
                    and proposal.get("status") not in {"cancelled", "committed"}):
                try:
                    await send_event(event("clear_cancel", {"proposal_id": proposal["id"], "reason": "Confirmation timed out"}))
                except Exception:
                    pass


async def websocket_handler(request: web.Request):
    global username, local_presence_status, messages, attachments, polls
    if not access_allowed(request):
        raise web.HTTPForbidden(text="Invalid web access token")
    ws = web.WebSocketResponse(heartbeat=20, max_msg_size=2_000_000)
    await ws.prepare(request)
    ws_clients.add(ws)
    await ws.send_str(json.dumps(public_state(), ensure_ascii=False))
    try:
        async for incoming in ws:
            if incoming.type != aiohttp.WSMsgType.TEXT:
                continue
            try:
                data = json.loads(incoming.data)
                kind = data.get("type")
                feature_for_action = {
                    "topic_create": "topics", "topic_rename": "topics", "topic_delete": "topics", "role_set": "topics",
                    "attachment": "attachments", "poll_create": "polls", "poll_vote": "polls",
                    "view_once_open": "view_once", "typing": "presence", "presence_status": "presence",
                }
                required_feature = feature_for_action.get(str(kind))
                if required_feature and not FEATURES.get(required_feature, True):
                    raise ValueError(f"{required_feature.replace('_', ' ').title()} is disabled by this client configuration")
                if kind == "panic":
                    if not FEATURES["panic"]: raise ValueError("Panic mode is disabled")
                    if not is_local_request(request): raise ValueError("Panic is restricted to the host computer")
                    await ws.send_str(json.dumps({"type": "panic", "ok": True}))
                    asyncio.create_task(panic_shutdown())
                    break
                if kind == "send":
                    text = str(data.get("content", "")).strip()
                    if not text or len(text) > MAX_TEXT: raise ValueError(f"The message must contain between 1 and {MAX_TEXT} characters")
                    topic_id = normalize_topic_id(data.get("topic_id", DEFAULT_TOPIC))
                    if topic_id not in topics: raise ValueError("Topic not found")
                    if topic_role(topic_id, str(CONFIG["user_id"])) == "read_only": raise ValueError("This topic is read-only for you")
                    ttl = max(0, min(86400, int(data.get("ttl", 0))))
                    if ttl and not FEATURES["disappearing"]: raise ValueError("Disappearing messages are disabled")
                    if bool(data.get("view_once", False)) and not FEATURES["view_once"]: raise ValueError("View-once messages are disabled")
                    await send_event(event("message", {"id": str(uuid.uuid4()), "content": text,
                        "reply_to": data.get("reply_to"), "expires_at": time.time() + ttl if ttl else None,
                        "mentions": [str(value) for value in data.get("mentions", []) if str(value).isdigit()][:20],
                        "view_once": bool(data.get("view_once", False))}, topic_id))
                elif kind == "view_once_open":
                    mid = str(data.get("id", "")); msg = messages.get(mid)
                    if not msg or not msg.get("view_once") or msg.get("opened_by") or msg.get("sender_id") == str(CONFIG["user_id"]):
                        raise ValueError("View-once message is unavailable")
                    # Capture only in process memory before the authenticated
                    # deletion event clears the shared message state.
                    reveal = {"type": "view_once_reveal", "id": mid, "content": str(msg.get("content", "")),
                              "username": str(msg.get("username", "User")), "timestamp": str(msg.get("timestamp", ""))}
                    # This plaintext travels only over the already-authorized
                    # local browser WebSocket; it is never placed on Discord.
                    # Deliver it before broadcasting deletion so a fast state
                    # refresh cannot erase the content before it is rendered.
                    await ws.send_str(json.dumps(reveal, ensure_ascii=False))
                    await send_event(event("view_once_open", {"id": mid}, msg["topic_id"]))
                elif kind == "edit":
                    mid, text = str(data.get("id", "")), str(data.get("content", "")).strip()
                    if mid not in messages or messages[mid]["sender_id"] != str(CONFIG["user_id"]): raise ValueError("You can only edit your own messages")
                    if not text or len(text) > MAX_TEXT: raise ValueError("Invalid edited text")
                    await send_event(event("edit", {"id": mid, "content": text}, messages[mid]["topic_id"]))
                elif kind == "delete":
                    mid = str(data.get("id", ""))
                    if mid not in messages or messages[mid]["sender_id"] != str(CONFIG["user_id"]): raise ValueError("You can only delete your own messages")
                    await send_event(event("delete", {"id": mid}, messages[mid]["topic_id"]))
                elif kind in {"pin", "highlight"}:
                    mid = str(data.get("id", ""))
                    if mid not in messages: raise ValueError("Message not found")
                    await send_event(event(kind, {"id": mid, "state": bool(data.get("state"))}, messages[mid]["topic_id"]))
                elif kind == "topic_create":
                    topic_id = normalize_topic_id(data.get("topic_id", ""))
                    if topic_id in topics: raise ValueError("That topic_id already exists")
                    if len(topics) >= 20: raise ValueError("A room can contain at most 20 topics")
                    await send_event(event("topic_create", {"name": clean_name(data.get("name", ""))}, topic_id))
                elif kind == "topic_rename":
                    topic_id = normalize_topic_id(data.get("topic_id", "")); topic = topics.get(topic_id)
                    if not topic or topic_id == DEFAULT_TOPIC: raise ValueError("Topic cannot be renamed")
                    if str(topic.get("created_by")) != str(CONFIG["user_id"]): raise ValueError("Only the topic creator can rename it")
                    name = clean_name(data.get("name", ""))
                    if not name: raise ValueError("Topic name cannot be empty")
                    await send_event(event("topic_rename", {"name": name}, topic_id))
                elif kind == "topic_delete":
                    topic_id = normalize_topic_id(data.get("topic_id", ""))
                    if topic_id == DEFAULT_TOPIC: raise ValueError("The default topic cannot be deleted")
                    if topic_id not in topics: raise ValueError("Topic not found")
                    if str(topics[topic_id].get("created_by")) != str(CONFIG["user_id"]): raise ValueError("Only the topic creator can delete it")
                    await send_event(event("topic_delete", {}, topic_id))
                elif kind == "role_set":
                    topic_id = normalize_topic_id(data.get("topic_id", ""))
                    if topic_id == DEFAULT_TOPIC or topic_id not in topics or str(topics[topic_id].get("created_by")) != str(CONFIG["user_id"]): raise ValueError("Only the topic creator can change permissions")
                    await send_event(event("role_set", {"user_id": str(data.get("user_id", "")), "role": str(data.get("role", ""))}, topic_id))
                elif kind == "reaction":
                    mid = str(data.get("id", "")); emoji = str(data.get("emoji", ""))
                    if mid not in messages: raise ValueError("Message not found")
                    await send_event(event("reaction", {"id": mid, "emoji": emoji}, messages[mid]["topic_id"]))
                elif kind == "receipt" and READ_RECEIPTS_ENABLED:
                    mid = str(data.get("id", "")); state = str(data.get("state", "read"))
                    if mid in messages: await send_event(event("receipt", {"id": mid, "state": state}, messages[mid]["topic_id"]))
                elif kind == "poll_create":
                    topic_id = normalize_topic_id(data.get("topic_id", DEFAULT_TOPIC)); options = data.get("options", [])
                    await send_event(event("poll_create", {"id": str(uuid.uuid4()), "question": str(data.get("question", "")), "options": options}, topic_id))
                elif kind == "poll_vote":
                    poll = polls.get(str(data.get("id", "")))
                    if not poll: raise ValueError("Poll not found")
                    await send_event(event("poll_vote", {"id": poll["id"], "option": int(data.get("option", -1))}, poll["topic_id"]))
                elif kind == "clear_local":
                    scope = str(data.get("scope", "expired")); topic_id = str(data.get("topic_id", ""))
                    if scope == "topic" and topic_id: messages = {k:v for k,v in messages.items() if v.get("topic_id") != topic_id}
                    elif scope == "attachments": attachments.clear()
                    elif scope == "expired": messages = {k:v for k,v in messages.items() if not v.get("expires_at") or float(v["expires_at"]) > time.time()}
                    elif scope == "all": messages.clear(); attachments.clear(); polls.clear()
                    save_history(); await broadcast()
                elif kind == "typing":
                    topic_id = normalize_topic_id(data.get("topic_id", DEFAULT_TOPIC))
                    if topic_id not in topics: raise ValueError("Topic not found")
                    now = time.monotonic()
                    if now - typing_last_sent.get(topic_id, 0) >= TYPING_RATE_LIMIT:
                        typing_last_sent[topic_id] = now
                        await send_event(event("typing", {"expires_at": time.time() + TYPING_TTL}, topic_id))
                elif kind == "presence_status":
                    status = str(data.get("status", "online"))
                    if status not in {"online", "idle", "away"}: raise ValueError("Invalid status")
                    if status != local_presence_status:
                        local_presence_status = status
                        participants[str(CONFIG["user_id"])] = {"name": username, "seen": time.time(), "status": status}
                        await send_event(event("presence", {"status": status}), apply_local=False)
                        await broadcast_telemetry()
                elif kind == "attachment":
                    if not FEATURES["attachments"]: raise ValueError("Attachments are disabled")
                    topic_id = normalize_topic_id(data.get("topic_id", DEFAULT_TOPIC))
                    try: payload = base64.b64decode(str(data.get("content", "")), validate=True)
                    except Exception: raise ValueError("Incorrectly encoded file") from None
                    await send_attachment(topic_id, str(data.get("name", "file")), str(data.get("mime", "application/octet-stream")), payload)
                elif kind == "set_username":
                    username = clean_name(data.get("username", ""))
                    await send_event(event("profile", {"name": username}))
                elif kind == "clear_request":
                    active_ids = {str(uid) for uid, participant in participants.items()
                                  if time.time() - float(participant.get("seen", 0)) < 95}
                    active_ids.add(str(CONFIG["user_id"]))
                    if any(clear_status(proposal) in {"pending", "approved"} for proposal in clear_proposals.values()):
                        raise ValueError("A deletion request is already awaiting decisions")
                    proposal_id = str(uuid.uuid4())
                    await send_event(event("clear_request", {"proposal_id": proposal_id,
                        "target_ids": sorted(active_ids, key=int), "expires_at": time.time() + 90}))
                    # The requester explicitly consents by starting the proposal.
                    await send_event(event("clear_vote", {"proposal_id": proposal_id, "accept": True}))
                elif kind == "clear_vote":
                    proposal_id = str(data.get("proposal_id", ""))
                    proposal = clear_proposals.get(proposal_id)
                    if not proposal or str(CONFIG["user_id"]) not in proposal.get("target_ids", []):
                        raise ValueError("The deletion request is no longer valid for this user")
                    if clear_status(proposal) not in {"pending", "approved"}:
                        raise ValueError("The deletion request has already ended")
                    if str(CONFIG["user_id"]) in proposal.get("votes", {}):
                        raise ValueError("You have already responded to this request")
                    await send_event(event("clear_vote", {"proposal_id": proposal_id, "accept": bool(data.get("accept"))}))
                elif kind == "import":
                    imported = data.get("events", [])
                    if not isinstance(imported, list) or len(imported) > 5000: raise ValueError("Invalid or oversized import")
                    count = 0
                    for original in imported:
                        validate_event(original)
                        if apply_event(original):
                            count += 1
                            await send_event(event("import", {"event": original}), apply_local=False)
                    await ws.send_str(json.dumps({"type": "notice", "message": f"{count} events imported and synchronized"}))
                    await broadcast()
                elif kind == "export":
                    exported = [item for item in event_log.values() if item.get("kind") not in {"presence", "import"}]
                    password = str(data.get("password", ""))
                    blob = await asyncio.get_running_loop().run_in_executor(None, encrypted_export, password, {"format": PROTOCOL, "events": exported})
                    await ws.send_str(json.dumps({"type": "export", "format": "silo-encrypted-v1", "blob": blob}, ensure_ascii=False))
            except Exception as exc:
                await ws.send_str(json.dumps({"type": "error", "message": str(exc)}))
    finally:
        ws_clients.discard(ws)
    return ws


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Silo Client</title><style>
*{box-sizing:border-box} :root{--bg:#05070c;--panel:rgba(15,21,33,.78);--card:#141d2b;--line:#27354a;--text:#edf2fb;--muted:#8c9aaf;--a:#6e7cff;--b:#a855f7;--ok:#55d6a8;--danger:#ff607a;--gold:#f5c66b}
html,body{height:100%;margin:0;font:14px Inter,Segoe UI,sans-serif;background:var(--bg);color:var(--text);overflow:hidden}.aurora{position:fixed;inset:-40%;background:radial-gradient(circle at 25% 35%,#4f46e544,transparent 30%),radial-gradient(circle at 75% 65%,#a855f73d,transparent 28%),radial-gradient(circle at 50% 90%,#06b6d422,transparent 24%);filter:blur(65px);animation:drift 14s ease-in-out infinite alternate}@keyframes drift{50%{transform:rotate(-7deg) scale(1.06) translate(2%,1%)}to{transform:rotate(12deg) scale(1.14) translate(-2%,-1%)}}.gridfx{position:fixed;inset:0;opacity:.12;background-image:linear-gradient(#ffffff08 1px,transparent 1px),linear-gradient(90deg,#ffffff08 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(circle at 50% 50%,#000,transparent 82%);animation:gridmove 18s linear infinite}@keyframes gridmove{to{background-position:44px 44px}}.grain{position:fixed;inset:0;pointer-events:none;opacity:.025;background:url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
.app{position:relative;display:grid;grid-template-columns:290px 1fr 330px;height:100%;backdrop-filter:blur(22px);animation:reveal .7s cubic-bezier(.2,.8,.2,1)}@keyframes reveal{from{opacity:0;transform:scale(.985);filter:blur(8px)}}aside{background:var(--panel);border-right:1px solid var(--line);padding:22px;overflow:auto}.right{border-left:1px solid var(--line);border-right:0}.logo{display:flex;gap:12px;align-items:center;margin-bottom:22px}.mark{position:relative;display:grid;place-items:center;width:44px;height:44px;border-radius:13px;background:linear-gradient(135deg,var(--a),var(--b));font-weight:900;font-size:20px;box-shadow:0 0 25px #6e7cff66;animation:logoFloat 4s ease-in-out infinite}.mark:after{content:"";position:absolute;inset:-5px;border:1px solid #8993ff55;border-radius:17px;animation:ring 2.4s ease-out infinite}@keyframes logoFloat{50%{transform:translateY(-3px) rotate(3deg);box-shadow:0 9px 35px #6e7cff88}}@keyframes ring{to{inset:-14px;opacity:0;border-radius:24px}}.logo b{font-size:19px}.logo small{display:block;color:var(--muted);margin-top:2px}.box{position:relative;background:linear-gradient(145deg,#ffffff08,#ffffff03);border:1px solid var(--line);border-radius:15px;padding:14px;margin:12px 0;overflow:hidden;transition:.3s ease}.box:before{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 25%,#ffffff08 48%,transparent 70%);transform:translateX(-120%);transition:.7s}.box:hover{transform:translateY(-2px);border-color:#6e7cff66;box-shadow:0 12px 35px #0004}.box:hover:before{transform:translateX(120%)}.box h3{font-size:10px;letter-spacing:1.3px;color:var(--muted);margin:0 0 10px}.row{display:flex;justify-content:space-between;gap:8px;margin:7px 0;font-size:12px}.row span:first-child{color:var(--muted)}.mono{font-family:Consolas,monospace}.online{color:var(--ok);text-shadow:0 0 10px #55d6a888}button,input,select,textarea{font:inherit}button{border:0;cursor:pointer;transition:transform .2s,filter .2s}button:active{transform:scale(.96)}.action{width:100%;padding:10px;margin-top:8px;border-radius:9px;color:var(--text);background:var(--card);border:1px solid var(--line)}.action:hover{border-color:var(--a);filter:brightness(1.2);transform:translateX(3px)}input,textarea,select{color:var(--text);background:#080c13;border:1px solid var(--line);outline:0;transition:.25s}.name-row{display:flex;gap:7px}.name-row input{width:100%;padding:9px;border-radius:8px}.name-row input:focus,textarea:focus{border-color:var(--a);box-shadow:0 0 0 3px #6e7cff18}.name-row button{padding:0 11px;border-radius:8px;background:var(--a);color:#fff}
main{min-width:0;display:flex;flex-direction:column}.header{height:72px;display:flex;align-items:center;justify-content:space-between;padding:0 22px;background:var(--panel);border-bottom:1px solid var(--line)}.room-title b{font-size:16px}.room-title small{display:block;color:var(--muted);margin-top:4px}.secure{display:inline-flex;align-items:center;gap:7px;padding:6px 10px;margin-left:10px;border-radius:99px;background:#55d6a811;border:1px solid #55d6a833;color:var(--ok);font-size:10px}.secure i{width:6px;height:6px;border-radius:50%;background:var(--ok);box-shadow:0 0 10px var(--ok);animation:blink 1.8s infinite}@keyframes blink{50%{opacity:.35}}.people{display:flex}.avatar{width:32px;height:32px;border-radius:50%;margin-left:-7px;display:grid;place-items:center;background:linear-gradient(135deg,var(--a),var(--b));border:2px solid #101722;font-weight:bold;transition:.25s;animation:pop .35s ease}.avatar:hover{transform:translateY(-4px) scale(1.1);z-index:2}@keyframes pop{from{transform:scale(0)}}.pins{display:none;padding:10px 20px;background:#6e7cff10;border-bottom:1px solid var(--line);color:var(--muted);cursor:pointer;animation:slideDown .3s ease}@keyframes slideDown{from{transform:translateY(-100%);opacity:0}}.messages{flex:1;overflow:auto;padding:22px;display:flex;flex-direction:column;gap:14px;scroll-behavior:smooth}.messages::-webkit-scrollbar,aside::-webkit-scrollbar{width:6px}.messages::-webkit-scrollbar-thumb,aside::-webkit-scrollbar-thumb{background:#ffffff1c;border-radius:5px}.msg{max-width:72%;animation:up .38s cubic-bezier(.2,.9,.2,1);transition:opacity .32s,transform .38s cubic-bezier(.2,.8,.2,1),filter .32s}.msg.mine{align-self:flex-end}.sender{font-size:11px;color:var(--muted);margin:0 7px 5px}.mine .sender{text-align:right}.bubble{position:relative;padding:12px 15px;border-radius:17px;background:var(--card);border:1px solid var(--line);line-height:1.45;word-break:break-word;cursor:pointer;transition:.25s}.bubble:hover{transform:translateY(-2px);box-shadow:0 10px 25px #0005;border-color:#6e7cff66}.mine .bubble{background:linear-gradient(135deg,#5865e8,#8549c7);border:0;background-size:180% 180%;animation:gradflow 7s ease infinite}.highlight .bubble{box-shadow:0 0 24px #ec489955;border-color:#ec4899;animation:starPulse 2.6s ease-in-out infinite}.deleted .bubble{color:var(--muted);font-style:italic}.quote{padding:7px 9px;margin-bottom:8px;border-left:3px solid #ffffff88;background:#00000025;border-radius:5px;font-size:11px;opacity:.9;transition:.2s}.quote:hover{background:#00000040}.meta{font-size:9px;opacity:.65;margin-top:7px;text-align:right}.badge{padding:2px 5px;border-radius:4px;background:#0003;margin-right:4px}@keyframes up{from{opacity:0;transform:translateY(18px) scale(.96)}}@keyframes gradflow{50%{background-position:100% 50%}}@keyframes starPulse{50%{box-shadow:0 0 38px #ec489977}}
.replybar{display:none;padding:10px 18px;background:#6e7cff12;border-top:1px solid var(--line);color:var(--muted);animation:slideDown .25s reverse}.replybar b{color:#aeb7ff}.replybar button{float:right;background:none;color:var(--danger)}.composer{padding:13px 18px 18px;background:var(--panel);border-top:1px solid var(--line)}.tools{display:flex;gap:10px;align-items:center;color:var(--muted);font-size:11px;margin-bottom:9px}.tools select{padding:4px;border-radius:6px}.write{display:flex;gap:10px}.write textarea{flex:1;resize:none;border-radius:15px;padding:12px;max-height:120px}.send{width:46px;border-radius:14px;color:#fff;background:linear-gradient(135deg,var(--a),var(--b));font-size:18px;box-shadow:0 5px 20px #6e7cff44}.send:hover{transform:translateY(-3px) rotate(-4deg);box-shadow:0 10px 30px #6e7cff77}.ctx{display:none;position:fixed;z-index:8;min-width:160px;padding:6px;background:#0b1019dd;backdrop-filter:blur(18px);border:1px solid var(--line);border-radius:11px;box-shadow:0 15px 50px #000a;animation:ctxIn .18s ease}@keyframes ctxIn{from{opacity:0;transform:scale(.9) translateY(-5px)}}.ctx button{display:block;width:100%;text-align:left;padding:9px;border-radius:6px;color:var(--text);background:none}.ctx button:hover{background:var(--card);transform:translateX(3px)}.ctx .danger{color:var(--danger)}.stat-group{font-size:10px;color:#aeb7ff;letter-spacing:1.4px;margin:18px 0 5px;padding-bottom:6px;border-bottom:1px solid #6e7cff33}.stat{padding:7px 0}.stat-head{display:flex;justify-content:space-between;gap:8px}.stat span{color:var(--muted);font-size:9px}.stat b{font:11px Consolas,monospace;text-align:right}.meter{height:3px;margin-top:5px;background:#ffffff0a;border-radius:9px;overflow:hidden}.meter i{display:block;height:100%;border-radius:9px;background:linear-gradient(90deg,var(--a),var(--b),#ec4899);transition:width .8s cubic-bezier(.2,.8,.2,1)}.toast{position:fixed;z-index:20;right:24px;bottom:24px;padding:12px 17px;border-radius:10px;background:#182236dd;backdrop-filter:blur(12px);border:1px solid var(--line);transform:translateY(90px);opacity:0;transition:.35s cubic-bezier(.2,.8,.2,1)}.toast.show{transform:none;opacity:1}@media(max-width:1050px){.app{grid-template-columns:240px 1fr}.right{display:none}}@media(max-width:700px){.app{display:block}.left{display:none}main{height:100%}.msg{max-width:88%}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
.msg.fresh{opacity:0;transform:translateY(18px) scale(.92);filter:blur(4px)}.msg.fresh.mine{transform:translate(22px,12px) scale(.9)}.msg.fresh:not(.mine){transform:translate(-22px,12px) scale(.9)}.msg.changed .bubble{animation:messageChanged .65s cubic-bezier(.2,.8,.2,1)}.msg.vanish{pointer-events:none;animation:messageVanish .32s ease forwards}.msg.spark .bubble:after{content:"✦";position:absolute;right:-9px;top:-12px;color:#f9a8d4;font-size:18px;animation:sparkFly .7s ease-out forwards}.msg.soft-delete .bubble{animation:softDelete .6s ease}.send.sending{animation:sendLaunch .45s cubic-bezier(.2,.8,.2,1)}.replybar.open{display:block;animation:replyOpen .3s cubic-bezier(.2,.8,.2,1)}
@keyframes messageChanged{0%{transform:scale(.98)}35%{box-shadow:0 0 0 4px #6e7cff25,0 8px 30px #0005}100%{transform:none}}@keyframes messageVanish{to{opacity:0;transform:scale(.88) translateY(-12px);filter:blur(6px)}}@keyframes sparkFly{to{transform:translate(15px,-24px) rotate(100deg) scale(.3);opacity:0}}@keyframes softDelete{30%{filter:blur(3px);transform:scale(.97)}100%{filter:none}}@keyframes sendLaunch{45%{transform:translate(8px,-8px) rotate(-18deg) scale(1.12)}100%{transform:none}}@keyframes replyOpen{from{opacity:0;transform:translateY(12px)}}
/* Stable viewport: only the message list scrolls; headers and composer never leave the screen. */
html,body{width:100%;height:100%;height:100dvh;min-height:0;overflow:hidden}.app{height:var(--silo-vh,100dvh);max-height:var(--silo-vh,100dvh);min-height:0;grid-template-rows:minmax(0,1fr);overflow:hidden}aside,main,.chat-view{height:100%;min-height:0;max-height:100%;overflow:hidden}aside{overflow-y:auto;overscroll-behavior:contain}main{display:flex;flex-direction:column}.header,.pins,.replybar,.composer{flex:0 0 auto}.messages{flex:1 1 0;min-height:0;max-height:none;overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain;scrollbar-gutter:stable;contain:layout paint}.composer{position:relative;z-index:5;padding-bottom:max(18px,env(safe-area-inset-bottom));box-shadow:0 -14px 35px #05070c55}.write{min-width:0}.write textarea{min-width:0;max-height:min(120px,20vh)}.new-messages{position:absolute;z-index:7;right:24px;bottom:104px;display:none;align-items:center;gap:7px;padding:9px 13px;border-radius:99px;color:#fff;background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 10px 30px #6e7cff66;animation:newNotice .3s ease}.new-messages.show{display:flex}@keyframes newNotice{from{opacity:0;transform:translateY(12px) scale(.9)}}
@media(max-height:680px){.header{height:58px}.messages{padding:14px;gap:10px}.composer{padding:9px 14px 11px}.tools{margin-bottom:5px}.write textarea{padding:9px;max-height:70px}.logo{margin-bottom:12px}.box{margin:8px 0;padding:10px}aside{padding:14px}}
@media(max-width:700px){.app{height:var(--silo-vh,100dvh);max-height:var(--silo-vh,100dvh)}main{height:100%;min-height:0}.header{padding:0 14px}.messages{padding:14px}.composer{padding:10px 12px max(12px,env(safe-area-inset-bottom))}.secure{display:none}.new-messages{right:14px;bottom:94px}}
/* Definitive layout contract: fixed viewport + an independent composer row. */
.app{position:fixed!important;inset:0 auto auto 0!important;width:100vw!important;height:var(--silo-vh,100dvh)!important;max-height:var(--silo-vh,100dvh)!important;min-height:0!important;overflow:hidden!important}
main{position:relative!important;display:grid!important;grid-template-columns:minmax(0,1fr)!important;grid-template-rows:auto auto auto minmax(0,1fr) auto auto auto!important;height:100%!important;min-height:0!important;max-height:100%!important;overflow:hidden!important}
.header{grid-row:1}.topicbar{grid-row:2;display:flex;gap:7px;padding:8px 14px;overflow-x:auto;border-bottom:1px solid var(--line);background:#080c13}.topic{padding:7px 11px;border:1px solid var(--line);border-radius:99px;color:var(--muted);white-space:nowrap}.topic.active{color:#fff;border-color:var(--a);background:#6e7cff22}.topic-add{color:var(--ok)}.pins{grid-row:3}.messages{grid-row:4!important;width:100%;height:auto!important;min-height:0!important;max-height:100%!important;overflow-y:auto!important;overflow-x:hidden!important}.typing{grid-row:5;min-height:22px;padding:2px 18px;color:var(--muted);font-size:11px}.replybar{grid-row:6}.composer{grid-row:7!important;position:relative!important;inset:auto!important;width:100%!important;min-height:0;overflow:visible;transform:none!important}.new-messages{grid-row:4;align-self:end;justify-self:end}
.file-card{margin-top:8px;padding:10px;border:1px solid #ffffff18;border-radius:10px;background:#0003}.file-card b,.file-card small{display:block}.file-card small{margin:4px 0;color:var(--muted)}.file-card a{margin-right:10px;color:#bdc5ff}.preview{display:block;max-width:min(360px,100%);max-height:260px;margin-top:8px;border-radius:8px}
.qr-wrap{display:flex;align-items:center;gap:11px}.qr-wrap img{width:82px;height:82px;padding:6px;border-radius:12px;background:#fff;box-shadow:0 8px 24px #0005;transition:.3s}.qr-wrap img:hover{transform:scale(1.06) rotate(2deg);box-shadow:0 12px 32px #6e7cff44}.qr-wrap b{display:block;font-size:11px}.qr-wrap small{display:block;margin-top:5px;color:var(--muted);font-size:10px}.mobile-link{margin-top:10px;padding:8px;border:1px solid var(--line);border-radius:8px;background:#080c13;color:var(--muted);font:9px Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.mobile-mode{display:none}
.mobile-protection{border-color:#6e7cff55}.mobile-protection .protect-status{margin:0 0 9px;color:var(--ok);font-size:11px}.mobile-protection small{display:block;margin-top:8px;color:var(--muted);font-size:10px;line-height:1.4}.pw-input{width:100%;padding:9px;margin-top:7px;border-radius:8px}.pw-input::placeholder{color:#71809a}
.clear-request{margin-left:auto;margin-right:10px;padding:8px 10px;border-radius:9px;color:#ffb1bd;background:#ff607a12;border:1px solid #ff607a44;font-size:11px}.clear-request:hover{background:#ff607a24;border-color:#ff607a}.clear-request:disabled{opacity:.45;cursor:not-allowed;transform:none}.clear-modal{display:none;position:fixed;z-index:30;inset:0;place-items:center;padding:18px;background:#03050bb8;backdrop-filter:blur(8px)}.clear-modal.show{display:grid;animation:fadeIn .22s ease}.clear-dialog{width:min(92vw,420px);padding:25px;border:1px solid #ff607a55;border-radius:19px;background:linear-gradient(145deg,#1b1624,#101722);box-shadow:0 28px 80px #000b;animation:dialogIn .28s cubic-bezier(.2,.8,.2,1)}.clear-dialog h2{margin:0 0 9px;font-size:20px}.clear-dialog p{color:var(--muted);line-height:1.45}.clear-progress{margin:15px 0;padding:10px;border-radius:10px;background:#ffffff08;color:#dce5f5;font-size:12px}.clear-actions{display:flex;gap:10px}.clear-actions button{flex:1;padding:12px;border-radius:10px;font-weight:700}.clear-accept{color:#fff;background:#336f5f}.clear-reject{color:#fff;background:#843448}@keyframes fadeIn{from{opacity:0}}@keyframes dialogIn{from{opacity:0;transform:translateY(18px) scale(.94)}}
@media(max-width:700px){.room-title b{font-size:14px}.room-title small{font-size:10px}.people .avatar{width:28px;height:28px}.tools{overflow-x:auto;white-space:nowrap}.write textarea{font-size:16px}.send{flex:0 0 46px}.msg{max-width:91%}.bubble{font-size:14px}.mobile-mode{display:inline;color:var(--ok);font-size:9px;margin-left:6px}}
/* Obsidian UI: true-black foundation, restrained glass and consistent controls. */
:root{--bg:#000;--panel:rgba(7,7,9,.94);--card:#101014;--line:#24242b;--text:#f5f5f7;--muted:#9898a2;--a:#7c6cff;--b:#a855f7;--ok:#48d7a0}
html,body{background:#000}.aurora{opacity:.34;background:radial-gradient(circle at 54% 15%,#4834d433,transparent 31%),radial-gradient(circle at 86% 82%,#7c3aed20,transparent 27%);filter:blur(90px)}.gridfx{opacity:.045}.grain{opacity:.018}
.app{background:#000;backdrop-filter:none}aside,.header,.composer{background:rgba(5,5,7,.96);border-color:#1c1c22}.box{background:#09090c;border-color:#202027;box-shadow:inset 0 1px #ffffff05}.box:hover{border-color:#34343e;box-shadow:0 14px 38px #000,inset 0 1px #ffffff08}.mark{background:linear-gradient(145deg,#29243f,#0d0d12);border:1px solid #51477c;box-shadow:0 8px 30px #000,0 0 24px #6e5cff22}.mark:after{display:none}
.header{box-shadow:0 1px #000}.topicbar{gap:8px;padding:10px 16px;background:#030304;border-color:#1c1c22;scrollbar-width:none}.topicbar::-webkit-scrollbar{display:none}.topic{display:inline-flex;align-items:center;gap:7px;min-height:34px;padding:7px 13px;border:1px solid #26262e;border-radius:10px;color:#a7a7b0;background:#0b0b0e;font-weight:600;letter-spacing:.01em}.topic:before{content:"#";color:#5f5f69}.topic:hover{color:#fff;border-color:#4b465f;background:#121218;transform:translateY(-1px)}.topic.active{color:#fff;border-color:#675cba;background:linear-gradient(145deg,#211d36,#111117);box-shadow:inset 0 1px #ffffff0a,0 6px 20px #000}.topic.active:before{color:#9e91ff}.topic-add{margin-left:4px;color:#d7d3ff;border-style:dashed;border-color:#4a4369;background:#121019}.topic-add:before{content:"＋";color:#a99eff}.topic-add:hover{border-color:#8175d4;background:#1b1729}
.messages{background:linear-gradient(180deg,#010102,#050507);padding:24px}.bubble{background:#111115;border-color:#24242b;box-shadow:0 8px 22px #0007}.bubble:hover{border-color:#393943;box-shadow:0 12px 30px #000}.mine .bubble{background:linear-gradient(145deg,#41388b,#29235e);border:1px solid #5e53aa;box-shadow:0 10px 28px #0009}.file-card{padding:12px;border-color:#2d2d35;background:#0b0b0e;box-shadow:inset 0 1px #ffffff06}.file-card a{display:inline-flex;margin-top:7px;padding:6px 9px;border-radius:7px;color:#d8d3ff;background:#1b1827;text-decoration:none}.file-card a:hover{background:#29233f}
.composer{padding-top:11px;box-shadow:0 -18px 45px #000}.tools{gap:8px;margin-bottom:10px}.tools label{display:flex;align-items:center;gap:6px;padding:7px 10px;border:1px solid #24242b;border-radius:9px;background:#0b0b0e}.tools select{min-height:32px;padding:5px 9px;border-color:#292932;background:#0b0b0e}.tool-button{display:inline-flex;align-items:center;gap:8px;min-height:34px;padding:7px 12px;border:1px solid #353044;border-radius:9px;color:#e6e2ff;background:linear-gradient(145deg,#191622,#0d0d11);font-weight:650}.tool-button:hover{border-color:#7065b7;background:#211c31;transform:translateY(-1px)}.tool-button svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.8}.write{padding:4px;border:1px solid #24242c;border-radius:17px;background:#0a0a0d;transition:.25s}.write:focus-within{border-color:#5b528d;box-shadow:0 0 0 3px #7568d112}.write textarea{border:0;background:transparent;box-shadow:none!important}.send{width:44px;margin:2px;border-radius:13px;background:linear-gradient(145deg,#7768df,#4d429a);box-shadow:0 8px 22px #000}.send:hover{transform:translateY(-2px);box-shadow:0 12px 26px #000,0 0 18px #7467d833}
.typing{display:flex;align-items:center;min-height:32px;padding:4px 20px;background:#050507;color:#aaaab3}.typing-indicator{display:inline-flex;align-items:center;gap:8px;animation:typingIn .2s ease}.typing-bubble{display:inline-flex;align-items:center;gap:3px;padding:8px 10px;border:1px solid #282830;border-radius:12px 12px 12px 4px;background:#111115;box-shadow:0 6px 18px #000}.typing-dot{width:5px;height:5px;border-radius:50%;background:#aaa6c7;animation:typingDot 1.25s ease-in-out infinite}.typing-dot:nth-child(2){animation-delay:.16s}.typing-dot:nth-child(3){animation-delay:.32s}.typing-name{font-size:10px;color:#85858f}.typing-name b{color:#c8c5da;font-weight:600}@keyframes typingDot{0%,60%,100%{transform:translateY(0);opacity:.35}30%{transform:translateY(-4px);opacity:1}}@keyframes typingIn{from{opacity:0;transform:translateY(4px)}}
.action,.clear-request,.ctx button,.clear-actions button{font-weight:600}.toast{background:#0c0c10f2;border-color:#303039;box-shadow:0 20px 55px #000}.ctx{background:#09090cf2;border-color:#2a2a32}.clear-dialog{background:#09090d;border-color:#49313a}
.header{overflow:hidden}.header-actions{display:flex;align-items:center;gap:9px;margin-left:auto;min-width:0}.people{flex:0 0 auto;max-width:190px;overflow:hidden}.icon-button{display:inline-flex;align-items:center;gap:7px;min-height:36px;padding:8px 11px;border:1px solid #292932;border-radius:10px;color:#d6d6dc;background:#0b0b0e}.icon-button:hover{color:#fff;border-color:#4f496b;background:#15131c}.icon-button svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:2}.presence-list{display:grid;gap:3px;min-width:0;overflow:hidden}.presence-row{display:grid;grid-template-columns:8px minmax(0,1fr);gap:9px;align-items:center;min-width:0;padding:6px 0}.presence-dot{display:block!important;position:static!important;width:8px!important;height:8px!important;min-width:8px;border-radius:50%;background:#555;box-shadow:none}.presence-dot.online{background:#48d7a0;box-shadow:0 0 8px #48d7a077}.presence-dot.typing{background:#7c6cff;animation:blink 1s infinite}.presence-dot.idle{background:#f1c75b}.presence-dot.away{background:#e58a4b}.presence-dot.offline{background:#555}.presence-user{min-width:0}.presence-user b,.presence-user small{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.presence-user b{font-size:11px}.presence-user small{margin-top:2px;color:var(--muted);font-size:9px}.topic-wrap{display:inline-flex;align-items:center;border:1px solid #26262e;border-radius:10px;background:#0b0b0e}.topic-wrap .topic{border:0;background:transparent}.topic-remove{width:28px;height:28px;margin-right:3px;border-radius:7px;color:#777;background:transparent}.topic-remove:hover{color:#ff7188;background:#ff607a16}.topic-wrap:has(.topic.active){border-color:#675cba;background:linear-gradient(145deg,#211d36,#111117)}
.search-panel{display:none;position:fixed;z-index:25;inset:0;place-items:start center;padding:8vh 18px;background:#000b;backdrop-filter:blur(12px)}.search-panel.show{display:grid;animation:fadeIn .18s ease}.search-dialog{width:min(760px,96vw);max-height:82vh;display:grid;grid-template-rows:auto auto minmax(0,1fr);overflow:hidden;border:1px solid #303039;border-radius:18px;background:#08080b;box-shadow:0 30px 100px #000}.search-head{display:flex;align-items:center;gap:10px;padding:15px;border-bottom:1px solid #222229}.search-head input{flex:1;padding:11px 13px;border-radius:11px;background:#101014}.search-head button{width:34px;height:34px;border-radius:9px;color:var(--muted);background:#15151a}.search-filters{display:flex;flex-wrap:wrap;gap:8px;padding:11px 15px;border-bottom:1px solid #1c1c22}.search-filters input,.search-filters select{min-height:32px;padding:6px 9px;border-radius:8px;background:#0d0d11}.search-filters label{display:flex;align-items:center;gap:5px;padding:5px 8px;border:1px solid #25252c;border-radius:8px;color:var(--muted);font-size:10px}.search-results{overflow:auto;padding:12px}.search-count{padding:4px 5px 10px;color:var(--muted);font-size:11px}.search-result{display:block;width:100%;padding:12px;margin-bottom:7px;text-align:left;border:1px solid #202027;border-radius:11px;color:var(--text);background:#0d0d11}.search-result:hover{border-color:#51496f;background:#15131d;transform:translateY(-1px)}.search-result b,.search-result small,.search-result span{display:block}.search-result small{margin:3px 0 7px;color:#777780}.search-result span{color:#c8c8ce;line-height:1.4}.search-hit{animation:searchHit 1.5s ease}.search-hit .bubble{box-shadow:0 0 0 2px #8f82ff,0 0 35px #6e5cff55}@keyframes searchHit{50%{transform:scale(1.025)}}
.expiry{margin-top:10px;padding-top:8px;border-top:1px solid #ffffff16}.expiry-head{display:flex;justify-content:space-between;gap:12px;color:#d9d6e8;font-size:9px}.expiry-time{font:700 12px Consolas,monospace}.expiry-track{height:4px;margin-top:6px;overflow:hidden;border-radius:9px;background:#0005}.expiry-track i{display:block;height:100%;border-radius:9px;background:linear-gradient(90deg,#ff6b81,#f2a65a);transition:width 1s linear}.expiry.hot .expiry-time{color:#ff8495}.expiry.hot .expiry-track i{animation:expiryPulse .8s infinite}@keyframes expiryPulse{50%{filter:brightness(1.55)}}
.security-center{margin-top:8px}.security-title{display:flex;align-items:center;gap:8px;margin-bottom:11px;color:#ddd9ff;font-size:10px;letter-spacing:1.3px}.security-title:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 10px #48d7a077}.security-item{display:grid;grid-template-columns:8px 1fr;gap:9px;padding:9px 0;border-bottom:1px solid #19191f}.security-item:last-child{border:0}.security-item i{width:7px;height:7px;margin-top:4px;border-radius:50%;background:var(--ok)}.security-item span,.security-item b{display:block}.security-item span{color:var(--muted);font-size:9px}.security-item b{margin-top:3px;font:10px Consolas,monospace;word-break:break-word}.security-verified{display:inline-flex;margin-top:9px;padding:6px 9px;border:1px solid #285743;border-radius:8px;color:#66e3b2;background:#0b1b15;font-size:9px;font-weight:700}
.message-text strong{font-weight:750;color:#fff}.message-text em{color:#ddd9ef}.message-text code{padding:2px 5px;border:1px solid #ffffff12;border-radius:5px;background:#0007;color:#c9c2ff;font:12px Consolas,monospace}.message-text pre{position:relative;margin:9px 0 2px;padding:28px 12px 12px;overflow:auto;border:1px solid #292933;border-radius:10px;background:#050507;color:#d9d9e0;font:12px/1.55 Consolas,monospace}.message-text pre:before{content:attr(data-lang);position:absolute;top:7px;left:11px;color:#73737e;font-size:9px;text-transform:uppercase}.message-text pre code{padding:0;border:0;background:none;color:inherit}.message-text blockquote{margin:7px 0;padding:7px 10px;border-left:3px solid var(--a);border-radius:0 7px 7px 0;background:#ffffff08;color:#c8c8d0}.message-text ul{margin:7px 0;padding-left:21px}.message-text li{margin:3px 0}
.appearance-grid{display:grid;gap:9px}.appearance-grid label{color:var(--muted);font-size:9px}.appearance-grid select{width:100%;margin-top:4px;padding:8px;border-radius:8px}.custom-colors{display:none;grid-template-columns:repeat(3,1fr);gap:7px}.custom-colors.show{display:grid}#accentColors{grid-template-columns:repeat(2,1fr)}.color-field{display:grid;gap:3px;color:var(--muted);font-size:8px}.color-field input{width:100%;height:30px;padding:2px;border-radius:7px}.accent-preview{height:4px;border-radius:9px;background:linear-gradient(90deg,var(--a),var(--b))}
body[data-theme="midnight"]{--bg:#020611;--panel:rgba(5,10,24,.96);--card:#0c1428;--line:#1d2a48;--text:#eef4ff;--muted:#8491aa}body[data-theme="graphite"]{--bg:#111214;--panel:rgba(22,23,26,.97);--card:#292a2e;--line:#3b3c42;--text:#f1f1f2;--muted:#a0a0a6}body[data-theme="amoled"]{--bg:#000;--panel:#000;--card:#080808;--line:#1b1b1b;--text:#fff;--muted:#888}body[data-theme="light"]{--bg:#f2f3f7;--panel:rgba(255,255,255,.97);--card:#fff;--line:#d9dbe5;--text:#17171c;--muted:#686a76;--ok:#16865f}body[data-theme="custom"]{--bg:var(--custom-bg,#050507);--panel:var(--custom-panel,#101014);--card:var(--custom-panel,#101014);--text:var(--custom-text,#f5f5f7)}
body:not([data-theme="silo-dark"]){background:var(--bg)}body:not([data-theme="silo-dark"]) .app{background:var(--bg)}body:not([data-theme="silo-dark"]) aside,body:not([data-theme="silo-dark"]) .header,body:not([data-theme="silo-dark"]) .composer,body:not([data-theme="silo-dark"]) .topicbar,body:not([data-theme="silo-dark"]) .typing{background:var(--panel);border-color:var(--line)}body:not([data-theme="silo-dark"]) .messages{background:var(--bg)}body:not([data-theme="silo-dark"]) .box,body:not([data-theme="silo-dark"]) .bubble,body:not([data-theme="silo-dark"]) .file-card,body:not([data-theme="silo-dark"]) .topic,body:not([data-theme="silo-dark"]) .write,body:not([data-theme="silo-dark"]) input,body:not([data-theme="silo-dark"]) select{background:var(--card);border-color:var(--line);color:var(--text)}body[data-theme="light"] .message-text strong{color:#111}body[data-theme="light"] .message-text code{background:#eff0f5;color:#4b3ca3}body[data-theme="light"] .message-text pre{background:#202127;color:#f4f4f5}body[data-theme="light"] .topic.active{background:#ebe8ff;color:#262039}body[data-theme="light"] .search-dialog,body[data-theme="light"] .ctx{background:#fff}body[data-theme="light"] .search-result{background:#f7f7fa;color:#17171c}
.reaction-bar{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}.reaction{padding:3px 7px;border:1px solid #ffffff18;border-radius:99px;color:var(--text);background:#0004;font-size:11px}.reaction.mine{border-color:var(--a);background:#6e7cff22}.receipt{margin-top:5px;color:#b9b2e7;font-size:9px;text-align:right}.mention{padding:1px 4px;border-radius:5px;color:#fff;background:#7165bd55}.poll-card{width:min(520px,90%);padding:14px;border:1px solid var(--line);border-radius:15px;background:var(--card)}.poll-card h4{margin:0 0 11px}.poll-option{display:flex;width:100%;justify-content:space-between;margin:6px 0;padding:9px;border:1px solid var(--line);border-radius:9px;color:var(--text);background:#ffffff06}.drop-active:after{content:"Drop to send encrypted";position:absolute;z-index:18;inset:16px;display:grid;place-items:center;border:2px dashed var(--a);border-radius:20px;color:#fff;background:#08080de8;font-size:18px;font-weight:700}.privacy-on .messages,.privacy-on .pins{filter:blur(12px);user-select:none}body.focus-shield .messages,body.focus-shield .people{filter:blur(15px)}.activity-feed{display:grid;gap:6px}.activity-item{padding:7px;border-left:2px solid var(--a);color:var(--muted);font-size:9px;background:#ffffff04}.alert-item{padding:8px;margin:6px 0;border:1px solid #74404a;border-radius:8px;color:#ffadb9;background:#32121a55;font-size:9px}.diagnostic-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}.diagnostic-grid div{padding:7px;border:1px solid var(--line);border-radius:8px}.diagnostic-grid small,.diagnostic-grid b{display:block}.diagnostic-grid small{color:var(--muted);font-size:8px}.diagnostic-grid b{margin-top:3px;font:10px Consolas}.mention-alert{box-shadow:0 0 0 1px var(--a),0 0 25px #6e5cff44}
@media(max-width:700px){.topicbar{padding:8px 12px}.topic{min-height:32px;padding:6px 10px}.tools label{padding:6px 8px}.tool-button{padding:7px 10px}.tool-button .tool-label,.icon-button span{display:none}.icon-button{width:36px;padding:8px;justify-content:center}.header-actions{gap:6px}.clear-request{max-width:38px;overflow:hidden;white-space:nowrap;margin-right:0}.typing{padding-left:14px}.messages{padding:15px}.search-filters input{width:calc(50% - 5px)}}
.lock-screen{display:none;position:fixed;z-index:100;inset:0;place-items:center;background:#030305f2;backdrop-filter:blur(24px)}.lock-screen.show{display:grid}.lock-card{width:min(90vw,360px);padding:28px;border:1px solid var(--line);border-radius:20px;background:#0b0b0f;text-align:center;box-shadow:0 30px 90px #000}.lock-card input{width:100%;box-sizing:border-box;margin:14px 0 5px;padding:12px;border-radius:10px}.view-once{padding:12px;border:1px dashed #8f82ff;border-radius:10px;color:#dcd8ff;background:#6e5cff16}.panic{color:#ff9cab!important;border-color:#74303d!important}.voice-recording{color:#ff8495!important;animation:blink .8s infinite}
</style></head><body><div class="aurora"></div><div class="gridfx"></div><div class="grain"></div><div class="lock-screen" id="lockScreen"><div class="lock-card"><h2>🔒 Silo locked</h2><p id="lockHint">Enter your local lock PIN.</p><input id="lockPin" type="password" minlength="6" maxlength="64" autocomplete="off" placeholder="Local PIN"><button class="action" id="unlock">Unlock</button><small>The PIN only protects this local interface.</small></div></div><div class="app">
<aside class="left"><div class="logo"><div class="mark">S</div><div><b>Silo Client</b><small>Secure room v2</small></div></div>
<div class="box"><h3>IDENTITY</h3><div class="name-row"><input id="name" maxlength="40"><button id="saveName">✓</button></div></div>
<div class="box"><h3>CONNECTION</h3><div class="row"><span>Discord</span><b class="online" id="discord">Connecting</b></div><div class="row"><span>Participants</span><b id="users">1</b></div><div class="row"><span>Room</span><b class="mono">__CHANNEL__</b></div></div><div class="box"><h3>PRESENCE</h3><div class="presence-list" id="presenceList"></div></div><div class="box"><h3>APPEARANCE</h3><div class="appearance-grid"><label>Theme<select id="themeSelect"><option value="silo-dark">Silo Dark</option><option value="midnight">Midnight</option><option value="graphite">Graphite</option><option value="amoled">AMOLED</option><option value="light">Light</option><option value="custom">Custom</option></select></label><label>Accent<select id="accentSelect"><option value="purple">Purple</option><option value="blue">Blue</option><option value="green">Green</option><option value="red">Red</option><option value="orange">Orange</option><option value="custom">Custom</option></select></label><div class="custom-colors" id="themeColors"><label class="color-field">Background<input type="color" id="customBg" value="#050507"></label><label class="color-field">Panel<input type="color" id="customPanel" value="#101014"></label><label class="color-field">Text<input type="color" id="customText" value="#f5f5f7"></label></div><div class="custom-colors" id="accentColors"><label class="color-field">Primary<input type="color" id="customAccent" value="#7c6cff"></label><label class="color-field">Secondary<input type="color" id="customAccent2" value="#a855f7"></label></div><div class="accent-preview"></div></div></div>
__MOBILE_LOCAL_CONTROLS__
<div class="box"><h3>DATA & PRIVACY</h3><button class="action" id="export">↓ Encrypted export</button><button class="action" id="import">↑ Import and sync</button><button class="action" id="clearExpired">Clean expired</button><button class="action" id="clearFiles">Clean attachments</button><button class="action" id="privacyMode">◉ Privacy mode</button><input hidden type="file" id="file" accept=".json,.silo.json"></div></aside>
<main><div class="header"><div class="room-title"><b>Secure room</b><span class="secure"><i></i> AEAD ACTIVE</span><small id="roomState">Waiting for connection…</small></div><div class="header-actions"><button class="icon-button" id="openSearch" title="Search messages"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M16 16l5 5"/></svg><span>Search</span></button><button class="icon-button" id="quickPrivacy" title="Toggle privacy">◉</button><button class="clear-request" id="clearChat" title="Request consensual deletion">⌫ Delete chat</button><div class="people" id="people"></div></div></div><div class="topicbar" id="topics"></div><div class="pins" id="pins"></div><div class="messages" id="messages"></div><button class="new-messages" id="newMessages">↓ New messages</button><div class="typing" id="typing"></div>
<div class="replybar" id="replybar">Replying to <b id="replyname"></b><button id="cancelReply">✕</button></div><div class="composer"><div class="tools"><label title="Disappearing message"><input type="checkbox" id="expire"> 🔥 Disappearing</label><select id="ttl" aria-label="Disappearing message duration"><option value="10">10 seconds</option><option value="30">30 seconds</option><option value="60">1 minute</option><option value="300">5 minutes</option><option value="3600">1 hour</option><option value="86400">24 hours</option><option value="custom">Custom…</option></select><button class="tool-button" id="attach" title="Attach encrypted file">📎 <span class="tool-label">Attach</span></button><button class="tool-button" id="createPoll">▥ <span class="tool-label">Poll</span></button><input hidden type="file" id="attachment"></div><div class="write"><textarea id="text" rows="2" maxlength="1200" placeholder="Write a message…"></textarea><button class="send" id="send" title="Send message">➜</button></div></div></main>
<aside class="right"><div class="logo"><div><b>Security Center</b><small>Real-time cryptographic status</small></div></div><div class="box security-center" id="securityCenter"></div><div class="box"><h3>DIAGNOSTICS</h3><div id="diagnostics"></div></div><div class="box"><h3>SECURITY ALERTS</h3><div id="securityAlerts"></div></div><div class="box"><h3>RECENT ACTIVITY</h3><div class="activity-feed" id="activityFeed"></div></div><div id="stats"></div></aside></div>
<div class="ctx" id="ctx"><button data-a="reply">↩ Reply</button><button data-a="react">☺ React</button><button data-a="revisions">◷ Edit history</button><button data-a="edit">✎ Edit</button><button data-a="pin">⌖ Pin / unpin</button><button data-a="highlight">★ Highlight</button><button class="danger" data-a="delete">⌫ Delete</button></div><div class="toast" id="toast"></div><div class="search-panel" id="searchPanel"><div class="search-dialog"><div class="search-head"><input id="searchText" placeholder="Search messages…" autocomplete="off"><button id="closeSearch" aria-label="Close">✕</button></div><div class="search-filters"><input id="searchUser" placeholder="User"><input id="searchDate" type="date"><label><input id="searchPinned" type="checkbox"> Pinned</label><label><input id="searchHighlighted" type="checkbox"> Highlighted</label><label><input id="searchExact" type="checkbox"> Exact phrase</label></div><div class="search-results" id="searchResults"></div></div></div><div class="clear-modal" id="clearModal" role="dialog" aria-modal="true"><div class="clear-dialog"><h2>Full deletion request</h2><p id="clearText"></p><div class="clear-progress" id="clearProgress"></div><p>The history will be deleted for everyone only if every participant accepts before the request expires.</p><div class="clear-actions"><button class="clear-reject" id="rejectClear">Reject</button><button class="clear-accept" id="acceptClear">Accept deletion</button></div></div></div>
<script>
const $=x=>document.getElementById(x), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let ws,state={messages:[],attachments:[],topics:[],polls:[],activity:[],security_alerts:[],typing:[],participants:{},clear_proposals:[],self_id:'',stats:{}},active=null,reply=null,clearPromptId=null,activeTopic='lobby',lastTyping=0,readSent=new Set();
function toast(s){$('toast').textContent=s;$('toast').classList.add('show');setTimeout(()=>$('toast').classList.remove('show'),2600)}
function connect(){ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws');ws.onmessage=e=>{let d=JSON.parse(e.data);if(d.type==='state'){state=d;render()}else if(d.type==='telemetry'){state.participants=d.participants;state.typing=d.typing||[];state.clear_proposals=d.clear_proposals||[];state.stats=d.stats;state.username=d.username;state.self_id=d.self_id;renderTelemetry();renderTyping()}else if(d.type==='view_once_reveal')revealViewOnce(d);else if(d.type==='error')toast('Error: '+d.message);else if(d.type==='notice')toast(d.message);else if(d.type==='export')download(d)};ws.onopen=()=>{$('discord').textContent='Connected'};ws.onclose=()=>{$('discord').textContent='Reconnecting';setTimeout(connect,1800)}}
function metric(label,value,meter=null){return `<div class="stat"><div class="stat-head"><span>${label}</span><b>${esc(value)}</b></div>${meter==null?'':`<div class="meter"><i style="width:${Math.max(0,Math.min(100,meter))}%"></i></div>`}</div>`}function group(name,items){return `<div class="stat-group">${name}</div>`+items.join('')}
let rendered=new Map(),previousIds=new Set(),statsFrame=0;
function messageSignature(m,q){return JSON.stringify([m.content,m.username,m.edited,m.deleted,m.pinned,m.highlighted,m.reply_to,m.expires_at,m.reactions,m.receipts,m.mentions,q&&q.content])}
function inlineMarkdown(value){let tokens=[];value=value.replace(/`([^`\n]+)`/g,(_,code)=>{tokens.push(`<code>${code}</code>`);return `\u0000${tokens.length-1}\u0000`});value=value.replace(/\*\*([^*\n]+)\*\*/g,'<strong>$1</strong>').replace(/(^|[^*])\*([^*\n]+)\*/g,'$1<em>$2</em>').replace(/(^|\s)(@[\w.-]{1,40})/g,'$1<span class="mention">$2</span>');return value.replace(/\u0000(\d+)\u0000/g,(_,i)=>tokens[+i])}
function renderMarkdown(raw){let lines=esc(raw).split('\n'),out=[],code=[],language='',inCode=false,list=[];let flushList=()=>{if(list.length){out.push('<ul>'+list.map(x=>'<li>'+inlineMarkdown(x)+'</li>').join('')+'</ul>');list=[]}};for(let line of lines){let fence=line.match(/^```([\w#+.-]*)\s*$/);if(fence){if(inCode){out.push(`<pre data-lang="${esc(language||'code')}"><code>${code.join('\n')}</code></pre>`);code=[];inCode=false}else{flushList();language=fence[1];inCode=true}continue}if(inCode){code.push(line);continue}let item=line.match(/^\s*[-*]\s+(.+)$/);if(item){list.push(item[1]);continue}flushList();let quote=line.match(/^&gt;\s?(.*)$/);if(quote)out.push('<blockquote>'+inlineMarkdown(quote[1])+'</blockquote>');else if(line.trim())out.push('<div>'+inlineMarkdown(line)+'</div>');else out.push('<br>')}flushList();if(inCode)out.push(`<pre data-lang="${esc(language||'code')}"><code>${code.join('\n')}</code></pre>`);return out.join('')}
function messageHtml(m,q){let expiry=m.expires_at?`<div class="expiry" data-expires="${+m.expires_at}" data-start="${new Date(m.timestamp).getTime()/1000}"><div class="expiry-head"><span>🔥 Disappearing message</span><b class="expiry-time">--:--</b></div><div class="expiry-track"><i></i></div></div>`:'',reactions=Object.entries(m.reactions||{}).map(([emoji,users])=>`<button class="reaction ${users.includes(state.self_id)?'mine':''}" data-emoji="${esc(emoji)}">${esc(emoji)} ${users.length}</button>`).join(''),receipts=Object.values(m.receipts||{}),receipt=m.sender_id===state.self_id&&receipts.length?`<div class="receipt">${receipts.some(x=>x.state==='read')?'✓✓ Read':'✓ Delivered'}</div>`:'';return `<div class="sender">${esc(m.username)}</div><div class="bubble">${q?`<div class="quote">↩ ${esc(q.username)}: ${esc(q.content).slice(0,90)}</div>`:''}<div class="message-text">${m.deleted?'Message deleted':renderMarkdown(m.content)}</div>${expiry}${reactions?`<div class="reaction-bar">${reactions}</div>`:''}${receipt}<div class="meta">${m.pinned?'<span class="badge">PIN</span>':''}${m.highlighted?'<span class="badge">★</span>':''}${m.edited?'<span class="badge">EDITED</span>':''}${new Date(m.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</div></div>`}
function fileHtml(f){let url='/api/attachment/'+encodeURIComponent(f.transfer_id),ready=f.status==='ready',preview=ready&&(/^image\//.test(f.mime)||/^audio\//.test(f.mime)||f.mime==='application/pdf');return `<div class="file-card"><b>${/^audio\//.test(f.mime)?'🎙':'📎'} ${esc(f.name)}</b><small>${Math.ceil(f.size/1024)} KB · ${esc(f.username)} · ${esc(f.status)}</small>${ready?`<a href="${url}" download>Download</a>${preview?`<a href="${url}?preview=1" target="_blank">Preview</a>`:''}${/^image\//.test(f.mime)?`<img class="preview" src="${url}?preview=1" alt="${esc(f.name)}">`:''}${/^audio\//.test(f.mime)?`<audio class="preview" controls preload="metadata" src="${url}?preview=1"></audio>`:''}`:`<small>${esc(f.error||'Receiving encrypted chunks…')}</small>`}</div>`}
function renderMessages(map){const area=$('messages'),visible=state.messages.filter(m=>m.topic_id===activeTopic),files=state.attachments.filter(f=>f.topic_id===activeTopic),topicPolls=(state.polls||[]).filter(p=>p.topic_id===activeTopic),nearBottom=area.scrollHeight-area.scrollTop-area.clientHeight<110,current=new Set(visible.map(m=>m.id));for(const [id,node] of rendered){if(!current.has(id)){node.remove();rendered.delete(id)}}for(const m of visible){let q=m.reply_to&&map[m.reply_to],sig=messageSignature(m,q),node=rendered.get(m.id),mine=m.sender_id===state.self_id,mentioned=(m.mentions||[]).includes(state.self_id);if(!node){node=document.createElement('div');node.dataset.id=m.id;area.appendChild(node);rendered.set(m.id,node)}node.className=`msg ${mine?'mine':''} ${mentioned?'mention-alert':''}`;if(node.dataset.sig!==sig){node.dataset.sig=sig;node.innerHTML=messageHtml(m,q)}if(!mine&&state.settings&&state.settings.read_receipts&&!readSent.has(m.id)){readSent.add(m.id);send({type:'receipt',id:m.id,state:'read'})}}area.querySelectorAll('.file-transfer,.poll-card').forEach(n=>n.remove());for(const f of files){let node=document.createElement('div');node.className='msg file-transfer '+(f.sender_id===state.self_id?'mine':'');node.innerHTML=fileHtml(f);area.appendChild(node)}for(const p of topicPolls){let counts=p.options.map((_,i)=>Object.values(p.votes||{}).filter(v=>v===i).length),node=document.createElement('div');node.className='poll-card';node.innerHTML=`<small>${esc(p.username)}</small><h4>${esc(p.question)}</h4>`+p.options.map((o,i)=>`<button class="poll-option" data-poll="${esc(p.id)}" data-option="${i}"><span>${esc(o)}</span><b>${counts[i]}</b></button>`).join('');area.appendChild(node)}if(nearBottom)requestAnimationFrame(()=>area.scrollTo({top:area.scrollHeight,behavior:'smooth'}));previousIds=current}
function draftKey(topic){return'silo-draft-'+location.host+'-'+topic}function saveDraft(){try{localStorage.setItem(draftKey(activeTopic),$('text').value)}catch(e){}}function loadDraft(){try{$('text').value=localStorage.getItem(draftKey(activeTopic))||''}catch(e){$('text').value=''}}
function renderTopics(){$('topics').innerHTML=state.topics.map(t=>`<span class="topic-wrap"><button class="topic ${t.id===activeTopic?'active':''}" data-topic="${esc(t.id)}">${esc(t.name)}</button>${t.id==='lobby'?'':`<button class="topic-remove" data-remove="${esc(t.id)}" title="Delete topic">×</button>`}</span>`).join('')+'<button class="topic topic-add" data-add="1">Create topic</button>';$('topics').onclick=e=>{let b=e.target.closest('button');if(!b)return;if(b.dataset.add){let name=prompt('Topic name');if(!name)return;let id=name.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g,'-').replace(/^-|-$/g,'').toLowerCase().slice(0,48)||('topic-'+Date.now());send({type:'topic_create',topic_id:id,name})}else if(b.dataset.remove){let id=b.dataset.remove,topic=state.topics.find(t=>t.id===id);if(confirm(`Delete #${topic?topic.name:id}? Its local messages and attachments will be removed for everyone.`)){send({type:'topic_delete',topic_id:id});if(activeTopic===id)activeTopic='lobby'}}else{saveDraft();activeTopic=b.dataset.topic;loadDraft();reply=null;render()}}}
function renderTyping(){let writers=state.typing.filter(t=>t.topic_id===activeTopic).map(t=>t.name),host=$('typing');if(!writers.length){host.replaceChildren();return}let label=writers.length===1?`<b>${esc(writers[0])}</b> is typing`:`<b>${esc(writers.slice(0,2).join(' and '))}</b> are typing`;host.innerHTML=`<div class="typing-indicator" role="status" aria-live="polite"><span class="typing-bubble" aria-hidden="true"><i class="typing-dot"></i><i class="typing-dot"></i><i class="typing-dot"></i></span><span class="typing-name">${label}</span></div>`}
function formatRemaining(seconds){seconds=Math.max(0,Math.ceil(seconds));if(seconds>=3600)return String(Math.floor(seconds/3600)).padStart(2,'0')+':'+String(Math.floor(seconds%3600/60)).padStart(2,'0')+':'+String(seconds%60).padStart(2,'0');return String(Math.floor(seconds/60)).padStart(2,'0')+':'+String(seconds%60).padStart(2,'0')}
function updateExpiry(){let now=Date.now()/1000;document.querySelectorAll('.expiry').forEach(node=>{let end=+node.dataset.expires,start=+node.dataset.start,total=Math.max(1,end-start),left=Math.max(0,end-now),pct=Math.max(0,Math.min(100,left/total*100));node.querySelector('.expiry-time').textContent=formatRemaining(left);node.querySelector('.expiry-track i').style.width=pct+'%';node.classList.toggle('hot',left<=10)})}
function render(){let map=Object.fromEntries(state.messages.map(m=>[m.id,m]));renderTelemetry();renderTopics();renderMessages(map);let pins=state.messages.filter(m=>m.topic_id===activeTopic&&m.pinned&&!m.deleted),pinText=pins.length?'⌖ '+pins[pins.length-1].username+': '+pins[pins.length-1].content:'';$('pins').style.display=pins.length?'block':'none';$('pins').textContent=pinText;renderTyping()}
function normalizedPresence(p){let allowed=['online','idle','away','typing','offline'],status=allowed.includes(p&&p.status)?p.status:'offline';return{name:String(p&&p.name||'User').slice(0,40),status,last_seen:p&&p.last_seen||''}}
function presenceLabel(raw){let p=normalizedPresence(raw);if(p.status==='typing')return'Typing…';if(p.status==='online')return'Online';if(p.status==='idle')return'Idle';if(p.status==='away')return'Away';let d=new Date(p.last_seen);return'Last seen '+(isNaN(d)?'unknown':d.toLocaleString([],{dateStyle:'short',timeStyle:'short'}))}
function renderPresence(){let entries=Object.entries(state.participants||{}).map(([id,p])=>[id,normalizedPresence(p)]).sort((a,b)=>(a[1].status==='offline')-(b[1].status==='offline')||a[1].name.localeCompare(b[1].name));$('presenceList').innerHTML=entries.map(([id,p])=>`<div class="presence-row"><i class="presence-dot ${p.status}" aria-hidden="true"></i><div class="presence-user"><b>${esc(p.name)}${id===state.self_id?' · You':''}</b><small>${esc(presenceLabel(p))}</small></div></div>`).join('')||'<small>No participants yet</small>'}
function renderSecurity(){let s=state.stats||{},finger=String(s.fingerprint||'').match(/.{1,4}/g)?.join('-')||'n/d',items=[['Encryption',s.encryption],['Key Derivation',s.kdf],['Room','Verified'],['Safety code',finger],['Session','Secure · anti-replay'],['Storage',state.settings&&state.settings.memory_only?'Memory only':'Encrypted transport / local history'],['Mobile access',s.mobile_ready?'Protected':'Local only'],['Connection',s.mobile_ready?'LAN':'Localhost']];$('securityCenter').innerHTML='<div class="security-title">SILO SECURITY</div>'+items.map(x=>`<div class="security-item"><i></i><div><span>${esc(x[0])}</span><b>${esc(x[1]||'n/d')}</b></div></div>`).join('')+'<div class="security-verified">✓ ROOM VERIFIED</div>';$('securityAlerts').innerHTML=(state.security_alerts||[]).map(a=>`<div class="alert-item">${esc(a.message)}<br><small>${new Date(a.at).toLocaleString()}</small></div>`).join('')||'<small>No security alerts</small>';$('activityFeed').innerHTML=(state.activity||[]).slice().reverse().map(a=>`<div class="activity-item"><b>${esc(a.sender)}</b> · ${esc(a.kind.replaceAll('_',' '))}<br><small>${new Date(a.at).toLocaleTimeString()}</small></div>`).join('')||'<small>No recent activity</small>';$('diagnostics').innerHTML=`<div class="diagnostic-grid"><div><small>Pending files</small><b>${s.pending_transfers||0}</b></div><div><small>Rejected</small><b>${s.rejected||0}</b></div><div><small>Message cache</small><b>${s.cache_messages||0}/${s.cache_limit||0}</b></div><div><small>WebSockets</small><b>${s.websockets||0}</b></div></div>`}
function renderTelemetry(){if(document.activeElement!==$('name'))$('name').value=state.username;let normalized=Object.values(state.participants||{}).map(normalizedPresence),active=normalized.filter(p=>p.status!=='offline'),activeCount=active.length;$('users').textContent=activeCount;$('roomState').textContent=activeCount+' active participant(s) · '+state.messages.length+' messages';let peopleHtml=active.slice(0,8).map(p=>`<div class="avatar" title="${esc(p.name)} · ${esc(presenceLabel(p))}">${esc(p.name.charAt(0)||'?')}</div>`).join('');if($('people').dataset.snapshot!==peopleHtml){$('people').dataset.snapshot=peopleHtml;$('people').innerHTML=peopleHtml}renderPresence();renderSecurity();renderClearConsensus();cancelAnimationFrame(statsFrame);statsFrame=requestAnimationFrame(renderStats)}
function renderStats(){let s=state.stats,up=Math.floor(s.uptime/3600)+'h '+Math.floor(s.uptime%3600/60)+'m',html=
group('SYSTEM',[metric('HOST',s.hostname),metric('SO',s.os),metric('ARCHITECTURE',s.architecture),metric('CPU',s.cpu==null?'n/d':s.cpu+'%',s.cpu),metric('CORES',s.cpu_count),metric('RAM',s.ram==null?'n/d':s.ram+'% · '+s.ram_used+'/'+s.ram_total+' GB',s.ram),metric('DISK',s.disk==null?'n/d':s.disk+'% · '+s.disk_free+' GB free',s.disk),metric('PROCESS',s.process_ram+' MB · '+s.threads+' threads'),metric('PID',s.pid),metric('UPTIME',up)])+
group('NETWORK AND TRANSPORT',[metric('DISCORD',s.discord_latency==null?'n/d':s.discord_latency+' ms',Math.min(100,(s.discord_latency||0)/3)),metric('E2E DELIVERY',s.delivery_latency+' ms',Math.min(100,s.delivery_latency/5)),metric('LAN IP',s.lan_ip),metric('MOBILE ACCESS',s.mobile_ready?'QR ready':'This device only'),metric('HOST NETWORK ↑',s.net_sent+' MB'),metric('HOST NETWORK ↓',s.net_received+' MB'),metric('SILO SENT',s.bytes_sent+' B'),metric('SILO RECEIVED',s.bytes_received+' B'),metric('WEBSOCKETS',s.websockets),metric('LOCAL PORT',s.port)])+
group('CRYPTOGRAPHY',[metric('AEAD',s.encryption),metric('KDF',s.kdf),metric('NONCE',s.nonce),metric('ANTI-REPLAY',s.replay_cache+' nonces'),metric('KEY ID',s.key_id),metric('FINGERPRINT',s.fingerprint),metric('ENCRYPTED',s.encrypted),metric('DECRYPTED',s.decrypted),metric('REJECTED',s.rejected)])+
group('CHAT ACTIVITY',[metric('PARTICIPANTS',s.participants_active+' active · '+s.participants_total+' seen'),metric('TOPICS',s.topics),metric('ATTACHMENTS',s.attachments+' · '+s.attachment_bytes+' B'),metric('MESSAGES',s.messages),metric('OWN / OTHERS',s.mine+' / '+s.others),metric('CHARACTERS',s.characters),metric('EVENTS',s.events),metric('SENT / RECEIVED',s.events_sent+' / '+s.events_received),metric('PINS',s.pinned),metric('HIGHLIGHTED',s.highlighted),metric('EDITED',s.edited),metric('DELETED',s.deleted)]);let host=$('stats');if(!host.dataset.ready){host.innerHTML=html;host.dataset.ready='1'}else{let tpl=document.createElement('template');tpl.innerHTML=html;let oldValues=host.querySelectorAll('.stat-head b'),newValues=tpl.content.querySelectorAll('.stat-head b'),oldMeters=host.querySelectorAll('.meter i'),newMeters=tpl.content.querySelectorAll('.meter i');if(oldValues.length!==newValues.length){host.innerHTML=html}else{oldValues.forEach((node,i)=>{let value=newValues[i].textContent;if(node.textContent!==value)node.textContent=value});oldMeters.forEach((node,i)=>{if(newMeters[i])node.style.width=newMeters[i].style.width})}}}
$('messages').onclick=e=>{let poll=e.target.closest('[data-poll]');if(poll){send({type:'poll_vote',id:poll.dataset.poll,option:+poll.dataset.option});return}let box=e.target.closest('.msg');if(!box||!box.dataset.id)return;active=state.messages.find(m=>m.id===box.dataset.id);if(!active)return;let reaction=e.target.closest('[data-emoji]');if(reaction){send({type:'reaction',id:active.id,emoji:reaction.dataset.emoji});return}let mine=active.sender_id===state.self_id;$('ctx').querySelector('[data-a="edit"]').style.display=mine?'block':'none';$('ctx').querySelector('[data-a="delete"]').style.display=mine?'block':'none';$('ctx').style.display='block';$('ctx').style.left=Math.min(e.clientX,innerWidth-190)+'px';$('ctx').style.top=Math.min(e.clientY,innerHeight-260)+'px';e.stopPropagation()};document.onclick=()=>$('ctx').style.display='none';
$('ctx').onclick=e=>{let a=e.target.dataset.a;if(!a||!active)return;if(a==='reply'){reply=active.id;$('replyname').textContent=active.username;$('replybar').classList.add('open')}else if(a==='react'){let emoji=prompt('Reaction: 👍 ❤️ 😂 🔥 ✅ 👀','👍');if(emoji)send({type:'reaction',id:active.id,emoji})}else if(a==='revisions'){let revisions=active.revisions||[];alert(revisions.length?revisions.map((r,i)=>`${i+1}. ${new Date(r.at).toLocaleString()}\n${r.content}`).join('\n\n'):'No previous revisions')}else if(a==='edit'){let v=prompt('Edit message',active.content);if(v)send({type:'edit',id:active.id,content:v})}else if(a==='delete'){if(confirm('Delete this message?'))send({type:'delete',id:active.id})}else send({type:a,id:active.id,state:!active[a==='highlight'?'highlighted':'pinned']})};
function renderClearConsensus(){let proposals=state.clear_proposals||[],pending=proposals.find(p=>p.status==='pending'||p.status==='approved'),modal=$('clearModal'),button=$('clearChat');button.disabled=!!pending;if(!pending){modal.classList.remove('show');clearPromptId=null;return}let votes=pending.votes||{},total=(pending.target_ids||[]).length,yes=Object.values(votes).filter(v=>v&&v.accept).length,mine=votes[state.self_id];button.title=`Active request: ${yes}/${total} acceptances`;if(!mine&&pending.initiator_id!==state.self_id){clearPromptId=pending.id;$('clearText').textContent=`${pending.initiator_name||'A participant'} requests deletion of the entire room history.`;$('clearProgress').textContent=`${yes} of ${total} participants accepted · expires soon`;modal.classList.add('show')}else{modal.classList.remove('show')}}
$('clearChat').onclick=()=>{if(confirm('Request deletion of the entire history? It will only be deleted if every active participant accepts. If anyone rejects or does not respond within 90 seconds, nothing will be deleted.'))send({type:'clear_request'})};$('acceptClear').onclick=()=>{if(clearPromptId){send({type:'clear_vote',proposal_id:clearPromptId,accept:true});$('clearModal').classList.remove('show')}};$('rejectClear').onclick=()=>{if(clearPromptId){send({type:'clear_vote',proposal_id:clearPromptId,accept:false});$('clearModal').classList.remove('show')}};
function runSearch(){let query=$('searchText').value.trim().toLocaleLowerCase(),user=$('searchUser').value.trim().toLocaleLowerCase(),date=$('searchDate').value,exact=$('searchExact').checked,terms=query.split(/\s+/).filter(Boolean);let results=state.messages.filter(m=>{let content=(m.content||'').toLocaleLowerCase();return(!query||(exact?content.includes(query):terms.every(term=>content.includes(term))))&&(!user||(m.username||'').toLocaleLowerCase().includes(user))&&(!date||new Date(m.timestamp).toLocaleDateString('en-CA')===date)&&(!$('searchPinned').checked||m.pinned)&&(!$('searchHighlighted').checked||m.highlighted)&&!m.deleted});let host=$('searchResults');host.innerHTML=`<div class="search-count">${results.length} result(s)</div>`+results.map(m=>`<button class="search-result" data-result="${esc(m.id)}"><b>${esc(m.username)}${m.sender_id===state.self_id?' · You':''}</b><small># ${esc((state.topics.find(t=>t.id===m.topic_id)||{}).name||m.topic_id)} · ${new Date(m.timestamp).toLocaleString()}</small><span>${esc(m.content).slice(0,220)}</span></button>`).join('');host.querySelectorAll('[data-result]').forEach(button=>button.onclick=()=>jumpToMessage(button.dataset.result))}
function jumpToMessage(id){let message=state.messages.find(m=>m.id===id);if(!message)return;activeTopic=message.topic_id;$('searchPanel').classList.remove('show');render();requestAnimationFrame(()=>{let node=rendered.get(id);if(node){node.scrollIntoView({behavior:'smooth',block:'center'});node.classList.add('search-hit');setTimeout(()=>node.classList.remove('search-hit'),1600)}})}
$('openSearch').onclick=()=>{$('searchPanel').classList.add('show');$('searchText').focus();runSearch()};$('closeSearch').onclick=()=>$('searchPanel').classList.remove('show');$('searchPanel').onclick=e=>{if(e.target===$('searchPanel'))$('searchPanel').classList.remove('show')};['searchText','searchUser','searchDate','searchPinned','searchHighlighted','searchExact'].forEach(id=>$(id).addEventListener('input',runSearch));document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='f'){e.preventDefault();$('openSearch').click()}if(e.key==='Escape')$('searchPanel').classList.remove('show')});
function send(o){if(ws&&ws.readyState===1)ws.send(JSON.stringify(o));else toast('WebSocket disconnected')};function selectedTtl(){if(!$('expire').checked)return 0;let value=$('ttl').value;if(value!=='custom')return +value;let custom=prompt('Duration in seconds (1–86400)','120');if(custom===null)return null;let seconds=Number(custom);if(!Number.isInteger(seconds)||seconds<1||seconds>86400){toast('Duration must be between 1 second and 24 hours');return null}return seconds}function sendText(){let v=$('text').value.trim();if(!v)return;let ttl=selectedTtl();if(ttl===null)return;let wanted=[...v.matchAll(/@([\w.-]{1,40})/g)].map(x=>x[1].toLowerCase()),mentions=Object.entries(state.participants||{}).filter(([,p])=>wanted.includes(String(p.name||'').toLowerCase())).map(([id])=>id);send({type:'send',topic_id:activeTopic,content:v,reply_to:reply,ttl,mentions});$('send').classList.add('sending');setTimeout(()=>$('send').classList.remove('sending'),480);$('text').value='';saveDraft();reply=null;$('replybar').classList.remove('open')}$('send').onclick=sendText;$('text').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendText()}};$('text').oninput=()=>{saveDraft();markActivity();let now=Date.now();if(now-lastTyping>=2250){lastTyping=now;send({type:'typing',topic_id:activeTopic})}};$('cancelReply').onclick=()=>{reply=null;$('replybar').classList.remove('open')};$('saveName').onclick=()=>send({type:'set_username',username:$('name').value});
function sendFile(f){if(!f)return;if(f.size>1500000){toast('The maximum size is 1.5 MB');return}let r=new FileReader;r.onload=()=>{let content=String(r.result).split(',',2)[1];send({type:'attachment',topic_id:activeTopic,name:f.name,mime:f.type||'application/octet-stream',content});toast('Encrypting and sending attachment')};r.readAsDataURL(f)}$('attach').onclick=()=>$('attachment').click();$('attachment').onchange=e=>{sendFile(e.target.files[0]);e.target.value=''};$('messages').ondragover=e=>{e.preventDefault();document.querySelector('main').classList.add('drop-active')};$('messages').ondragleave=()=>document.querySelector('main').classList.remove('drop-active');$('messages').ondrop=e=>{e.preventDefault();document.querySelector('main').classList.remove('drop-active');[...e.dataTransfer.files].slice(0,5).forEach(sendFile)};
$('createPoll').onclick=()=>{let question=prompt('Poll question');if(!question)return;let raw=prompt('Options separated by |','Yes | No');if(!raw)return;let options=raw.split('|').map(x=>x.trim()).filter(Boolean).slice(0,8);if(options.length<2)return toast('A poll needs at least two options');send({type:'poll_create',topic_id:activeTopic,question,options})};
if($('copyMobile'))$('copyMobile').onclick=async()=>{try{await navigator.clipboard.writeText('__MOBILE_URL__');toast('Secure mobile link copied')}catch(e){toast('The link could not be copied')}};
if($('saveMobilePassword'))$('saveMobilePassword').onclick=async()=>{let password=$('mobilePassword').value,confirmation=$('mobilePasswordConfirm').value,status=$('mobilePasswordStatus');if(password.length<12){toast('Use a password with at least 12 characters');return}if(password!==confirmation){toast('Passwords do not match');return}try{let response=await fetch('/api/mobile-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,confirmation})}),data=await response.json();if(!response.ok)throw Error(data.message||'Could not save');$('mobilePassword').value='';$('mobilePasswordConfirm').value='';status.textContent='Password enabled · previous mobile sessions were closed';toast('Mobile password saved')}catch(error){toast(error.message||'The password could not be saved')}};
$('newMessages').onclick=()=>{$('messages').scrollTo({top:$('messages').scrollHeight,behavior:'smooth'});$('newMessages').classList.remove('show')};$('messages').onscroll=()=>{if($('messages').scrollHeight-$('messages').scrollTop-$('messages').clientHeight<70)$('newMessages').classList.remove('show')};function syncViewport(){let h=window.visualViewport?window.visualViewport.height:window.innerHeight;document.documentElement.style.setProperty('--silo-vh',Math.round(h)+'px')}syncViewport();addEventListener('resize',syncViewport,{passive:true});if(window.visualViewport)visualViewport.addEventListener('resize',syncViewport,{passive:true});
$('export').onclick=()=>{let password=prompt('Export password (12+ characters)');if(password)send({type:'export',password})};function download(d){let b=new Blob([d.blob],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='Silo_Encrypted_'+Date.now()+'.silo.enc';a.click();URL.revokeObjectURL(a.href)}$('import').onclick=()=>$('file').click();$('file').onchange=e=>{let f=e.target.files[0];if(!f)return;let r=new FileReader;r.onload=()=>{try{let d=JSON.parse(r.result);if(d.format!=='silo-v2'||!Array.isArray(d.events))throw Error('Invalid Silo v2 format');send({type:'import',events:d.events})}catch(x){toast(x.message)}};r.readAsText(f);e.target.value=''};$('clearExpired').onclick=()=>send({type:'clear_local',scope:'expired'});$('clearFiles').onclick=()=>{if(confirm('Remove all locally assembled attachments?'))send({type:'clear_local',scope:'attachments'})};function togglePrivacy(){document.querySelector('.app').classList.toggle('privacy-on')}$('privacyMode').onclick=togglePrivacy;$('quickPrivacy').onclick=togglePrivacy;document.addEventListener('visibilitychange',()=>document.body.classList.toggle('focus-shield',document.hidden));addEventListener('blur',()=>document.body.classList.add('focus-shield'));addEventListener('focus',()=>document.body.classList.remove('focus-shield'));
const accentSets={purple:['#7c6cff','#a855f7'],blue:['#3988ff','#27c2ff'],green:['#20c989','#68df8f'],red:['#ef476f','#ff6b4a'],orange:['#f28c28','#ffc04d']};function appearanceValue(key,fallback){try{return localStorage.getItem('silo-'+key)||fallback}catch(e){return fallback}}function saveAppearance(key,value){try{localStorage.setItem('silo-'+key,value)}catch(e){}}
function applyAppearance(){let theme=$('themeSelect').value,accent=$('accentSelect').value,root=document.documentElement;document.body.dataset.theme=theme;$('themeColors').classList.toggle('show',theme==='custom');$('accentColors').classList.toggle('show',accent==='custom');if(theme==='custom'){root.style.setProperty('--custom-bg',$('customBg').value);root.style.setProperty('--custom-panel',$('customPanel').value);root.style.setProperty('--custom-text',$('customText').value)}let colors=accent==='custom'?[$('customAccent').value,$('customAccent2').value]:accentSets[accent];root.style.setProperty('--a',colors[0]);root.style.setProperty('--b',colors[1]);saveAppearance('theme',theme);saveAppearance('accent',accent);['customBg','customPanel','customText','customAccent','customAccent2'].forEach(id=>saveAppearance(id,$(id).value))}
$('themeSelect').value=appearanceValue('theme','silo-dark');$('accentSelect').value=appearanceValue('accent','purple');['customBg','customPanel','customText','customAccent','customAccent2'].forEach(id=>{$(id).value=appearanceValue(id,$(id).value);$(id).addEventListener('input',applyAppearance)});$('themeSelect').onchange=applyAppearance;$('accentSelect').onchange=applyAppearance;applyAppearance();loadDraft();function integrityCheck(){let topicIds=new Set((state.topics||[]).map(t=>t.id)),messageIds=new Set((state.messages||[]).map(m=>m.id)),issues=[];for(const m of state.messages||[]){if(!topicIds.has(m.topic_id))issues.push('orphan message');if(m.reply_to&&!messageIds.has(m.reply_to))issues.push('missing reply target')}for(const f of state.attachments||[])if(!topicIds.has(f.topic_id))issues.push('orphan attachment');if(issues.length)toast('Integrity warning: '+[...new Set(issues)].join(', '));return issues.length===0}setInterval(integrityCheck,30000);
let lastActivity=Date.now(),presenceMode='online';function markActivity(){lastActivity=Date.now();if(presenceMode!=='online'){presenceMode='online';send({type:'presence_status',status:'online'})}}['pointerdown','keydown','touchstart'].forEach(name=>addEventListener(name,markActivity,{passive:true}));setInterval(()=>{let age=Date.now()-lastActivity,next=age>=180000?'away':age>=60000?'idle':'online';if(next!==presenceMode){presenceMode=next;send({type:'presence_status',status:next})}updateExpiry()},1000);connect();

// Hardened local privacy controls.
const toolsHost=document.querySelector('.tools'),onceLabel=document.createElement('label'),voiceButton=document.createElement('button'),roleButton=document.createElement('button'),panicButton=document.createElement('button');onceLabel.innerHTML='<input type="checkbox" id="viewOnce"> ◉ View once';voiceButton.id='voice';voiceButton.className='tool-button';voiceButton.textContent='🎙 Voice';roleButton.className='tool-button';roleButton.textContent='♙ Roles';roleButton.title='Topic owner permissions';panicButton.className='tool-button panic';panicButton.textContent='⚠ Panic';toolsHost.append(onceLabel,voiceButton,roleButton,panicButton);roleButton.onclick=()=>{let people=Object.entries(state.participants||{}).filter(([id])=>id!==state.self_id).map(([id,p])=>`${p.name}: ${id}`).join('\n');let userId=prompt('Participant ID for this topic:\n'+(people||'No other participants'));if(!userId)return;let role=prompt('Role: admin, member, or read_only','member');if(role)send({type:'role_set',topic_id:activeTopic,user_id:userId.trim(),role:role.trim()})};
$('text').maxLength=900;
let recorder=null,voiceParts=[];voiceButton.onclick=async()=>{try{if(recorder&&recorder.state==='recording'){recorder.stop();return}let stream=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true,noiseSuppression:true,channelCount:1}});voiceParts=[];recorder=new MediaRecorder(stream,{audioBitsPerSecond:64000});recorder.ondataavailable=e=>{if(e.data.size)voiceParts.push(e.data)};recorder.onstop=()=>{stream.getTracks().forEach(t=>t.stop());voiceButton.classList.remove('voice-recording');let blob=new Blob(voiceParts,{type:recorder.mimeType||'audio/webm'});if(blob.size>1500000)return toast('Voice note exceeds 1.5 MB');sendFile(new File([blob],'voice-'+Date.now()+'.webm',{type:blob.type}));voiceParts=[]};recorder.start(250);voiceButton.classList.add('voice-recording');toast('Recording — tap again to encrypt and send')}catch(e){toast('Microphone permission was not granted')}};panicButton.onclick=()=>{if(confirm('Panic now? Local data will be erased and Silo will shut down.'))send({type:'panic'})};
const originalSendText=sendText;sendText=function(){let v=$('text').value.trim();if(!v)return;let ttl=selectedTtl();if(ttl===null)return;send({type:'send',topic_id:activeTopic,content:v,reply_to:reply,ttl,mentions:[],view_once:$('viewOnce').checked});$('text').value='';$('viewOnce').checked=false;saveDraft();reply=null;$('replybar').classList.remove('open')};$('send').onclick=sendText;$('text').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendText()}};
const onceLayer=document.createElement('div');onceLayer.className='once-reveal-layer';onceLayer.innerHTML='<section class="once-reveal-card" role="dialog" aria-modal="true" aria-labelledby="onceRevealTitle"><div class="once-reveal-icon">◉</div><small>VIEW ONCE · NOW DELETED FROM THE ROOM</small><h2 id="onceRevealTitle"></h2><div class="once-reveal-content" id="onceRevealContent"></div><button class="action" id="closeOnceReveal">Close and erase from screen</button></section>';document.body.appendChild(onceLayer);const onceStyle=document.createElement('style');onceStyle.textContent='.once-reveal-layer{display:none;position:fixed;z-index:120;inset:0;place-items:center;padding:16px;background:#020307ed;backdrop-filter:blur(24px)}.once-reveal-layer.show{display:grid;animation:veilIn .2s ease}.once-reveal-card{width:min(560px,94vw);max-height:82dvh;box-sizing:border-box;padding:26px;overflow:auto;border:1px solid color-mix(in srgb,var(--a) 50%,#292c38);border-radius:22px;background:#0b0d13;box-shadow:0 35px 100px #000,0 0 55px color-mix(in srgb,var(--a) 16%,transparent);animation:menuBloom .28s cubic-bezier(.2,.9,.2,1)}.once-reveal-icon{display:grid;place-items:center;width:45px;height:45px;margin-bottom:15px;border-radius:50%;color:#fff;background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 30px color-mix(in srgb,var(--a) 35%,transparent)}.once-reveal-card small{color:#8d94a5;font-size:9px;letter-spacing:1.2px}.once-reveal-card h2{margin:7px 0 17px;font-size:15px}.once-reveal-content{padding:17px;border:1px solid #242733;border-radius:14px;background:#07080c;line-height:1.55;user-select:none}.once-reveal-card .action{margin-top:18px}@media(max-width:700px){.once-reveal-layer{padding:9px}.once-reveal-card{width:100%;max-height:90dvh;padding:20px;border-radius:18px}}';document.head.appendChild(onceStyle);function eraseOnceReveal(){onceLayer.classList.remove('show');$('onceRevealContent').replaceChildren();$('onceRevealTitle').textContent=''}function revealViewOnce(data){$('onceRevealTitle').textContent='From '+String(data.username||'User');$('onceRevealContent').innerHTML=renderMarkdown(String(data.content||''));onceLayer.classList.add('show');$('closeOnceReveal').focus()}$('closeOnceReveal').onclick=eraseOnceReveal;document.addEventListener('keydown',e=>{if(e.key==='Escape'&&onceLayer.classList.contains('show'))eraseOnceReveal()});
document.addEventListener('visibilitychange',()=>{if(document.hidden&&onceLayer.classList.contains('show'))eraseOnceReveal()});
// Live microphone capture needs a secure browser context. QR/LAN sessions use
// the phone's native recorder and feed the original audio to E2EE attachments.
if(!window.isSecureContext||!navigator.mediaDevices?.getUserMedia){let capture=document.createElement('input');capture.type='file';capture.accept='audio/*';capture.setAttribute('capture','microphone');capture.className='mobile-audio-capture';document.body.appendChild(capture);voiceButton.onclick=()=>capture.click();capture.onchange=e=>{let file=e.target.files[0];if(file)sendFile(file);e.target.value=''}};if(!window.crypto?.subtle){pinDigest=async value=>{let hash=2166136261;for(let char of 'Silo/local-lock/'+value){hash^=char.charCodeAt(0);hash=Math.imul(hash,16777619)}return String(hash>>>0)}};if(!['127.0.0.1','localhost','::1'].includes(location.hostname))panicButton.remove();
const baseMessageHtml=messageHtml;messageHtml=function(m,q){if(m.view_once&&!m.deleted&&m.sender_id!==state.self_id)return `<div class="sender">${esc(m.username)}</div><div class="bubble"><button class="view-once" data-view-once="${esc(m.id)}">◉ Open once</button><div class="meta">Content will be erased after opening</div></div>`;return baseMessageHtml(m,q)};document.addEventListener('click',e=>{let button=e.target.closest('[data-view-once]');if(button){e.preventDefault();e.stopPropagation();if(confirm('Open this message once? It will be erased for the room immediately.'))send({type:'view_once_open',id:button.dataset.viewOnce})}},true);
let lockDigest='',lockActivity=Date.now(),locked=false;async function pinDigest(v){let raw=await window.crypto.subtle.digest('SHA-256',new TextEncoder().encode('Silo/local-lock/'+v));return [...new Uint8Array(raw)].map(x=>x.toString(16).padStart(2,'0')).join('')}async function lockNow(){if(locked)return;if(!lockDigest){let pin=prompt('Create a local lock PIN (6+ characters)');if(!pin||pin.length<6){lockActivity=Date.now();return toast('Automatic lock needs a 6+ character PIN')}lockDigest=await pinDigest(pin)}locked=true;$('lockScreen').classList.add('show');$('lockPin').value='';$('lockPin').focus()}$('unlock').onclick=async()=>{if(await pinDigest($('lockPin').value)===lockDigest){locked=false;lockActivity=Date.now();$('lockScreen').classList.remove('show')}else toast('Incorrect PIN')};$('lockPin').onkeydown=e=>{if(e.key==='Enter')$('unlock').click()};['pointerdown','keydown','touchstart'].forEach(n=>addEventListener(n,()=>{if(!locked)lockActivity=Date.now()},{passive:true}));setInterval(()=>{if(!locked&&Date.now()-lockActivity>=__AUTO_LOCK_MS__)lockNow()},1000);
document.addEventListener('keyup',e=>{if(e.key==='PrintScreen'){document.body.classList.add('focus-shield');toast('Screenshot protection activated');setTimeout(()=>document.body.classList.remove('focus-shield'),5000)}});

async function openWallpaperStore(){return await new Promise((resolve,reject)=>{let request=indexedDB.open('silo-local-appearance',1);request.onupgradeneeded=()=>request.result.createObjectStore('assets');request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error)})}
async function wallpaperBlob(value){let db=await openWallpaperStore();return await new Promise((resolve,reject)=>{let request=db.transaction('assets','readonly').objectStore('assets').get(value);request.onsuccess=()=>resolve(request.result||null);request.onerror=()=>reject(request.error)})}
async function saveWallpaperBlob(value,blob){let db=await openWallpaperStore();return await new Promise((resolve,reject)=>{let tx=db.transaction('assets','readwrite');tx.objectStore('assets').put(blob,value);tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error)})}
async function removeWallpaperBlob(value){let db=await openWallpaperStore();return await new Promise((resolve,reject)=>{let tx=db.transaction('assets','readwrite');tx.objectStore('assets').delete(value);tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error)})}
let wallpaperObjectUrl='';function wallpaperSetting(key,fallback){try{return localStorage.getItem('silo-wallpaper-'+key)??fallback}catch(e){return fallback}}function storeWallpaperSetting(key,value){try{localStorage.setItem('silo-wallpaper-'+key,String(value))}catch(e){}}
async function setupWallpaper(settingsHost){
 const layer=document.createElement('div');layer.className='silo-wallpaper';layer.setAttribute('aria-hidden','true');document.body.prepend(layer);const wallpaperStyle=document.createElement('style');wallpaperStyle.textContent=`.silo-wallpaper{pointer-events:none;position:fixed;z-index:-4;inset:-24px;background-color:#050609;background-repeat:no-repeat;background-position:center;background-size:cover;opacity:var(--wallpaper-opacity,.72);filter:blur(var(--wallpaper-blur,0px));transform:scale(1.025);transition:opacity .35s,filter .35s,background-position .35s}.app{background:rgba(7,8,11,var(--surface-alpha,.84))!important}.left,.header,.composer{background:rgba(8,9,13,var(--surface-alpha,.84))!important;backdrop-filter:blur(18px)}.minimal-drawer,.minimal-menu,.presence-pop,.composer .tools{background:rgba(10,11,16,var(--surface-alpha,.9))!important}.wallpaper-box .wallpaper-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.wallpaper-box label{display:grid;gap:5px;color:var(--muted);font-size:9px}.wallpaper-box select,.wallpaper-box input[type=range]{width:100%;box-sizing:border-box}.wallpaper-box .wallpaper-wide{grid-column:1/-1}.wallpaper-file{display:none}.wallpaper-preview{height:92px;margin:8px 0;border:1px solid var(--line);border-radius:10px;background:linear-gradient(135deg,color-mix(in srgb,var(--a) 18%,#111),#08090d);background-size:cover;background-position:center;overflow:hidden}.wallpaper-readout{color:#8e95a5;font:9px Consolas,monospace}`;document.head.appendChild(wallpaperStyle);
 const box=document.createElement('div');box.className='box wallpaper-box';box.innerHTML=`<h3>WALLPAPER</h3><div class="wallpaper-preview" id="wallpaperPreview"></div><input class="wallpaper-file" id="wallpaperFile" type="file" accept="image/png,image/jpeg,image/webp,image/gif,image/avif"><button class="action" id="chooseWallpaper">Choose original image</button><div class="wallpaper-grid"><label>Fit<select id="wallpaperFit"><option value="cover">Cover · fill without distortion</option><option value="contain">Contain · show entire image</option><option value="native">Original size</option><option value="tile">Tile original</option></select></label><label>Position<select id="wallpaperPosition"><option value="center center">Center</option><option value="center top">Top</option><option value="center bottom">Bottom</option><option value="left center">Left</option><option value="right center">Right</option><option value="left top">Top left</option><option value="right top">Top right</option><option value="left bottom">Bottom left</option><option value="right bottom">Bottom right</option></select></label><label class="wallpaper-wide">Image opacity <span class="wallpaper-readout" id="wallpaperOpacityValue"></span><input id="wallpaperOpacity" type="range" min="0" max="100" value="72"></label><label>Background blur <span class="wallpaper-readout" id="wallpaperBlurValue"></span><input id="wallpaperBlur" type="range" min="0" max="24" value="0"></label><label>Panel opacity <span class="wallpaper-readout" id="surfaceOpacityValue"></span><input id="surfaceOpacity" type="range" min="35" max="100" value="84"></label></div><button class="action" id="removeWallpaper">Remove wallpaper</button><small>The original file stays on this device. It is never uploaded or recompressed.</small>`;settingsHost.prepend(box);
 const fit=$('wallpaperFit'),position=$('wallpaperPosition'),opacity=$('wallpaperOpacity'),blur=$('wallpaperBlur'),surface=$('surfaceOpacity'),preview=$('wallpaperPreview');fit.value=wallpaperSetting('fit','cover');position.value=wallpaperSetting('position','center center');opacity.value=wallpaperSetting('opacity','72');blur.value=wallpaperSetting('blur','0');surface.value=wallpaperSetting('surface','84');
 function applyWallpaperControls(){let mode=fit.value;layer.style.backgroundSize=mode==='cover'?'cover':mode==='contain'?'contain':'auto';layer.style.backgroundRepeat=mode==='tile'?'repeat':'no-repeat';layer.style.backgroundPosition=position.value;document.documentElement.style.setProperty('--wallpaper-opacity',(+opacity.value/100).toFixed(2));document.documentElement.style.setProperty('--wallpaper-blur',blur.value+'px');document.documentElement.style.setProperty('--surface-alpha',(+surface.value/100).toFixed(2));$('wallpaperOpacityValue').textContent=opacity.value+'%';$('wallpaperBlurValue').textContent=blur.value+' px';$('surfaceOpacityValue').textContent=surface.value+'%';storeWallpaperSetting('fit',mode);storeWallpaperSetting('position',position.value);storeWallpaperSetting('opacity',opacity.value);storeWallpaperSetting('blur',blur.value);storeWallpaperSetting('surface',surface.value)}
 async function displayWallpaper(){let blob=await wallpaperBlob('main');if(wallpaperObjectUrl)URL.revokeObjectURL(wallpaperObjectUrl);wallpaperObjectUrl=blob?URL.createObjectURL(blob):'';layer.style.backgroundImage=wallpaperObjectUrl?`url("${wallpaperObjectUrl}")`:'none';preview.style.backgroundImage=wallpaperObjectUrl?`url("${wallpaperObjectUrl}")`:'';applyWallpaperControls()}
 [fit,position,opacity,blur,surface].forEach(control=>control.addEventListener('input',applyWallpaperControls));$('chooseWallpaper').onclick=()=>$('wallpaperFile').click();$('wallpaperFile').onchange=async e=>{let file=e.target.files[0];if(!file)return;if(!file.type.startsWith('image/'))return toast('Select a valid image');if(file.size>25*1024*1024)return toast('Wallpaper limit: 25 MB');try{await saveWallpaperBlob('main',file);await displayWallpaper();toast('Wallpaper saved locally without recompression')}catch(error){toast('The wallpaper could not be stored')}e.target.value=''};$('removeWallpaper').onclick=async()=>{await removeWallpaperBlob('main');await displayWallpaper();toast('Wallpaper removed')};await displayWallpaper();
}

// Minimal workspace shell. Existing controls are moved, never cloned or removed,
// so all established handlers and security-sensitive flows remain intact.
function setupMinimalWorkspace(){
 const style=document.createElement('style');style.textContent=`
 :root{--nav:232px;--top:58px}body:before,.aurora,.gridfx,.grain{opacity:.22!important}.app{grid-template-columns:var(--nav) minmax(0,1fr)!important;background:#07080b!important}.left{display:flex!important;flex-direction:column!important;padding:16px 12px!important;background:#08090c!important;border-color:#191b22!important}.left>.logo{margin:2px 7px 18px!important}.left>.box,.left>.mobile-mode{display:none!important}.minimal-topics{flex:1;min-height:0;overflow:auto}.minimal-topics:before{content:'TOPICS';display:block;padding:0 9px 8px;color:#656a78;font-size:9px;font-weight:800;letter-spacing:1.4px}.minimal-topics .topicbar{display:flex!important;position:static!important;flex-direction:column;padding:0!important;border:0!important;background:transparent!important;overflow:visible!important}.minimal-topics .topic-wrap{display:flex!important;width:100%;box-sizing:border-box;border:0!important;border-radius:8px!important;background:transparent!important}.minimal-topics .topic{flex:1;text-align:left;padding:9px 10px!important;border:0!important;border-radius:8px!important}.minimal-topics .topic:before{content:'#';margin-right:8px;color:#555b69}.minimal-topics .topic.active{background:#171922!important;color:#fff!important}.minimal-topics .topic-remove{opacity:0}.minimal-topics .topic-wrap:hover .topic-remove{opacity:1}.minimal-topics .topic-add{width:100%;margin-top:5px;color:#8c93a5!important;background:transparent!important}.minimal-topics .topic-add:before{content:'+'!important}.minimal-profile{display:flex;align-items:center;gap:8px;padding:9px 8px;border-top:1px solid #191b22}.minimal-profile-name{flex:1;min-width:0}.minimal-profile-name b,.minimal-profile-name small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.minimal-profile-name small{color:var(--muted);font-size:9px}.mini-btn{display:grid;place-items:center;width:34px;height:34px;border:1px solid transparent;border-radius:9px;color:#9da3b2;background:transparent}.mini-btn:hover{color:#fff;background:#171922;border-color:#242733}.header{height:var(--top)!important;padding:0 16px!important;background:#090a0eeb!important}.room-title b{font-size:14px!important}.secure{padding:4px 7px!important;margin-left:7px!important}.header-actions .clear-request,.header-actions>.icon-button:not(#openSearch){display:none!important}.people{cursor:pointer}.minimal-overflow{position:relative}.minimal-menu{display:none;position:absolute;z-index:45;right:0;top:42px;width:220px;padding:6px;border:1px solid #242733;border-radius:12px;background:#0d0f14f5;box-shadow:0 22px 65px #000b;backdrop-filter:blur(18px)}.minimal-menu.show{display:block;animation:fadeIn .15s}.minimal-menu button{display:flex;width:100%;gap:9px;padding:10px;border-radius:8px;color:#cbd0da;background:transparent;text-align:left}.minimal-menu button:hover{background:#191c25;color:#fff}.minimal-menu .danger{color:#ff8a9c}.topicbar-placeholder{display:none}.composer{padding:10px 14px 14px!important;background:#090a0e!important}.composer .tools{display:none;position:absolute;z-index:35;left:14px;bottom:76px;width:min(310px,calc(100vw - 28px));max-height:55vh;overflow:auto;box-sizing:border-box;padding:9px;gap:5px!important;flex-direction:column;align-items:stretch!important;border:1px solid #242733;border-radius:14px;background:#0d0f14f7;box-shadow:0 20px 65px #000b;backdrop-filter:blur(18px)}.composer .tools.show{display:flex}.composer .tools>*{width:100%;box-sizing:border-box;justify-content:flex-start!important;margin:0!important;padding:9px!important;border-radius:8px!important}.write{gap:8px!important}.composer-plus{flex:0 0 42px;width:42px;border-radius:13px;color:#aeb4c2;background:#15171e;border:1px solid #242733;font-size:20px}.write textarea{min-height:42px!important;padding:11px 13px!important;border-color:#20232c!important;background:#101217!important}.send{width:42px!important;box-shadow:none!important}.right{display:none!important}.minimal-drawer-layer{display:none;position:fixed;z-index:60;inset:0;background:#0008;backdrop-filter:blur(5px)}.minimal-drawer-layer.show{display:block}.minimal-drawer{position:absolute;right:0;top:0;width:min(420px,92vw);height:100%;box-sizing:border-box;padding:18px;overflow:auto;border-left:1px solid #242733;background:#0a0b0f;animation:drawerIn .22s ease}.minimal-drawer-head{position:sticky;z-index:2;top:-18px;display:flex;align-items:center;justify-content:space-between;margin:-18px -18px 15px;padding:18px;background:#0a0b0ff2;border-bottom:1px solid #191b22}.minimal-drawer-head h2{margin:0;font-size:15px}.minimal-drawer-content>.box,.minimal-drawer-content>.mobile-mode{display:block!important;margin:8px 0!important;border-color:#1f222b!important;background:#0e1015!important}.minimal-drawer-content .box:hover{transform:none!important;box-shadow:none!important}.minimal-drawer-content .box:before{display:none}.drawer-tabs{display:flex;gap:5px;margin-bottom:12px}.drawer-tabs button{flex:1;padding:8px;border-radius:8px;color:#858b99;background:#111319}.drawer-tabs button.active{color:#fff;background:#1d2029}.presence-pop{display:none;position:fixed;z-index:48;right:16px;top:64px;width:260px;max-height:55vh;overflow:auto;padding:12px;border:1px solid #242733;border-radius:13px;background:#0d0f14f6;box-shadow:0 20px 60px #000a}.presence-pop.show{display:block}.presence-pop h3{margin:3px 3px 10px;font-size:10px;color:#777e8d;letter-spacing:1px}@keyframes drawerIn{from{transform:translateX(35px);opacity:0}}main{grid-template-rows:var(--top) minmax(0,1fr) auto auto!important}.header{grid-row:1!important}.messages{grid-row:2!important}.typing{grid-row:3!important}.replybar{grid-row:4!important}.composer{grid-row:5!important}.pins{position:absolute;z-index:9;top:65px;left:12px;right:12px;border:1px solid #292c37!important;border-radius:9px!important}.minimal-mobile-topics{display:none}
 /* Theme-synchronised motion system: transforms and opacity stay on the GPU. */
 .app:after{content:'';pointer-events:none;position:fixed;z-index:-1;width:42vw;height:42vw;right:-15vw;bottom:-22vw;border-radius:50%;background:radial-gradient(circle,color-mix(in srgb,var(--a) 15%,transparent),transparent 68%);filter:blur(34px);animation:ambientDrift 13s ease-in-out infinite alternate}.mark{background:linear-gradient(135deg,var(--a),var(--b))!important;box-shadow:0 0 28px color-mix(in srgb,var(--a) 32%,transparent)!important}.minimal-topics .topic,.mini-btn,.composer-plus,.minimal-menu button,.drawer-tabs button,.tool-button{position:relative;overflow:hidden;transition:color .18s ease,background .18s ease,border-color .18s ease,transform .18s cubic-bezier(.2,.8,.2,1),box-shadow .22s ease!important}.minimal-topics .topic:hover,.minimal-menu button:hover,.tool-button:hover{transform:translateX(3px)!important}.minimal-topics .topic.active{background:linear-gradient(105deg,color-mix(in srgb,var(--a) 22%,#12141a),color-mix(in srgb,var(--b) 10%,#12141a))!important;box-shadow:inset 3px 0 var(--a),0 8px 24px color-mix(in srgb,var(--a) 10%,transparent)!important;animation:activeTopicIn .35s cubic-bezier(.2,.9,.2,1)}.minimal-topics .topic.active:after{content:'';position:absolute;inset:0;background:linear-gradient(110deg,transparent 20%,color-mix(in srgb,var(--a) 16%,transparent) 48%,transparent 75%);transform:translateX(-120%);animation:accentSweep 4.8s ease-in-out infinite}.mini-btn:hover,.composer-plus:hover{color:#fff!important;border-color:color-mix(in srgb,var(--a) 55%,#242733)!important;background:color-mix(in srgb,var(--a) 13%,#15171e)!important;box-shadow:0 8px 24px color-mix(in srgb,var(--a) 15%,transparent)!important;transform:translateY(-2px)}.composer-plus.open{color:#fff;background:linear-gradient(135deg,var(--a),var(--b));border-color:transparent;transform:rotate(45deg) scale(1.04);box-shadow:0 8px 26px color-mix(in srgb,var(--a) 28%,transparent)}.send{background:linear-gradient(135deg,var(--a),var(--b))!important;box-shadow:0 7px 22px color-mix(in srgb,var(--a) 22%,transparent)!important}.send:hover{transform:translateY(-2px) scale(1.04)!important;box-shadow:0 11px 30px color-mix(in srgb,var(--a) 35%,transparent)!important}.send.sending{animation:sendPulse .46s cubic-bezier(.2,.9,.2,1)!important}.minimal-menu.show{transform-origin:top right;animation:menuBloom .2s cubic-bezier(.2,.9,.2,1)}.composer .tools.show{transform-origin:bottom left;animation:menuBloom .22s cubic-bezier(.2,.9,.2,1)}.minimal-drawer-layer.show{animation:veilIn .2s ease}.minimal-drawer-layer.show .minimal-drawer{animation:drawerSpring .32s cubic-bezier(.16,1,.3,1)}.presence-pop.show{transform-origin:top right;animation:menuBloom .2s cubic-bezier(.2,.9,.2,1)}.presence-row{transition:background .18s,transform .18s}.presence-row:hover{padding-left:5px;border-radius:7px;background:color-mix(in srgb,var(--a) 8%,transparent);transform:translateX(2px)}.presence-dot.online{animation:presenceGlow 2.2s ease-in-out infinite}.msg .bubble{transition:transform .2s cubic-bezier(.2,.8,.2,1),border-color .2s,box-shadow .2s!important}.msg:hover .bubble{transform:translateY(-2px)!important;box-shadow:0 12px 32px #0008,0 0 0 1px color-mix(in srgb,var(--a) 20%,transparent)!important}.msg.mine .bubble{background:linear-gradient(135deg,var(--a),var(--b))!important;background-size:160% 160%!important;animation:bubbleFlow 9s ease infinite}.minimal-drawer-content>.box{animation:panelRise .32s both}.minimal-drawer-content>.box:nth-child(2){animation-delay:.035s}.minimal-drawer-content>.box:nth-child(3){animation-delay:.07s}.minimal-drawer-content>.box:nth-child(4){animation-delay:.105s}.ui-ripple{pointer-events:none;position:absolute;border-radius:50%;background:color-mix(in srgb,var(--a) 32%,white);transform:translate(-50%,-50%) scale(0);animation:rippleOut .55s ease-out forwards}.accent-flash{animation:accentFlash .5s ease}
 @keyframes ambientDrift{to{transform:translate(-10vw,-7vh) scale(1.18);opacity:.7}}@keyframes activeTopicIn{from{opacity:.4;transform:translateX(-9px)}}@keyframes accentSweep{0%,62%{transform:translateX(-120%)}85%,100%{transform:translateX(120%)}}@keyframes menuBloom{from{opacity:0;transform:translateY(8px) scale(.95);filter:blur(5px)}to{opacity:1;transform:none;filter:none}}@keyframes drawerSpring{from{transform:translateX(45px);opacity:.2}to{transform:none;opacity:1}}@keyframes veilIn{from{opacity:0}}@keyframes sendPulse{40%{transform:translate(5px,-4px) rotate(-8deg) scale(1.12);filter:brightness(1.35)}}@keyframes presenceGlow{50%{box-shadow:0 0 15px color-mix(in srgb,var(--ok) 70%,transparent);filter:brightness(1.25)}}@keyframes bubbleFlow{50%{background-position:100% 50%}}@keyframes panelRise{from{opacity:0;transform:translateY(10px)}}@keyframes rippleOut{to{transform:translate(-50%,-50%) scale(4);opacity:0}}@keyframes accentFlash{50%{box-shadow:0 0 0 3px color-mix(in srgb,var(--a) 22%,transparent),0 0 34px color-mix(in srgb,var(--a) 22%,transparent)}}
 .drawer-section{display:none}.drawer-section.active{display:block}.drawer-section>.box,.drawer-section>.mobile-mode{display:block!important;margin:8px 0!important;border-color:#1f222b!important;background:#0e1015!important}.drawer-section>.box:hover,.drawer-section>.mobile-mode:hover{transform:none!important;box-shadow:none!important}.drawer-section>.box:before{display:none!important}.drawer-empty{padding:24px;color:var(--muted);text-align:center}.minimal-drawer-content #stats{display:block!important}.minimal-drawer-content #stats .stat-group{margin-top:16px}.minimal-drawer-content #stats .stat{padding:8px 2px}.left-mobile-close{display:none}
 @media(max-width:700px){:root{--nav:0px}.app{display:grid!important;grid-template-columns:1fr!important}.left{display:none!important}.left.mobile-open{display:flex!important;position:fixed;z-index:70;inset:0 auto 0 0;width:min(286px,86vw);box-sizing:border-box;box-shadow:25px 0 80px #000d;animation:drawerLeft .28s cubic-bezier(.16,1,.3,1)}.left.mobile-open .left-mobile-close{display:grid;position:absolute;right:10px;top:10px}.minimal-mobile-topics{display:grid;place-items:center}.header-actions{gap:4px!important}.room-title small{max-width:42vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.composer .tools{bottom:70px}.msg{max-width:90%!important}}@keyframes drawerLeft{from{transform:translateX(-35px);opacity:.2}}
 @media(prefers-reduced-motion:reduce){.app:after{display:none}.minimal-topics .topic.active:after,.presence-dot.online,.msg.mine .bubble{animation:none!important}.ui-ripple{display:none!important}}
 /* Keep dropdowns visible and permanently suppress lateral navigation scroll. */
 .header{position:relative!important;z-index:42!important;overflow:visible!important}.header-actions,.minimal-overflow{overflow:visible!important}.minimal-menu{z-index:90!important}.left{min-width:0!important;overflow-x:hidden!important}.minimal-topics{min-width:0!important;overflow-x:hidden!important;overflow-y:auto!important;scrollbar-width:thin}.minimal-topics .topicbar{width:100%!important;min-width:0!important;box-sizing:border-box!important;overflow-x:hidden!important;overflow-y:visible!important}.minimal-topics .topic-wrap,.minimal-topics .topic{min-width:0!important;max-width:100%!important;box-sizing:border-box!important}.minimal-profile{min-width:0;width:100%;box-sizing:border-box;overflow:hidden}.minimal-profile-name{min-width:0}.left::-webkit-scrollbar:horizontal,.minimal-topics::-webkit-scrollbar:horizontal,.topicbar::-webkit-scrollbar:horizontal{display:none!important;height:0!important}
 /* Complete phone/tablet layout, including QR-access sessions. */
 html,body{max-width:100%;overscroll-behavior:none}body{overflow:hidden!important}.app,main,.header,.composer,.write{min-width:0!important;max-width:100%!important;box-sizing:border-box!important}.mobile-audio-capture{display:none!important}
 @media(max-width:820px){:root{--top:56px}button,.action,.tool-button,select,input{min-height:44px}.app{width:100vw!important;height:var(--silo-vh,100dvh)!important;grid-template-columns:minmax(0,1fr)!important}.left{display:none!important}.left.mobile-open{display:flex!important;width:min(310px,88vw)!important;padding-top:max(16px,env(safe-area-inset-top))!important;padding-bottom:max(12px,env(safe-area-inset-bottom))!important}.minimal-mobile-topics{display:grid!important}.header{width:100%!important;padding-left:max(10px,env(safe-area-inset-left))!important;padding-right:max(10px,env(safe-area-inset-right))!important;gap:6px}.room-title{min-width:0;flex:1}.room-title b{display:block;max-width:42vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.room-title small{max-width:46vw!important}.secure{display:none!important}.header-actions{flex:0 0 auto;gap:3px!important}.header-actions #openSearch{width:42px;padding:0!important;justify-content:center}.header-actions #openSearch span{display:none}.people{max-width:64px!important}.people .avatar:nth-child(n+3){display:none}.minimal-menu{position:fixed!important;left:10px!important;right:10px!important;top:auto!important;bottom:max(10px,env(safe-area-inset-bottom))!important;width:auto!important;max-height:70dvh;overflow-y:auto;border-radius:18px!important;padding:9px!important;transform-origin:bottom center!important}.minimal-menu button{min-height:48px;font-size:13px}.messages{width:100%!important;padding:14px 10px!important;gap:11px!important;scrollbar-width:none}.messages::-webkit-scrollbar{display:none}.msg{max-width:88%!important}.bubble{padding:11px 13px!important;border-radius:16px!important}.composer{width:100%!important;padding:8px max(9px,env(safe-area-inset-right)) max(8px,env(safe-area-inset-bottom)) max(9px,env(safe-area-inset-left))!important}.write{width:100%;align-items:stretch}.write textarea{min-height:44px!important;max-height:min(112px,24dvh)!important;font-size:16px!important}.composer-plus,.send{flex:0 0 44px!important;width:44px!important;min-height:44px}.composer .tools{position:fixed!important;z-index:75!important;left:8px!important;right:8px!important;bottom:max(68px,calc(env(safe-area-inset-bottom) + 58px))!important;width:auto!important;max-height:62dvh!important;border-radius:18px!important}.composer .tools>*{min-height:46px!important}.typing{padding:3px 11px!important}.replybar{padding:8px 12px!important}.minimal-drawer{width:100vw!important;max-width:none!important;padding:16px max(14px,env(safe-area-inset-right)) max(18px,env(safe-area-inset-bottom)) max(14px,env(safe-area-inset-left))!important;border-left:0!important}.minimal-drawer-head{top:-16px;margin:-16px max(-14px,calc(-1 * env(safe-area-inset-right))) 13px;padding:max(15px,env(safe-area-inset-top)) 14px 13px}.presence-pop{position:fixed!important;left:8px!important;right:8px!important;top:64px!important;width:auto!important;max-height:60dvh;border-radius:16px!important}.search-panel{padding:0!important;align-items:stretch!important}.search-dialog{width:100vw!important;max-width:none!important;height:var(--silo-vh,100dvh)!important;max-height:none!important;border:0!important;border-radius:0!important}.search-head{padding:max(12px,env(safe-area-inset-top)) 12px 10px}.search-head input{font-size:16px}.search-filters{max-height:30dvh;overflow:auto;padding:9px 12px}.search-filters input{width:100%!important;box-sizing:border-box}.search-results{padding:9px 10px max(14px,env(safe-area-inset-bottom))}.ctx{position:fixed!important;z-index:85!important;left:8px!important;right:8px!important;top:auto!important;bottom:max(8px,env(safe-area-inset-bottom))!important;width:auto!important;border-radius:17px!important;padding:8px!important}.ctx button{min-height:47px}.clear-modal{padding:10px}.clear-dialog{width:100%!important;box-sizing:border-box;padding:20px!important}.toast{left:10px!important;right:10px!important;bottom:max(76px,calc(env(safe-area-inset-bottom) + 66px))!important;text-align:center}.wallpaper-box .wallpaper-grid{grid-template-columns:1fr!important}.wallpaper-box .wallpaper-wide{grid-column:auto!important}.file-card audio,.file-card img{max-width:100%!important}.poll-card{width:calc(100% - 8px)!important;box-sizing:border-box}}
 @media(min-width:821px) and (max-width:1180px){:root{--nav:210px}.right{display:none!important}.minimal-drawer{width:min(440px,70vw)}}
 /* Wallpaper must be above the root paint layer but below every UI surface. */
 body{isolation:isolate!important}.silo-wallpaper{display:block!important;visibility:visible!important;z-index:0!important}.aurora,.gridfx,.grain{z-index:0!important}.app{position:relative!important;z-index:1!important}
 `;document.head.appendChild(style);
 const app=document.querySelector('.app'),left=document.querySelector('.left'),right=document.querySelector('.right'),header=document.querySelector('.header'),composer=document.querySelector('.composer'),write=document.querySelector('.write'),tools=document.querySelector('.tools'),topicsNode=$('topics');
 const topicHost=document.createElement('nav');topicHost.className='minimal-topics';topicHost.appendChild(topicsNode);left.insertBefore(topicHost,left.children[1]||null);
 const storedLeft=[...left.querySelectorAll(':scope > .box,:scope > .mobile-mode')],profile=document.createElement('div');profile.className='minimal-profile';profile.innerHTML=`<div class="avatar">${esc((state.username||'U')[0])}</div><div class="minimal-profile-name"><b>${esc(state.username||'User')}</b><small>Encrypted session</small></div><button class="mini-btn" data-open-drawer="settings" title="Settings">⚙</button>`;left.appendChild(profile);const leftClose=document.createElement('button');leftClose.className='mini-btn left-mobile-close';leftClose.textContent='✕';leftClose.title='Close topics';left.appendChild(leftClose);
 const plus=document.createElement('button');plus.className='composer-plus';plus.title='More actions';plus.textContent='+';write.insertBefore(plus,write.firstChild);plus.onclick=e=>{e.stopPropagation();tools.classList.toggle('show');plus.classList.toggle('open',tools.classList.contains('show'))};tools.onclick=e=>e.stopPropagation();
 const overflow=document.createElement('div');overflow.className='minimal-overflow';overflow.innerHTML=`<button class="mini-btn" id="roomMenuButton" title="Room menu">•••</button><div class="minimal-menu" id="roomMenu"><button data-menu="search">⌕ Search messages</button><button data-menu="participants">♙ Participants</button><button data-menu="details">♢ Security center</button><button data-menu="stats">⌁ Statistics & diagnostics</button><button data-menu="settings">⚙ Settings</button><button data-menu="privacy">◉ Privacy mode</button><button class="danger" data-menu="delete">⌫ Delete chat</button></div>`;header.querySelector('.header-actions').insertBefore(overflow,header.querySelector('.people'));
 const mobileTopics=document.createElement('button');mobileTopics.className='mini-btn minimal-mobile-topics';mobileTopics.textContent='#';mobileTopics.title='Topics';header.querySelector('.header-actions').prepend(mobileTopics);
 const drawerLayer=document.createElement('div');drawerLayer.className='minimal-drawer-layer';drawerLayer.innerHTML='<section class="minimal-drawer"><div class="minimal-drawer-head"><h2 id="drawerTitle">Details</h2><button class="mini-btn" id="closeDrawer">✕</button></div><div class="drawer-tabs" id="drawerTabs"></div><div class="minimal-drawer-content" id="drawerContent"></div></section>';document.body.appendChild(drawerLayer);const drawerContent=$('drawerContent'),drawerTitle=$('drawerTitle');
 const settingsBucket=document.createElement('div');settingsBucket.className='drawer-section';settingsBucket.dataset.section='settings';storedLeft.forEach(n=>settingsBucket.appendChild(n));const detailsBucket=document.createElement('div');detailsBucket.className='drawer-section';detailsBucket.dataset.section='details';while(right.firstChild)detailsBucket.appendChild(right.firstChild);drawerContent.append(settingsBucket,detailsBucket);setupWallpaper(settingsBucket).catch(()=>toast('Wallpaper storage is unavailable in this browser'));
 function closeDrawer(){drawerLayer.classList.remove('show')}function showBucket(kind){drawerTitle.textContent=kind==='settings'?'Settings':'Security & room details';settingsBucket.classList.toggle('active',kind==='settings');detailsBucket.classList.toggle('active',kind==='details');drawerLayer.classList.add('show')}
 $('closeDrawer').onclick=closeDrawer;drawerLayer.onclick=e=>{if(e.target===drawerLayer)closeDrawer()};
 const presencePop=document.createElement('div');presencePop.className='presence-pop';presencePop.innerHTML='<h3>PARTICIPANTS</h3>';const presenceList=$('presenceList');presencePop.appendChild(presenceList);document.body.appendChild(presencePop);header.querySelector('.people').onclick=e=>{e.stopPropagation();presencePop.classList.toggle('show')};
 $('roomMenuButton').onclick=e=>{e.stopPropagation();$('roomMenu').classList.toggle('show')};$('roomMenu').onclick=e=>{let action=e.target.closest('[data-menu]')?.dataset.menu;if(!action)return;$('roomMenu').classList.remove('show');if(action==='search')$('openSearch').click();else if(action==='participants')presencePop.classList.toggle('show');else if(action==='details')showBucket('details');else if(action==='stats'){showBucket('details');requestAnimationFrame(()=>$('stats')?.scrollIntoView({behavior:'smooth',block:'start'}))}else if(action==='settings')showBucket('settings');else if(action==='privacy')$('privacyMode').click();else if(action==='delete')$('clearChat').click()};
 profile.querySelector('[data-open-drawer]').onclick=()=>showBucket('settings');mobileTopics.onclick=e=>{e.stopPropagation();left.classList.add('mobile-open')};leftClose.onclick=()=>left.classList.remove('mobile-open');
 document.addEventListener('pointerdown',e=>{let button=e.target.closest('button');if(!button||matchMedia('(prefers-reduced-motion: reduce)').matches)return;let rect=button.getBoundingClientRect(),ripple=document.createElement('i'),size=Math.max(rect.width,rect.height);ripple.className='ui-ripple';ripple.style.cssText=`width:${size}px;height:${size}px;left:${e.clientX-rect.left}px;top:${e.clientY-rect.top}px`;button.appendChild(ripple);setTimeout(()=>ripple.remove(),600)},true);
 document.addEventListener('click',e=>{tools.classList.remove('show');plus.classList.remove('open');$('roomMenu').classList.remove('show');presencePop.classList.remove('show');if(left.classList.contains('mobile-open')&&!left.contains(e.target))left.classList.remove('mobile-open')});document.addEventListener('keydown',e=>{if(e.key==='Escape'){tools.classList.remove('show');plus.classList.remove('open');$('roomMenu').classList.remove('show');presencePop.classList.remove('show');left.classList.remove('mobile-open');closeDrawer()}});
 ['themeSelect','accentSelect','customBg','customPanel','customText','customAccent','customAccent2'].forEach(id=>$(id)?.addEventListener('change',()=>{app.classList.remove('accent-flash');requestAnimationFrame(()=>app.classList.add('accent-flash'));setTimeout(()=>app.classList.remove('accent-flash'),550)}));
}
function applyFeatureVisibility(){let f=state.settings?.features;if(!f)return;let show=(node,enabled)=>{if(node)node.style.display=enabled?'':'none'};show($('openSearch'),f.search);show(document.querySelector('[data-menu="search"]'),f.search);show(document.querySelector('[data-menu="participants"]'),f.presence);show(document.querySelector('.people'),f.presence);show(document.querySelector('.minimal-topics'),f.topics);show(document.querySelector('.minimal-mobile-topics'),f.topics);show($('attach'),f.attachments);show($('voice'),f.attachments&&f.voice_notes);show($('createPoll'),f.polls);show($('viewOnce')?.closest('label'),f.view_once);show($('expire')?.closest('label'),f.disappearing);show($('ttl'),f.disappearing);show(document.querySelector('.wallpaper-box'),f.wallpapers);show(document.querySelector('[data-menu="details"]'),f.security_panel);show(document.querySelector('[data-menu="stats"]'),f.statistics);show($('securityCenter'),f.security_panel);show($('stats'),f.statistics);show($('diagnostics')?.closest('.box'),f.statistics);show(document.querySelector('.panic'),f.panic)}
setupMinimalWorkspace();const renderWithFeatures=render;render=function(){renderWithFeatures();applyFeatureVisibility()};
</script></body></html>'''

# UI security hardening for view-once content and per-topic unread indicators.
CLIENT_ENHANCEMENTS = r'''
<style>
.topic-unread-dot{display:inline-block;width:8px;height:8px;margin-left:8px;border-radius:50%;background:var(--a);box-shadow:0 0 0 0 color-mix(in srgb,var(--a) 65%,transparent);vertical-align:middle;animation:topicUnreadPulse 1.45s ease-in-out infinite}
.topic-rename{width:24px;height:24px;padding:0;border:1px solid var(--line);border-radius:7px;color:var(--muted);background:#11141b;cursor:pointer;transition:.18s}.topic-rename:hover{color:#fff;border-color:var(--a);transform:translateY(-1px)}.topic-add:disabled{opacity:.5;cursor:not-allowed}
.silo-wallpaper{z-index:0!important;inset:-28px!important}.app{background:rgba(4,5,8,var(--surface-alpha,.84))!important}.messages{background:rgba(1,2,5,var(--wallpaper-message-alpha,.52))!important;backdrop-filter:blur(1px)}.topicbar,.typing{background:rgba(3,4,7,var(--wallpaper-message-alpha,.52))!important}.left,.header,.composer{background:rgba(6,7,11,var(--surface-alpha,.84))!important}
.ctx-reactions{display:grid;grid-template-columns:repeat(5,1fr);gap:4px;padding:5px;margin:2px 0 5px;border:1px solid var(--line);border-radius:10px;background:#ffffff05}.ctx-reactions button{display:grid!important;place-items:center!important;min-width:30px!important;min-height:34px!important;padding:4px!important;font-size:18px!important;text-align:center!important}.ctx-reactions button:hover{transform:translateY(-2px) scale(1.08);background:color-mix(in srgb,var(--a) 18%,#14161c)!important}
.msg.is-highlighted{position:relative}.msg.is-highlighted:before{content:'★';position:absolute;z-index:2;top:16px;left:-20px;color:#ffd76a;font-size:13px;filter:drop-shadow(0 0 7px #ffc857)}.msg.is-highlighted .sender{color:#ffe39a;font-weight:750}.msg.is-highlighted .bubble{border-color:#ffd166!important;box-shadow:0 0 0 1px #ffd16655,0 12px 38px #0009,0 0 30px #f5b64235!important;background-image:linear-gradient(135deg,#f3bc2618,transparent 44%)!important}.msg.mine.is-highlighted .bubble{background-image:linear-gradient(135deg,#68551f55,transparent 38%),linear-gradient(135deg,var(--a),var(--b))!important}
@keyframes topicUnreadPulse{50%{transform:scale(1.32);box-shadow:0 0 0 7px transparent;filter:brightness(1.35)}}
.once-reveal-layer.capture-shield .once-reveal-card{position:relative;isolation:isolate;-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
.once-reveal-layer.capture-shield .once-reveal-card:after{content:attr(data-watermark);pointer-events:none;position:absolute;z-index:3;inset:42% -12%;color:#fff1;font:700 12px/1.8 Consolas,monospace;letter-spacing:2px;text-align:center;transform:rotate(-18deg);white-space:pre-wrap}
.once-security-note{margin-top:12px;color:#949bad;font-size:10px;letter-spacing:.3px}
@media print{.once-reveal-layer,.once-reveal-layer *{display:none!important;visibility:hidden!important}}
</style>
<script>
(()=>{
 const unreadTopics=new Map(),knownMessages=new Set();let unreadPrimed=false,onceEraseTimer=0,onceCountdownTimer=0;
 const oldReactButton=$('ctx').querySelector('[data-a="react"]'),reactionPicker=document.createElement('div');if(oldReactButton)oldReactButton.style.display='none';reactionPicker.className='ctx-reactions';reactionPicker.setAttribute('aria-label','Choose a reaction');reactionPicker.innerHTML=['👍','❤️','😂','🔥','✅'].map(emoji=>`<button type="button" data-quick-reaction="${emoji}" title="React ${emoji}">${emoji}</button>`).join('');oldReactButton?.after(reactionPicker);reactionPicker.onclick=event=>{let button=event.target.closest('[data-quick-reaction]');if(!button||!active)return;event.preventDefault();event.stopPropagation();send({type:'reaction',id:active.id,emoji:button.dataset.quickReaction});$('ctx').style.display='none'};
 const surfaceControl=$('surfaceOpacity');function syncWallpaperSurface(){let value=Math.max(.08,Math.min(.78,(+(surfaceControl?.value||84)/100)*.68));document.documentElement.style.setProperty('--wallpaper-message-alpha',value.toFixed(2))}surfaceControl?.addEventListener('input',syncWallpaperSurface);syncWallpaperSurface();
 function decorateUnread(){document.querySelectorAll('[data-topic]').forEach(button=>{let topic=button.dataset.topic,old=button.querySelector('.topic-unread-dot');if(unreadTopics.has(topic)&&topic!==activeTopic){if(!old){let dot=document.createElement('i');dot.className='topic-unread-dot';dot.title=`${unreadTopics.get(topic)} unread message(s)`;dot.setAttribute('aria-label',dot.title);button.appendChild(dot)}}else old?.remove()})}
 renderTopics=function(){
  let atLimit=state.topics.length>=20;
  $('topics').innerHTML=state.topics.map(topic=>{let owner=topic.id!=='lobby'&&String(topic.created_by)===String(state.self_id);return `<span class="topic-wrap"><button class="topic ${topic.id===activeTopic?'active':''}" data-topic="${esc(topic.id)}">${esc(topic.name)}</button>${owner?`<button class="topic-rename" data-rename="${esc(topic.id)}" title="Rename topic">✎</button><button class="topic-remove" data-remove="${esc(topic.id)}" title="Delete topic">×</button>`:''}</span>`}).join('')+`<button class="topic topic-add" data-add="1" ${atLimit?'disabled title="Maximum of 20 topics reached"':''}>${atLimit?'20 topics maximum':'Create topic'}</button>`;
  $('topics').onclick=event=>{let button=event.target.closest('button');if(!button||button.disabled)return;if(button.dataset.add){let name=prompt('Topic name');if(!name)return;let id=name.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g,'-').replace(/^-|-$/g,'').toLowerCase().slice(0,48)||('topic-'+Date.now());send({type:'topic_create',topic_id:id,name})}else if(button.dataset.rename){let topic=state.topics.find(item=>item.id===button.dataset.rename),name=prompt('New topic name',topic?.name||'');if(name&&name.trim())send({type:'topic_rename',topic_id:button.dataset.rename,name:name.trim()})}else if(button.dataset.remove){let id=button.dataset.remove,topic=state.topics.find(item=>item.id===id);if(confirm(`Delete #${topic?.name||id}? Its local messages and attachments will be removed for everyone.`)){send({type:'topic_delete',topic_id:id});if(activeTopic===id)activeTopic='lobby'}}else{saveDraft();activeTopic=button.dataset.topic;unreadTopics.delete(activeTopic);loadDraft();reply=null;render()}}
 };
 const renderBeforeUnread=render;
 render=function(){
  if(!unreadPrimed){state.messages.forEach(message=>knownMessages.add(message.id));unreadPrimed=true}
  else for(const message of state.messages){if(!knownMessages.has(message.id)){knownMessages.add(message.id);if(message.sender_id!==state.self_id&&message.topic_id!==activeTopic)unreadTopics.set(message.topic_id,(unreadTopics.get(message.topic_id)||0)+1)}}
  unreadTopics.delete(activeTopic);renderBeforeUnread();for(const message of state.messages)rendered.get(message.id)?.classList.toggle('is-highlighted',!!message.highlighted);decorateUnread();let permissionButton=document.querySelector('[title="Topic owner permissions"]'),topic=state.topics.find(item=>item.id===activeTopic);if(permissionButton)permissionButton.style.display=topic&&topic.id!=='lobby'&&String(topic.created_by)===String(state.self_id)?'':'none'
 };
 function eraseProtectedView(reason){clearTimeout(onceEraseTimer);clearInterval(onceCountdownTimer);if(onceLayer.classList.contains('show')){eraseOnceReveal();onceLayer.classList.remove('capture-shield');onceLayer.querySelector('.once-reveal-card')?.removeAttribute('data-watermark');if(reason)toast(reason)}}
 const revealBeforeProtection=revealViewOnce;
 revealViewOnce=function(data){revealBeforeProtection(data);let card=onceLayer.querySelector('.once-reveal-card'),remaining=15;onceLayer.classList.add('capture-shield');card.dataset.watermark=`SILO VIEW ONCE · ${state.username||state.self_id||'AUTHORIZED USER'} · ${new Date().toISOString()}`;let note=document.createElement('div');note.className='once-security-note';note.id='onceSecurityNote';note.textContent=`Protected view · closes in ${remaining}s · closes if focus is lost`;$('onceRevealContent').after(note);onceCountdownTimer=setInterval(()=>{remaining--;if(note.isConnected)note.textContent=`Protected view · closes in ${remaining}s · closes if focus is lost`},1000);onceEraseTimer=setTimeout(()=>eraseProtectedView('View-once content erased'),15000)};
 const eraseBeforeProtection=eraseOnceReveal;
 eraseOnceReveal=function(){clearTimeout(onceEraseTimer);clearInterval(onceCountdownTimer);$('onceSecurityNote')?.remove();onceLayer.classList.remove('capture-shield');onceLayer.querySelector('.once-reveal-card')?.removeAttribute('data-watermark');eraseBeforeProtection()};
 $('closeOnceReveal').onclick=()=>eraseProtectedView();
 window.addEventListener('blur',()=>eraseProtectedView('Protected content hidden when focus was lost'));
 document.addEventListener('visibilitychange',()=>{if(document.hidden)eraseProtectedView('Protected content hidden when the app was backgrounded')});
 document.addEventListener('keydown',event=>{if(event.key==='PrintScreen'&&onceLayer.classList.contains('show')){event.preventDefault();eraseProtectedView('Screenshot attempt detected; protected content erased');navigator.clipboard?.writeText('').catch(()=>{})}},true);
 for(const type of ['copy','cut','contextmenu','dragstart'])onceLayer.addEventListener(type,event=>{if(onceLayer.classList.contains('show'))event.preventDefault()},true);
})();
</script>
'''
HTML = HTML.replace("</body></html>", CLIENT_ENHANCEMENTS + "</body></html>")


def is_local_request(request: web.Request) -> bool:
    """Only the browser on the computer hosting this client is an administrator."""
    return (request.remote or "") in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def link_allowed(request: web.Request) -> bool:
    expected = str(CONFIG.get("web_access_token", ""))
    supplied = request.query.get("access", "") or request.cookies.get("silo_link", "")
    return bool(expected) and hmac.compare_digest(supplied, expected)


def new_mobile_session() -> str:
    expires = int(time.time()) + 8 * 60 * 60
    payload = f"v1:{expires}".encode()
    key = _unb64(mobile_auth["session_key"])
    signature = hmac.new(key, payload, hashlib.sha256).digest()
    return f"{expires}.{_b64(signature)}"


def mobile_session_allowed(request: web.Request) -> bool:
    if not mobile_password_configured():
        return False
    try:
        expires_raw, signature = request.cookies.get("silo_mobile_session", "").split(".", 1)
        expires = int(expires_raw)
        if expires < int(time.time()) or expires > int(time.time()) + 8 * 60 * 60 + 60:
            return False
        payload = f"v1:{expires}".encode()
        expected = _b64(hmac.new(_unb64(mobile_auth["session_key"]), payload, hashlib.sha256).digest())
        return hmac.compare_digest(signature, expected)
    except (AttributeError, KeyError, ValueError):
        return False


def access_allowed(request: web.Request) -> bool:
    return is_local_request(request) or (FEATURES["mobile_access"] and link_allowed(request) and mobile_session_allowed(request))


def secure_response(text: str, status: int = 200) -> web.Response:
    response = web.Response(status=status, text=text, content_type="text/html", charset="utf-8")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def local_mobile_controls() -> str:
    if not FEATURES["mobile_access"]:
        return '<div class="box"><h3>MOBILE ACCESS</h3><small>Disabled by the generated client configuration.</small></div>'
    status = "Password enabled" if mobile_password_configured() else "No password: the QR code will not allow mobile access"
    return f'''<div class="box"><h3>MOBILE ACCESS</h3><div class="qr-wrap"><img src="/qr.png" alt="Mobile access QR code"><div><b>Scan with your phone</b><small>Same Wi-Fi network</small></div></div><div class="mobile-link">http://{LAN_IP}:{CONFIG["port"]}</div><button class="action" id="copyMobile">⧉ Copy secure link</button></div>
<div class="box mobile-protection"><h3>MOBILE PASSWORD</h3><p class="protect-status" id="mobilePasswordStatus">{status}</p><input class="pw-input" id="mobilePassword" type="password" minlength="12" autocomplete="new-password" placeholder="New password (12+ characters)"><input class="pw-input" id="mobilePasswordConfirm" type="password" minlength="12" autocomplete="new-password" placeholder="Repeat password"><button class="action" id="saveMobilePassword">Save / replace password</button><small>Only this local browser can change it. A Scrypt verifier is stored, never the plaintext password. Changing it closes existing mobile sessions.</small></div>'''


MOBILE_LOGIN_HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Mobile access · Silo Client</title><style>body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#070a12;color:#edf2fb;font:15px Inter,Segoe UI,sans-serif}body:before{content:"";position:fixed;inset:-30%;background:radial-gradient(circle at 30% 30%,#6e7cff55,transparent 28%),radial-gradient(circle at 80% 70%,#a855f744,transparent 30%);filter:blur(65px);animation:f 12s ease-in-out infinite alternate}@keyframes f{to{transform:scale(1.15) rotate(13deg)}}main{position:relative;width:min(92vw,390px);padding:30px;border:1px solid #33415c;border-radius:22px;background:#101722dd;box-shadow:0 30px 80px #0009;backdrop-filter:blur(18px)}.mark{display:grid;place-items:center;width:48px;height:48px;border-radius:15px;background:linear-gradient(135deg,#6e7cff,#a855f7);font-size:22px;font-weight:800;box-shadow:0 0 30px #6e7cff88}h1{font-size:22px;margin:18px 0 8px}p{color:#9aa8bd;line-height:1.5}input,button{width:100%;box-sizing:border-box;font:inherit;border-radius:12px}input{margin:17px 0 10px;padding:13px;background:#080c13;border:1px solid #34435c;color:#fff;outline:0}input:focus{border-color:#7684ff;box-shadow:0 0 0 3px #6e7cff22}button{padding:13px;border:0;color:#fff;background:linear-gradient(135deg,#6e7cff,#a855f7);font-weight:700;cursor:pointer}.error{min-height:20px;margin-top:12px;color:#ff8aa0;font-size:13px}</style></head><body><main><div class="mark">S</div><h1>Silo Client</h1><p>Enter the password configured on the computer to open this chat on your phone.</p><input id="password" type="password" autocomplete="current-password" autofocus placeholder="Access password"><button id="enter">Open chat</button><div class="error" id="error"></div></main><script>const p=document.getElementById('password'),b=document.getElementById('enter'),e=document.getElementById('error');async function login(){b.disabled=true;e.textContent='';try{const r=await fetch('/api/mobile-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p.value})}),d=await r.json();if(!r.ok)throw Error(d.message||'Access denied');location.replace('/')}catch(x){e.textContent=x.message;b.disabled=false;p.focus()}}b.onclick=login;p.onkeydown=x=>{if(x.key==='Enter')login()}</script></body></html>'''


MOBILE_NOT_CONFIGURED_HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Silo Client</title><style>body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#070a12;color:#edf2fb;font:16px Segoe UI,sans-serif}main{width:min(90vw,410px);padding:30px;border:1px solid #33415c;border-radius:20px;background:#101722;text-align:center}b{color:#aeb7ff}</style></head><body><main><h2>Mobile protection pending</h2><p>The owner must first configure a password in the computer local interface.</p><p><b>Scan the QR code again after configuring it.</b></p></main></body></html>'''


def app_response(request: web.Request) -> web.Response:
    local = is_local_request(request)
    safe_display = f'http://{LAN_IP}:{CONFIG["port"]}'
    html = (HTML.replace("__CHANNEL__", str(CONFIG["channel_id"]))
                .replace("__MOBILE_LOCAL_CONTROLS__", local_mobile_controls() if local else "")
                .replace("__MOBILE_URL_DISPLAY__", safe_display)
                .replace("__MOBILE_URL__", mobile_url() if local else "")
                .replace("__AUTO_LOCK_MS__", str(AUTO_LOCK_SECONDS * 1000)))
    response = secure_response(html)
    if not local and link_allowed(request):
        response.set_cookie("silo_link", str(CONFIG["web_access_token"]), httponly=True, samesite="Strict", max_age=8 * 60 * 60)
    return response


async def index(request: web.Request):
    if is_local_request(request):
        return app_response(request)
    if not FEATURES["mobile_access"]:
        return secure_response("<h1>Mobile access disabled</h1>", 403)
    if not link_allowed(request):
        return secure_response("<h1>Access denied</h1><p>Scan the Silo Client QR code to sign in.</p>", 403)
    if not mobile_password_configured():
        response = secure_response(MOBILE_NOT_CONFIGURED_HTML, 423)
        response.set_cookie("silo_link", str(CONFIG["web_access_token"]), httponly=True, samesite="Strict", max_age=8 * 60 * 60)
        return response
    if not mobile_session_allowed(request):
        response = secure_response(MOBILE_LOGIN_HTML)
        response.set_cookie("silo_link", str(CONFIG["web_access_token"]), httponly=True, samesite="Strict", max_age=8 * 60 * 60)
        return response
    return app_response(request)


async def set_mobile_password_endpoint(request: web.Request):
    if not is_local_request(request):
        raise web.HTTPForbidden(text="Only the local interface can change the mobile password")
    try:
        data = await request.json()
        password = data.get("password", "")
        confirmation = data.get("confirmation", "")
    except (json.JSONDecodeError, AttributeError):
        return web.json_response({"message": "Invalid request"}, status=400)
    if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
        return web.json_response({"message": "The password must contain between 12 and 256 characters"}, status=400)
    if password != confirmation:
        return web.json_response({"message": "Passwords do not match"}, status=400)
    set_mobile_password(password)
    return web.json_response({"ok": True, "message": "Mobile password updated"}, headers={"Cache-Control": "no-store"})


async def mobile_login_endpoint(request: web.Request):
    if not link_allowed(request):
        return web.json_response({"message": "Invalid or expired QR link"}, status=403)
    if not mobile_password_configured():
        return web.json_response({"message": "The owner has not configured a mobile password yet"}, status=423)
    try:
        password = (await request.json()).get("password", "")
    except (json.JSONDecodeError, AttributeError):
        return web.json_response({"message": "Invalid request"}, status=400)
    if not isinstance(password, str) or not verify_mobile_password(password):
        await asyncio.sleep(0.35)
        return web.json_response({"message": "Incorrect password"}, status=401)
    response = web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})
    response.set_cookie("silo_mobile_session", new_mobile_session(), httponly=True, samesite="Strict", max_age=8 * 60 * 60)
    return response


async def qr_image(request: web.Request):
    if not is_local_request(request):
        raise web.HTTPForbidden()
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=7, border=3)
    qr.add_data(mobile_url())
    qr.make(fit=True)
    image = qr.make_image(fill_color="#111827", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return web.Response(body=buffer.getvalue(), content_type="image/png", headers={"Cache-Control": "private, max-age=3600"})


async def attachment_download(request: web.Request):
    if not access_allowed(request):
        raise web.HTTPForbidden()
    transfer = attachments.get(request.match_info["transfer_id"])
    if not transfer or transfer.get("status") != "ready" or not isinstance(transfer.get("bytes"), bytes):
        raise web.HTTPNotFound(text="Attachment unavailable")
    disposition = "inline" if request.query.get("preview") == "1" and str(transfer["mime"]).startswith(("image/", "audio/", "text/", "application/pdf")) else "attachment"
    safe_name = str(transfer["name"]).replace('"', "").replace("\\", "_")
    return web.Response(body=transfer["bytes"], content_type=transfer["mime"], headers={
        "Cache-Control": "no-store", "Content-Disposition": f'{disposition}; filename="{safe_name}"',
        "X-Content-Type-Options": "nosniff"})


async def run_web():
    app = web.Application(client_max_size=3_000_000)
    app.router.add_get("/", index)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_get("/qr.png", qr_image)
    app.router.add_get("/api/attachment/{transfer_id}", attachment_download)
    app.router.add_post("/api/mobile-password", set_mobile_password_endpoint)
    app.router.add_post("/api/mobile-login", mobile_login_endpoint)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    requested_port = int(CONFIG["port"])
    site = None
    for offset in range(101):
        candidate = requested_port + offset
        if candidate > 65535:
            candidate = 1024 + (candidate - 65536)
        try:
            candidate_site = web.TCPSite(runner, "0.0.0.0", candidate)
            await candidate_site.start()
            site = candidate_site
            CONFIG["port"] = candidate
            if candidate != requested_port:
                print(f"[INFO] Port {requested_port} was busy; this client is using {candidate}")
            break
        except OSError:
            continue
    if site is None:
        await runner.cleanup()
        raise RuntimeError(f"No free local web port was found near {requested_port}")
    url = f'http://127.0.0.1:{CONFIG["port"]}/'
    print(f'[OK] Silo Client Web UI local: http://127.0.0.1:{CONFIG["port"]}')
    print(f'[OK] Mobile LAN access ready at: http://{LAN_IP}:{CONFIG["port"]} (use the QR)')
    await asyncio.sleep(0.6)
    try: webbrowser.open(url)
    except Exception: pass
    await asyncio.Event().wait()


async def main():
    global last_visible_ids
    required = ["bot_token", "server_id", "channel_id", "shared_key", "kdf_salt", "web_access_token", "user_id", "username", "port"]
    if DUAL_LAYER:
        required.append("secondary_key")
    missing = [key for key in required if not CONFIG.get(key)]
    if missing:
        raise SystemExit("Incomplete configuration: " + ", ".join(missing))
    load_history()
    last_visible_ids = current_visible_ids()
    start_panic_hotkey(asyncio.get_running_loop())
    print(f'Silo Client · {username} · http://127.0.0.1:{CONFIG["port"]}')
    # Client.start() does not accept the log_handler option used by Client.run().
    # Keep this call compatible with discord.py 2.x and Python 3.14.
    await asyncio.gather(client.start(CONFIG["bot_token"]), run_web(), maintenance_loop())


if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\nSilo Client closed")
