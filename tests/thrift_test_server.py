#!/usr/bin/env python3
"""
Thrift Binary Framed Test Server — DeathStarBench Social Network Emulator
==========================================================================
Emulates the inter-service RPC topology of DeathStarBench's Social Network:

  Client
    └─▶ FrontendService (port 9090)   compose_post(username, text)
              └─▶ BackendService  (port 9091)   store_post(post_id, content)

Both services use the Apache Thrift Strict-Binary Framed wire protocol over
plain TCP — exactly the same as the C++ services in DeathStarBench.

NO external thrift library is required: the protocol is implemented by hand
so you can run this test without installing anything beyond the Python stdlib.

Usage
-----
  # Terminal 1 — start back-end (PostStorageService)
  python3 thrift_test_server.py --role backend --port 9091

  # Terminal 2 — start front-end (ComposePostService)
  python3 thrift_test_server.py --role frontend --port 9090

  # Terminal 3 — attach the sniffer to both PIDs
  sudo python3 ../src/new-architecture-USC.py -p <frontend_pid> <backend_pid>

  # Terminal 4 — send requests
  python3 thrift_test_client.py

Thrift Strict-Binary Framed Wire Format
----------------------------------------
  [4 B  frame_size  BE u32]         ← TFramedTransport header
  [4 B  version|type BE u32]        ← 0x80_01_00_TT  (TT: 1=CALL 2=REPLY)
  [4 B  name_len    BE u32]
  [N B  method_name UTF-8]
  [4 B  seq_id      BE i32]
  [fields …]                         ← field_type (1B) + field_id (2B) + value
  [0x00]                             ← STOP sentinel
"""

import socket
import struct
import threading
import argparse
import time
import os
import hashlib
import random

# ─── Thrift type codes ────────────────────────────────────────────────────────
T_STOP   = 0
T_BOOL   = 2
T_I32    = 5
T_I64    = 6
T_STRING = 11
T_LIST   = 15

MSG_CALL    = 1
MSG_REPLY   = 2
MSG_ONEWAY  = 4

# ─── Low-level framing helpers ────────────────────────────────────────────────

def _recv_exactly(sock, n: int) -> bytes:
    """Read exactly n bytes from sock, raising ConnectionError on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return buf


def read_frame(sock) -> bytes:
    """Read one Thrift frame (4-byte size prefix + body) and return the body."""
    size_bytes = _recv_exactly(sock, 4)
    frame_size = struct.unpack(">I", size_bytes)[0]
    return _recv_exactly(sock, frame_size)


def write_frame(sock, body: bytes):
    """Write one Thrift frame (4-byte size prefix + body)."""
    sock.sendall(struct.pack(">I", len(body)) + body)


# ─── Encoding helpers ─────────────────────────────────────────────────────────

def encode_message_header(method: str, msg_type: int, seq_id: int) -> bytes:
    """Encode a strict-binary Thrift message header."""
    name = method.encode("utf-8")
    hdr  = struct.pack(">I", 0x80010000 | msg_type)   # version + type
    hdr += struct.pack(">I", len(name)) + name
    hdr += struct.pack(">i", seq_id)
    return hdr


def encode_string_field(field_id: int, value: str) -> bytes:
    v = value.encode("utf-8")
    return struct.pack(">BHI", T_STRING, field_id, len(v)) + v


def encode_i32_field(field_id: int, value: int) -> bytes:
    return struct.pack(">BHi", T_I32, field_id, value)


def encode_i64_field(field_id: int, value: int) -> bytes:
    return struct.pack(">BHq", T_I64, field_id, value)


def encode_stop() -> bytes:
    return struct.pack(">B", T_STOP)


# ─── Decoding helpers ─────────────────────────────────────────────────────────

def decode_message_header(body: bytes):
    """Return (method, msg_type, seq_id, offset_after_header)."""
    version = struct.unpack(">I", body[0:4])[0]
    if (version >> 16) != 0x8001:
        raise ValueError(f"Not strict binary: {hex(version)}")
    msg_type = version & 0xFF
    name_len = struct.unpack(">I", body[4:8])[0]
    method   = body[8:8 + name_len].decode("utf-8")
    seq_id   = struct.unpack(">i", body[8 + name_len:12 + name_len])[0]
    return method, msg_type, seq_id, 12 + name_len


def decode_fields(body: bytes, offset: int) -> dict:
    """Decode field_id → value pairs until STOP; ignores unsupported types."""
    fields = {}
    while offset < len(body):
        ftype = body[offset]; offset += 1
        if ftype == T_STOP:
            break
        fid = struct.unpack(">H", body[offset:offset+2])[0]; offset += 2
        if ftype == T_I32:
            fields[fid] = struct.unpack(">i", body[offset:offset+4])[0]; offset += 4
        elif ftype == T_I64:
            fields[fid] = struct.unpack(">q", body[offset:offset+8])[0]; offset += 8
        elif ftype == T_STRING:
            slen = struct.unpack(">I", body[offset:offset+4])[0]; offset += 4
            fields[fid] = body[offset:offset+slen].decode("utf-8", errors="replace")
            offset += slen
        else:
            # Skip unknown type gracefully
            break
    return fields


# ─── BackendService  (PostStorageService) ─────────────────────────────────────

class BackendService:
    """
    Mimics PostStorageService from DeathStarBench Social Network.

    Methods:
      store_post(post_id: i64, creator: string, content: string) -> i32
      get_post   (post_id: i64)                                  -> string
    """

    def __init__(self):
        self._store: dict = {}   # post_id → (creator, content)

    # ── Real work: allocate memory, hash, CPU-spin ──────────────────
    def _store_work(self, post_id: int, creator: str, content: str) -> str:
        """Mimic persistence work: index words, hash content, spin."""
        # 32 KB scratch buffer written with content bytes
        payload = bytearray(32 * 1024)
        encoded = content.encode()
        for i, b in enumerate(encoded):
            payload[i % len(payload)] ^= b

        # Build an in-memory word index (heap allocation)
        words = content.split()
        index = {w: [j for j, x in enumerate(words) if x == w] for w in set(words)}

        # Multi-round SHA-256 (CPU work, ~200+ rounds)
        digest = hashlib.sha256(content.encode())
        rounds = 200 + (post_id % 50) * 3
        for _ in range(rounds):
            digest = hashlib.sha256(digest.digest() + creator.encode())

        # Spin for 5–10 s to produce measurable CPU burst events
        spin_until = time.monotonic() + 5.0 + random.uniform(0, 5)
        acc = 0
        while time.monotonic() < spin_until:
            acc ^= random.getrandbits(32)

        return digest.hexdigest()

    def handle(self, method: str, seq_id: int, fields: dict) -> bytes:
        request_id = f"{method}_seq{seq_id}"
        if method == "store_post":
            post_id = fields.get(1, 0)
            creator = fields.get(2, "")
            content = fields.get(3, "")
            print(f"  [backend]  [RECV] request_id={request_id}  post_id={post_id} creator={creator!r}")
            chksum  = self._store_work(post_id, creator, content)
            self._store[post_id] = (creator, content)
            print(f"  [backend]  [DONE] request_id={request_id}  chksum={chksum[:12]}")
            # Reply: field 0 = success (i32 = 0)
            reply_fields = encode_i32_field(0, 0)
        elif method == "get_post":
            post_id = fields.get(1, 0)
            entry   = self._store.get(post_id, ("", "<not found>"))
            result  = f"creator={entry[0]} content={entry[1]}"
            print(f"  [backend] get_post    post_id={post_id}")
            reply_fields = encode_string_field(0, result)
        else:
            print(f"  [backend] unknown method: {method!r}")
            reply_fields = encode_i32_field(0, -1)

        body  = encode_message_header(method, MSG_REPLY, seq_id)
        body += reply_fields + encode_stop()
        return body


# ─── FrontendService  (ComposePostService) ────────────────────────────────────

class FrontendService:
    """
    Mimics ComposePostService from DeathStarBench Social Network.

    Accepts:
      compose_post(username: string, text: string) -> i32

    Internally calls BackendService.store_post() to persist the post.
    """

    def __init__(self, backend_host: str, backend_port: int):
        self._backend_host = backend_host
        self._backend_port = backend_port
        self._seq          = 0
        self._post_counter = 0
        self._lock         = threading.Lock()

    # ── Real work: validate/enrich the post before forwarding ───────
    def _compose_work(self, post_id: int, username: str, text: str) -> str:
        """Simulate compose-pipeline work: allocate, deduplicate, spin."""
        # 16 KB scratch buffer for text normalisation
        buf = bytearray(16 * 1024)
        for i, b in enumerate(text.encode()):
            buf[i % len(buf)] = b ^ (i & 0xFF)

        # Build mention/hashtag lists (heap allocation)
        words    = text.split()
        mentions = [w for w in words if w.startswith("@")]
        hashtags = [w for w in words if w.startswith("#")]
        enriched = {"username": username, "post_id": post_id,
                    "mentions": mentions, "tags": hashtags,
                    "words": [w.lower() for w in words]}

        # Multi-round BLAKE2b digest (CPU work)
        digest = hashlib.blake2b(text.encode(), key=username.encode()[:16].ljust(16, b'\x00'))
        rounds = 150 + (post_id % 40) * 2
        for _ in range(rounds):
            digest = hashlib.blake2b(digest.digest())

        # Spin 5–10 s
        spin_until = time.monotonic() + 5.0 + random.uniform(0, 5)
        acc = 0
        while time.monotonic() < spin_until:
            acc ^= random.getrandbits(16)

        return digest.hexdigest()

    def _call_backend(self, method: str, fields_bytes: bytes) -> dict:
        """Make a synchronous Thrift CALL to the backend, return reply fields."""
        with self._lock:
            self._seq += 1
            seq = self._seq

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self._backend_host, self._backend_port))
            body  = encode_message_header(method, MSG_CALL, seq)
            body += fields_bytes + encode_stop()
            write_frame(sock, body)

            reply_body = read_frame(sock)
            _, _, _, off = decode_message_header(reply_body)
            return decode_fields(reply_body, off)
        finally:
            sock.close()

    def handle(self, method: str, seq_id: int, fields: dict) -> bytes:
        request_id = f"{method}_seq{seq_id}"
        if method == "compose_post":
            username = fields.get(1, "anonymous")
            text     = fields.get(2, "")
            print(f"  [frontend] [RECV] request_id={request_id}  username={username!r}  text={text[:40]!r}")

            with self._lock:
                self._post_counter += 1
                post_id = self._post_counter

            # Run compose pipeline work (allocate, hash, spin)
            digest = self._compose_work(post_id, username, text)
            print(f"  [frontend] [DONE] request_id={request_id}  digest={digest[:12]}")

            # Call backend to persist
            be_fields  = encode_i64_field(1, post_id)
            be_fields += encode_string_field(2, username)
            be_fields += encode_string_field(3, text)
            reply = self._call_backend("store_post", be_fields)
            rc = reply.get(0, -1)
            print(f"  [frontend] backend replied: rc={rc}")
            reply_fields = encode_i32_field(0, post_id)
        else:
            print(f"  [frontend] unknown method: {method!r}")
            reply_fields = encode_i32_field(0, -1)

        body  = encode_message_header(method, MSG_REPLY, seq_id)
        body += reply_fields + encode_stop()
        return body


# ─── Generic TCP server ───────────────────────────────────────────────────────

def serve_client(conn: socket.socket, addr, service):
    """Handle one persistent client connection."""
    print(f"  [server] new connection from {addr}")
    try:
        while True:
            body = read_frame(conn)
            method, msg_type, seq_id, off = decode_message_header(body)
            fields = decode_fields(body, off)
            reply_body = service.handle(method, seq_id, fields)
            write_frame(conn, reply_body)
    except (ConnectionError, struct.error, BrokenPipeError, OSError):
        pass
    finally:
        conn.close()
        print(f"  [server] connection closed: {addr}")


def run_server(host: str, port: int, service, label: str):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    print(f"[{label}] listening on {host}:{port}   PID={os.getpid()}")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=serve_client, args=(conn, addr, service),
                             daemon=True)
        t.start()


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DeathStarBench Social Network Thrift service emulator")
    ap.add_argument("--role", choices=["frontend", "backend"], required=True,
                    help="Which service to run")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=None,
                    help="Listen port  (default: 9090 for frontend, 9091 for backend)")
    ap.add_argument("--backend-host", default="127.0.0.1",
                    help="Backend host for frontend to call (default: 127.0.0.1)")
    ap.add_argument("--backend-port", type=int, default=9091,
                    help="Backend port for frontend to call (default: 9091)")
    args = ap.parse_args()

    if args.role == "backend":
        port    = args.port or 9091
        service = BackendService()
        run_server(args.host, port, service, "BackendService / PostStorageService")
    else:
        port    = args.port or 9090
        service = FrontendService(args.backend_host, args.backend_port)
        run_server(args.host, port, service, "FrontendService / ComposePostService")


if __name__ == "__main__":
    main()
