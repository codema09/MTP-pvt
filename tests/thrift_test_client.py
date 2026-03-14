#!/usr/bin/env python3
"""
Thrift Binary Framed Test Client — DeathStarBench Social Network Emulator
==========================================================================
Sends compose_post() RPC calls to the FrontendService, emulating the wrk2
load generator used against DeathStarBench.

Supports sequential mode (default) and concurrent mode (--concurrency N).

Usage
-----
  # Single-threaded, 5 requests:
  python3 thrift_test_client.py --count 5

  # 4 concurrent clients, 10 requests each:
  python3 thrift_test_client.py --concurrency 4 --count 10

  # Target a remote frontend:
  python3 thrift_test_client.py --host 192.168.1.10 --port 9090
"""

import socket
import struct
import threading
import argparse
import time
import random
import string

# ─── Thrift protocol constants ────────────────────────────────────────────────
T_STOP   = 0
T_I32    = 5
T_I64    = 6
T_STRING = 11
MSG_CALL = 1
MSG_REPLY = 2

# ─── Framing helpers ──────────────────────────────────────────────────────────

def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def write_frame(sock, body: bytes):
    sock.sendall(struct.pack(">I", len(body)) + body)


def read_frame(sock) -> bytes:
    size = struct.unpack(">I", _recv_exactly(sock, 4))[0]
    return _recv_exactly(sock, size)


# ─── Encoding ─────────────────────────────────────────────────────────────────

def encode_string_field(fid: int, value: str) -> bytes:
    v = value.encode("utf-8")
    return struct.pack(">BHI", T_STRING, fid, len(v)) + v


def encode_i32_field(fid: int, value: int) -> bytes:
    return struct.pack(">BHi", T_I32, fid, value)


def encode_i64_field(fid: int, value: int) -> bytes:
    return struct.pack(">BHq", T_I64, fid, value)


def build_call(method: str, seq_id: int, fields_bytes: bytes) -> bytes:
    name = method.encode("utf-8")
    hdr  = struct.pack(">I", 0x80010000 | MSG_CALL)
    hdr += struct.pack(">I", len(name)) + name
    hdr += struct.pack(">i", seq_id)
    return hdr + fields_bytes + struct.pack(">B", T_STOP)


# ─── Decoding ─────────────────────────────────────────────────────────────────

def decode_reply(body: bytes):
    """Return the first i32 field from a reply (the return value / post_id)."""
    version = struct.unpack(">I", body[0:4])[0]
    if (version >> 16) != 0x8001:
        return None
    name_len = struct.unpack(">I", body[4:8])[0]
    off = 12 + name_len   # skip method name + seq_id
    while off < len(body):
        ftype = body[off]; off += 1
        if ftype == T_STOP:
            break
        fid = struct.unpack(">H", body[off:off+2])[0]; off += 2
        if ftype == T_I32:
            val = struct.unpack(">i", body[off:off+4])[0]; off += 4
            return val
        elif ftype == T_STRING:
            slen = struct.unpack(">I", body[off:off+4])[0]; off += 4 + slen
        else:
            break
    return None


# ─── Workload helpers ─────────────────────────────────────────────────────────

USERNAMES = ["alice", "bob", "carol", "dave", "eve", "frank", "grace"]

def random_text(words=8) -> str:
    vocab = ["cloud", "service", "latency", "benchmark", "post", "social",
             "network", "thread", "memory", "ebpf", "trace", "monitor"]
    return " ".join(random.choices(vocab, k=words))


# ─── Client logic ─────────────────────────────────────────────────────────────

class ThriftClient:
    """Opens a fresh TCP connection for every RPC call.

    Each call gets its own connection so the server spawns a dedicated
    thread per request.  That thread exits after sending the reply,
    which fires the eBPF exit-event and triggers per-request stats.
    """

    def __init__(self, host: str, port: int):
        self.host  = host
        self.port  = port
        self._seq  = 0
        self._lock = threading.Lock()

    def compose_post(self, username: str, text: str) -> int:
        with self._lock:
            self._seq += 1
            seq = self._seq
        fields  = encode_string_field(1, username)
        fields += encode_string_field(2, text)
        body    = build_call("compose_post", seq, fields)

        # Fresh connection per request — server thread exits after reply.
        request_id = f"compose_post_seq{seq}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host, self.port))
            print(f"  → [SEND] request_id={request_id}")
            write_frame(sock, body)
            reply = read_frame(sock)
        finally:
            sock.close()
        return seq, decode_reply(reply) or -1

    def close(self):
        pass  # nothing persistent to close


def worker(host: str, port: int, count: int, results: list,
           worker_id: int, verbose: bool):
    """Send `count` compose_post calls and record latencies."""
    try:
        client = ThriftClient(host, port)
    except Exception as e:
        print(f"[worker-{worker_id}] connect failed: {e}")
        return

    for i in range(count):
        username = random.choice(USERNAMES)
        text     = random_text()
        t0 = time.perf_counter()
        try:
            seq, post_id = client.compose_post(username, text)
            latency = (time.perf_counter() - t0) * 1000
            results.append(latency)
            if verbose:
                print(f"  [worker-{worker_id}] req {i+1:4d}: "
                      f"seq={seq:<4d} username={username:<8} post_id={post_id:5d}  "
                      f"latency={latency:.2f} ms")
        except Exception as e:
            print(f"  [worker-{worker_id}] req {i+1:4d}: ERROR {e}")

    client.close()


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DeathStarBench-style Thrift client for compose_post")
    ap.add_argument("--host",        default="127.0.0.1")
    ap.add_argument("--port",        type=int, default=9090)
    ap.add_argument("--count",       type=int, default=5,
                    help="Requests per worker thread (default: 5)")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="Number of concurrent worker threads (default: 1)")
    ap.add_argument("--delay",       type=float, default=0.3,
                    help="Seconds between requests per worker (default: 0.3)")
    ap.add_argument("--verbose",     action="store_true", default=True)
    args = ap.parse_args()

    print(f"Sending {args.count} request(s) × {args.concurrency} worker(s)  "
          f"→  {args.host}:{args.port}")
    print()

    all_results: list = []
    lock = threading.Lock()

    def wrapped_worker(wid):
        local = []
        worker(args.host, args.port, args.count, local, wid, args.verbose)
        with lock:
            all_results.extend(local)

    threads = [threading.Thread(target=wrapped_worker, args=(i,), daemon=True)
               for i in range(args.concurrency)]

    t_start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t_start

    if all_results:
        total   = len(all_results)
        avg_ms  = sum(all_results) / total
        min_ms  = min(all_results)
        max_ms  = max(all_results)
        p99_ms  = sorted(all_results)[int(total * 0.99)]
        rps     = total / elapsed
        print()
        print("=" * 55)
        print(f"  Total requests : {total}")
        print(f"  Elapsed        : {elapsed:.2f} s")
        print(f"  Throughput     : {rps:.1f} req/s")
        print(f"  Latency avg    : {avg_ms:.2f} ms")
        print(f"  Latency min    : {min_ms:.2f} ms")
        print(f"  Latency max    : {max_ms:.2f} ms")
        print(f"  Latency p99    : {p99_ms:.2f} ms")
        print("=" * 55)
    else:
        print("No successful requests.")


if __name__ == "__main__":
    main()
