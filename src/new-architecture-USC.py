#!/usr/bin/env python3
"""
Integrated HTTPS Server Sniffer & Resource Profiler (FINAL FIXED + IO + Disk + CPU Burst/Cycles)
==============================================================================================
- Added: CPU Burst Tracking (Avg Duration, Count, Total Duration).
- Added: CPU Cycle Tracking (Avg Cycles, Total Cycles).
- Maintained: Original Table layouts are untouched.
- Maintained: All previous IO/Disk/Memory tracking.

Usage: sudo python3 integrated_sniffer_full.py -p <PID1> [PID2 ...]
"""

from bcc import BPF, PerfType, PerfHWConfig
import hashlib
import socket
import struct
import ctypes
import time
import re
import os
import sys
import argparse
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

LOG_FILENAME = "memory_debug.log"

# ═══════════════════════════════════════════════════════════════
# BPF PROGRAM LOADER
# ═══════════════════════════════════════════════════════════════

# Directory containing the modular eBPF source files (relative to this script)
EBPF_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ebpf")

# Files are loaded in dependency order: headers first, then implementations
BPF_SOURCE_FILES = [
    # Headers (order matters: common -> maps -> helpers)
    "include/common.h",
    "include/maps.h",
    "include/helpers.h",
    # Tracepoints & Uprobes
    "tracepoints/cpu_tracking.c",
    "tracepoints/io_tracking.c",
    "tracepoints/conn_tracking.c",
    "uprobes/ssl_interception.c",
    "tracepoints/lifecycle.c",
    "tracepoints/memory_tracking.c",
]

def load_bpf_program(num_cpus):
    """Read all eBPF source files, concatenate, and substitute runtime values."""
    parts = []
    for relpath in BPF_SOURCE_FILES:
        filepath = os.path.join(EBPF_SRC_DIR, relpath)
        with open(filepath, "r") as f:
            parts.append(f"// === {relpath} ===\n")
            parts.append(f.read())
            parts.append("\n")

    program = "".join(parts)
    program = program.replace("__NUM_CPUS__", str(num_cpus))
    return program


class IntegratedSnifferFull:
    def __init__(self, pids):
        self.pids = list(pids)          # list of tracked PIDs
        self.pid = self.pids[0]         # primary PID (used for /proc lookups)
        self.bpf = None
        self.request_buffers = {}
        self.request_counter = 0
        self.recorded_requests = []
        self.pending_conn_events = {}  # tid -> [(src_ip, src_port, dst_ip, dst_port)]

        # Prepare Log File
        self.log_file = open(LOG_FILENAME, "w")
        self.log_file.write(f"TIMESTAMP             | TID   | EVENT | SIZE (KB) | CURRENT TID RSS (KB) | PFN\n")
        self.log_file.write("-" * 90 + "\n")

    def ip_to_str(self, ip):
        try:
            return socket.inet_ntoa(struct.pack("<I", ip))
        except Exception:
            return "0.0.0.0"

    def parse_http_headers(self, data):
        try:
            text = data.decode('utf-8', errors='ignore')
            header_end = text.find('\r\n\r\n')
            if header_end == -1:
                header_end = text.find('\n\n')
                if header_end == -1: header_end = len(text)
            return text[:header_end]
        except:
            return ""

    def extract_request_id(self, headers_text):
        for line in headers_text.split('\n'):
            line = line.strip()
            if line.lower().startswith('x-request-id:'):
                return line[13:].strip()[:63]
        first_line = headers_text.split('\n')[0] if headers_text else ""
        match = re.search(r'[?&]id=([^&\s]+)', first_line)
        if match: return match.group(1)[:63]
        self.request_counter += 1
        return f"AUTO_{self.request_counter:06d}"

    def extract_user_info(self, headers_text):
        user_info = {'username': '', 'cookie': '', 'authorization': '',
                     'has_username': False, 'has_cookie': False, 'has_authorization': False}
        try:
            for line in headers_text.split('\n'):
                line = line.strip()
                if line.lower().startswith('cookie:'):
                    cookie_value = line[7:].strip()
                    user_info['cookie'] = cookie_value[:255]
                    user_info['has_cookie'] = True
                    for part in cookie_value.split(';'):
                        part = part.strip()
                        if '=' in part:
                            key, val = part.split('=', 1)
                            if key.lower() in ['user', 'username', 'user_id']:
                                user_info['username'] = val[:63]
                                user_info['has_username'] = True
                                break
                elif line.lower().startswith('authorization:'):
                    auth_value = line[14:].strip()
                    user_info['authorization'] = auth_value[:127]
                    user_info['has_authorization'] = True
                    if auth_value.lower().startswith('basic '):
                        try:
                            import base64
                            decoded = base64.b64decode(auth_value[6:]).decode('utf-8', 'ignore')
                            if ':' in decoded:
                                user_info['username'] = decoded.split(':')[0][:63]
                                user_info['has_username'] = True
                        except: pass
                elif not user_info['has_username']:
                    if line.lower().startswith('x-user:') or line.lower().startswith('x-username:'):
                        colon_pos = line.find(':')
                        if colon_pos > 0:
                            user_info['username'] = line[colon_pos+1:].strip()[:63]
                            user_info['has_username'] = True
        except: pass
        return user_info

    def update_user_history(self, username, request_id, tid, src_ip, src_port):
        if not username: return
        try:
            user_history_map = self.bpf.get_table("user_request_history")
            username_key = user_history_map.Key(name=username.encode('utf-8')[:63])
            try:
                history = user_history_map[username_key]
            except KeyError:
                history = user_history_map.Leaf(username=username.encode('utf-8')[:63], request_count=0)
            
            idx = history.request_count
            if idx >= 100:
                for i in range(99): history.requests[i] = history.requests[i + 1]
                idx = 99
            else:
                history.request_count += 1
            
            history.requests[idx].request_id = request_id.encode('utf-8')[:63]
            history.requests[idx].timestamp_ns = int(time.time_ns())
            history.requests[idx].tid = tid
            history.requests[idx].src_ip = src_ip
            history.requests[idx].src_port = src_port
            history.last_updated_ns = int(time.time_ns())
            user_history_map[username_key] = history
            self.display_user_history(username, history)
        except Exception: pass

    def update_resource_tracking(self, request_id, tid, src_ip, src_port, dst_ip=0, dst_port=0):
        try:
            tid_to_req_map = self.bpf.get_table("tid_to_request_id")
            resource_map = self.bpf.get_table("request_resources")
            
            tid_mmap_map = self.bpf.get_table("tid_mmap_bytes")
            tid_mprot_map = self.bpf.get_table("tid_mprotect_bytes")
            tid_phys_map = self.bpf.get_table("tid_curr_phys")
            
            acc_mmap = 0
            acc_mprot = 0
            acc_phys = 0
            try: acc_mmap = tid_mmap_map[ctypes.c_uint(tid)].value
            except: pass
            try: acc_mprot = tid_mprot_map[ctypes.c_uint(tid)].value
            except: pass
            try: acc_phys = tid_phys_map[ctypes.c_uint(tid)].value
            except: pass
            
            # Check for temp ID
            temp_request_id = None
            try:
                existing_key = tid_to_req_map[ctypes.c_uint(tid)]
                temp_request_id = existing_key.id.decode('utf-8', 'ignore').rstrip('\x00')
            except KeyError: pass
            
            if temp_request_id and temp_request_id != request_id and temp_request_id.startswith(f"TID_{tid}_"):
                try:
                    temp_key = resource_map.Key(id=temp_request_id.encode('utf-8')[:63])
                    temp_usage = resource_map[temp_key]
                    
                    usage = resource_map.Leaf(
                        request_id=request_id.encode('utf-8')[:63],
                        tid=tid,
                        start_time_ns=temp_usage.start_time_ns,
                        cpu_cycles_start=temp_usage.cpu_cycles_start,
                        memory_kb=self._get_tid_memory_kb(tid),
                        is_complete=0,
                        system_overhead_ns=0,
                        thread_lifetime_ns=0,
                        mmap_bytes=acc_mmap,
                        mprotect_bytes=acc_mprot,
                        peak_physical_bytes=max(temp_usage.peak_physical_bytes, acc_phys),
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        bytes_sent=temp_usage.bytes_sent,
                        bytes_recv=temp_usage.bytes_recv,
                        disk_read_bytes=temp_usage.disk_read_bytes,
                        disk_write_bytes=temp_usage.disk_write_bytes,
                        # Transfer CPU Stats
                        cpu_burst_total_ns=temp_usage.cpu_burst_total_ns,
                        cpu_burst_count=temp_usage.cpu_burst_count,
                        cpu_cycles_total=temp_usage.cpu_cycles_total,
                        cpu_instructions_total=temp_usage.cpu_instructions_total
                    )
                    req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
                    resource_map[req_key] = usage
                    
                    req_id_key_val = tid_to_req_map.Leaf(id=request_id.encode('utf-8')[:63])
                    tid_to_req_map[ctypes.c_uint(tid)] = req_id_key_val
                    del resource_map[temp_key]
                    return
                except KeyError: pass

            req_id_key_val = tid_to_req_map.Leaf(id=request_id.encode('utf-8')[:63])
            tid_to_req_map[ctypes.c_uint(tid)] = req_id_key_val
            
            usage = resource_map.Leaf(
                request_id=request_id.encode('utf-8')[:63],
                tid=tid,
                start_time_ns=int(time.time_ns()),
                cpu_cycles_start=int(time.time_ns()),
                memory_kb=self._get_tid_memory_kb(tid),
                is_complete=0,
                system_overhead_ns=0,
                thread_lifetime_ns=0,
                mmap_bytes=acc_mmap,
                mprotect_bytes=acc_mprot,
                peak_physical_bytes=acc_phys,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                bytes_sent=0,
                bytes_recv=0,
                disk_read_bytes=0,
                disk_write_bytes=0,
                cpu_burst_total_ns=0,
                cpu_burst_count=0,
                cpu_cycles_total=0,
                cpu_instructions_total=0
            )
            req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
            resource_map[req_key] = usage
        except Exception as e: print(f"Error tracking: {e}")

    def complete_resource_tracking(self, request_id, thread_exit=False):
        try:
            resource_map = self.bpf.get_table("request_resources")
            req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
            usage = resource_map[req_key]

            completion_time_ns = int(time.time_ns())
            usage.end_time_ns = completion_time_ns
            usage.duration_ns = usage.end_time_ns - usage.start_time_ns
            
            # --- New CPU Stats Calculation ---
            total_cpu_ms = usage.cpu_burst_total_ns / 1_000_000.0
            avg_burst_ms = 0
            if usage.cpu_burst_count > 0:
                avg_burst_ms = total_cpu_ms / usage.cpu_burst_count
            
            total_cycles = usage.cpu_cycles_total
            avg_cycles = 0
            if usage.cpu_burst_count > 0:
                avg_cycles = total_cycles / usage.cpu_burst_count
            
            total_instructions = usage.cpu_instructions_total
            avg_instructions = 0
            if usage.cpu_burst_count > 0:
                avg_instructions = total_instructions / usage.cpu_burst_count
            # ---------------------------------

            try:
                overhead_map = self.bpf.get_table("tid_to_overhead_ns")
                usage.system_overhead_ns = overhead_map[ctypes.c_uint(usage.tid)].value
            except KeyError: pass

            if usage.thread_lifetime_ns == 0:
                 try:
                    thread_start_map = self.bpf.get_table("tid_to_thread_start")
                    thread_start_ns = thread_start_map[ctypes.c_uint(usage.tid)].value
                    usage.thread_lifetime_ns = completion_time_ns - thread_start_ns
                 except: 
                    usage.thread_lifetime_ns = usage.duration_ns
            
            usage.memory_kb = max(usage.memory_kb, self._get_tid_memory_kb(usage.tid))
            try:
                tid_phys_map = self.bpf.get_table("tid_curr_phys")
                curr_phys = tid_phys_map[ctypes.c_uint(usage.tid)].value
                if curr_phys > usage.peak_physical_bytes:
                    usage.peak_physical_bytes = curr_phys
            except KeyError: pass
            usage.is_complete = 1
            resource_map[req_key] = usage
            
            # Re-read to ensure we have kernel updates
            usage = resource_map[req_key]
            
            # Save to python list
            record = {
                'id': request_id,
                'ts': datetime.fromtimestamp(usage.start_time_ns / 1e9).strftime('%Y-%m-%d %H:%M:%S'),
                'tid': usage.tid,
                'src': f"{self.ip_to_str(usage.src_ip)}:{usage.src_port}",
                'dst': f"{self.ip_to_str(usage.dst_ip)}:{usage.dst_port}",
                'mmap': usage.mmap_bytes / 1024.0,
                'mprot': usage.mprotect_bytes / 1024.0,
                'peak': usage.peak_physical_bytes / 1024.0,
                'overhead': usage.system_overhead_ns,
                'latency': usage.duration_ns / 1_000_000.0,
                'send': usage.bytes_sent / 1024.0,
                'recv': usage.bytes_recv / 1024.0,
                'disk_rd': usage.disk_read_bytes / 1024.0,
                'disk_wr': usage.disk_write_bytes / 1024.0
            }
            
            # Only add to list if not present (or update it)
            found = False
            for i, r in enumerate(self.recorded_requests):
                if r['id'] == request_id:
                    self.recorded_requests[i] = record
                    found = True
                    break
            if not found:
                self.recorded_requests.append(record)

            if thread_exit:
                print(f"\n[Thread Exit] Stats for Request: {request_id}")
                self.print_table_header()
                self.print_table_row(record)
                # Print separate block for CPU stats to preserve table structure
                print(f"   ↳ [CPU DETAILED] Bursts: {usage.cpu_burst_count} | Avg Duration: {avg_burst_ms:.3f} ms | Total CPU: {total_cpu_ms:.3f} ms")
                print(f"                    Avg Cycles: {avg_cycles:,.0f} | Total Cycles: {total_cycles:,.0f}")
                print(f"                    Avg Instructions: {avg_instructions:,.0f} | Total Instructions: {total_instructions:,.0f}")
            
        except KeyError: pass
        except Exception as e: print(f"Error completing: {e}")

    def print_table_header(self):
        print("-" * 238)
        print(f"{'Request-ID':<20} | {'Date & Time':<19} | {'Thread':<7} | {'Source IP:Port':<21} | {'Dest IP:Port':<21} | {'MMap(KB)':>10} | {'Mprot(KB)':>10} | {'Peak Phy(KB)':>13} | {'Send(KB)':>10} | {'Recv(KB)':>10} | {'DiskRd(KB)':>11} | {'DiskWr(KB)':>11} | {'Overhead(ns)':>13} | {'Latency(ms)':>11}")
        print("-" * 238)

    def print_table_row(self, r):
        print(f"{r['id']:<20} | {r['ts']:<19} | {r['tid']:<7} | {r['src']:<21} | {r.get('dst',''):<21} | {r['mmap']:>10.1f} | {r['mprot']:>10.1f} | {r['peak']:>13.1f} | {r['send']:>10.1f} | {r['recv']:>10.1f} | {r['disk_rd']:>11.1f} | {r['disk_wr']:>11.1f} | {r['overhead']:>13,d} | {r['latency']:>11.2f}")

    def _get_tid_memory_kb(self, tid):
        for pid in self.pids:
            try:
                with open(f"/proc/{pid}/task/{tid}/status", 'r') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            return int(line.split()[1])
            except:
                continue
        return 0

    def display_user_history(self, username, history):
        print(f"\n--- User History: {username} ---")
        print(f"| {'#':<3} | {'Request ID':<20} | {'Thread':<7} | {'Overhead(ns)':>13} | {'Peak RSS(MB)':>13} |")
        print("-" * 75)
        if history.request_count > 0:
            resource_map = self.bpf.get_table("request_resources")
            for i in range(history.request_count):
                req_entry = history.requests[i]
                req_id = req_entry.request_id.decode('utf-8', 'ignore').rstrip('\x00')
                if not req_id: continue
                overhead_ns = 0
                peak_mem = 0
                try:
                    req_key = resource_map.Key(id=req_id.encode('utf-8')[:63])
                    usage = resource_map[req_key]
                    overhead_ns = usage.system_overhead_ns
                    peak_mem = usage.peak_physical_bytes / 1024 / 1024
                except KeyError: pass
                print(f"| {i+1:<3} | {req_id:<20} | {req_entry.tid:<7} | {overhead_ns:>13,d} | {peak_mem:>13.2f} |")
        print()

    def handle_ssl_event(self, cpu, data, size):
        event = self.bpf["ssl_events"].event(data)
        tid = event.tid

        if tid not in self.request_buffers:
            # Detect whether this SSL_read belongs to an outgoing (client-side) SSL
            # connection made by the same thread while handling its real request.
            # If tid_to_request_id already holds a real (non-TID_xxx) entry, this
            # SSL_read is reading an upstream HTTPS response — NOT a new inbound request.
            _is_outgoing = False
            try:
                tid_to_req_map = self.bpf.get_table("tid_to_request_id")
                existing_rid = tid_to_req_map[ctypes.c_uint(tid)].id.decode('utf-8', 'ignore').rstrip('\x00')
                if existing_rid and not existing_rid.startswith(f"TID_{tid}_"):
                    _is_outgoing = True
            except KeyError:
                pass

            temp_request_id = f"TID_{tid}_{int(time.time_ns())}"
            self.request_buffers[tid] = {
                'data': b'', 'pid': event.pid, 'tid': tid,
                'comm': event.comm.decode('utf-8', 'ignore'),
                'has_conn_info': event.has_conn_info, 'src_ip': event.src_ip,
                'dst_ip': event.dst_ip, 'src_port': event.src_port, 'dst_port': event.dst_port,
                'timestamp': time.time(),
                '_is_outgoing': _is_outgoing,
            }

            if not _is_outgoing:
                # Initialize BPF tracking so mmap/alloc events are caught early
                try:
                    tid_to_req_map = self.bpf.get_table("tid_to_request_id")
                    req_id_key_val = tid_to_req_map.Leaf(id=temp_request_id.encode('utf-8')[:63])
                    tid_to_req_map[ctypes.c_uint(tid)] = req_id_key_val

                    resource_map = self.bpf.get_table("request_resources")
                    usage = resource_map.Leaf(
                        request_id=temp_request_id.encode('utf-8')[:63],
                        tid=tid,
                        start_time_ns=int(time.time_ns()),
                        peak_physical_bytes=0,
                        src_ip=event.src_ip,
                        src_port=event.src_port,
                        dst_ip=event.dst_ip,
                        dst_port=event.dst_port,
                        bytes_sent=0,
                        bytes_recv=0,
                        disk_read_bytes=0,
                        disk_write_bytes=0,
                        cpu_burst_total_ns=0,
                        cpu_burst_count=0,
                        cpu_cycles_total=0,
                        cpu_instructions_total=0
                    )
                    req_key = resource_map.Key(id=temp_request_id.encode('utf-8')[:63])
                    resource_map[req_key] = usage
                except Exception:
                    pass

        self.request_buffers[tid]['data'] += bytes(event.data[:event.data_len])
        if event.has_conn_info:
            self.request_buffers[tid].update({
                'has_conn_info': True, 'src_ip': event.src_ip, 'dst_ip': event.dst_ip,
                'src_port': event.src_port, 'dst_port': event.dst_port
            })

        full_data = self.request_buffers[tid]['data']
        is_outgoing = self.request_buffers[tid].get('_is_outgoing', False)

        if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
            if not is_outgoing and full_data.startswith((b'GET', b'POST', b'PUT', b'DELETE')):
                self.display_complete_request(tid)
            elif not is_outgoing:
                # Complete SSL data but not an HTTP request — clean up orphaned temp entry
                try:
                    tid_to_req_map = self.bpf.get_table("tid_to_request_id")
                    resource_map   = self.bpf.get_table("request_resources")
                    existing = tid_to_req_map[ctypes.c_uint(tid)]
                    rid = existing.id.decode('utf-8', 'ignore').rstrip('\x00')
                    if rid.startswith(f"TID_{tid}_"):
                        try:
                            del resource_map[resource_map.Key(id=rid.encode('utf-8')[:63])]
                        except KeyError:
                            pass
                        del tid_to_req_map[ctypes.c_uint(tid)]
                except KeyError:
                    pass
            # outgoing reads: buffer simply discarded — BPF maps were never touched
            del self.request_buffers[tid]

    def display_complete_request(self, tid):
        req = self.request_buffers[tid]
        headers = self.parse_http_headers(req['data'])
        request_id = self.extract_request_id(headers)
        user_info = self.extract_user_info(headers)

        if user_info['has_username'] and req['has_conn_info']:
            self.update_user_history(user_info['username'], request_id, tid, req['src_ip'], req['src_port'])

        self.update_resource_tracking(request_id, tid, req['src_ip'], req['src_port'],
                                       req.get('dst_ip', 0), req.get('dst_port', 0))
        self._flush_pending_conn_events(tid, request_id)
        self.complete_resource_tracking(request_id)

    def handle_conn_event(self, cpu, data, size):
        ev = self.bpf["conn_events"].event(data)
        tid = ev.tid

        # The conn event fires after SSL_read, so perf buffer ordering
        # guarantees tid_to_request_id already holds the real request_id.
        req_id = None
        try:
            tid_to_req = self.bpf.get_table("tid_to_request_id")
            rid = tid_to_req[ctypes.c_uint(tid)].id.decode('utf-8', 'ignore').rstrip('\x00')
            if rid and not rid.startswith('TID_'):
                req_id = rid
        except Exception:
            pass

        conn = (ev.src_ip, ev.src_port, ev.dst_ip, ev.dst_port)
        if req_id:
            self._print_conn_event(req_id, *conn)
        else:
            self.pending_conn_events.setdefault(tid, []).append(conn)

    def _print_conn_event(self, request_id, src_ip, src_port, dst_ip, dst_port):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src = f"{self.ip_to_str(src_ip)}:{src_port}"
        dst = f"{self.ip_to_str(dst_ip)}:{dst_port}"
        print(f"\n[{ts}] NEW CONNECTION MADE FOR {request_id} WITH THE 4 TUPLE: {src} -> {dst}")

    def _flush_pending_conn_events(self, tid, request_id):
        for conn in self.pending_conn_events.pop(tid, []):
            self._print_conn_event(request_id, *conn)

    def handle_mem_event(self, cpu, data, size):
        ev = self.bpf["mem_events"].event(data)
        ts = datetime.fromtimestamp(ev.timestamp_ns / 1e9).strftime('%H:%M:%S.%f')
        etype = "ALLOC" if ev.type == 1 else "FREE "
        size_kb = ev.size_bytes / 1024
        total_kb = ev.current_total_bytes / 1024
        log_line = f"{ts} | {ev.tid:<5} | {etype} | {size_kb:>9.2f} | {total_kb:>20.2f} | {ev.pfn}\n"
        self.log_file.write(log_line)
        self.log_file.flush()

    def handle_exit_event(self, cpu, data, size):
        ev = self.bpf["exit_events"].event(data)
        req_id = ev.request_id.decode('utf-8', 'ignore').rstrip('\x00')
        self.complete_resource_tracking(req_id, thread_exit=True)

    # ───────────────────────────────────────────────────────────
    # Thrift RPC support (DeathStarBench / plain-TCP inter-service)
    # ───────────────────────────────────────────────────────────

    def _parse_thrift_header(self, data: bytes):
        """Parse a Thrift strict-binary framed (or unframed) message header.

        Wire layout — framed (TFramedTransport + TBinaryProtocol strict):
            [4 B frame_size BE][4 B 0x80 0x01 0x00 TT][4 B name_len BE]
            [name_len B method][4 B seq_id BE][fields…]

        Unframed (TBinaryProtocol strict, no framing):
            [4 B 0x80 0x01 0x00 TT][4 B name_len BE]
            [name_len B method][4 B seq_id BE][fields…]

        Message type TT: 1=CALL  2=REPLY  3=EXCEPTION  4=ONEWAY

        Returns (method_name, msg_type, seq_id) or (None, None, None).
        """
        import struct
        try:
            if len(data) < 8:
                return None, None, None

            # Detect framed vs unframed by checking magic position.
            if data[4] == 0x80 and data[5] == 0x01 and data[6] == 0x00:
                off = 4   # framed: skip the 4-byte frame-size prefix
            elif data[0] == 0x80 and data[1] == 0x01 and data[2] == 0x00:
                off = 0   # unframed
            else:
                return None, None, None

            msg_type = data[off + 3]
            if msg_type not in (1, 2, 3, 4):
                return None, None, None

            name_len = struct.unpack('>I', data[off+4:off+8])[0]
            if name_len == 0 or name_len > 255:
                return None, None, None
            if off + 8 + name_len + 4 > len(data):
                return None, None, None

            method  = data[off+8:off+8+name_len].decode('utf-8', errors='replace')
            seq_id  = struct.unpack('>i', data[off+8+name_len:off+12+name_len])[0]
            return method, msg_type, seq_id
        except Exception:
            return None, None, None

    def handle_thrift_event(self, cpu, data, size):
        """Receive a Thrift binary message detected on a plain-TCP recv().

        Only CALL (type=1) and ONEWAY (type=4) messages are tracked as new
        requests; REPLY/EXCEPTION are replies from downstream and are ignored.
        """
        event = self.bpf["thrift_events"].event(data)
        tid   = event.tid
        raw   = bytes(event.data[:event.data_len])

        method, msg_type, seq_id = self._parse_thrift_header(raw)
        if method is None:
            return

        # Track inbound RPC calls only (CALL=1, ONEWAY=4).
        if msg_type not in (1, 4):
            return

        src_ip   = event.src_ip   if event.has_conn_info else 0
        src_port = event.src_port if event.has_conn_info else 0
        dst_ip   = event.dst_ip   if event.has_conn_info else 0
        dst_port = event.dst_port if event.has_conn_info else 0

        # Build a collision-free request-id: <method>_<16-char hash>
        # Hash input: src_ip + src_port + current nanosecond timestamp.
        _hash_src  = f"{src_ip}:{src_port}:{time.time_ns()}".encode()
        uid        = hashlib.sha256(_hash_src).hexdigest()[:16]
        request_id = f"{method}_seq{seq_id}_{uid}"

        self.update_resource_tracking(request_id, tid,
                                      src_ip, src_port, dst_ip, dst_port)
        self._flush_pending_conn_events(tid, request_id)
        # Do NOT call complete_resource_tracking here.
        # The server spawns one thread per connection; that thread exits after
        # replying, which fires handle_exit_event → complete_resource_tracking
        # (thread_exit=True) — exactly the same path as SSL requests.

    def run(self):
        print("="*60)
        print("🔍 INTEGRATED FULL SNIFFER (FIXED + IO + CPU BURSTS)".center(60))
        print("="*60)
        print(f"Target PIDs: {self.pids}")
        print(f"Log File:    {os.path.abspath(LOG_FILENAME)}")
        print("Initializing BPF... (Please wait)")

        num_cpus = os.cpu_count() or 128
        bpf_source = load_bpf_program(num_cpus)
        self.bpf = BPF(text=bpf_source, cflags=["-Wno-array-bounds"])

        # Populate the target_pids map so kernel filters on all registered PIDs
        pid_map = self.bpf.get_table("target_pids")
        for pid in self.pids:
            key = ctypes.c_uint(pid)
            val = ctypes.c_uint(1)
            pid_map[key] = val
        ssl_lib = BPF.find_library("ssl") or "/usr/lib/libssl.so.3"
        
        # Open Hardware Perf Counters for Cycles and Instructions
        self.bpf["perf_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
        self.bpf["perf_instructions"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.INSTRUCTIONS)
        
        self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read", fn_name="probe_ssl_read_enter")
        self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read", fn_name="probe_ssl_read_exit")
        try:
            self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read_ex", fn_name="probe_ssl_read_ex_enter")
            self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read_ex", fn_name="probe_ssl_read_ex_exit")
        except: pass
        
        print("✓ BPF Loaded. Monitoring...")
        # self.print_table_header()


        #register callbacks from ebpf programs to our python functions
        _no_lost = lambda lost, *_: None   # silence "Possibly lost N samples"
        self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event,     lost_cb=_no_lost)
        self.bpf["mem_events"].open_perf_buffer(self.handle_mem_event,     lost_cb=_no_lost)
        self.bpf["exit_events"].open_perf_buffer(self.handle_exit_event,   lost_cb=_no_lost)
        self.bpf["conn_events"].open_perf_buffer(self.handle_conn_event,   lost_cb=_no_lost)
        self.bpf["thrift_events"].open_perf_buffer(self.handle_thrift_event, lost_cb=_no_lost)
        
        while True:
            try:
                self.bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\n\n" + "="*238)
                print("FINAL SESSION SUMMARY".center(238))
                self.print_table_header()
                for r in self.recorded_requests:
                    self.print_table_row(r)
                print("="*238)
                print(f"Memory log saved to: {LOG_FILENAME}")
                self.log_file.close()
                break

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", type=int, nargs="+", required=True,
                        help="One or more target PIDs to monitor")
    args = parser.parse_args()

    IntegratedSnifferFull(args.pid).run()