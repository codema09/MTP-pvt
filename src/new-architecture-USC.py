#!/usr/bin/env python3
"""
Integrated HTTPS Server Sniffer & Resource Profiler (FINAL FIXED + IO + Disk + CPU Burst/Cycles)
==============================================================================================
- Added: CPU Burst Tracking (Avg Duration, Count, Total Duration).
- Added: CPU Cycle Tracking (Avg Cycles, Total Cycles).
- Maintained: Original Table layouts are untouched.
- Maintained: All previous IO/Disk/Memory tracking.

Usage: sudo python3 integrated_sniffer_full.py -p <PID>
"""

from bcc import BPF, PerfType, PerfHWConfig
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
    "uprobes/ssl_interception.c",
    "tracepoints/lifecycle.c",
    "tracepoints/memory_tracking.c",
]

def load_bpf_program(target_pid, num_cpus):
    """Read all eBPF source files, concatenate, and substitute runtime values."""
    parts = []
    for relpath in BPF_SOURCE_FILES:
        filepath = os.path.join(EBPF_SRC_DIR, relpath)
        with open(filepath, "r") as f:
            parts.append(f"// === {relpath} ===\n")
            parts.append(f.read())
            parts.append("\n")
    
    program = "".join(parts)
    program = program.replace("__TARGET_PID__", str(target_pid))
    program = program.replace("__NUM_CPUS__", str(num_cpus))
    return program


class IntegratedSnifferFull:
    def __init__(self, pid):
        self.pid = pid
        self.bpf = None
        self.request_buffers = {}
        self.request_counter = 0
        self.recorded_requests = [] # Store local copy for final summary
        
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

    def update_resource_tracking(self, request_id, tid, src_ip, src_port):
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
            usage.is_complete = 1
            resource_map[req_key] = usage
            
            # Re-read to ensure we have kernel updates
            usage = resource_map[req_key]
            
            # Save to python list
            record = {
                'id': request_id,
                'ts': datetime.fromtimestamp(usage.start_time_ns / 1e9).strftime('%H:%M:%S'),
                'tid': usage.tid,
                'src': f"{self.ip_to_str(usage.src_ip)}:{usage.src_port}",
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
        print("-" * 205)
        print(f"{'Request-ID':<20} | {'Timestamp':<10} | {'Thread':<7} | {'Source IP:Port':<21} | {'MMap(KB)':>10} | {'Mprot(KB)':>10} | {'Peak Phy(KB)':>13} | {'Send(KB)':>10} | {'Recv(KB)':>10} | {'DiskRd(KB)':>11} | {'DiskWr(KB)':>11} | {'Overhead(ns)':>13} | {'Latency(ms)':>11}")
        print("-" * 205)

    def print_table_row(self, r):
        print(f"{r['id']:<20} | {r['ts']:<10} | {r['tid']:<7} | {r['src']:<21} | {r['mmap']:>10.1f} | {r['mprot']:>10.1f} | {r['peak']:>13.1f} | {r['send']:>10.1f} | {r['recv']:>10.1f} | {r['disk_rd']:>11.1f} | {r['disk_wr']:>11.1f} | {r['overhead']:>13,d} | {r['latency']:>11.2f}")

    def _get_tid_memory_kb(self, tid):
        try:
            with open(f"/proc/{self.pid}/task/{tid}/status", 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'): return int(line.split()[1])
        except: return 0
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
            temp_request_id = f"TID_{tid}_{int(time.time_ns())}"
            self.request_buffers[tid] = {
                'data': b'', 'pid': event.pid, 'tid': tid,
                'comm': event.comm.decode('utf-8', 'ignore'),
                'has_conn_info': event.has_conn_info, 'src_ip': event.src_ip,
                'dst_ip': event.dst_ip, 'src_port': event.src_port, 'dst_port': event.dst_port,
                'timestamp': time.time()
            }
            # Initialize tracking so Alloc/Mmap are caught early
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
                    bytes_sent=0,
                    bytes_recv=0,
                    disk_read_bytes=0,
                    disk_write_bytes=0,
                    # New fields init
                    cpu_burst_total_ns=0,
                    cpu_burst_count=0,
                    cpu_cycles_total=0,
                    cpu_instructions_total=0
                )
                req_key = resource_map.Key(id=temp_request_id.encode('utf-8')[:63])
                resource_map[req_key] = usage
            except: pass
        
        self.request_buffers[tid]['data'] += bytes(event.data[:event.data_len])
        if event.has_conn_info:
            self.request_buffers[tid].update({
                'has_conn_info': True, 'src_ip': event.src_ip, 'dst_ip': event.dst_ip,
                'src_port': event.src_port, 'dst_port': event.dst_port
            })
        
        full_data = self.request_buffers[tid]['data']
        if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
            if full_data.startswith((b'GET', b'POST', b'PUT', b'DELETE')):
                self.display_complete_request(tid)
            del self.request_buffers[tid]

    def display_complete_request(self, tid):
        req = self.request_buffers[tid]
        headers = self.parse_http_headers(req['data'])
        request_id = self.extract_request_id(headers)
        user_info = self.extract_user_info(headers)
        
        if user_info['has_username'] and req['has_conn_info']:
            self.update_user_history(user_info['username'], request_id, tid, req['src_ip'], req['src_port'])
        
        self.update_resource_tracking(request_id, tid, req['src_ip'], req['src_port'])
        self.complete_resource_tracking(request_id)

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

    def run(self):
        print("="*60)
        print("🔍 INTEGRATED FULL SNIFFER (FIXED + IO + CPU BURSTS)".center(60))
        print("="*60)
        print(f"Target PID: {self.pid}")
        print(f"Log File:   {os.path.abspath(LOG_FILENAME)}")
        print("Initializing BPF... (Please wait)")
        
        num_cpus = os.cpu_count() or 128
        bpf_source = load_bpf_program(self.pid, num_cpus)
        self.bpf = BPF(text=bpf_source)
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
        self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
        self.bpf["mem_events"].open_perf_buffer(self.handle_mem_event)
        self.bpf["exit_events"].open_perf_buffer(self.handle_exit_event)
        
        while True:
            try:
                self.bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\n\n" + "="*205)
                print("FINAL SESSION SUMMARY".center(205))
                self.print_table_header()
                for r in self.recorded_requests:
                    self.print_table_row(r)
                print("="*205)
                print(f"Memory log saved to: {LOG_FILENAME}")
                self.log_file.close()
                break

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", type=int, required=True, help="Target PID")
    args = parser.parse_args()
    
    IntegratedSnifferFull(args.pid).run()