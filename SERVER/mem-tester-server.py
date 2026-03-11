
import http.server
import urllib.request
import ssl
import socketserver
import threading
import os
import sys
import time
import random
import ctypes
import os

# Load the C standard library
# libc = ctypes.CDLL(None)
# Access the raw syscall function
# syscall = libc.syscall

# On x86-64 Linux, the syscall number for brk is 12
# SYS_BRK = 12



import pandas as pd
import numpy as np
import time
import os
import psutil

def get_process_memory():
    process = psutil.Process(os.getpid())
    # memory_info().rss gives the "Resident Set Size" in bytes
    return process.memory_info().rss

def monitor_memory():
    # 1. Baseline Memory (Python runtime overhead)
    base_memory = get_process_memory()
    print(f"PID: {os.getpid()}")
    print(f"Baseline Memory (Python Overhead): {base_memory / 1024:.2f} KB")

    # 2. Create the 100KB DataFrame
    rows = 1024
    cols = 1000
    df = pd.DataFrame(np.random.randn(rows, cols))
    
    # Force a small calculation to ensure allocation happens immediately
    _ = df.sum()

    # 3. Check Memory Increase
    current_memory = get_process_memory()
    increment = current_memory - base_memory
    
    print(f"Memory after DataFrame creation: {current_memory / 1024:.2f} KB")
    print(f"Approximate Increase: {increment / 1024:.2f} KB")
    print("-" * 30)

    # 4. Monitor Loop
    start_time = time.time()
    while (time.time() - start_time) < 120:
        # "Touch" the data to keep it active
        _ = df.sum()
        
        # Check actual physical memory again
        live_rss = get_process_memory()
        print(f"Live Physical RAM (RSS): {live_rss / 1024:.2f} KB", end='\r')
        
        time.sleep(1)

    print("\nDone.")



# --- Server Configuration ---
HOST = "localhost"
PORT = 8443
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
ENABLE_RANDOM_DELAY = True  # Set to False for normal operation
MIN_DELAY = 1  # seconds
MAX_DELAY = 10  # seconds

# --- Helper function to get kernel TID ---
def get_kernel_tid():
    """Get the actual kernel Thread ID that eBPF sees (not pthread ID)"""
    try:
        # Python 3.8+ has os.gettid() - this is the CORRECT way
        return os.gettid()
    except AttributeError:
        # Fallback for Python < 3.8: use ctypes to call gettid syscall directly
        import ctypes
        libc = ctypes.CDLL('libc.so.6')
        SYS_gettid = 186  # syscall number for gettid on x86_64
        return libc.syscall(SYS_gettid)

# --- A simple handler that prints detailed thread info ---
class ThreadInfoHandler(http.server.SimpleHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        """Override to add detailed thread info to every request log."""
        pid = os.getpid()
        kernel_tid = get_kernel_tid()
        
        print(f"\n{'='*70}")
        print(f"[REQUEST] {self.command} {self.path} | RESPONSE: {code}")
        print(f"{'='*70}")
        print(f"  Process ID (PID):         {pid}")
        print(f"  Kernel Thread ID (TID):   {kernel_tid} <-- THIS SHOULD MATCH THE SNIFFER")
        print(f"  Client Address:           {self.client_address[0]}:{self.client_address[1]}")
        print(f"  Active Threads in Server: {threading.active_count()}")
        print(f"{'='*70}\n")
        
    def do_brk(self):
        # 1. Get the current program break (call brk(0) indirectly via sbrk(0))
        # The C library function sbrk(0) returns the current break without changing it.
        # We can approximate this by using ctypes to call the sbrk function wrapper.
        # A direct brk(0) call returns the new break on success, which would be 0 (failure) if not handled carefully.
        # The standard C library function sbrk is a wrapper around brk.

        try:
            # Use sbrk(0) to get the current break address (sbrk returns void*)
            sbrk = libc.sbrk
            sbrk.restype = ctypes.c_void_p
            current_break = sbrk(0)
            print(f"Initial program break: {hex(current_break)}")
        except AttributeError:
            print("sbrk not available via ctypes. Falling back to direct brk syscall approximation.")
            # On some systems, sbrk might not be directly in the default CDLL(None)
            # or you might want the raw syscall.
            # A raw brk(0) call on Linux returns the *current* break on success.
            # The return type needs to be handled as a long or void*
            syscall.restype = ctypes.c_void_p
            current_break = syscall(SYS_BRK, 0)
            print(f"Initial program break (via raw syscall): {hex(current_break)}")


        # 2. Increase the program break (allocate memory)
        # We want to increase the break by, say, one page size (4096 bytes)
        page_size = 4096
        new_break_address = current_break + page_size

        print(f"Attempting to set new program break to: {hex(new_break_address)}")

        # Call the brk syscall with the new address
        # The syscall returns the new program break address on success
        result_addr = syscall(SYS_BRK, new_break_address)

        if result_addr == new_break_address:
            print("Successfully increased program break.")
            # You could now use the memory in the newly allocated range, e.g., by writing to it using ctypes pointers
            # Note: this is advanced/dangerous and requires careful memory handling.
        else:
            print("Failed to increase program break. Return value:", hex(result_addr))


        # 3. Reset the program break (deallocate memory)
        print(f"Resetting program break to initial address: {hex(current_break)}")
        syscall(SYS_BRK, current_break)
        print("Program break reset.")


    def do_GET(self):
        # Extract request ID from query params for testing
        request_id = "unknown"
        if '?' in self.path:
            params = self.path.split('?')[1]
            for param in params.split('&'):
                if param.startswith('id='):
                    request_id = param.split('=')[1]
        
        # monitor_memory()

        # print("Allocating 100KB memory")
        # mem = "A"*(100*1024)

        # mem += "B"

        print(f"  [MEMORY] Allocating 50 MB string...")
        mem_hog1 = "A" * (500 * 1024 * 1024)
        print(f"  [MEMORY] Allocated 50 MB. Length: {len(mem_hog1)}")

        print(f"  [MEMORY] Allocating 20 MB string...")
        mem_hog2 = "A" * (20 * 1024 * 1024)
        print(f"  [MEMORY] Allocated 20 MB. Length: {len(mem_hog2)}")
        
        print(f"  [MEMORY] Allocating 30 MB string...")
        mem_hog3 = "A" * (30 * 1024 * 1024)
        print(f"  [MEMORY] Allocated 30 MB. Length: {len(mem_hog3)}")
        # CPU Spin: burn CPU for 500ms

        print(f"  [CPU-SPIN] Spinning for 69 Million additions...")
        dummy = 0
        for i in range(69000000):
            dummy += i
        # spin_start = time.perf_counter()
        # while (time.perf_counter() - spin_start) < 1.69:
        #     pass  # busy wait
        # print(f"  [CPU-SPIN] Done spinning.")

        #Wait for a random time between 5 and 10 seconds
        delay = random.uniform(5, 10)
        print(f"  [DELAY] Sleeping for {delay:.2f}s (Request ID: {request_id})")
        time.sleep(delay)
        print(f"  [RESUME] Finished waiting {delay:.2f}s (Request ID: {request_id})")
        
        # Test Memory Usage: Allocate 100 MB
        # We assign it to a variable to keep it in scope during the sleep
        # print(f"  [MEMORY] Allocating 200 MB string...")
        # mem_hog = "A" * (200 * 1024 * 1024)
        #print(f"  [MEMORY] Allocated 200 MB. Length: {len(mem_hog)}")

        # self.do_brk()

        # Call Loopback Server (HTTP)
        try:
            print(f"  [LOOPBACK] sending 100B request to http://localhost:9009 ...")
            req = urllib.request.Request("http://localhost:9009/", data=b"X"*100, method='POST')
            with urllib.request.urlopen(req, timeout=2) as f:
                 resp = f.read().decode('utf-8')
                 print(f"  [LOOPBACK] Response: {resp}")
        except Exception as e:
            print(f"  [LOOPBACK] Error: {e}")

        # --- File I/O: Read 8600B from memory_debug.log ---
        # try:
        #     print(f"  [FILE-IO] Reading 8600 bytes from memory_debug.log ...")
        #     with open("memory_debug.log", "rb") as f:
        #         file_data = f.read(8600)
        #     print(f"  [FILE-IO] Read {len(file_data)} bytes from memory_debug.log")
        # except Exception as e:
        #     print(f"  [FILE-IO] Read error: {e}")
        #     file_data = b""

        # --- File I/O: Write  15000B to a new file ---
        try:
            out_filename = f"/tmp/mem_test_output_{request_id}_{int(time.time())}.bin"
            print(f"  [FILE-IO] Writing 15000 bytes to {out_filename} ...")
            with open(out_filename, "wb") as f:
                f.write(b"D" * 15000)
            print(f"  [FILE-IO] Wrote 15000 bytes to {out_filename}")
        except Exception as e:
            print(f"  [FILE-IO] Write error: {e}")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response = f"<h1>Request {request_id} processed</h1>\n"
        response += f"<p>PID: {os.getpid()}, TID: {get_kernel_tid()}</p>\n"
        response += f"<p>Client: {self.client_address[0]}:{self.client_address[1]}</p>\n"
        response += f"<p>Memory Allocated: 100 MB</p>\n"
        self.wfile.write(response.encode())


# --- A ThreadingTCPServer to handle each request in a new thread ---
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

# --- Main execution ---
if __name__ == "__main__":
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("=" * 60)
        print(" ERROR: Certificate (cert.pem) or Key (key.pem) not found.")
        print(" Please run this command first:")
        print(" openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj \"/CN=localhost\"")
        print("=" * 60)
        exit(1)

    httpd = ThreadingTCPServer((HOST, PORT), ThreadInfoHandler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("\n" + "=" * 70)
    print("🔒 DEFINITIVE HTTPS SERVER STARTED")
    print("=" * 70)
    print(f"  Server PID:               {os.getpid()}")
    print(f"  Listening on:             https://{HOST}:{PORT}")
    print("=" * 70)
    print("Ready to be traced by 'server-sniffer.py'. Waiting for connections...")
    print("=" * 70 + "\n")
    
    httpd.serve_forever()


""""
 watch -n 1 'echo "PID        MEMORY(Bytes)   MEM%       COMMAND"; ps -eo pid,rss,pmem,args --sort=-rss | grep "[p]ython" | head -n 15 | awk "{printf \"%-10s %-15s %-10s \", \$1, \$2*1024, \$3\"%\"; for(i=4;i<=NF;i++) printf \"%s \", \$i; print \"\"}"'
"""




# import http.server
# import ssl
# import socketserver
# import threading
# import os
# import sys
# import time
# import random
# import ctypes
# import pandas as pd
# import numpy as np
# import psutil

# # --- Helper function to get kernel TID ---
# # Defined early so it can be used in monitor_memory
# def get_kernel_tid():
#     """Get the actual kernel Thread ID that eBPF sees (not pthread ID)"""
#     try:
#         # Python 3.8+ has os.gettid() - this is the CORRECT way
#         return os.gettid()
#     except AttributeError:
#         # Fallback for Python < 3.8: use ctypes to call gettid syscall directly
#         libc = ctypes.CDLL('libc.so.6')
#         SYS_gettid = 186  # syscall number for gettid on x86_64
#         return libc.syscall(SYS_gettid)

# def get_process_rss_bytes():
#     """Returns the Resident Set Size (Physical Memory) of the entire process in bytes."""
#     process = psutil.Process(os.getpid())
#     return process.memory_info().rss

# def monitor_memory():
#     # 0. Get Identity
#     tid = get_kernel_tid()
#     print(f"\n[TID: {tid}] --- Starting Memory Monitor ---")

#     # 1. Baseline Memory (Before Allocation)
#     base_rss = get_process_rss_bytes()
#     print(f"[TID: {tid}] Baseline RSS:          {base_rss / 1024:,.2f} KB")

#     # 2. Create the DataFrame (Virtual Allocation phase)
#     # 1024 * 1000 * 8 bytes (float64) ≈ 7.8 MB
#     rows = 1024
#     cols = 1000
#     print(f"[TID: {tid}] Allocating DataFrame ({rows}x{cols})...")
    
#     df = pd.DataFrame(np.random.randn(rows, cols))
    
#     # Check Memory after Python object creation
#     # Note: Linux might lazy-load, so RSS might not spike fully yet
#     rss_after_alloc = get_process_rss_bytes()
#     inc_alloc = rss_after_alloc - base_rss
#     print(f"[TID: {tid}] RSS after Creation:      {rss_after_alloc / 1024:,.2f} KB (Increase: {inc_alloc / 1024:,.2f} KB)")

#     time.sleep(15)
#     # 3. Touch the data (Force Physical Allocation via Page Faults)
#     print(f"[TID: {tid}] Touching data (df.sum()) to force page faults...")
#     _ = df.sum()

#     # Check Memory after access
#     rss_after_touch = get_process_rss_bytes()
#     inc_touch = rss_after_touch - rss_after_alloc
#     total_inc = rss_after_touch - base_rss
    
#     print(f"[TID: {tid}] RSS after Touch:         {rss_after_touch / 1024:,.2f} KB (Step Increase: {inc_touch / 1024:,.2f} KB)")
#     print(f"[TID: {tid}] >> TOTAL RSS INCREASE:   {total_inc / 1024:,.2f} KB")
#     print("-" * 60)

#     # 4. Monitor Loop
#     # Keeps the thread alive and holds the memory
#     # start_time = time.time()
#     # while (time.time() - start_time) < 120:
#     #     # "Touch" the data to prevent swap-out (keep it hot)
#     #     _ = df.sum()
        
#     #     # Check actual physical memory again
#     #     live_rss = get_process_rss_bytes()
        
#     #     # Overwrite the line to create a live dashboard effect
#     #     sys.stdout.write(f"[TID: {tid}] Holding Memory | Live RSS: {live_rss / 1024:,.2f} KB   \r")
#     #     sys.stdout.flush()
        
#     #     time.sleep(1)

#     print(f"\n[TID: {tid}] Memory Monitor finished. Releasing DataFrame.")

# # --- Server Configuration ---
# HOST = "localhost"
# PORT = 8443
# CERT_FILE = "cert.pem"
# KEY_FILE = "key.pem"

# # --- A simple handler that prints detailed thread info ---
# class ThreadInfoHandler(http.server.SimpleHTTPRequestHandler):
#     def log_request(self, code='-', size='-'):
#         """Override to add detailed thread info to every request log."""
#         pid = os.getpid()
#         kernel_tid = get_kernel_tid()
        
#         print(f"\n{'='*70}")
#         print(f"[REQUEST] {self.command} {self.path} | RESPONSE: {code}")
#         print(f"{'='*70}")
#         print(f"  Process ID (PID):         {pid}")
#         print(f"  Kernel Thread ID (TID):   {kernel_tid} <-- THIS SHOULD MATCH THE SNIFFER")
#         print(f"  Client Address:           {self.client_address[0]}:{self.client_address[1]}")
#         print(f"  Active Threads:           {threading.active_count()}")
#         print(f"{'='*70}\n")

#     def do_GET(self):
#         # Extract request ID from query params for logging
#         request_id = "unknown"
#         if '?' in self.path:
#             try:
#                 params = self.path.split('?')[1]
#                 for param in params.split('&'):
#                     if param.startswith('id='):
#                         request_id = param.split('=')[1]
#             except:
#                 pass
        
#         # Trigger the memory allocation monitor
#         monitor_memory()

#         # Send Response
#         self.send_response(200)
#         self.send_header("Content-type", "text/html")
#         self.end_headers()
#         response = f"<h1>Request {request_id} processed</h1>\n"
#         response += f"<p>PID: {os.getpid()}, TID: {get_kernel_tid()}</p>\n"
#         response += f"<p>Check server console for memory logs.</p>\n"
#         self.wfile.write(response.encode())


# # --- A ThreadingTCPServer to handle each request in a new thread ---
# class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
#     daemon_threads = True # Allow Ctrl-C to kill threads easier
#     pass

# # --- Main execution ---
# if __name__ == "__main__":
#     if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
#         print("=" * 60)
#         print(" ERROR: Certificate (cert.pem) or Key (key.pem) not found.")
#         print(" Please run this command first:")
#         print(" openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj \"/CN=localhost\"")
#         print("=" * 60)
#         exit(1)

#     # Create the server
#     httpd = ThreadingTCPServer((HOST, PORT), ThreadInfoHandler)

#     # Wrap the socket with SSL
#     context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#     context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
#     httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

#     print("\n" + "=" * 70)
#     print("🔒 HTTPS SERVER WITH MEMORY TRACKING STARTED")
#     print("=" * 70)
#     print(f"  Server PID:               {os.getpid()}")
#     print(f"  Listening on:             https://{HOST}:{PORT}")
#     print("=" * 70)
#     print("Ready. Send a request to trigger memory allocation.")
#     print("Example: curl -k https://localhost:8443/?id=test1")
#     print("=" * 70 + "\n")
    
#     try:
#         httpd.serve_forever()
#     except KeyboardInterrupt:
#         print("\nShutting down server.")
#         httpd.shutdown()


