import http.server
import ssl
import socketserver
import threading
import os
import sys
import time
import random

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
        
    def do_GET(self):
        # Extract request ID from query params for testing
        request_id = "unknown"
        if '?' in self.path:
            params = self.path.split('?')[1]
            for param in params.split('&'):
                if param.startswith('id='):
                    request_id = param.split('=')[1]
        
        # Test Memory Usage: Allocate 100 MB
        # We assign it to a variable to keep it in scope during the sleep
        print(f"  [MEMORY] Allocating 100 MB string...")
        mem_hog = "A" * (100 * 1024 * 1024)
        print(f"  [MEMORY] Allocated 100 MB. Length: {len(mem_hog)}")

        # Random delay if enabled (for stress testing)
        if ENABLE_RANDOM_DELAY:
            delay = random.uniform(MIN_DELAY, MAX_DELAY)
            print(f"  [DELAY] Sleeping for {delay:.2f}s (Request ID: {request_id})")
            time.sleep(delay)
            print(f"  [RESUME] Processing request ID: {request_id}")
        
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
