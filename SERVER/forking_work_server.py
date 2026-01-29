
import socket
import ssl
import os
import time
import signal
import threading
import sys

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

def handle_client(conn, client_addr):
    try:
        # Parent (Request Handler) reads the request
        request_line = ""
        try:
             # Read headers (rudimentary)
            data = conn.read(4096)
            if not data:
                return
            
            text_data = data.decode('utf-8', errors='ignore')
            first_line = text_data.split('\n')[0].strip()
            request_line = first_line
        except Exception as e:
            request_line = f"Error reading request: {e}"

        pid = os.getpid()
        tid = get_kernel_tid()

        print(f"\n{'='*70}")
        print(f"[REQUEST] {request_line}")
        print(f"{'='*70}")
        print(f"  Process ID (PID):         {pid}")
        print(f"  Kernel Thread ID (TID):   {tid}")
        print(f"  Client Address:           {client_addr[0]}:{client_addr[1]}")
        print(f"  Active Threads in Server: {threading.active_count()}")
        print(f"{'='*70}")
        
        # Fork a child to do "heavy work"
        print(f"[PID {pid}] Forking child for heavy work...")
        child_pid = os.fork()
        
        if child_pid == 0:
            # Child
            try:
                c_pid = os.getpid()
                c_tid = get_kernel_tid()
                p_pid = os.getppid()
                
                import random
                duration = random.uniform(0.1, 1.0)
                
                print(f"    [Child PID {c_pid} TID {c_tid}] Started work for parent {p_pid}")
                print(f"    [Child PID {c_pid}] Sleeping for {duration:.2f}s...")
                time.sleep(duration)
                print(f"    [Child PID {c_pid}] Work finished")
            except Exception as e:
                print(f"    [Child Error] {e}")
            finally:
                os._exit(0)
        else:
            # Parent waits for child
            # simulate synchronous delegation
            os.waitpid(child_pid, 0)
            
            # Send response
            response_body = f"Forked work complete. Processed by Parent PID {pid}, Child PID {child_pid}"
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                "\r\n"
                f"{response_body}"
            )
            conn.write(response.encode('utf-8'))
            print(f"[PID {pid}] Response sent\n")

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        conn.close()

def main():
    # Ignore SIGCHLD to avoid zombies if we were async, 
    # but strictly we are synchronous here so waitpid reaps them.
    # However, good practice if we ever change.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL) 

    cert_file = '/home/khr/homefr/MTP/ebpf/bcc-latest/SERVER/cert.pem'
    key_file = '/home/khr/homefr/MTP/ebpf/bcc-latest/SERVER/key.pem'
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"Error: Cert/Key not found at {cert_file}")
        return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)

    bindsocket = socket.socket()
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind(('0.0.0.0', 8443))
    bindsocket.listen(5)

    print("\n" + "=" * 70)
    print("🔒 FORKING WORK HTTPS SERVER STARTED")
    print("=" * 70)
    print(f"  Server PID:               {os.getpid()}")
    print(f"  Listening on:             https://0.0.0.0:8443")
    print("=" * 70)
    print("Ready to be traced. Waiting for connections...")
    print("=" * 70 + "\n")

    while True:
        try:
            newsocket, fromaddr = bindsocket.accept()
            try:
                conn = context.wrap_socket(newsocket, server_side=True)
                handle_client(conn, fromaddr) 
            except ssl.SSLError as e:
                print(f"SSL Error: {e}")
                newsocket.close()
        except Exception as e:
            print(f"Accept error: {e}")

if __name__ == "__main__":
    main()
