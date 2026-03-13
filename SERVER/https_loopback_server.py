#!/usr/bin/env python3
"""
HTTPS Loopback Server
Mirrors the plain-HTTP loopback_server.py but wraps the socket with TLS.
Reuses the same cert.pem / key.pem as the main HTTPS server.
Default port: 9443
"""
import http.server
import socketserver
import ssl
import argparse
import os

CERT_FILE = "cert.pem"
KEY_FILE  = "key.pem"


class EchoRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress per-request access log noise

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(f"GET {self.path}".encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        self.do_POST()


class ThreadingHTTPSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTPS echo/loopback server")
    parser.add_argument("-P", "--port", type=int, default=9443,
                        help="Port to listen on (default: 9443)")
    args = parser.parse_args()

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print(f"ERROR: {CERT_FILE} or {KEY_FILE} not found.")
        print("Generate with:")
        print('  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem '
              '-sha256 -days 365 -nodes -subj "/CN=localhost"')
        raise SystemExit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with ThreadingHTTPSServer(("localhost", args.port), EchoRequestHandler) as httpd:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"HTTPS loopback listening on https://localhost:{args.port}")
        print(f"PID: {os.getpid()}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
