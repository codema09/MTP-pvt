#!/usr/bin/env python3
import http.server
import socketserver

PORT = 9009

class EchoRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        response = f"GET request to {self.path}".encode('utf-8')
        self.wfile.write(response)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        self.do_POST()

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), EchoRequestHandler) as httpd:
        print(f"Serving loopback on port {PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
