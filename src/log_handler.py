#!/usr/bin/env python3
#python3 log_handler.py 
#curl http://localhost:5000/graph/print > src/graphs/gp2.log


"""
Central Log-Handler for Distributed USC Attribution
=====================================================
Receives structured request data from multiple USC instances,
stores per-request metrics, and builds a directed call graph (DAG)
by matching outgoing connections to incoming request entries via
exact TCP 4-tuple matching.

Usage:
    python3 log_handler.py [--port 5000] [--host 0.0.0.0]

Endpoints:
    POST /ingest          — Receive data from a USC instance
    GET  /graph           — JSON call graph (adjacency list)
    GET  /graph/print     — Human-readable tree rendering
    GET  /requests        — All requests with full metrics
    GET  /requests/<id>   — Single request detail
    GET  /machines        — Which USCs have reported
    POST /rebuild         — Force call graph rebuild
"""

import argparse
import json
import threading
from collections import defaultdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ═══════════════════════════════════════════════════════════════
# Known external service ports (won't have USC entries)
# ═══════════════════════════════════════════════════════════════
KNOWN_SERVICES = {
    53: 'DNS',
    6379: 'Redis',
    27017: 'MongoDB',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    11211: 'Memcached',
}


class LogHandler:
    def __init__(self):
        self.lock = threading.Lock()

        # Dict-of-dicts: request_id -> {all metrics + machine_id}
        self.requests = {}

        # Connection events grouped by originating request
        # request_id -> [list of connection dicts]
        self.connections = defaultdict(list)

        # The call graph: adjacency list (parent -> [children])
        self.call_graph = defaultdict(list)

        # Reverse lookup: ENTRY 4-tuple -> [request_ids]
        self.entry_index = defaultdict(list)

        # Unmatched connections (no corresponding ENTRY found)
        self.unmatched = []

        # Track external database connections (Memcached/Redis/Mongo) to render as leaves
        self.backend_edges = defaultdict(list)

        # Track which machines have reported
        self.machines = {}

        # Whether graph needs rebuilding
        self._graph_dirty = True

    # ───────────────────────────────────────────────────────────
    # Data Ingestion
    # ───────────────────────────────────────────────────────────

    def ingest(self, payload):
        """Merge data from one USC instance into the global stores."""
        machine_id = payload.get('machine_id', 'unknown')
        pids = payload.get('pids', [])
        requests = payload.get('requests', [])
        connections = payload.get('connections', [])
        ts = payload.get('timestamp', datetime.now().isoformat())

        with self.lock:
            # Track machine
            self.machines[machine_id] = {
                'timestamp': ts,
                'pids': pids,
                'request_count': len(requests),
                'connection_count': len(connections),
            }

            # Merge requests
            for req in requests:
                req_id = req.get('id')
                if not req_id:
                    continue
                req['machine_id'] = machine_id
                self.requests[req_id] = req

            # Merge connections
            for conn in connections:
                req_id = conn.get('request_id')
                if not req_id:
                    continue
                conn['machine_id'] = machine_id
                self.connections[req_id].append(conn)

            self._graph_dirty = True

        return {
            'status': 'ok',
            'machine_id': machine_id,
            'requests_ingested': len(requests),
            'connections_ingested': len(connections),
        }

    # ───────────────────────────────────────────────────────────
    # Call Graph Construction
    # ───────────────────────────────────────────────────────────

    def _build_entry_index(self):
        """Map each request's ENTRY 4-tuple to its request_id."""
        self.entry_index.clear()
        for req_id, req in self.requests.items():
            src_ip = req.get('src_ip')
            src_port = req.get('src_port')
            dst_ip = req.get('dst_ip')
            dst_port = req.get('dst_port')
            if src_ip and src_port is not None and dst_ip and dst_port is not None:
                key = (src_ip, int(src_port), dst_ip, int(dst_port))
                self.entry_index[key].append(req_id)

    def _ts_diff(self, ts1, ts2):
        """Absolute difference in seconds between two timestamp strings."""
        formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f']
        def parse(s):
            for fmt in formats:
                try:
                    return datetime.strptime(s, fmt)
                except (ValueError, TypeError):
                    continue
            return datetime.min
        return abs((parse(ts1) - parse(ts2)).total_seconds())

    def _build_call_graph(self):
        """Match each NEW CONNECTION to an ENTRY to build parent→child edges."""
        self.call_graph.clear()
        self.unmatched.clear()
        self.backend_edges.clear()
        self._build_entry_index()

        for parent_req_id, conns in self.connections.items():
            for conn in conns:
                key = (
                    conn['src_ip'], int(conn['src_port']),
                    conn['dst_ip'], int(conn['dst_port']),
                )

                candidates = self.entry_index.get(key, [])

                # Fallback purely to explicit Thrift payload_req_id + child_prefix if 4-tuple yields 0 candidates
                if not candidates and conn.get('payload_req_id') and conn.get('child_prefix'):
                    for rid, req in self.requests.items():
                        if req.get('payload_req_id') == conn['payload_req_id'] and rid.startswith(conn['child_prefix']):
                            candidates.append(rid)

                expected_prefix = conn.get('child_prefix')
                if expected_prefix:
                    candidates = [c for c in candidates if c.startswith(expected_prefix)]

                # Explicit payload_req_id filtering to guarantee trace exactness
                expected_payload_req_id = conn.get('payload_req_id')
                if expected_payload_req_id:
                    candidates = [c for c in candidates if self.requests[c].get('payload_req_id') == expected_payload_req_id]

                if not candidates:
                    dst_port = int(conn['dst_port'])
                    category = KNOWN_SERVICES.get(dst_port, 'External')
                    self.unmatched.append({
                        'parent_request_id': parent_req_id,
                        'connection': {
                            'src': f"{conn['src_ip']}:{conn['src_port']}",
                            'dst': f"{conn['dst_ip']}:{conn['dst_port']}",
                            'timestamp': conn.get('timestamp', ''),
                        },
                        'reason': 'no_matching_entry',
                        'category': category,
                    })
                    
                    # Add to visual render queue
                    backend_label = f"[{category}] {conn['dst_ip']}:{dst_port}"
                    self.backend_edges[parent_req_id].append(backend_label)
                    continue

                if len(candidates) == 1:
                    child_req_id = candidates[0]
                else:
                    # Multiple candidates: pick closest by timestamp
                    conn_ts = conn.get('timestamp', '')
                    child_req_id = min(
                        candidates,
                        key=lambda rid: self._ts_diff(conn_ts, self.requests[rid].get('ts', ''))
                    )

                # Avoid self-edges
                if child_req_id != parent_req_id:
                    if child_req_id not in self.call_graph[parent_req_id]:
                        self.call_graph[parent_req_id].append(child_req_id)

        self._graph_dirty = False

    def _ensure_graph(self):
        """Rebuild the call graph if data has changed since last build."""
        with self.lock:
            if self._graph_dirty:
                start_time = datetime.now()
                self._build_call_graph()
                end_time = datetime.now()
                print(f"[GRAPH] [{end_time.isoformat()}] Call graph structurally processed and built in {(end_time - start_time).total_seconds()} seconds.")

    # ───────────────────────────────────────────────────────────
    # Query Methods
    # ───────────────────────────────────────────────────────────

    def _find_roots(self):
        """Find requests with no incoming edges (root of call chains)."""
        all_children = set()
        for children in self.call_graph.values():
            all_children.update(children)
        return sorted(rid for rid in self.requests if rid not in all_children)

    def get_graph_json(self):
        """Return the call graph as a JSON-serializable dict."""
        self._ensure_graph()
        with self.lock:
            roots = self._find_roots()

            # Count edges
            total_edges = sum(len(v) for v in self.call_graph.values())

            return {
                'edges': dict(self.call_graph),
                'unmatched': self.unmatched,
                'roots': roots,
                'stats': {
                    'total_nodes': len(self.requests),
                    'total_edges': total_edges,
                    'unmatched_count': len(self.unmatched),
                    'machines_reported': len(self.machines),
                },
            }

    def get_graph_text(self):
        """Return a human-readable tree rendering of the DAG."""
        self._ensure_graph()
        with self.lock:
            roots = self._find_roots()
            lines = []
            lines.append("=" * 80)
            lines.append("DISTRIBUTED CALL GRAPH (DAG)".center(80))
            lines.append("=" * 80)
            lines.append(f"Machines reported: {len(self.machines)}  |  "
                         f"Total requests: {len(self.requests)}  |  "
                         f"Total edges: {sum(len(v) for v in self.call_graph.values())}  |  "
                         f"Unmatched: {len(self.unmatched)}")
            lines.append("")

            visited = set()
            for root in roots:
                self._render_tree(root, "", True, lines, visited)
                lines.append("")

            lines.append("")
            lines.append("=" * 80)

            # Per-request resource summary table
            lines.append("")
            lines.append("PER-REQUEST RESOURCE SUMMARY")
            lines.append("-" * 260)
            hdr = (f"{'Request-ID':<50} | {'Machine':<20} | {'Service':<45} | {'Latency(ms)':>11} | "
                   f"{'CPU(ms)':>8} | {'Bursts':>6} | {'Cycles':>14} | "
                   f"{'Virtual Mem(KB)':>15} | {'Peak Physical(KB)':>17} | "
                   f"{'Send(KB)':>9} | {'Recv(KB)':>9} | "
                   f"{'DiskRd(KB)':>10} | {'DiskWr(KB)':>10}")
            lines.append(hdr)
            lines.append("-" * 260)
            for rid in sorted(self.requests.keys()):
                r = self.requests[rid]
                svc = r.get('service_name', '')
                pid = r.get('pid', '')
                display_svc = f"{svc}({pid})" if svc else ""
                
                lines.append(
                    f"{rid:<50} | {r.get('machine_id',''):<20} | "
                    f"{display_svc:<45} | "
                    f"{r.get('latency',0):>11.3f} | "
                    f"{r.get('cpu_burst_total_ms',0):>8.3f} | "
                    f"{r.get('cpu_burst_count',0):>6} | "
                    f"{r.get('cpu_cycles_total',0):>14,} | "
                    f"{r.get('vmem',0):>15.1f} | "
                    f"{r.get('peak',0):>17.1f} | "
                    f"{r.get('send',0):>9.1f} | "
                    f"{r.get('recv',0):>9.1f} | "
                    f"{r.get('disk_rd',0):>10.1f} | "
                    f"{r.get('disk_wr',0):>10.1f}"
                )

            # Accumulated resource summary table for root spans
            lines.append("")
            lines.append("ACCUMULATED RESOURCE SUMMARY (ROOT TRACES)")
            lines.append("-" * 260)
            lines.append(hdr)
            lines.append("-" * 260)
            for root in sorted(roots):
                r = self.requests.get(root, {})
                svc = r.get('service_name', '')
                pid = r.get('pid', '')
                display_svc = f"{svc}({pid})" if svc else ""
                
                acc = self._accumulate_metrics(root, set())
                
                lines.append(
                    f"{root:<50} | {r.get('machine_id',''):<20} | "
                    f"{display_svc:<45} | "
                    f"{r.get('latency',0):>11.3f} | "
                    f"{acc.get('cpu_burst_total_ms',0):>8.3f} | "
                    f"{acc.get('cpu_burst_count',0):>6} | "
                    f"{acc.get('cpu_cycles_total',0):>14,} | "
                    f"{acc.get('vmem',0):>15.1f} | "
                    f"{acc.get('peak',0):>17.1f} | "
                    f"{acc.get('send',0):>9.1f} | "
                    f"{acc.get('recv',0):>9.1f} | "
                    f"{acc.get('disk_rd',0):>10.1f} | "
                    f"{acc.get('disk_wr',0):>10.1f}"
                )

            return "\n".join(lines)

    def _render_tree(self, req_id, prefix, is_last, lines, visited):
        """Recursive DFS tree rendering with cycle detection."""
        req = self.requests.get(req_id, {})
        latency = req.get('latency', 0)
        dst = req.get('dst', '')
        machine = req.get('machine_id', '')
        svc = req.get('service_name')
        pid = req.get('pid')
        display_svc = f" | {svc}({pid})" if svc else ""

        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{req_id}  [{dst}] ({latency:.2f}ms) @{machine}{display_svc}")

        if req_id in visited:
            new_prefix = prefix + ("    " if is_last else "│   ")
            lines.append(f"{new_prefix}    (cycle detected, skipping)")
            return
        visited.add(req_id)

        children = self.call_graph.get(req_id, [])
        backends = self.backend_edges.get(req_id, [])
        
        # Group identical backend calls (e.g. 5x Memcached calls)
        grouped_backends = {}
        for b in backends:
            grouped_backends[b] = grouped_backends.get(b, 0) + 1
            
        unique_backends = []
        for name, count in grouped_backends.items():
            if count > 1:
                unique_backends.append(f"{name} ({count} calls)")
            else:
                unique_backends.append(name)

        new_prefix = prefix + ("    " if is_last else "│   ")
        total = len(children) + len(unique_backends)
        
        # 1. Render actual Thrift children
        for i, child_id in enumerate(children):
            is_child_last = (i == total - 1)
            self._render_tree(child_id, new_prefix, is_child_last, lines, visited)

        # 2. Render backend database calls as terminal leaf nodes
        for i, backend_str in enumerate(unique_backends):
            idx = len(children) + i
            is_child_last = (idx == total - 1)
            child_connector = "└── " if is_child_last else "├── "
            lines.append(f"{new_prefix}{child_connector}⛁ {backend_str}")

    def _accumulate_metrics(self, req_id, visited):
        """Recursively sum metrics for a request and its children."""
        if req_id in visited:
            return {}  # break cycles
        visited.add(req_id)
        
        req = self.requests.get(req_id, {})
        acc = {
            'cpu_burst_total_ms': req.get('cpu_burst_total_ms', 0),
            'cpu_burst_count': req.get('cpu_burst_count', 0),
            'cpu_cycles_total': req.get('cpu_cycles_total', 0),
            'vmem': req.get('vmem', 0),
            'peak': req.get('peak', 0),
            'send': req.get('send', 0),
            'recv': req.get('recv', 0),
            'disk_rd': req.get('disk_rd', 0),
            'disk_wr': req.get('disk_wr', 0),
        }
        
        for child_id in self.call_graph.get(req_id, []):
            child_acc = self._accumulate_metrics(child_id, visited)
            for k, v in child_acc.items():
                acc[k] = acc.get(k, 0) + v
                
        return acc


# ═══════════════════════════════════════════════════════════════
# HTTP Server (stdlib, no Flask dependency)
# ═══════════════════════════════════════════════════════════════

handler_instance = LogHandler()


class RequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data):
        body = json.dumps(data, indent=2, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status, text):
        body = text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == '/ingest':
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len)
            try:
                payload = json.loads(body)
            except json.JSONDecodeError as e:
                self._send_json(400, {'error': f'Invalid JSON: {e}'})
                return
            result = handler_instance.ingest(payload)
            print(f"[INGEST] [{datetime.now().isoformat()}] {result['machine_id']}: "
                  f"{result['requests_ingested']} requests, "
                  f"{result['connections_ingested']} connections")
            self._send_json(200, result)

        elif path == '/rebuild':
            with handler_instance.lock:
                handler_instance._graph_dirty = True
            handler_instance._ensure_graph()
            self._send_json(200, {'status': 'rebuilt'})

        else:
            self._send_json(404, {'error': 'Not found'})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/graph':
            self._send_json(200, handler_instance.get_graph_json())

        elif path == '/graph/print':
            self._send_text(200, handler_instance.get_graph_text())

        elif path == '/requests':
            self._send_json(200, handler_instance.requests)

        elif path.startswith('/requests/'):
            req_id = path[len('/requests/'):]
            req = handler_instance.requests.get(req_id)
            if req:
                # Include connections made by this request
                conns = handler_instance.connections.get(req_id, [])
                children = handler_instance.call_graph.get(req_id, [])
                resp = {**req, 'outgoing_connections': conns, 'called_requests': children}
                self._send_json(200, resp)
            else:
                self._send_json(404, {'error': f'Request {req_id} not found'})

        elif path == '/machines':
            self._send_json(200, handler_instance.machines)

        else:
            self._send_json(404, {'error': 'Not found'})

    def log_message(self, format, *args):
        # Suppress default access logs, we print our own
        pass


def main():
    parser = argparse.ArgumentParser(description='Central Log-Handler for Distributed USC')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on (default: 5000)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), RequestHandler)
    print("=" * 60)
    print("USC CENTRAL LOG-HANDLER".center(60))
    print("=" * 60)
    print(f"Listening on {args.host}:{args.port}")
    print(f"Endpoints:")
    print(f"  POST /ingest        — Receive USC data")
    print(f"  GET  /graph         — JSON call graph")
    print(f"  GET  /graph/print   — Text call graph")
    print(f"  GET  /requests      — All request metrics")
    print(f"  GET  /requests/<id> — Single request detail")
    print(f"  GET  /machines      — Reporting machines")
    print(f"  POST /rebuild       — Force graph rebuild")
    print("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
