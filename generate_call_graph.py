#!/usr/bin/env python3
"""Reproduce the existing DAG style exactly, adding Redis/Memcached/MongoDB nodes."""
import subprocess

# Exact same style as generate_dag.py
DOT_CONTENT = r'''digraph CallGraph {
    graph [
        rankdir=LR
        fontname="Helvetica"
        bgcolor="white"
        nodesep=0.05
        ranksep=2.0
    ]
    node [
        shape=box
        style="rounded,filled"
        fontname="Helvetica"
        fontsize=10
        fillcolor="#f0f9ff"
        color="#005b96"
        penwidth=2
    ]
    edge [
        color="#555555"
        penwidth=1.5
        arrowhead=vee
        fontname="Helvetica"
        fontsize=9
    ]

    // ── Service nodes (exact label format from generate_dag.py) ──────────
    ComposePost [
        label="ComposePost\n(10070.65ms)\n@shrest-VB0\nsocialnetwork_compose-post-service"
        fillcolor="#ffebee" color="#c62828"
    ]
    WriteUserTimeline [
        label="WriteUserTimeline\n(8.91ms)\n@shrest-VB8\nsocialnetwork_user-timeline-service"
    ]
    WriteHomeTimeline [
        label="WriteHomeTimeline\n(21.47ms)\n@shrest-VB8\nsocialnetwork_home-timeline-service"
    ]
    GetFollowers [
        label="GetFollowers\n(7.65ms)\n@shrest-VB12\nsocialnetwork_social-graph-service"
        fillcolor="#e8f5e9" color="#2e7d32"
    ]
    ComposeCreatorWithUserId [
        label="ComposeCreatorWithUserId\n(3.11ms)\n@shrest-VB9\nsocialnetwork_user-service"
    ]
    ComposeUniqueId [
        label="ComposeUniqueId\n(4.07ms)\n@shrest-VB10\nsocialnetwork_unique-id-service"
    ]
    StorePost [
        label="StorePost\n(4.84ms)\n@shrest-VB6\nsocialnetwork_post-storage-service"
    ]
    ComposeText [
        label="ComposeText\n(4.75ms)\n@shrest-VB6\nsocialnetwork_text-service"
    ]
    ComposeUserMentions [
        label="ComposeUserMentions\n(1.75ms)\n@shrest-VB7\nsocialnetwork_user-mention-service"
    ]
    ComposeUrls [
        label="ComposeUrls\n(1.92ms)\n@shrest-VB12\nsocialnetwork_url-shorten-service"
    ]
    ComposeMedia [
        label="ComposeMedia\n(1.74ms)\n@shrest-VB14\nsocialnetwork_media-service"
    ]

    // ── DB backend nodes (new additions) ─────────────────────────────────
    Redis [
        label="Redis\n@shrest-VB15"
        shape=cylinder style="filled" fillcolor="#fff3e0" color="#e65100"
        penwidth=2 fontsize=10 fontname="Helvetica"
    ]
    Memcached [
        label="Memcached\n@shrest-VB15"
        shape=cylinder style="filled" fillcolor="#fff3e0" color="#e65100"
        penwidth=2 fontsize=10 fontname="Helvetica"
    ]
    MongoDB [
        label="MongoDB\n@shrest-VB16"
        shape=cylinder style="filled" fillcolor="#fff3e0" color="#e65100"
        penwidth=2 fontsize=10 fontname="Helvetica"
    ]

    { rank=sink; Redis; Memcached; MongoDB }

    // ── Thrift RPC edges (unchanged from existing graph) ──────────────────
    ComposePost -> WriteUserTimeline
    ComposePost -> WriteHomeTimeline
    ComposePost -> ComposeCreatorWithUserId
    ComposePost -> ComposeUniqueId
    ComposePost -> StorePost
    ComposePost -> ComposeText
    ComposePost -> ComposeMedia
    WriteHomeTimeline -> GetFollowers
    ComposeText -> ComposeUserMentions
    ComposeText -> ComposeUrls

    // ── DB call edges (dashed — confirmed from eBPF logs) ─────────────────
    // WriteUserTimeline → Redis + MongoDB  [generate_dag.py data + first.ansi]
    WriteUserTimeline -> Redis    [style=dashed color="#e65100" penwidth=1.5]
    WriteUserTimeline -> MongoDB  [style=dashed color="#e65100" penwidth=1.5]

    // WriteHomeTimeline → Redis  [gp_first.log tree]
    WriteHomeTimeline -> Redis    [style=dashed color="#e65100" penwidth=1.5]

    // GetFollowers → Redis + MongoDB  [first.ansi]
    GetFollowers -> Redis         [style=dashed color="#e65100" penwidth=1.5]
    GetFollowers -> MongoDB       [style=dashed color="#e65100" penwidth=1.5]

    // StorePost → MongoDB  [first.ansi]
    StorePost -> MongoDB          [style=dashed color="#e65100" penwidth=1.5]

    // ComposeCreatorWithUserId → Memcached + MongoDB  [gp_init.log user-service]
    ComposeCreatorWithUserId -> Memcached [style=dashed color="#e65100" penwidth=1.5]
    ComposeCreatorWithUserId -> MongoDB   [style=dashed color="#e65100" penwidth=1.5]

    // ComposeUrls → Memcached  [generate_dag.py data: 10.11.0.10:11211]
    ComposeUrls -> Memcached      [style=dashed color="#e65100" penwidth=1.5]
}
'''

dot_path = 'src/graphs/call_graph.dot'
png_path = 'src/graphs/call_graph.png'

with open(dot_path, 'w') as f:
    f.write(DOT_CONTENT)

result = subprocess.run(
    ['dot', '-Tpng', '-Gdpi=180', dot_path, '-o', png_path],
    capture_output=True, text=True
)
if result.returncode == 0:
    print(f"Rendered → {png_path}")
else:
    print(f"Error:\n{result.stderr}")
