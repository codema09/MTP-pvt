import re
import graphviz

data = """
└── ComposePost_seq0_fabdd7e4871eff23  [10.11.0.77:9090] (10070.65ms) @shrest-VB0 | socialnetwork_compose-post-service(61528)
    ├── ComposeText_seq0_3e1368e078df1a56  [10.11.0.95:9090] (4.75ms) @shrest-VB6 | socialnetwork_text-service(31996)
    │   ├── ComposeUrls_seq0_af59af19834f1d4c  [10.11.0.43:9090] (1.92ms) @shrest-VB12 | socialnetwork_url-shorten-service(12140)
    │   │   └── ⛁ [Memcached] 10.11.0.10:11211 (3 calls)
    │   └── ComposeUserMentions_seq0_b13fd0bac3c06cd7  [10.11.0.89:9090] (1.75ms) @shrest-VB7 | socialnetwork_user-mention-service(11647)
    ├── ComposeCreatorWithUserId_seq0_73ba854fd241032a  [10.11.0.91:9090] (3.11ms) @shrest-VB9 | socialnetwork_user-service(23808)
    ├── ComposeUniqueId_seq0_4743a2c5417df296  [10.11.0.65:9090] (4.07ms) @shrest-VB10 | socialnetwork_unique-id-service(13227)
    ├── WriteUserTimeline_seq0_c7da759388bbd772  [10.11.0.30:9090] (8.91ms) @shrest-VB8 | socialnetwork_user-timeline-service(11738)
    │   ├── ⛁ [Redis] 10.11.0.8:6379 (2 calls)
    │   └── ⛁ [MongoDB] 10.11.0.12:27017
    ├── WriteHomeTimeline_seq0_9f1fa50a318a25c3  [10.11.0.74:9090] (21.47ms) @shrest-VB8 | socialnetwork_home-timeline-service(11897)
    │   └── GetFollowers_seq0_4e4e5a386649c765  [10.11.0.82:9090] (7.65ms) @shrest-VB12 | socialnetwork_social-graph-service(12496)
    ├── StorePost_seq0_385f9c7cf08766bc  [10.11.0.97:9090] (4.84ms) @shrest-VB6 | socialnetwork_post-storage-service(32146)
    └── ComposeMedia_seq0_883dcba0f61b73c3  [10.11.0.71:9090] (1.74ms) @shrest-VB14 | socialnetwork_media-service(12067)

"""

def generate_dag(text_data, output_filename="request_dag"):
    # Initialize the Graphviz directed graph object
    dot = graphviz.Digraph(comment='Request Trace DAG')
    dot.attr(rankdir='LR')
    dot.attr('node', shape='box', style='rounded,filled', fontname='Helvetica', fillcolor='#f0f9ff', color='#005b96', penwidth='2')
    dot.attr('edge', color='#555555', penwidth='1.5', arrowhead='vee')
    dot.attr(nodesep='0.05', ranksep='2.0')

    stack = {}
    
    # Split raw data by lines and remove empty strings
    lines = [line for line in text_data.split('\n') if line.strip()]

    for i, line in enumerate(lines):
        # Try formatting as a backend leaf node first
        backend_match = re.search(r'⛁\s+\[([^\]]+)\]\s+([^ ]+)(?:\s+\(([0-9]+)\s+calls\))?', line)
        if backend_match:
            category = backend_match.group(1)
            ip_port = backend_match.group(2)
            calls_val = backend_match.group(3)
            
            prefix = line[:backend_match.start()]
            level = len(prefix) // 4 - 1
            node_id = f"node_{i}"
            
            call_text = f" ({calls_val} calls)" if calls_val else ""
            label = f"{category}{call_text}\n{ip_port}"
            
            # Use cylinder shape for databases
            dot.node(node_id, label, shape='cylinder', fillcolor='#fff3e0', color='#e65100', style='filled')
            
            if level > 0:
                parent_id = stack[level - 1]
                dot.edge(parent_id, node_id, color="#e65100", style="dashed")
            continue

        # Extract metadata using regex
        # Pattern captures: 1: Method name, 2: IP:Port, 3: Duration, 4: Swarm node, 5: Service Info
        match = re.search(r'([a-zA-Z_0-9]+)\s+\[([^\]]+)\]\s+\(([^)]+)\)\s+@([^\s]+)\s+\|\s+(.*)', line)
        
        if not match:
            continue
            
        full_method_name = match.group(1)
        method_name = full_method_name.split('_')[0]
        
        ip_port = match.group(2)
        duration = match.group(3)
        swarm_node = match.group(4)
        service = match.group(5).split('(')[0] # Strip the trailing PID 
        
        # Calculate level in tree based on indentation prefix length 
        # (each indent step adds exactly 4 characters like "    " or "│   ")
        prefix = line[:match.start(1)]
        level = len(prefix) // 4 - 1
        
        node_id = f"node_{i}"
        
        label = f"{method_name}\n({duration})\n{swarm_node}\n{service}"
        
        if "GetFollowers" in method_name:
            dot.node(node_id, label, fillcolor="#e8f5e9", color="#2e7d32")
        elif "ComposePost" in method_name:
            dot.node(node_id, label, fillcolor="#ffebee", color="#c62828")
        else:
            dot.node(node_id, label)
        
        # Keep track of the nodes at current depth levels to figure out parent-child linkages
        stack[level] = node_id
        
        if level > 0:
            parent_id = stack[level - 1]
            dot.edge(parent_id, node_id)

    # Output to a file and render graphic
    # This will render a request_dag.png and request_dag.pdf automatically
    dot.render(output_filename, format='png', cleanup=True)
    print(f"Successfully generated {output_filename}.png")

if __name__ == "__main__":
    generate_dag(data)
