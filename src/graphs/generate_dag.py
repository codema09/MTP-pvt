import re
import graphviz

data = """
└── ComposePost_seq0_05adee7c6572bd5a  [10.0.1.10:9090] (10099.19ms) @swarm-node-2 | socialnetwork-compose-post-service-1(276239)
    ├── ComposeUniqueId_seq0_0edb3c3f93e46fc8  [10.0.1.62:9090] (0.60ms) @swarm-node-3 | socialnetwork-unique-id-service-1(278313)
    ├── ComposeText_seq0_7ec6cbcc15aad283  [10.0.1.7:9090] (13.73ms) @swarm-node-2 | socialnetwork-text-service-1(276188)
    │   ├── ComposeUserMentions_seq0_6ba286c918b56639  [10.0.1.69:9090] (0.26ms) @swarm-node-3 | socialnetwork-user-mention-service-1(278537)
    │   └── ComposeUrls_seq0_b67646ee7f8a2844  [10.0.1.254:9090] (0.31ms) @swarm-node-2 | socialnetwork-url-shorten-service-1(276089)
    ├── WriteUserTimeline_seq0_091b1913f8dd9e96  [10.0.1.87:9090] (3.31ms) @swarm-node-5 | socialnetwork-user-timeline-service-1(267973)
    ├── WriteHomeTimeline_seq0_30ccbc3cc12fb968  [10.0.1.84:9090] (4.89ms) @swarm-node-5 | socialnetwork-home-timeline-service-1(268115)
    │   ├── GetFollowers_seq0_6578fa13cbb45b1c  [10.0.1.76:9090] (5.72ms) @swarm-node-4 | socialnetwork-social-graph-service-1(269126)
    │   └── GetFollowers_seq0_62d1056aa0fce24c  [10.0.1.76:9090] (3.87ms) @swarm-node-4 | socialnetwork-social-graph-service-1(269126)
    ├── ComposeMedia_seq0_56f8716c004503a5  [10.0.1.65:9090] (0.52ms) @swarm-node-3 | socialnetwork-media-service-1(278554)
    ├── WriteUserTimeline_seq0_b869f15f70d8a546  [10.0.1.87:9090] (12.29ms) @swarm-node-5 | socialnetwork-user-timeline-service-1(267973)
    ├── WriteHomeTimeline_seq0_6799ab9581277eeb  [10.0.1.84:9090] (15.01ms) @swarm-node-5 | socialnetwork-home-timeline-service-1(268115)
    │   └── GetFollowers_seq0_cc3dd26869e4bbcb  [10.0.1.76:9090] (10.09ms) @swarm-node-4 | socialnetwork-social-graph-service-1(269126)
    ├── StorePost_seq0_8d8951ab3aebf064  [10.0.1.79:9090] (1.36ms) @swarm-node-4 | socialnetwork-post-storage-service-1(269233)
    └── ComposeCreatorWithUserId_seq0_c824ebbea410ae52  [10.0.1.64:9090] (0.29ms) @swarm-node-3 | socialnetwork-user-service-1(278394)
"""

def generate_dag(text_data, output_filename="request_dag"):
    # Initialize the Graphviz directed graph object
    dot = graphviz.Digraph(comment='Request Trace DAG')
    dot.attr(rankdir='TB') # Top to Bottom hierarchy
    dot.attr(dpi='300') # Increase resolution to fix pixelation
    dot.attr(nodesep='0.03', ranksep='1.6') # More vertical space and narrower width
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue', fontname='Helvetica', fontsize='10')

    stack = {}
    
    # Split raw data by lines and remove empty strings
    lines = [line for line in text_data.split('\n') if line.strip()]

    for i, line in enumerate(lines):
        # Extract metadata using regex
        # Pattern captures: 1: Method name, 2: IP:Port, 3: Duration, 4: Swarm node, 5: Service Info
        match = re.search(r'([a-zA-Z_0-9]+)\s+\[([^\]]+)\]\s+\(([^)]+)\)\s+@([^\s]+)\s+\|\s+(.*)', line)
        
        if not match:
            continue
            
        full_method_name = match.group(1)
        # Keep the request-ID but drop the final hash (e.g. ComposePost_seq0)
        method_name = "_".join(full_method_name.split('_')[:-1])
        
        ip_port = match.group(2)
        duration = match.group(3)
        swarm_node = match.group(4)
        service = match.group(5).split('(')[0] # Strip the trailing PID 
        
        # Calculate level in tree based on indentation prefix length 
        # (each indent step adds exactly 4 characters like "    " or "│   ")
        prefix = line[:match.start(1)]
        level = len(prefix) // 4 - 1
        
        node_id = f"node_{i}"
        
        # Design a multiline layout for the node box
        label = f"<<B>{method_name}</B><BR/>" \
                f"<FONT POINT-SIZE='9' COLOR='gray30'>{service}</FONT><BR/>" \
                f"<FONT POINT-SIZE='9' COLOR='red'>{duration}</FONT> | " \
                f"<FONT POINT-SIZE='9' COLOR='blue'>{swarm_node}</FONT>>"
        
        dot.node(node_id, label=label)
        
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
