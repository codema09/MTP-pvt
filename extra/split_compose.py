import yaml

source_file = "DeathStarBench/socialNetwork/docker-compose.yml"

with open(source_file, 'r') as f:
    data = yaml.safe_load(f)

parts = {
    1: ['nginx-thrift', 'media-frontend', 'jaeger-agent', 'compose-post-service', 'text-service', 'url-shorten-service', 'url-shorten-memcached', 'url-shorten-mongodb'],
    2: ['user-service', 'user-memcached', 'user-mongodb', 'user-mention-service', 'unique-id-service', 'media-service', 'media-memcached', 'media-mongodb'],
    3: ['social-graph-service', 'social-graph-mongodb', 'social-graph-redis', 'post-storage-service', 'post-storage-memcached', 'post-storage-mongodb'],
    4: ['home-timeline-service', 'home-timeline-redis', 'user-timeline-service', 'user-timeline-redis', 'user-timeline-mongodb']
}

for part_num, svcs in parts.items():
    new_data = {
        'version': data.get('version', '3'),
        'services': {},
        'networks': {
            'default': {
                'external': True,
                'name': 'social-network-overlay'
            }
        }
    }
    
    for s_name in svcs:
        if s_name in data['services']:
            new_data['services'][s_name] = data['services'][s_name]
    
    # Clean up depends_on to only include services in the SAME file!
    # Wait, if we use separate compose files on an attachable overlay, 
    # cross-compose depends_on will fail validation (service not found).
    # Since they are distributed, we just strip depends_on completely, or rely on restart: always to eventually sync.
    for s_name in new_data['services']:
        if 'depends_on' in new_data['services'][s_name]:
            del new_data['services'][s_name]['depends_on']
            
    with open(f"DeathStarBench/socialNetwork/docker-compose-node{part_num}.yml", 'w') as f:
        yaml.dump(new_data, f, default_flow_style=False, sort_keys=False)
        
print("Successfully generated 4 partitioned docker-compose files!")
