import yaml
import copy
from collections import defaultdict
import os

with open('DSB/socialNetwork/docker-compose-swarm.yml', 'r') as f:
    compose = yaml.safe_load(f)

# The pool of 25 nodes
ips = [f"10.5.30.{i}" for i in range(93, 118)]

# We need to map service to Node ID (0 to 24).
node_assignments = defaultdict(list)
service_to_ip = {}

services = list(compose['services'].keys())

# Keep track of port classes to ensure we never put two services with identical ports on same Node
port_groups = {
    'web': ['nginx-web-server', 'media-frontend'],
    'thrift': [s for s in services if s.endswith('-service') and 'frontend' not in s and 'nginx' not in s],
    'mongo': [s for s in services if 'mongodb' in s],
    'memcache': [s for s in services if 'memcached' in s],
    'redis': [s for s in services if 'redis' in s],
    'database': ['cassandra'],
    'other': ['jaeger-agent', 'jaeger-collector', 'jaeger-query', 'cassandra-schema']
}

node_idx = 0
for group, svcs in port_groups.items():
    for svc in svcs:
        node_assignments[node_idx].append(svc)
        service_to_ip[svc] = ips[node_idx]
        node_idx = (node_idx + 1) % 25

# Generate the global compose file
new_compose = {'version': '3', 'services': {}}
for svc, conf in compose['services'].items():
    conf_copy = copy.deepcopy(conf)
    if 'deploy' in conf_copy:
        del conf_copy['deploy']
    if 'networks' in conf_copy:
        del conf_copy['networks']
    if 'depends_on' in conf_copy:
        del conf_copy['depends_on']
    if 'ports' in conf_copy:
        del conf_copy['ports'] # Host mode exposes its Native ports automatically directly onto VM
        
    conf_copy['network_mode'] = 'host'
    # Inject universal routing table
    conf_copy['extra_hosts'] = [f"{s}:{ip}" for s, ip in service_to_ip.items()]
    
    new_compose['services'][svc] = conf_copy

# Save global modified compose
with open('DSB/socialNetwork/docker-compose-host.yml', 'w') as f:
    yaml.dump(new_compose, f, sort_keys=False)

# Save an assignment string for bash orchestrator!
with open('distribution_mapping.txt', 'w') as f:
    for node, svcs in node_assignments.items():
        f.write(f"{ips[node]}:{' '.join(svcs)}\n")

# Patch Nginx Lua Scripts to bypass OpenResty DNS explicitly
lua_dir = 'DSB/socialNetwork/nginx-web-server/lua-scripts'
if os.path.exists(lua_dir):
    for root, dirs, files in os.walk(lua_dir):
        for file in files:
            if file.endswith('.lua'):
                path = os.path.join(root, file)
                with open(path, 'r') as fw:
                    content = fw.read()
                for svc, ip in service_to_ip.items():
                    content = content.replace(f'"{svc}"', f'"{ip}"')
                    content = content.replace(f"'{svc}'", f"'{ip}'")
                with open(path, 'w') as fw:
                    fw.write(content)

import json
# Patch Service Config to overcome Docker Host Network ignoring extra_hosts and missing eth0
svc_path = 'DSB/socialNetwork/config/service-config.json'
if os.path.exists(svc_path):
    with open(svc_path, 'r') as f:
        s_conf = json.load(f)
    for k, v in s_conf.items():
        if isinstance(v, dict):
            if 'addr' in v and v['addr'] in service_to_ip:
                v['addr'] = service_to_ip[v['addr']]
            if 'netif' in v and (v['netif'] == 'eth0' or v['netif'] == 'enp0s8'):
                v['netif'] = 'enp0s3'
    with open(svc_path, 'w') as f:
        json.dump(s_conf, f, indent=2)

# Patch Jaeger Nginx config
j_path = 'DSB/socialNetwork/nginx-web-server/jaeger-config.json'
if os.path.exists(j_path) and 'jaeger-agent' in service_to_ip:
    with open(j_path, 'r') as f:
        j_cont = f.read()
    j_cont = j_cont.replace('jaeger-agent', service_to_ip['jaeger-agent'])
    with open(j_path, 'w') as f:
        f.write(j_cont)

print("Generated Distributed Host Compose configuration and Static IP bindings successfully!")
