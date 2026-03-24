import os
import stat

SERVICES_DISTRIBUTION = [
    # Node 93 (Manager)
    ['nginx-thrift', 'media-frontend'],
    # Node 94
    ['jaeger-agent', 'compose-post-service'],
    # Node 95
    ['text-service', 'url-shorten-service'],
    # Node 96
    ['url-shorten-memcached', 'url-shorten-mongodb'],
    # Node 97
    ['user-service', 'user-memcached'],
    # Node 98
    ['user-mongodb', 'user-mention-service'],
    # Node 99
    ['unique-id-service', 'media-service'],
    # Node 100
    ['media-memcached', 'media-mongodb'],
    # Node 101
    ['social-graph-service', 'social-graph-mongodb'],
    # Node 102
    ['social-graph-redis', 'post-storage-service'],
    # Node 103
    ['post-storage-memcached', 'post-storage-mongodb'],
    # Node 104
    ['home-timeline-service', 'home-timeline-redis'],
    # Node 105
    ['user-timeline-service'],
    # Node 106
    ['user-timeline-redis'],
    # Node 107
    ['user-timeline-mongodb']
]

# Base service definitions extracted from docker-compose-swarm.yml and old node files
SERVICE_DEFINITIONS = {
    'nginx-thrift': """
  nginx-thrift:
    image: yg397/openresty-thrift:xenial
    hostname: nginx-thrift
    ports:
    - "8080:8080"
    restart: always
    volumes:
    - ../../DSB/socialNetwork/nginx-web-server/lua-scripts:/usr/local/openresty/nginx/lua-scripts
    - ../../DSB/socialNetwork/nginx-web-server/pages:/usr/local/openresty/nginx/pages
    - ../../DSB/socialNetwork/nginx-web-server/conf/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf
    - ../../DSB/socialNetwork/nginx-web-server/jaeger-config.json:/usr/local/openresty/nginx/jaeger-config.json
    - ../../DSB/socialNetwork/gen-lua:/gen-lua
    - ../../DSB/socialNetwork/docker/openresty-thrift/lua-thrift:/usr/local/openresty/lualib/thrift
""",
    'media-frontend': """
  media-frontend:
    image: yg397/media-frontend:xenial
    hostname: media-frontend
    ports:
    - "8081:8080"
    restart: always
    volumes:
    - ../../DSB/socialNetwork/media-frontend/lua-scripts:/usr/local/openresty/nginx/lua-scripts
    - ../../DSB/socialNetwork/media-frontend/conf/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf
""",
    'jaeger-agent': """
  jaeger-agent:
    image: jaegertracing/all-in-one:latest
    hostname: jaeger-agent
    ports:
    - "16686:16686"
    restart: always
    environment:
    - COLLECTOR_ZIPKIN_HTTP_PORT=9411
""",
    'compose-post-service': """
  compose-post-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: compose-post-service
    restart: always
    entrypoint: ComposePostService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'text-service': """
  text-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: text-service
    restart: always
    entrypoint: TextService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'url-shorten-service': """
  url-shorten-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: url-shorten-service
    restart: always
    entrypoint: UrlShortenService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'url-shorten-memcached': """
  url-shorten-memcached:
    image: memcached
    hostname: url-shorten-memcached
    restart: always
    command: ["-m", "16384", "-t", "8", "-I", "32m", "-c", "4096"]
""",
    'url-shorten-mongodb': """
  url-shorten-mongodb:
    image: mongo:4.4.6
    hostname: url-shorten-mongodb
    restart: always
    command: mongod --nojournal --quiet --config /social-network-microservices/config/mongod.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'user-service': """
  user-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: user-service
    restart: always
    entrypoint: UserService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'user-memcached': """
  user-memcached:
    image: memcached
    hostname: user-memcached
    restart: always
    command: ["-m", "16384", "-t", "8", "-I", "32m", "-c", "4096"]
""",
    'user-mongodb': """
  user-mongodb:
    image: mongo:4.4.6
    hostname: user-mongodb
    restart: always
    command: mongod --nojournal --quiet --config /social-network-microservices/config/mongod.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'user-mention-service': """
  user-mention-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: user-mention-service
    restart: always
    entrypoint: UserMentionService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'unique-id-service': """
  unique-id-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: unique-id-service
    restart: always
    entrypoint: UniqueIdService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'media-service': """
  media-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: media-service
    restart: always
    entrypoint: MediaService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'media-memcached': """
  media-memcached:
    image: memcached
    hostname: media-memcached
    restart: always
    command: ["-m", "16384", "-t", "8", "-I", "32m", "-c", "4096"]
""",
    'media-mongodb': """
  media-mongodb:
    image: mongo:4.4.6
    hostname: media-mongodb
    restart: always
    command: mongod --nojournal --quiet --config /social-network-microservices/config/mongod.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'social-graph-service': """
  social-graph-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: social-graph-service
    restart: always
    entrypoint: SocialGraphService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'social-graph-mongodb': """
  social-graph-mongodb:
    image: mongo:4.4.6
    hostname: social-graph-mongodb
    restart: always
    command: mongod --nojournal --quiet --config /social-network-microservices/config/mongod.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'social-graph-redis': """
  social-graph-redis:
    image: redis
    hostname: social-graph-redis
    restart: always
    command: redis-server /social-network-microservices/config/redis.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'post-storage-service': """
  post-storage-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: post-storage-service
    ports:
    - "10002:9090"
    restart: always
    entrypoint: PostStorageService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'post-storage-memcached': """
  post-storage-memcached:
    image: memcached
    hostname: post-storage-memcached
    restart: always
    command: ["-m", "16384", "-t", "8", "-I", "32m", "-c", "4096"]
""",
    'post-storage-mongodb': """
  post-storage-mongodb:
    image: mongo:4.4.6
    hostname: post-storage-mongodb
    restart: always
    command: mongod --nojournal --quiet --config /social-network-microservices/config/mongod.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'home-timeline-service': """
  home-timeline-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: home-timeline-service
    restart: always
    entrypoint: HomeTimelineService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'home-timeline-redis': """
  home-timeline-redis:
    image: redis
    hostname: home-timeline-redis
    restart: always
    command: redis-server /social-network-microservices/config/redis.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'user-timeline-service': """
  user-timeline-service:
    image: deathstarbench/social-network-microservices:latest
    hostname: user-timeline-service
    restart: always
    entrypoint: UserTimelineService
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'user-timeline-redis': """
  user-timeline-redis:
    image: redis
    hostname: user-timeline-redis
    restart: always
    command: redis-server /social-network-microservices/config/redis.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
""",
    'user-timeline-mongodb': """
  user-timeline-mongodb:
    image: mongo:4.4.6
    hostname: user-timeline-mongodb
    restart: always
    command: mongod --nojournal --quiet --config /social-network-microservices/config/mongod.conf
    volumes:
    - ../../DSB/socialNetwork/config:/social-network-microservices/config
"""
}

BASH_TEMPLATE = """#!/bin/bash
set -e

# Node {ip} Setup Script

DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "=========================================="
echo "    Deploying Services for {ip}   "
echo "=========================================="

if [ "{is_manager}" == "true" ]; then
    echo "[1/4] Initializing Docker Swarm as Manager on {ip}..."
    docker swarm init --advertise-addr {ip} || echo "Already in a swarm"
    docker network create --driver overlay --attachable social-network-overlay || true
    
    TOKEN=$(docker swarm join-token worker -q)
    echo ""
    echo "==================================================================="
    echo "SWARM MANAGER INITIALIZED."
    echo "JOIN TOKEN FOR OTHER WORKERS: \\033[92m$TOKEN\\033[0m"
    echo "Pass this token to other setup scripts:"
    echo "./setup_node_10.5.30.XX.sh $TOKEN"
    echo "==================================================================="
else
    if [ -z "$1" ]; then
        echo "Error: You must provide the Swarm Join Token as the first argument."
        echo "Usage: ./setup_node_{ip}.sh <SWARM_JOIN_TOKEN>"
        exit 1
    fi
    TOKEN=$1
    echo "[1/4] Joining Docker Swarm at 10.5.30.93 as Worker..."
    docker swarm join --token $TOKEN 10.5.30.93:2377 || echo "Already joined or failed."
fi

echo "[2/4] Starting docker-compose services..."
docker-compose -f docker-compose-{ip}.yml up -d

echo "[3/4] Extracting PIDs and populating service_mapping.txt..."
sleep 5

# Clear/create the mapping file if run on same machine, but usually they are independent
touch ../service_mapping.txt

PIDS=""
for container in $(docker-compose -f docker-compose-{ip}.yml ps -q); do
    PID=$(docker inspect -f '{{{{.State.Pid}}}}' $container)
    NAME=$(docker inspect -f '{{{{.Name}}}}' $container | sed 's/\\///' | sed 's/_[0-9]\\+$//' )
    echo "$NAME: $PID" >> ../service_mapping.txt
    if [ -n "$PID" ] && [ "$PID" != "0" ]; then
        PIDS="$PIDS $PID"
    fi
done

if [ -z "$PIDS" ]; then
    echo "No valid PIDs found. Exiting."
    exit 1
fi

echo "Captured Host PIDs: $PIDS"

echo "[4/4] Starting Sniffer in the background..."
pkill -f new-architecture-USC.py || true

# We must CD to src so that local imports and BPF includes work correctly
cd ..
sudo nohup python3 new-architecture-USC.py -p $PIDS > "sniffer_{ip}.log" 2>&1 &

echo "==========================================================="
echo "✅ Setup Complete!"
echo "Docker services are UP."
echo "Sniffer is detached and logging to: src/sniffer_{ip}.log"
echo "Check \`tail -f src/sniffer_{ip}.log\` for live memory profiling."
echo "==========================================================="
"""

DEPLOY_ALL_TEMPLATE = """#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "Are you sure you want to magically deploy to all 15 servers from this machine?"
echo "This requires passwordless SSH access to khr@10.5.30.93-107."
read -p "Press enter to continue..."

# 1. Start Manager and get token
echo "Starting Manager on 10.5.30.93..."
ssh -o StrictHostKeyChecking=no 10.5.30.93 "cd $(pwd) && bash setup_node_10.5.30.93.sh" > manager_out.log 2>&1
TOKEN=$(grep -oE 'SWMTKN-[a-zA-Z0-9-]+' manager_out.log | head -1)

if [ -z "$TOKEN" ]; then
    echo "Failed to extract swarm token from 10.5.30.93. Check manager_out.log"
    exit 1
fi

echo "Obtained Token: $TOKEN"

# 2. Start Workers
for i in {94..107}; do
    IP="10.5.30.$i"
    echo "Starting Worker on $IP..."
    ssh -o StrictHostKeyChecking=no $IP "cd $(pwd) && bash setup_node_$IP.sh $TOKEN" &
done

wait
echo "All servers deployed!"
"""

def generate():
    os.makedirs("swarm_scripts", exist_ok=True)
    
    base_ip = 93
    for i, services in enumerate(SERVICES_DISTRIBUTION):
        ip = f"10.5.30.{base_ip + i}"
        is_manager = "true" if ip == "10.5.30.93" else "false"
        
        # 1. Generate docker-compose file
        compose_content = f"version: '3.9'\nservices:\n"
        for s in services:
            compose_content += SERVICE_DEFINITIONS[s]
            
        compose_content += "\nnetworks:\n  default:\n    external: true\n    name: social-network-overlay\n"
        
        with open(f"swarm_scripts/docker-compose-{ip}.yml", "w") as f:
            f.write(compose_content)
            
        # 2. Generate setup script
        script_content = BASH_TEMPLATE.format(ip=ip, is_manager=is_manager)
        script_path = f"swarm_scripts/setup_node_{ip}.sh"
        with open(script_path, "w") as f:
            f.write(script_content)
            
        # Make script executable
        os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IEXEC)
        
    # Generate super deploy script
    deploy_path = "swarm_scripts/deploy_all.sh"
    with open(deploy_path, "w") as f:
        f.write(DEPLOY_ALL_TEMPLATE)
    os.chmod(deploy_path, os.stat(deploy_path).st_mode | stat.S_IEXEC)
        
    print(f"✅ Generated 15 setup scripts and compose files in 'swarm_scripts' directory.")

if __name__ == "__main__":
    generate()
