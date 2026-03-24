#!/bin/bash
set -e

# Node 10.5.30.106 Setup Script

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "=========================================="
echo "    Deploying Services for 10.5.30.106   "
echo "=========================================="

if [ "false" == "true" ]; then
    echo "[1/4] Initializing Docker Swarm as Manager on 10.5.30.106..."
    docker swarm init --advertise-addr 10.5.30.106 || echo "Already in a swarm"
    docker network create --driver overlay --attachable social-network-overlay || true
    
    TOKEN=$(docker swarm join-token worker -q)
    echo ""
    echo "==================================================================="
    echo "SWARM MANAGER INITIALIZED."
    echo "JOIN TOKEN FOR OTHER WORKERS: \033[92m$TOKEN\033[0m"
    echo "Pass this token to other setup scripts:"
    echo "./setup_node_10.5.30.XX.sh $TOKEN"
    echo "==================================================================="
else
    if [ -z "$1" ]; then
        echo "Error: You must provide the Swarm Join Token as the first argument."
        echo "Usage: ./setup_node_10.5.30.106.sh <SWARM_JOIN_TOKEN>"
        exit 1
    fi
    TOKEN=$1
    echo "[1/4] Joining Docker Swarm at 10.5.30.93 as Worker..."
    docker swarm join --token $TOKEN 10.5.30.93:2377 || echo "Already joined or failed."
fi

echo "[2/4] Starting docker-compose services..."
docker compose -f docker-compose-10.5.30.106.yml up -d

echo "[3/4] Extracting PIDs and populating service_mapping.txt..."
sleep 5

# Clear/create the mapping file
> ../service_mapping.txt

PIDS=""
for container in $(docker compose -f docker-compose-10.5.30.106.yml ps -q); do
    PID=$(docker inspect -f '{{.State.Pid}}' $container)
    NAME=$(docker inspect -f '{{.Name}}' $container | sed 's/\///' | sed 's/_[0-9]\+$//' )
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

echo "[4/4] Starting Sniffer in a detached tmux session..."
pkill -f new-architecture-USC.py || true

# We must CD to src so that local imports and BPF includes work correctly
cd ..
tmux kill-session -t ebpf_sniffer 2>/dev/null || true
tmux new-session -d -s ebpf_sniffer "sudo python3 new-architecture-USC.py -p $PIDS --log-handler http://10.105.18.100:5000/ingest 2>&1 | tee sniffer_10.5.30.106.log"

echo "==========================================================="
echo "✅ Setup Complete!"
echo "Docker services are UP."
echo "Sniffer is running safely in a foreground tmux session!"
echo "To view the live output anytime, SSH into this server and type:"
echo "    tmux attach -t ebpf_sniffer"
echo "To detach again without stopping it, press Ctrl+B, then D."
echo "==========================================================="
