#!/bin/bash
set -e

USER="shrest"
PASS="1234"
# Generate nodes dynamically from 93 to 117
NODES=($(seq -f "10.5.30.%g" 93 117))
MANAGER="${NODES[0]}"
WORKERS=("${NODES[@]:1}")
PROJECT_DIR="~/bcc-latest"

echo "========================================================="
echo " Starting Multi-Node Docker Swarm Deployment (25 nodes)"
echo " Manager: $MANAGER"
echo " Workers: ${WORKERS[*]}"
echo "========================================================="

MY_IP=$(ip route get $MANAGER | awk '{print $7; exit}')
if [ -z "$MY_IP" ]; then
    MY_IP=$(hostname -I | awk '{print $1}')
fi
echo "Log Handler (archlinux) IP detected as: $MY_IP"

trap '
    trap - SIGINT
    echo -e "\n[+] Intercepted Ctrl+C! Gracefully stopping distributed BPF sniffers precisely on ALL servers..."
    
    # Parallel teardown, storing pids to wait ONLY on these cleanup commands
    TEARDOWN_PIDS=()
    for NODE in "${NODES[@]}"; do
        sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$NODE" "echo '"'$PASS'"' | sudo -S -p '"''"' pkill -15 -f \"python3.*new-architecture-USC.py\"" >/dev/null 2>&1 &
        TEARDOWN_PIDS+=($!)
    done
    
    echo "[+] Sending termination signals to all nodes concurrently (~2 secs)..."
    for TPID in "${TEARDOWN_PIDS[@]}"; do
        wait $TPID 2>/dev/null || true
    done
    
    echo "✅ Distributed Teardown cleanly completed. Exiting entirely."
    exit 0
' SIGINT

echo ""
echo "[0/4] Pre-compiling static IP assignments in Host Topology natively..."
python3 generate_distributed_compose.py

echo ""
if [[ " $* " =~ " --skip-sync " ]]; then
    echo "[1/4] Skipping codebase synchronization..."
else
    echo "[1/4] Syncing codebase to all nodes..."
    tar --exclude='.git' --exclude='node_modules' --exclude='*.ansi' --exclude='*.log' --exclude='yay' --exclude='DeathStarBench' --exclude='Python' --exclude='extras/venv' --exclude='wrk2' -czf /tmp/bcc-latest-cluster.tar.gz .
    
    for NODE in "${NODES[@]}"; do
        echo "  [+] Syncing to $NODE..."
        sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$NODE" "mkdir -p $PROJECT_DIR"
        sshpass -p "$PASS" scp -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" /tmp/bcc-latest-cluster.tar.gz "$USER@$NODE:/tmp/bcc-latest.tar.gz"
        sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$NODE" "tar -xzf /tmp/bcc-latest.tar.gz -C $PROJECT_DIR/" &
    done
    wait
fi

echo ""
if [[ " $* " =~ " --skip-deploy " ]]; then
    echo "[2,3/4] Skipping Distributed deployment and graph initialization..."
else
    echo "  [+] Tearing down existing infrastructure & Syncing allocation topology..."
    for W in "${NODES[@]}"; do
        sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" "$USER@$W" "
            cd $PROJECT_DIR/DSB/socialNetwork
            echo '$PASS' | sudo -S docker compose down >/dev/null 2>&1 || true
            echo '$PASS' | sudo -S docker stack rm socialnetwork >/dev/null 2>&1 || true
            echo '$PASS' | sudo -S sh -c 'docker rm -f \$(docker ps -aq)' >/dev/null 2>&1 || true
            echo '$PASS' | sudo -S docker swarm leave --force >/dev/null 2>&1 || true
            echo '$PASS' | sudo -S docker network prune -f >/dev/null 2>&1 || true
        " &
    done
    wait
    
    for W in "${NODES[@]}"; do
        sshpass -p "$PASS" scp -o "StrictHostKeyChecking=no" distribution_mapping.txt "$USER@$W:$PROJECT_DIR/distribution_mapping.txt" >/dev/null 2>&1 &
        sshpass -p "$PASS" scp -o "StrictHostKeyChecking=no" DSB/socialNetwork/docker-compose-host.yml "$USER@$W:$PROJECT_DIR/DSB/socialNetwork/docker-compose-host.yml" >/dev/null 2>&1 &
    done
    wait
    
    echo "  [+] Natively deploying allocated services directly over gigabit Host networking..."
    while IFS= read -r line; do
        NODE_IP=$(echo "$line" | cut -d: -f1)
        SERVICES=$(echo "$line" | cut -d: -f2)
        if [ ! -z "$SERVICES" ]; then
            sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" "$USER@$NODE_IP" "cd $PROJECT_DIR/DSB/socialNetwork && echo '$PASS' | sudo -S docker compose -f docker-compose-host.yml up -d $SERVICES >/dev/null 2>&1" &
        fi
    done < distribution_mapping.txt
    wait

    echo ""
    echo "Polling port 8080 on Nginx node ($MANAGER) until Nginx fully boots..."
    while ! curl -s -f -m 2 -o /dev/null "http://$MANAGER:8080" && ! curl -s -o /dev/null "http://$MANAGER:8080"; do
        echo -n "."
        sleep 5
    done
    echo " [OK] Nginx is up natively across the Distributed Layout!"

    echo "Waiting 45 seconds to ensure backend Thrift instances initialize past Jaeger tracer blockers..."
    sleep 45

    echo ""
    echo "[3/4] Initializing Social Graph Database cleanly over physical endpoints..."
    if [ -f "$PWD/extras/venv/bin/activate" ]; then
        source "$PWD/extras/venv/bin/activate"
    fi
    (cd DSB/socialNetwork && python3 scripts/init_social_graph.py --ip $MANAGER --port 8080 --max-nodes 1000) || echo "WARNING: Failed to run init_social_graph.py. Ensure your virtual env is active."
fi

echo ""
echo "[4/4] Populating service_mapping.txt and natively injecting background eBPF profilers on ALL nodes..."

PAYLOAD=$(cat << EOF
$PASS
cd /home/shrest/bcc-latest/src

echo '[+] Purging any broken BPF ghosts...'
pkill -9 -f new-architecture-USC.py || true
pkill -9 -f attach_sniffers.py || true
tmux kill-session -t ebpf_sniffer 2>/dev/null || true

rm -f service_mapping.txt
PIDS=""

for c in \$(docker ps -q); do
    PID=\$(docker inspect -f '{{.State.Pid}}' \$c)
    NAME=\$(docker inspect -f '{{.Name}}' \$c | sed 's/\///' | sed 's/_[0-9]\+$//' | sed 's/socialnetwork-//')
    
    echo "\$NAME: \${PID}" >> service_mapping.txt
    
    if [ -n "\$PID" ] && [ "\$PID" != "0" ]; then
        PIDS="\$PIDS \$PID"
    fi
done

if [ -n "\$PIDS" ]; then
    echo "========================================================="
    echo "✅ Sniffer actively capturing PIDs: \$PIDS"
    echo "Traffic is bound for http://$MY_IP:5000/ingest"
    echo "Logs are being silently written to live_single.log"
    echo "(Press Ctrl+C at any time to softly kill the sniffer)"
    echo "========================================================="
    sudo -E TERM=xterm-256color python3 -u new-architecture-USC.py -p \$PIDS --log-handler http://$MY_IP:5000/ingest > live_single.log 2>&1
else
    echo "[ Server ] No containers found on this node to profile."
fi
EOF
)

# Run the SSH stream natively in the background holding instances without closing standard io.
DEPLOY_PIDS=()
for NODE in "${NODES[@]}"; do
    echo "$PAYLOAD" | sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" "$USER@$NODE" "sudo -S -p '' bash -s" &
    DEPLOY_PIDS+=($!)
done

for PID in "${DEPLOY_PIDS[@]}"; do
    wait $PID 2>/dev/null
done