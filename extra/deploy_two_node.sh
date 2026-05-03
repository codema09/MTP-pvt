#!/bin/bash
set -e

USER="shrest"
PASS="1234"
MANAGER="10.5.30.93"
WORKER="10.5.30.94"
PROJECT_DIR="~/bcc-latest"

echo "========================================================="
echo " Starting Two-Node Docker Swarm Deployment on $MANAGER & $WORKER "
echo "========================================================="

MY_IP=$(ip route get $MANAGER | awk '{print $7; exit}')
if [ -z "$MY_IP" ]; then
    MY_IP=$(hostname -I | awk '{print $1}')
fi
echo "Log Handler (archlinux) IP detected as: $MY_IP"

trap '
    echo -e "\n[+] Intercepted Ctrl+C! Gracefully stopping distributed BPF sniffers precisely on both servers..."
    
    # Using wildcard .* to catch the -u flag or any other python arguments while keeping -15
    sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$MANAGER" "echo '"'$PASS'"' | sudo -S -p '"''"' pkill -15 -f \"python3.*new-architecture-USC.py\"" >/dev/null 2>&1 || true
    sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$WORKER" "echo '"'$PASS'"' | sudo -S -p '"''"' pkill -15 -f \"python3.*new-architecture-USC.py\"" >/dev/null 2>&1 || true
    
    echo "[+] Waiting for final teardown logs to cleanly flush to live_single.log on BOTH nodes..."
    wait $PID_93 2>/dev/null || true
    wait $PID_94 2>/dev/null || true
    echo "✅ Distributed Teardown complete. Exiting definitively."
    exit 0
' SIGINT

echo ""
if [[ " $* " =~ " --skip-sync " ]]; then
    echo "[1/4] Skipping codebase synchronization..."
else
    echo "[1/4] Syncing codebase to $MANAGER and $WORKER..."
    tar --exclude='.git' --exclude='node_modules' --exclude='*.ansi' --exclude='*.log' --exclude='yay' --exclude='DeathStarBench' --exclude='Python' --exclude='extras/venv' --exclude='wrk2' -czf /tmp/bcc-latest-two.tar.gz .
    sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$MANAGER" "mkdir -p $PROJECT_DIR"
    sshpass -p "$PASS" scp -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" /tmp/bcc-latest-two.tar.gz "$USER@$MANAGER:/tmp/bcc-latest.tar.gz"
    sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$MANAGER" "tar -xzf /tmp/bcc-latest.tar.gz -C $PROJECT_DIR/"

    sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$WORKER" "mkdir -p $PROJECT_DIR"
    sshpass -p "$PASS" scp -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" /tmp/bcc-latest-two.tar.gz "$USER@$WORKER:/tmp/bcc-latest.tar.gz"
    sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=5" "$USER@$WORKER" "tar -xzf /tmp/bcc-latest.tar.gz -C $PROJECT_DIR/"
fi

echo ""
if [[ " $* " =~ " --skip-deploy " ]]; then
    echo "[2,3/4] Skipping Docker Swarm deployment and graph initialization..."
else
    echo "[2/4] Initializing Swarm and deploying DSB Social Network natively..."
    
    echo "  [+] Tearing down existing infrastructure on $MANAGER..."
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "
        cd $PROJECT_DIR/DSB/socialNetwork
        echo '$PASS' | sudo -S docker-compose down >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker stack rm socialnetwork >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker swarm leave --force >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker network rm socialnetwork_default >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker network prune -f >/dev/null 2>&1 || true
    "
    
    echo "  [+] Tearing down existing infrastructure on $WORKER..."
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$WORKER" "
        echo '$PASS' | sudo -S docker swarm leave --force >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker network prune -f >/dev/null 2>&1 || true
    "
    
    echo "  [+] Creating Swarm Cluster on $MANAGER..."
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "echo '$PASS' | sudo -S docker swarm init --advertise-addr $MANAGER >/dev/null"
    JOIN_TOKEN=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "echo '$PASS' | sudo -S docker swarm join-token worker -q")
    
    echo "  [+] Joining $WORKER to the Swarm..."
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$WORKER" "echo '$PASS' | sudo -S docker swarm join --token $JOIN_TOKEN $MANAGER:2377 >/dev/null"
    
    echo "  [+] Deploying Stack on $MANAGER (will perfectly load-balance to $WORKER)..."
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "cd $PROJECT_DIR/DSB/socialNetwork && echo '$PASS' | sudo -S docker stack deploy -c docker-compose-swarm.yml socialnetwork"

    echo ""
    echo "Polling port 8080 on Manager ($MANAGER) until Nginx fully boots..."
    while ! curl -s -f -m 2 -o /dev/null "http://$MANAGER:8080" && ! curl -s -o /dev/null "http://$MANAGER:8080"; do
        echo -n "."
        sleep 5
    done
    echo " [OK] Nginx is up natively across the Swarm ingress!"

    echo "Waiting 45 seconds to ensure backend Thrift instances initialize past Jaeger tracer blockers..."
    sleep 45

    echo ""
    echo "[3/4] Initializing Social Graph Database cleanly over the Swarm..."
    if [ -f "$PWD/extras/venv/bin/activate" ]; then
        source "$PWD/extras/venv/bin/activate"
    fi
    (cd DSB/socialNetwork && python3 scripts/init_social_graph.py --ip $MANAGER --port 8080 --max-nodes 1000) || echo "WARNING: Failed to run init_social_graph.py. Ensure your virtual env is active."
fi

echo ""
echo "[4/4] Populating service_mapping.txt and natively injecting background eBPF profilers on BOTH 93 & 94..."

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
    sudo -E TERM=xterm-256color python3 -u new-architecture-USC.py -p \$PIDS --log-handler http://$MY_IP:5000/ingest >> live_single.log 2>&1
else
    echo "[ Server ] No containers found on this node to profile."
fi
EOF
)

# Run the SSH stream natively in the background holding both instances without closing standard io.
echo "$PAYLOAD" | sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" "$USER@$MANAGER" "sudo -S -p '' bash -s" &
PID_93=$!

echo "$PAYLOAD" | sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" "$USER@$WORKER" "sudo -S -p '' bash -s" &
PID_94=$!

wait $PID_93 2>/dev/null
wait $PID_94 2>/dev/null