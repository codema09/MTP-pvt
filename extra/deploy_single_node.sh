#!/bin/bash
set -e

# ==========================================
# DSB Single-Node Deployment & EBPF Inject
# ==========================================

USER="shrest"
PASS="1234"
MANAGER="10.5.30.93"
PROJECT_DIR="~/bcc-latest"

echo "========================================================="
echo " Starting Single-Node Docker Compose Deployment on $MANAGER "
echo "========================================================="

# Get host IP for central log handler
MY_IP=$(ip route get $MANAGER | awk '{print $7; exit}')
if [ -z "$MY_IP" ]; then
    MY_IP="10.105.18.59" # fallback
fi
echo "Log Handler (archlinux) IP detected as: $MY_IP"

echo ""
if [[ " $* " =~ " --skip-sync " ]]; then
    echo "[1/4] Skipping codebase synchronization..."
else
    echo "[1/4] Syncing codebase to $MANAGER..."
    tar --exclude='.git' --exclude='node_modules' --exclude='*.ansi' --exclude='*.log' --exclude='yay' -czf /tmp/bcc-latest-single.tar.gz .
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "mkdir -p $PROJECT_DIR"
    sshpass -p "$PASS" scp -o StrictHostKeyChecking=no /tmp/bcc-latest-single.tar.gz "$USER@$MANAGER:/tmp/bcc-latest.tar.gz"
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "tar -xzf /tmp/bcc-latest.tar.gz -C $PROJECT_DIR/"
fi

echo ""
if [[ " $* " =~ " --skip-deploy " ]]; then
    echo "[2,3/4] Skipping Docker deployment and graph initialization..."
else
    echo "[2/4] Deploying DSB Social Network natively via docker-compose on $MANAGER..."
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "
        cd $PROJECT_DIR/DSB/socialNetwork
        echo '$PASS' | sudo -S docker stack rm socialnetwork >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker swarm leave --force >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker network prune -f >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker-compose down || true
        echo '$PASS' | sudo -S docker-compose build
        echo '$PASS' | sudo -S docker-compose up -d
    "

    echo ""
    echo "Polling port 8080 on Manager ($MANAGER) until Nginx fully boots..."
    while ! curl -s -f -m 2 -o /dev/null "http://$MANAGER:8080" && ! curl -s -o /dev/null "http://$MANAGER:8080"; do
        echo -n "."
        sleep 5
    done
    echo " [OK] Nginx is up!"

    echo ""
    echo "[3/4] Initializing Social Graph Database natively via local host script..."
    if [ -f "$PWD/extras/venv/bin/activate" ]; then
        source "$PWD/extras/venv/bin/activate"
    fi
    (cd DSB/socialNetwork && python3 scripts/init_social_graph.py --ip $MANAGER --port 8080 --max-nodes 1000) || echo "WARNING: Failed to run init_social_graph.py. Ensure your virtual env is active."
fi

echo ""
echo "[4/4] Populating service_mapping.txt and injecting EBPF sniffer in FOREGROUND on $MANAGER..."
# Note: Since this is foreground, the script will block here and stream outputs directly back to you!

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
    sudo -E TERM=xterm-256color python3 -u new-architecture-USC.py -p \$PIDS --log-handler http://$MY_IP:5000/ingest 2>&1 | tee -a live_single.log
else
    echo "[ Server ] No containers found on this node to profile."
fi
EOF
)

# Run the SSH stream in the background to shield it from abrupt local Ctrl+C termination
echo "$PAYLOAD" | sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" "$USER@$MANAGER" "sudo -S -p '' bash -s" &
SSH_PID=$!

trap '
    echo -e "\n[+] Intercepted Ctrl+C! Gracefully stopping remote BPF sniffer..."
    sshpass -p "$PASS" ssh -o "StrictHostKeyChecking=no" "$USER@$MANAGER" "echo '"'$PASS'"' | sudo -S -p '"''"' pkill -2 -x python3" >/dev/null 2>&1 || true
    echo "[+] Waiting for final teardown logs to flush to live_single.log..."
    wait $SSH_PID 2>/dev/null || true
    echo "✅ Teardown complete. Exiting cleanly."
    exit 0
' SIGINT

wait $SSH_PID 2>/dev/null
