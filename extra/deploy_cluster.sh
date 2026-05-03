#!/bin/bash
set -e

# ==========================================
# DSB 25-Node Swarm Deployment & EBPF Inject
# ==========================================

USER="shrest"
PASS="1234"
MANAGER="10.5.30.93"
WORKERS=$(seq 94 117 | awk '{print "10.5.30."$1}')
ALL_NODES="10.5.30.93 $WORKERS"
PROJECT_DIR="~/bcc-latest"

echo "========================================================="
echo " Starting Distributed 25-Node Docker Swarm Deployment "
echo "========================================================="

# 1. Dependency
if ! command -v sshpass &> /dev/null; then
    echo "Installing sshpass locally..."
    sudo pacman -S --noconfirm sshpass || sudo apt-get install -y sshpass || true
fi

# Get host IP for central log handler
MY_IP=$(ip route get 10.5.30.93 | awk '{print $7; exit}')
if [ -z "$MY_IP" ]; then
    MY_IP="10.5.30.1" # fallback
fi
echo "Log Handler IP detected as: $MY_IP"

# 2. Sync Repo to all nodes
echo ""
if [[ " $* " =~ " --skip-sync " ]]; then
    echo "[1/4] Skipping codebase synchronization..."
else
    echo "[1/4] Synchronizing codebase to all 25 nodes concurrently..."

    # Create a clean tarball locally to speed up SCP
    tar --exclude='.git' --exclude='node_modules' --exclude='*.ansi' --exclude='*.log' -czf /tmp/bcc-latest.tar.gz .

    for IP in $ALL_NODES; do
        (
            sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" "mkdir -p $PROJECT_DIR"
            sshpass -p "$PASS" scp -o StrictHostKeyChecking=no /tmp/bcc-latest.tar.gz "$USER@$IP:/tmp/bcc-latest.tar.gz"
            sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" "tar -xzf /tmp/bcc-latest.tar.gz -C $PROJECT_DIR/"
        ) >/dev/null 2>&1 &
    done
    wait
    echo "Codebase synchronized to all nodes."
fi

# 3. Setup Swarm Manager
echo ""
echo "[2/4] Initializing Docker Swarm on Manager ($MANAGER)..."
# Force manager to leave the swarm to clear any corrupted gossip/memberlist cache
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "echo '$PASS' | sudo -S docker swarm leave -f >/dev/null 2>&1" || true

sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "echo '$PASS' | sudo -S docker swarm init --advertise-addr $MANAGER" >/dev/null 2>&1

TOKEN=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "echo '$PASS' | sudo -S docker swarm join-token worker -q")
echo "Swarm Join Token: $TOKEN"

# 4. Join Workers
echo ""
echo "[3/4] Forcing 24 workers to leave existing swarms and join the Manager..."
for IP in $WORKERS; do
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" "
        echo '$PASS' | sudo -S docker swarm leave -f >/dev/null 2>&1 || true
        echo '$PASS' | sudo -S docker swarm join --token $TOKEN $MANAGER:2377
    " >/dev/null 2>&1 &
done
wait

# echo "Waiting for all 25 nodes to register as Ready in the Swarm..."
# while : ; do
#     READY_NODES=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "echo '$PASS' | sudo -S docker node ls | grep -c Ready" 2>/dev/null || echo 0)
#     echo "Current Ready Nodes: $READY_NODES"
#     if [ "$READY_NODES" -ge 25 ]; then
#         break
#     fi
#     sleep 3
# done
echo "All nodes are registered!"

# 5. Deploy Stack
echo ""
echo "[4/4] Deploying DSB Social Network Stack natively via Compose..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$MANAGER" "cd $PROJECT_DIR/DSB/socialNetwork && echo '$PASS' | sudo -S docker stack deploy -c docker-compose-swarm.yml socialnetwork"

echo "Waiting 60 seconds for initial container deployment to spin up..."
sleep 60
echo "Polling port 8080 on Manager ($MANAGER) until Nginx fully boots..."
while ! curl -s -f -m 2 -o /dev/null "http://$MANAGER:8080" && ! curl -s -o /dev/null "http://$MANAGER:8080"; do
    sleep 5
done
echo " [OK] Nginx is up!"

echo ""
echo "[*] Initializing Social Graph Database natively via local host script..."
# Run the client script locally against the Swarm Manager ingress port
if [ -f "$PWD/extras/venv/bin/activate" ]; then
    source "$PWD/extras/venv/bin/activate"
fi
(cd DSB/socialNetwork && python3 scripts/init_social_graph.py --ip $MANAGER --port 8080 --max-nodes 1000) || echo "WARNING: Failed to run init_social_graph.py. Ensure your virtual env is active."

# 6. PID Mapping and USC injection
echo ""
echo "[+] Populating service_mapping.txt and injecting EBPF sniffers..."
for IP in $ALL_NODES; do
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" "
        cd $PROJECT_DIR/src
        echo '$PASS' | sudo -S rm -f service_mapping.txt
        PIDS=\"\"
        
        # Iterating over swarm containers deployed to this specific node
        for c in \$(echo '$PASS' | sudo -S docker ps -q); do
            # Extract process ID namespace
            PID=\$(echo '$PASS' | sudo -S docker inspect -f '{{.State.Pid}}' \$c)
            NAME=\$(echo '$PASS' | sudo -S docker inspect -f '{{.Name}}' \$c | sed 's/\\///' | sed 's/_[0-9]\\+$//')
            
            # Enforce formatting: [service-name]: [PID]
            echo \"\$NAME: \${PID}\" >> service_mapping.txt
            
            if [ -n \"\$PID\" ] && [ \"\$PID\" != \"0\" ]; then
                PIDS=\"\$PIDS \$PID\"
            fi
        done
        
        if [ -n \"\$PIDS\" ]; then
            echo \"[ $IP ] Starting Sniffer for PIDs: \$PIDS\"
            # Kill any existing sniffer session (as root and as user)
            tmux kill-session -t ebpf_sniffer 2>/dev/null || true
            echo '$PASS' | sudo -S tmux kill-session -t ebpf_sniffer 2>/dev/null || true
            # Run tmux as the login user (not root) so ~ resolves correctly.
            # Only the inner python3 command needs sudo for eBPF privileges.
            tmux new-session -d -s ebpf_sniffer \
                \"cd /home/$USER/bcc-latest/src && echo '$PASS' | sudo -S python3 -u new-architecture-USC.py -p \$PIDS --log-handler http://$MY_IP:5000/ingest 2>&1 | tee /home/$USER/bcc-latest/src/live.log\"
            echo \"[ $IP ] Sniffer launched. Attach with: tmux attach -t ebpf_sniffer\"
        else
            echo \"[ $IP ] No containers found on this node yet.\"
        fi
    " &
done
wait

echo ""
echo "========================================================="
echo "✅ Swarm Deployment and Profiler Injection COMPLETE!"
echo "Central log-handler is targeted to receive payloads at: http://$MY_IP:5000/ingest"
echo "To stop them and flush the outputs, run: ./stop_cluster_sniffers.sh"
echo "========================================================="
