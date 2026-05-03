#!/bin/bash
set -e

# ==========================================
# Shutdown Remote EBPF Sniffers
# ==========================================

USER="shrest"
PASS="1234"
WORKERS=$(seq 94 117 | awk '{print "10.5.30."$1}')
ALL_NODES="10.5.30.93 $WORKERS"

echo "========================================================="
echo " Sending SIGINT to EBPF Sniffers on 25 Nodes "
echo "========================================================="

for IP in $ALL_NODES; do
    # Using tmux send-keys to gracefully interrupt the python script
    # This ensures it performs _flush_unexited_at_exit() and final payload submissions
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" "
        echo '[ $IP ] Stopping Sniffer...'
        echo '$PASS' | sudo -S tmux send-keys -t ebpf_sniffer C-c || true
    " &
done

wait
echo ""
echo "Signals Dispatched! Sleeping 10 seconds to allow USCs to safely flush payloads to the central handler..."
sleep 10

echo ""
echo "========================================================="
echo " Tearing down DSB Docker Swarm Stack "
echo "========================================================="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@10.5.30.93" "echo '$PASS' | sudo -S docker stack rm socialnetwork"
echo "Containers successfully terminated via Swarm Manager."
