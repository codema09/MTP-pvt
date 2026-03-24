#!/bin/bash
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
