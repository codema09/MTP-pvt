#!/bin/bash
PIDS=""
for name in "frontend" "social-graph-service" "user-service" "user-timeline-service" "url-shorten-service" "text-service" "post-storage-service" "media-service" "user-mention-service" "home-timeline-service" "compose-post-service"; do
    pid=$(docker inspect -f '{{.State.Pid}}' socialnetwork-${name}-1 2>/dev/null)
    if [ ! -z "$pid" ]; then
        PIDS="$PIDS $pid"
    fi
done
echo "Attaching to PIDS: $PIDS"
sudo python3 -u /home/khr/homefr/MTP/ebpf/bcc-latest/src/new-architecture-USC.py -p $PIDS > sniffer_output.txt 2>&1 &
SNIFFER_PID=$!
sleep 5
echo "Generating test request..."
wrk -d 15s -t 2 -c 5 -s /home/khr/homefr/DeathStarBench/socialNetwork/wrk2/scripts/social-network/compose-post.lua http://localhost:8080/wrk2-api/post/compose
sleep 5
sudo kill -INT $SNIFFER_PID
wait $SNIFFER_PID
echo "Done! Output saved to sniffer_output.txt"
