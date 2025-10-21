#!/bin/bash
# Quick test: Send 10 concurrent requests with unique IDs

echo "==================================================================="
echo "Quick Concurrent Request Test"
echo "==================================================================="
echo "Sending 10 requests simultaneously..."
echo ""

for i in {1..10}; do
    (
        ID=$(printf "REQ%03d" $i)
        echo "[START] $ID at $(date +%T)"
        curl -k -s \
            -H "X-Request-ID: $ID" \
            -H "User-Agent: Test-$i" \
            -b "session=sess_$i" \
            "https://localhost:8443/?id=$ID" > /dev/null
        echo "[DONE]  $ID at $(date +%T)"
    ) &
done

wait

echo ""
echo "==================================================================="
echo "All requests completed!"
echo "==================================================================="
echo ""
echo "Check your sniffer output for 10 requests with unique:"
echo "  - Source ports (e.g., 127.0.0.1:54321, 127.0.0.1:54322, etc.)"
echo "  - Request IDs (REQ001 through REQ010)"
echo "  - TIDs (each handled by different thread)"
echo ""

