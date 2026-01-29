#!/bin/bash

# Send 10 concurrent HTTPS requests to test connection attribution

echo "==============================================================================="
echo "Concurrent HTTPS Request Test"
echo "==============================================================================="
echo ""
echo "Sending 10 concurrent requests with random server delays (1-10s)..."
echo "Each request has a unique ID to verify correct attribution."
echo ""

for i in {1..10}; do
    (
        REQ_ID="REQ$(printf '%03d' $i)"
        START=$(date +%s.%N)
        
        echo "[$(date +%T)] Sending $REQ_ID..."
        
        curl -k -s \
            -H "X-Request-ID: $REQ_ID" \
            -H "X-Client-ID: client-$i" \
            -H "Authorization: Bearer token_$i" \
            -b "session_id=sess_$i; user=user_$i" \
            "https://localhost:8443/?id=$REQ_ID" \
            > /dev/null
        
        END=$(date +%s.%N)
        DURATION=$(echo "$END - $START" | bc)
        
        echo "[$(date +%T)] $REQ_ID completed in ${DURATION}s"
    ) &
done

echo ""
echo "All requests sent! Waiting for completion..."
wait

echo ""
echo "==============================================================================="
echo "✓ All 10 requests completed!"
echo "==============================================================================="
echo ""
echo "VERIFICATION CHECKLIST:"
echo ""
echo "  Check Server Output:"
echo "    □ Should show 10 different TIDs"
echo "    □ Should show 10 different client ports (54xxx)"
echo "    □ Request IDs: REQ001 through REQ010"
echo ""
echo "  Check Sniffer Output:"
echo "    □ Should show 10 [HTTPS REQUEST INTERCEPTED] blocks"
echo "    □ Each with unique source port"
echo "    □ TIDs should match server TIDs"
echo "    □ Connection 4-tuple should be present (not 'Tracking in progress')"
echo "    □ HTTP headers should contain correct X-Request-ID"
echo ""
echo "  Verify 1-to-1 Mapping:"
echo "    □ Server TID 49501 ↔ Sniffer TID 49501"
echo "    □ Port 54321 appears in same request as REQ001 in both outputs"
echo "    □ No mixing of request IDs between different ports/TIDs"
echo ""
echo "==============================================================================="

