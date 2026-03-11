#!/bin/bash

################################################################################
# INTEGRATED SNIFFER - CONCURRENT FEATURE TEST
################################################################################

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║         INTEGRATED SNIFFER - CONCURRENT FEATURE TEST                      ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "This test demonstrates ALL features with CONCURRENT/ASYNC requests:"
echo "  ✓ Connection attribution"
echo "  ✓ User information extraction"
echo "  ✓ Resource usage tracking"
echo "  ✓ User request history"
echo ""
echo "Requests are sent every 1s without waiting for responses."
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

# User Alice makes 3 requests
echo "[1/10] Alice - Request 1"
curl -k -s \
  --no-keepalive \
  -b "session_id=alice_sess_001; user=alice; role=admin" \
  "https://localhost:8443/?id=ALICE_REQ001" > /dev/null &

sleep 1

echo "[2/10] Alice - Request 2"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Bearer alice_token_xyz" \
  -b "user=alice" \
  "https://localhost:8443/?id=ALICE_REQ002" > /dev/null &

sleep 1

echo "[3/10] Alice - Request 3"
curl -k -s \
  --no-keepalive \
  -b "session=abc123; user=alice" \
  "https://localhost:8443/?id=ALICE_REQ003" > /dev/null &

sleep 1

# User Bob makes 2 requests
echo "[4/10] Bob - Request 1 (Basic Auth)"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Basic Ym9iOnBhc3N3b3JkMTIz" \
  "https://localhost:8443/?id=BOB_REQ001" > /dev/null &

sleep 1

echo "[5/10] Bob - Request 2"
curl -k -s \
  --no-keepalive \
  -H "X-User: bob" \
  -b "session=bob_session" \
  "https://localhost:8443/?id=BOB_REQ002" > /dev/null &

sleep 1

# User Charlie makes 2 requests
echo "[6/10] Charlie - Request 1"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Bearer charlie_admin_token" \
  -H "X-Username: charlie" \
  "https://localhost:8443/?id=CHARLIE_REQ001" > /dev/null &

sleep 1

echo "[7/10] Charlie - Request 2"
curl -k -s \
  --no-keepalive \
  -b "user_id=charlie; preferences=dark" \
  "https://localhost:8443/?id=CHARLIE_REQ002" > /dev/null &

sleep 1

# Anonymous requests (no user info)
echo "[8/10] Anonymous - Request 1"
curl -k -s --no-keepalive "https://localhost:8443/?id=ANON_REQ001" > /dev/null &

sleep 1

# Alice makes another request (should update her history)
echo "[9/10] Alice - Request 4 (testing history update)"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Bearer alice_new_token" \
  -b "session=new_session; user=alice" \
  "https://localhost:8443/?id=ALICE_REQ004" > /dev/null &

sleep 1

# Request without explicit ID (auto-generated)
echo "[10/10] Bob - Request 3 (auto-generated ID)"
curl -k -s \
  --no-keepalive \
  -H "X-User: bob" \
  "https://localhost:8443/" > /dev/null &

# Wait for all background jobs to finish
wait

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "✓ All test requests sent!"
echo "════════════════════════════════════════════════════════════════════════════"
