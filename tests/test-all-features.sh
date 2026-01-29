#!/bin/bash

################################################################################
# Comprehensive Test - All Integrated Features
################################################################################

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║         INTEGRATED SNIFFER - COMPREHENSIVE FEATURE TEST                   ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "This test demonstrates ALL features:"
echo "  ✓ Connection attribution (TID → FD → Connection)"
echo "  ✓ User information extraction"
echo "  ✓ Resource usage tracking per request"
echo "  ✓ User request history (updated live)"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

# User Alice makes 3 requests
echo "[1/10] Alice - Request 1"
curl -k -s \
  --no-keepalive \
  -b "session_id=alice_sess_001; user=alice; role=admin" \
  "https://localhost:8443/?id=ALICE_REQ001" > /dev/null

sleep 1

echo "[2/10] Alice - Request 2"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Bearer alice_token_xyz" \
  -b "user=alice" \
  "https://localhost:8443/?id=ALICE_REQ002" > /dev/null

sleep 1

echo "[3/10] Alice - Request 3"
curl -k -s \
  --no-keepalive \
  -b "session=abc123; user=alice" \
  "https://localhost:8443/?id=ALICE_REQ003" > /dev/null

sleep 1

# User Bob makes 2 requests
echo "[4/10] Bob - Request 1 (Basic Auth)"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Basic Ym9iOnBhc3N3b3JkMTIz" \
  "https://localhost:8443/?id=BOB_REQ001" > /dev/null

sleep 1

echo "[5/10] Bob - Request 2"
curl -k -s \
  --no-keepalive \
  -H "X-User: bob" \
  -b "session=bob_session" \
  "https://localhost:8443/?id=BOB_REQ002" > /dev/null

sleep 1

# User Charlie makes 2 requests
echo "[6/10] Charlie - Request 1"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Bearer charlie_admin_token" \
  -H "X-Username: charlie" \
  "https://localhost:8443/?id=CHARLIE_REQ001" > /dev/null

sleep 1

echo "[7/10] Charlie - Request 2"
curl -k -s \
  --no-keepalive \
  -b "user_id=charlie; preferences=dark" \
  "https://localhost:8443/?id=CHARLIE_REQ002" > /dev/null

sleep 1

# Anonymous requests (no user info)
echo "[8/10] Anonymous - Request 1"
curl -k -s --no-keepalive "https://localhost:8443/?id=ANON_REQ001" > /dev/null

sleep 1

# Alice makes another request (should update her history)
echo "[9/10] Alice - Request 4 (testing history update)"
curl -k -s \
  --no-keepalive \
  -H "Authorization: Bearer alice_new_token" \
  -b "session=new_session; user=alice" \
  "https://localhost:8443/?id=ALICE_REQ004" > /dev/null

sleep 1

# Request without explicit ID (auto-generated)
echo "[10/10] Bob - Request 3 (auto-generated ID)"
curl -k -s \
  --no-keepalive \
  -H "X-User: bob" \
  "https://localhost:8443/" > /dev/null

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "✓ All test requests sent!"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "VERIFICATION CHECKLIST:"
echo ""
echo "  1. Connection Attribution:"
echo "     □ All 10 requests show connection 4-tuple"
echo "     □ Each request has unique source port"
echo "     □ TIDs match between server and sniffer"
echo ""
echo "  2. User Information:"
echo "     □ Alice identified in requests 1-4"
echo "     □ Bob identified in requests 1-3 (including Basic auth decode)"
echo "     □ Charlie identified in requests 1-2"
echo "     □ Anonymous request shows no user info"
echo ""
echo "  3. Resource Tracking:"
echo "     □ Each request shows processing time"
echo "     □ CPU cycles calculated"
echo "     □ Request IDs properly tagged"
echo ""
echo "  4. User History (LIVE UPDATES!):"
echo "     □ After request 1: Alice history shows 1 request"
echo "     □ After request 2: Alice history shows 2 requests"
echo "     □ After request 3: Alice history shows 3 requests"
echo "     □ After request 4: Alice history shows 4 requests"
echo "     □ After request 5: Bob history shows 2 requests"
echo "     □ After request 10: Bob history shows 3 requests"
echo "     □ Each history entry shows unique request ID and timestamp"
echo ""
echo "  5. Final Summary (after Ctrl+C):"
echo "     □ Resource summary shows all 10 requests with durations"
echo "     □ User histories show:"
echo "        - Alice: 4 requests"
echo "        - Bob: 3 requests"
echo "        - Charlie: 2 requests"
echo "        - Anonymous requests: NOT in user history"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"

