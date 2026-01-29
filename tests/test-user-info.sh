#!/bin/bash

################################################################################
# Test User Information Extraction Feature
################################################################################

echo "================================================================================"
echo "Testing User Information Extraction from HTTPS Headers"
echo "================================================================================"
echo ""

# Test 1: Request with username in cookie
echo "[Test 1] Request with username in Cookie header"
curl -k -s \
  -b "session_id=abc123; user=alice; role=admin" \
  https://localhost:8443 > /dev/null
sleep 1

# Test 2: Request with Authorization Bearer token
echo "[Test 2] Request with Bearer token"
curl -k -s \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" \
  -b "session=xyz789" \
  https://localhost:8443 > /dev/null
sleep 1

# Test 3: Request with Basic Auth
echo "[Test 3] Request with Basic Authentication"
echo -n "bob:password123" | base64 > /tmp/basicauth.txt
BASIC_AUTH=$(cat /tmp/basicauth.txt)
curl -k -s \
  -H "Authorization: Basic $BASIC_AUTH" \
  https://localhost:8443 > /dev/null
rm -f /tmp/basicauth.txt
sleep 1

# Test 4: Request with custom X-User header
echo "[Test 4] Request with X-User header"
curl -k -s \
  -H "X-User: charlie" \
  -b "preferences=dark_mode" \
  https://localhost:8443 > /dev/null
sleep 1

# Test 5: Request with everything
echo "[Test 5] Request with all user info types"
curl -k -s \
  -H "Authorization: Bearer admin_secret_token_xyz" \
  -H "X-Username: david" \
  -b "session_id=sess_12345; user_id=david; role=superadmin; lang=en" \
  https://localhost:8443 > /dev/null
sleep 1

# Test 6: Request with no user info
echo "[Test 6] Request with no user information"
curl -k -s https://localhost:8443 > /dev/null
sleep 1

echo ""
echo "================================================================================"
echo "All test requests sent!"
echo "================================================================================"
echo ""
echo "VERIFICATION:"
echo ""
echo "Check the sniffer output for:"
echo ""
echo "  Test 1: Should show username='alice' from Cookie"
echo "  Test 2: Should show Bearer token and session cookie"
echo "  Test 3: Should show username='bob' from Basic auth"
echo "  Test 4: Should show username='charlie' from X-User header"
echo "  Test 5: Should show all three fields populated"
echo "  Test 6: Should show NO extracted user information section"
echo ""
echo "When you stop the sniffer (Ctrl+C), you should see a summary showing"
echo "all threads and their associated user information from the BPF map."
echo ""
echo "================================================================================"

