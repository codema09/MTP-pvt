#!/bin/bash

################################################################################
# HTTPS Server Connection Attribution Stress Test
################################################################################
# This script sends 10 concurrent HTTPS requests to test if the sniffer
# correctly attributes each request to the correct connection 4-tuple and thread.
################################################################################

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         HTTPS Server Connection Attribution Stress Test           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Configuration
NUM_REQUESTS=10
SERVER_URL="https://localhost:8443"
OUTPUT_DIR="./stress-test-results"

# Create output directory
mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*.txt

echo -e "${YELLOW}[INFO]${NC} Configuration:"
echo "  - Number of concurrent requests: $NUM_REQUESTS"
echo "  - Target server: $SERVER_URL"
echo "  - Output directory: $OUTPUT_DIR"
echo ""

# Check if server is running
# echo -e "${YELLOW}[CHECK]${NC} Verifying server is running..."
# if ! pgrep -f "SERVER/server.py" > /dev/null; then
#     echo -e "${RED}[ERROR]${NC} Server is not running!"
#     echo "  Start it with: cd SERVER && python3 server.py"
#     exit 1
# fi
# echo -e "${GREEN}[OK]${NC} Server is running (PID: $(pgrep -f 'SERVER/server.py'))"
# echo ""

# # Check if sniffer is running
# echo -e "${YELLOW}[CHECK]${NC} Verifying sniffer is running..."
# if ! pgrep -f "server-sniffer.py" > /dev/null; then
#     echo -e "${RED}[ERROR]${NC} Sniffer is not running!"
#     echo "  Start it with: sudo python3 server-sniffer.py"
#     exit 1
# fi
# echo -e "${GREEN}[OK]${NC} Sniffer is running (PID: $(pgrep -f 'server-sniffer.py'))"
# echo ""

# Send concurrent requests
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Sending $NUM_REQUESTS concurrent requests...${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo "Each request has a unique ID and will wait 1-10 seconds randomly."
echo "This tests if the sniffer correctly attributes each request to its connection."
echo ""

START_TIME=$(date +%s)

# Send requests in parallel
for i in $(seq 1 $NUM_REQUESTS); do
    (
        REQUEST_ID="REQ$(printf '%03d' $i)"
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S.%3N')
        
        echo -e "${GREEN}[SEND $REQUEST_ID]${NC} $TIMESTAMP - Sending request..."
        
        # Send request with unique headers to identify it
        RESPONSE=$(curl -k -s \
            -H "X-Request-ID: $REQUEST_ID" \
            -H "X-Client-ID: client-$i" \
            -H "User-Agent: StressTest/$i" \
            -b "session=sess_${i}; user_id=${i}" \
            "${SERVER_URL}/?id=${REQUEST_ID}" \
            -w "\n\nHTTP_CODE: %{http_code}\nTIME_TOTAL: %{time_total}s\n" 2>&1)
        
        END_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S.%3N')
        
        # Save response
        echo "Request ID: $REQUEST_ID" > "$OUTPUT_DIR/${REQUEST_ID}.txt"
        echo "Start Time: $TIMESTAMP" >> "$OUTPUT_DIR/${REQUEST_ID}.txt"
        echo "End Time: $END_TIMESTAMP" >> "$OUTPUT_DIR/${REQUEST_ID}.txt"
        echo "---" >> "$OUTPUT_DIR/${REQUEST_ID}.txt"
        echo "$RESPONSE" >> "$OUTPUT_DIR/${REQUEST_ID}.txt"
        
        echo -e "${GREEN}[DONE $REQUEST_ID]${NC} $END_TIMESTAMP - Response received"
    ) &
done

# Wait for all requests to complete
echo ""
echo -e "${YELLOW}[WAIT]${NC} Waiting for all requests to complete..."
wait

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  All requests completed!${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}[SUMMARY]${NC}"
echo "  - Total requests sent: $NUM_REQUESTS"
echo "  - Total time: ${DURATION}s"
echo "  - Results saved to: $OUTPUT_DIR/"
echo ""

# Show results
echo -e "${YELLOW}[RESULTS]${NC} Request completion times:"
echo ""
for file in "$OUTPUT_DIR"/REQ*.txt; do
    if [ -f "$file" ]; then
        REQ_ID=$(basename "$file" .txt)
        HTTP_CODE=$(grep "HTTP_CODE:" "$file" | cut -d' ' -f2)
        TIME_TOTAL=$(grep "TIME_TOTAL:" "$file" | cut -d' ' -f2)
        
        if [ "$HTTP_CODE" = "200" ]; then
            echo -e "  ${GREEN}✓${NC} $REQ_ID - Success (${TIME_TOTAL})"
        else
            echo -e "  ${RED}✗${NC} $REQ_ID - Failed (HTTP $HTTP_CODE)"
        fi
    fi
done

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Verification Instructions${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Now verify the sniffer output:"
echo ""
echo "1. Check that each of the $NUM_REQUESTS requests was captured by the sniffer"
echo "2. Verify that each request shows:"
echo "   - Unique source port (different for each request)"
echo "   - Correct X-Request-ID header (REQ001, REQ002, etc.)"
echo "   - Correct PID and TID matching the server output"
echo "   - Correct connection 4-tuple"
echo ""
echo "3. Compare server logs with sniffer output:"
echo "   - Each TID in sniffer should match a TID in server logs"
echo "   - Each request ID should appear in both server and sniffer"
echo ""
echo -e "${GREEN}If all matches correctly, the connection attribution is working! ✓${NC}"
echo ""

