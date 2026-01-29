#!/bin/bash

# Test script for server-sniffer.py

echo "=== HTTPS Server Sniffer Test ==="
echo ""

# Check if server is running
if ! pgrep -f "SERVER/server.py" > /dev/null; then
    echo "❌ Server is not running!"
    echo "   Please start it in another terminal:"
    echo "   cd SERVER && python3 server.py"
    exit 1
fi

SERVER_PID=$(pgrep -f "SERVER/server.py")
echo "✓ Server is running (PID: $SERVER_PID)"

# Check if SSL library is loaded
echo ""
echo "Checking SSL libraries loaded by server..."
lsof -p $SERVER_PID 2>/dev/null | grep -E "libssl|libcrypto" | head -5

echo ""
echo "Starting sniffer... (Run 'curl -k https://localhost:8443' in another terminal)"
echo ""

# Run the sniffer
sudo python3 server-sniffer.py

