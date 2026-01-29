#!/bin/bash
# Verify the fix for the fork tracking issue

echo "Starting forking server..."
python3 SERVER/forking_work_server.py > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

echo "Starting sniffer (requires sudo)..."
sudo python3 src/ag-architecture-USC.py > sniffer.log 2>&1 &
SNIFFER_PID=$!
echo "Sniffer PID: $SNIFFER_PID"

echo "Waiting for BPF initialization..."
sleep 10

echo "Sending request..."
curl -k https://localhost:8443
echo ""

echo "Waiting for processing..."
sleep 2

echo "Killing processes..."
sudo kill $SNIFFER_PID
kill $SERVER_PID

echo "========================================"
echo "Sniffer Output (Total Thread Time):"
grep "Total Thread Time" sniffer.log
echo "========================================"
