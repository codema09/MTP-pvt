#!/bin/bash

# Simple script to view eBPF trace output
echo "Viewing eBPF kernel traces (Ctrl+C to stop)..."
echo "This shows debug output from the eBPF probes"
echo "================================================"
sudo cat /sys/kernel/debug/tracing/trace_pipe

