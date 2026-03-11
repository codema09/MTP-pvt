#!/bin/bash
set -e

# Define the location for the virtual environment
VENV_DIR="/home/khr/homefr/MTP/ebpf/bcc-latest/extras/venv"

echo "Recreating virtual environment at $VENV_DIR..."

# Remove existing venv if it exists
if [ -d "$VENV_DIR" ]; then
    rm -rf "$VENV_DIR"
fi

# Create new venv
python3 -m venv "$VENV_DIR"

# Activate source
source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip

# Install dependencies
# Using numpy<2.0 to ensure compatibility with various pandas versions, just in case
# But standard install should work if pandas is updated.
echo "Installing pandas, numpy, and psutil..."
pip install pandas numpy psutil

echo "Environment setup complete."
echo "To use this environment, run: source $VENV_DIR/bin/activate"
