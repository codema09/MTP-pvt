import subprocess
import os

# Define the path to your Python script
script_path = "/home/khr/homefr/MTP/ebpf/bcc-latest/integrated_sniffer.py"

# Define the log file path for nohup output
log_file = "/home/khr/homefr/MTP/ebpf/bcc-latest/integrated_sniffer.log"

# Construct the command
# Using 'bash -c' to ensure proper handling of 'nohup' and '&'
command = f"sudo nohup python3 {script_path} > {log_file} 2>&1 &"

try:
    # Execute the command in the background
    # shell=True is necessary for using nohup and &
    # preexec_fn=os.setsid detaches the process from the current session
    process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
    print(f"Background process started with PID: {process.pid}")
    print(f"Output redirected to: {log_file}")
except Exception as e:
    print(f"Error starting background process: {e}")