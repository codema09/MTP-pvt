import sys
import pexpect
import threading

ALL_NODES = [f"10.5.30.{i}" for i in range(93, 108)]
USERNAME = "shrest"
PASSWORD = "1234"
SUDO_PASSWORD = "1234"

def ssh_command(ip, command, use_sudo=False):
    child = pexpect.spawn(f"ssh -o StrictHostKeyChecking=no {USERNAME}@{ip}", encoding='utf-8', timeout=60)
    idx = child.expect(['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(PASSWORD)
    else:
        return ""
        
    child.expect(r'[\$#] ')
    child.sendline(command)
    while True:
        idx = child.expect([r'\[sudo\] password for', r'[\$#] ', pexpect.EOF, pexpect.TIMEOUT], timeout=30)
        if idx == 0:
            child.sendline(SUDO_PASSWORD)
        elif idx == 1:
            output = child.before
            break
        else:
            output = child.before
            break
            
    child.sendline("exit")
    return output

def start_sniffer(ip):
    print(f"[{ip}] Scanning Swarm for alive containers...")
    
    script_content = """#!/bin/bash
PIDS=$(docker ps -f "label=com.docker.swarm.service.name" -q | xargs -r docker inspect -f '{{.State.Pid}}' | tr '\n' ' ')
if [ -n "$PIDS" ] && [ "$PIDS" != " " ] && [ "$PIDS" != "" ]; then
    echo "__FOUND__$PIDS"
    tmux kill-session -t ebpf_sniffer 2>/dev/null || true
    tmux new-session -d -s ebpf_sniffer "cd /home/shrest/MTP-pvt/src && sudo python3 -u new-architecture-USC.py -p $PIDS --log-handler http://10.5.30.93:5000/ingest"
else
    echo "__EMPTY__"
fi
"""
    import base64
    encoded = base64.b64encode(script_content.encode()).decode()
    ssh_command(ip, f"echo '{encoded}' | base64 -d > /tmp/run_sniffer.sh")
    out = ssh_command(ip, "sudo bash /tmp/run_sniffer.sh", use_sudo=True)
    
    if "__FOUND__" in out:
        pids = out.split("__FOUND__")[1].strip().split('\\n')[0].strip()
        print(f"[{ip}] ✔ Sniffer attached securely in tmux. PIDs: {pids}")
    else:
        print(f"[{ip}] No containers detected.")

def main():
    print("\\n[Phase 4] Concurrently hunting for dynamic PIDs and attaching sniffers to 15 nodes...")
    threads = []
    for ip in ALL_NODES:
        t = threading.Thread(target=start_sniffer, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
        
    print("==============================================================")
    print("✅ DEPLOYMENT COMPLETE!")
    print("To view sniffers, SSH into any node and type: tmux attach -t ebpf_sniffer")
    print("==============================================================")

if __name__ == "__main__":
    main()
