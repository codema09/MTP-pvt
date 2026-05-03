#!/usr/bin/env python3
import sys
import pexpect
import threading
import base64

ALL_NODES = [f"10.5.30.{i}" for i in range(93, 108)]
USERNAME = "shrest"
PASSWORD = "1234"
SUDO_PASSWORD = "1234"
LOG_HANDLER_IP = "10.105.18.100"

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
    
    script_content = f"""#!/bin/bash
pkill -SIGTERM -f new-architecture-USC.py 2>/dev/null || true
sleep 3
docker ps -f "label=com.docker.swarm.service.name" -q | xargs -r docker inspect -f '{{{{index .Config.Labels "com.docker.swarm.service.name"}}}}:{{{{.State.Pid}}}}' > /home/shrest/MTP-pvt/src/service_mapping.txt
PIDS=$(docker ps -f "label=com.docker.swarm.service.name" -q | xargs -r docker inspect -f '{{{{.State.Pid}}}}' | tr '\\n' ' ')
if [ -n "$PIDS" ] && [ "$PIDS" != " " ] && [ "$PIDS" != "" ]; then
    echo "__FOUND__$PIDS"
    mkdir -p /home/shrest/MTP-pvt/src/logs
    cd /home/shrest/MTP-pvt/src
    nohup sudo PYTHONUNBUFFERED=1 python3 new-architecture-USC.py -p $PIDS --log-handler http://{LOG_HANDLER_IP}:5000/ingest > /home/shrest/MTP-pvt/src/logs/latest.ansi 2>&1 &
else
    echo "__EMPTY__"
fi
"""
    encoded = base64.b64encode(script_content.encode()).decode()
    ssh_command(ip, f"echo '{encoded}' | base64 -d > /tmp/run_v2.sh")
    out = ssh_command(ip, "sudo bash /tmp/run_v2.sh", use_sudo=True)
    
    if "__FOUND__" in out:
        pids = out.split("__FOUND__")[1].strip().split('\\n')[0].strip()
        print(f"[{ip}] ✔ Sniffer attached as a background process! PIDs: {pids}")
    else:
        print(f"[{ip}] No containers detected.")

def main():
    print("\\n[Phase 4] Concurrently hunting for dynamic PIDs and attaching background sniffers...")
    threads = []
    for ip in ALL_NODES:
        t = threading.Thread(target=start_sniffer, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
        
    print("==============================================================")
    print("✅ DEPLOYMENT COMPLETE!")
    print("To view live logs, SSH into any node and type: tail -f ~/MTP-pvt/src/logs/latest.ansi")
    print("==============================================================")

if __name__ == "__main__":
    main()
