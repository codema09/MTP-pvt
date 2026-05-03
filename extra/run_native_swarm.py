#!/usr/bin/env python3
import sys
import pexpect
import threading
import time

WORKERS = [f"10.5.30.{i}" for i in range(94, 108)]
ALL_NODES = [f"10.5.30.{i}" for i in range(93, 108)]
MANAGER_IP = "10.5.30.93"
USERNAME = "shrest"
PASSWORD = "1234"
SUDO_PASSWORD = "1234"

def ssh_command(ip, command, use_sudo=False):
    child = pexpect.spawn(f"ssh -o StrictHostKeyChecking=no {USERNAME}@{ip}", encoding='utf-8', timeout=120)
    idx = child.expect(['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(PASSWORD)
    else:
        print(f"[{ip}] SSH Failed. Output: {child.before}")
        return False
        
    child.expect(r'[\$#] ')
    
    child.sendline(command)
    while True:
        idx = child.expect([r'\[sudo\] password for', r'[\$#] ', pexpect.EOF, pexpect.TIMEOUT], timeout=120)
        if idx == 0:
            child.sendline(SUDO_PASSWORD)
        elif idx == 1:
            output = child.before
            break
        else:
            output = child.before
            break
            
    child.sendline("exit")
    child.expect(pexpect.EOF)
    return output

def sync_repo(ip):
    print(f"[{ip}] SCPing socialNetwork archive to worker...")
    
    # 1. SCP the file
    child = pexpect.spawn(f"scp -o StrictHostKeyChecking=no /tmp/socialNetwork.tar.gz {USERNAME}@{ip}:/tmp/", encoding='utf-8', timeout=300)
    idx = child.expect(['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(PASSWORD)
    child.expect(pexpect.EOF, timeout=120)
    
    # 2. Extract the file
    cmd = "mkdir -p ~/MTP-pvt && tar -xzvf /tmp/socialNetwork.tar.gz -C ~/MTP-pvt/"
    ssh_command(ip, cmd)
    print(f"[{ip}] Repository & Configs Synced Successfully.")

def start_sniffer(ip):
    print(f"[{ip}] Searching for Swarm containers attached to this node...")
    
    # 1. Grab PIDs of Swarm containers on this node
    cmd = """PIDS=$(docker ps -f "label=com.docker.swarm.service.name" -q | xargs -r docker inspect -f '{{.State.Pid}}' | tr '\n' ' ') && if [ -n "$PIDS" ] && [ "$PIDS" != " " ]; then echo "__FOUND__$PIDS"; else echo "__EMPTY__"; fi"""
    
    out = ssh_command(ip, f"sudo bash -c '{cmd}'", use_sudo=True)
    
    if "__FOUND__" in out:
        pids = out.split("__FOUND__")[1].strip().split('\\n')[0].strip()
        print(f"[{ip}] Found local containers! PIDs: {pids}")
        
        # 2. Launch Sniffer in TMUX for these PIDs
        run_cmd = f"tmux kill-session -t ebpf_sniffer 2>/dev/null || true && tmux new-session -d -s ebpf_sniffer 'cd MTP-pvt/src && sudo python3 -u new-architecture-USC.py -p {pids} --log-handler http://10.5.30.93:5000/ingest'"
        ssh_command(ip, run_cmd)
        print(f"[{ip}] ✔ Sniffer attached securely in tmux.")
    else:
        print(f"[{ip}] No containers were placed on this node by Swarm (or they haven't started yet).")


def main():
    print("==============================================================")
    print("    NATIVE DOCKER SWARM ORCHESTRATION & EBPF INJECTION        ")
    print("==============================================================")
    
    # Phase 1: Parallel Repo Sync on ALL 15 NODES
    print("\\n[Phase 1] Concurrently synchronizing code to all nodes...")
    threads = []
    for ip in ALL_NODES:
        t = threading.Thread(target=sync_repo, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
        
    print("✅ All worker codebases synced.\\n")
    
    # Phase 2: Deploy Stack on Manager
    print("[Phase 2] Executing `docker stack deploy` natively on 10.5.30.93...")
    deploy_cmd = "cd ~/MTP-pvt/socialNetwork && sudo docker stack deploy -c docker-compose-swarm.yml socialnetwork"
    ssh_command(MANAGER_IP, deploy_cmd, use_sudo=True)
    print("✅ Stack deployed successfully! Docker Swarm is now load balancing the 27 services.\\n")
    
    # Phase 3: Wait for Containers
    print("[Phase 3] Waiting 45 seconds for images to pull and containers to start uniformly...")
    time.sleep(45)
    
    # Phase 4: Parallel Sniffer Attachment on 15 Nodes
    print("\\n[Phase 4] Concurrently hunting for dynamic PIDs and attaching sniffers...")
    threads = []
    for ip in ALL_NODES:
        t = threading.Thread(target=start_sniffer, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
        
    print("\\n==============================================================")
    print("✅ DEPLOYMENT COMPLETE!")
    print("To view sniffers, SSH into any node and type: tmux attach -t ebpf_sniffer")
    print("==============================================================")

if __name__ == "__main__":
    main()
