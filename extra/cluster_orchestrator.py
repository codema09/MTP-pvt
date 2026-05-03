#!/usr/bin/env python3
import os
import sys
import time
import pexpect

# Configuration
SERVERS = [f"10.5.30.{i}" for i in range(93, 108)]
MANAGER_IP = "10.5.30.93"
USERNAME = "shrest"
PASSWORD = "1234"
SUDO_PASSWORD = "1234"

def run_ssh(ip, cmds):
    print(f"\n=========================================")
    print(f"Connecting to {ip}")
    print(f"=========================================")
    
    # Spawn SSH session
    child = pexpect.spawn(f"ssh -o StrictHostKeyChecking=no {USERNAME}@{ip}", encoding='utf-8', timeout=600)
    child.logfile = sys.stdout
    
    # Wait for password prompt
    idx = child.expect(['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(PASSWORD)
    else:
        print(f"[{ip}] Could not connect (SSH key may already be loaded or host down). Output: {child.before}")
        return False, child.before

    # Wait for bash prompt (assumes $ or # or >)
    child.expect(r'[\$#] ')
    
    full_output = ""
    for cmd in cmds:
        print(f"[{ip}] Executing: {cmd}")
        # Use sudo implicitly if needed, or pass the command verbatim
        child.sendline(cmd)
        
        while True:
            idx = child.expect([
                r'\[sudo\] password for', # Sudo prompt
                r'[\$#] ',                # Bash prompt returns
                pexpect.EOF,
                pexpect.TIMEOUT
            ], timeout=600)
            
            if idx == 0:
                child.sendline(SUDO_PASSWORD)
            elif idx == 1:
                # Command finished
                full_output += child.before
                print(child.before)
                break
            else:
                print(f"[{ip}] Timeout or EOF while waiting for command to finish.")
                break
                
    # Close SSH session
    child.sendline("exit")
    child.expect(pexpect.EOF)
    print(f"[{ip}] Disconnected.")
    
    return True, full_output

def main():
    print("Initiating Cluster Orchestration...")
    
    # Run the generator locally to ensure we have the fresh bash scripts
    print("[Local] Running generate_15_node_setup.py...")
    os.chdir("src")
    os.system("python3 generate_15_node_setup.py")
    
    print("[Local] Committing and pushing the generated scripts so nodes can pull them...")
    os.chdir("..")
    os.system("git add src/swarm_scripts/")
    os.system('git commit -m "Update scripts via orchestrator"')
    os.system("git push origin HEAD:master")
    
    swarm_token = None
    
    for ip in SERVERS:
        cmds = []
        is_manager = (ip == MANAGER_IP)
        
        # 1. Install Dependencies
        if is_manager:
            cmds.append("sudo DEBIAN_FRONTEND=noninteractive apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y tmux")
        else:
            cmds.append("sudo DEBIAN_FRONTEND=noninteractive apt update")
            cmds.append("sudo DEBIAN_FRONTEND=noninteractive apt install -y docker.io docker-compose-v2 git tmux")
            # add to docker group (optional but good practice)
            cmds.append(f"sudo usermod -aG docker {USERNAME}")
            
        # 2. Clone or Update Repo
        cmds.append("if [ ! -d 'MTP-pvt' ]; then git clone https://github.com/codema09/MTP-pvt.git MTP-pvt; fi")
        cmds.append("cd MTP-pvt && git config pull.rebase false && git stash && git pull origin master")
        
        # 3. Run Setup Script
        if is_manager:
            cmds.append(f"sudo bash src/swarm_scripts/setup_node_{ip}.sh")
            # Grab token
            cmds.append("sudo docker swarm join-token worker -q")
        else:
            if not swarm_token:
                print("ERROR: Swarm token not found!")
                sys.exit(1)
            cmds.append(f"sudo bash src/swarm_scripts/setup_node_{ip}.sh {swarm_token}")
            
        success, output = run_ssh(ip, cmds)
        
        if is_manager and success:
            import re
            match = re.search(r'(SWMTKN-1-[a-zA-Z0-9-]+)', output)
            if match:
                swarm_token = match.group(1)
                print(f"-> Extracted Swarm Token: {swarm_token}")
            
            if not swarm_token:
                print("Failed to capture Swarm token from manager output. Check logs.")
                sys.exit(1)

    print("\n--------------------------------------------------------------")
    print("ALL 15 SERVERS SUCCESSFULLY ORCHESTRATED AND DEPLOYED!")
    print("The Sniffers are now running inside `tmux` sessions on each node.")
    print("--------------------------------------------------------------")

if __name__ == "__main__":
    main()
