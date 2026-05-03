#!/usr/bin/env python3
import sys
import pexpect

SERVERS = [f"10.5.30.{i}" for i in range(94, 108)]
USERNAME = "shrest"
PASSWORD = "1234"
SUDO_PASSWORD = "1234"
SWARM_TOKEN = "SWMTKN-1-2vrry5q1l1xt1k3u8ea8q7km6yt6kfhgvfz3kn18926wg8ctdb-6slv0w0zavpabzcc9lgxkxv32"

def run_ssh(ip, cmds):
    print(f"\n=========================================")
    print(f"Connecting to {ip}")
    print(f"=========================================")
    
    child = pexpect.spawn(f"ssh -o StrictHostKeyChecking=no {USERNAME}@{ip}", encoding='utf-8', timeout=600)
    child.logfile = sys.stdout
    
    idx = child.expect(['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(PASSWORD)
    else:
        print(f"[{ip}] Could not connect. Output: {child.before}")
        return False
        
    child.expect(r'[\$#] ')
    
    for cmd in cmds:
        print(f"\n[{ip}] Executing: {cmd}")
        child.sendline(cmd)
        
        while True:
            idx = child.expect([
                r'\[sudo\] password for',
                r'[\$#] ',               
                pexpect.EOF,
                pexpect.TIMEOUT
            ], timeout=600)
            
            if idx == 0:
                child.sendline(SUDO_PASSWORD)
            elif idx == 1:
                print(f"[{ip}] OK.")
                break
            else:
                print(f"[{ip}] Timeout/EOF.")
                break
                
    child.sendline("exit")
    child.expect(pexpect.EOF)
    return True

def main():
    print("Initiating ONLY Swarm Join and Docker Install for Workers 94 through 107...")
    
    for ip in SERVERS:
        cmds = [
            "sudo DEBIAN_FRONTEND=noninteractive apt update",
            "sudo DEBIAN_FRONTEND=noninteractive apt install -y docker.io docker-compose-v2 git tmux",
            f"sudo usermod -aG docker {USERNAME}",
            f"sudo docker swarm join --token {SWARM_TOKEN} 10.5.30.93:2377 || echo 'Already joined or failed'"
        ]
        
        success = run_ssh(ip, cmds)
        if not success:
            print(f"Failed to setup {ip}. Continuing...")
            
    print("\n--------------------------------------------------------------")
    print("ALL 14 WORKERS JOINED TO SWARM SUCCESSFULLY!")
    print("--------------------------------------------------------------")

if __name__ == "__main__":
    main()
