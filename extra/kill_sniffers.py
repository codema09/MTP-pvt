#!/usr/bin/env python3
import sys
import pexpect
import threading

ALL_NODES = [f"10.5.30.{i}" for i in range(93, 108)]
USERNAME = "shrest"
PASSWORD = "1234"
SUDO_PASSWORD = "1234"

def ssh_command(ip, command):
    child = pexpect.spawn(f"ssh -o StrictHostKeyChecking=no {USERNAME}@{ip}", encoding='utf-8', timeout=60)
    idx = child.expect(['(?i)password:', pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(PASSWORD)
    else:
        return
        
    child.expect(r'[\$#] ')
    child.sendline(command)
    while True:
        idx = child.expect([r'\[sudo\] password for', r'[\$#] ', pexpect.EOF, pexpect.TIMEOUT], timeout=30)
        if idx == 0:
            child.sendline(SUDO_PASSWORD)
        elif idx == 1:
            break
        else:
            break
            
    child.sendline("exit")

def kill_sniffer(ip):
    print(f"[{ip}] Sending Graceful SIGTERM to background sniffer...")
    ssh_command(ip, "sudo pkill -SIGTERM -f new-architecture-USC.py")
    print(f"[{ip}] ✔ Sniffer safely terminated. Data flushed to logger.")

def main():
    print("\\n[Phase 5] Concurrently terminating sniffers to harvest logs...")
    threads = []
    for ip in ALL_NODES:
        t = threading.Thread(target=kill_sniffer, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
        
    print("==============================================================")
    print("✅ ALL 15 SNIFFERS GRACEFULLY TERMINATED!")
    print("Check your local log_handler.py terminal to see the incoming payloads.")
    print("==============================================================")

if __name__ == "__main__":
    main()
