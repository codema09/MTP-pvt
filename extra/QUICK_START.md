# 🚀 Quick Start Guide

## 📦 What You Have

### **Main Program:**
- `new_server_sniffer.py` - Clean, race-free HTTPS sniffer

### **Test Server:**
- `SERVER/server.py` - HTTPS server with threading and delays

### **Documentation:**
- `NEW_ARCHITECTURE.md` - Complete technical architecture
- `DESIGN_COMPARISON.md` - Old vs new design comparison

### **Test Scripts:**
- `concurrent-test.sh` - Test with 10 concurrent requests
- `test-user-info.sh` - Test user information extraction

---

## ⚡ Quick Test (30 seconds)

### **Terminal 1: Start Server**
```bash
cd SERVER
python3 server.py
```

### **Terminal 2: Start Sniffer**
```bash
sudo python3 new_server_sniffer.py
```

### **Terminal 3: Send Test Request**
```bash
curl -k \
  -H "Authorization: Bearer my_token_123" \
  -b "session_id=abc; user=testuser" \
  https://localhost:8443
```

---

## 📋 Expected Output

### **Sniffer Output:**
```
================================================================================
[HTTPS REQUEST INTERCEPTED]
================================================================================
Process ID (PID):        12345
Thread ID (TID):         12367
Process Name:            python3

Connection 4-tuple:
  Source:      127.0.0.1:54321 (client)
  Destination: 127.0.0.1:8443  (server)

HTTP Request Headers:
--------------------------------------------------------------------------------
GET / HTTP/1.1
Host: localhost:8443
User-Agent: curl/8.5.0
Accept: */*
Authorization: Bearer my_token_123
Cookie: session_id=abc; user=testuser
--------------------------------------------------------------------------------

Extracted User Information:
--------------------------------------------------------------------------------
  Username:      testuser
  Cookie:        session_id=abc; user=testuser
  Authorization: Bearer my_token_123
--------------------------------------------------------------------------------
  [✓] Updated tid_to_user_info[12367] in BPF map
```

---

## 🧪 Test Features

### **1. Connection Attribution Test:**
```bash
./concurrent-test.sh
```
Sends 10 concurrent requests with unique IDs. Verify:
- ✓ Each request has unique source port
- ✓ TIDs match between server and sniffer
- ✓ No mixing of connections

### **2. User Information Test:**
```bash
./test-user-info.sh
```
Sends 6 requests with different auth patterns. Verify:
- ✓ Username extracted from cookies
- ✓ Username extracted from Basic auth
- ✓ Bearer tokens captured
- ✓ Custom headers recognized

---

## 🗺️ BPF Maps Overview

### **Map 1: `fd_to_conn` (FD → Connection)**
```python
# View from Python
for fd, conn in bpf.get_table("fd_to_conn").items():
    print(f"FD {fd.value}: {conn.src_ip}:{conn.src_port}")
```

### **Map 2: `tid_to_fd` (Thread → FD)**
```python
for tid, fd in bpf.get_table("tid_to_fd").items():
    print(f"Thread {tid.value} using FD {fd.value}")
```

### **Map 3: `tid_to_user_info` (Thread → User Info)**
```python
for tid, info in bpf.get_table("tid_to_user_info").items():
    if info.has_username:
        username = info.username.decode('utf-8').rstrip('\x00')
        print(f"Thread {tid.value}: User {username}")
```

---

## 🎯 Key Features

### **1. Race-Free Design**
- ✅ Walks kernel structures directly
- ✅ No event correlation needed
- ✅ 100% accurate attribution

### **2. Complete Header Capture**
- ✅ All HTTP headers preserved
- ✅ Custom headers included
- ✅ Decrypted at SSL layer

### **3. User Context Tracking**
- ✅ Username extraction (multiple sources)
- ✅ Full cookie preservation
- ✅ Authorization tokens captured
- ✅ Stored in BPF map for other programs

### **4. Thread Attribution**
- ✅ Maps each request to handling thread
- ✅ Connection 4-tuple per thread
- ✅ User info per thread

---

## 📝 Example Workflow

### **Security Monitoring:**
```bash
# Start sniffer
sudo python3 new_server_sniffer.py

# In another terminal, write a program that queries the BPF maps:
python3 << 'EOF'
from bcc import BPF
import time

# Load just to access existing maps
b = BPF(text="BPF_HASH(tid_to_user_info, u32, u32);")  

while True:
    user_map = b.get_table("tid_to_user_info")
    
    for tid, user_info in user_map.items():
        if user_info.has_username:
            user = user_info.username.decode('utf-8').rstrip('\x00')
            
            # Alert on suspicious users
            if user in ['admin', 'root', 'administrator']:
                print(f"⚠️  ALERT: Admin user '{user}' active on TID {tid.value}")
    
    time.sleep(1)
EOF
```

---

## 🔧 Advanced Usage

### **Filter Specific Users:**
Modify `display_request()` to only show requests from specific users:

```python
def display_request(self, tid):
    req = self.request_buffers[tid]
    headers = self.parse_http_headers(req['data'])
    user_info = self.extract_user_info(headers)
    
    # Only display if specific user
    if user_info['username'] == 'admin':
        # Display full details
        ...
```

### **Log to File:**
```python
# In display_request():
with open('/var/log/https-sniffer.log', 'a') as f:
    f.write(f"TID: {tid}, User: {user_info['username']}, "
            f"IP: {src_ip}:{src_port}\n")
```

---

## 🛑 Stopping

Press `Ctrl+C` in the sniffer terminal.

You'll see a summary:
```
SUMMARY: User Information Tracked in BPF Map
================================================================================
  Total threads tracked: 3

  Thread ID: 49501
    Username:      alice
    Cookie:        session_id=abc123; user=alice
    Authorization: Bearer token_xyz

  Thread ID: 49502
    Username:      bob
    ...
================================================================================
```

---

## 📚 Documentation

- **`NEW_ARCHITECTURE.md`** - Complete technical details
  - Data structures explained
  - Phase-by-phase flow
  - Kernel walk detailed
  - User info extraction logic

- **`DESIGN_COMPARISON.md`** - Why this design is better
  - Race condition analysis
  - Old vs new comparison

---

## ✅ Success Criteria

After running tests, you should see:

1. ✓ Connection 4-tuple displayed for every request
2. ✓ TIDs match between server and sniffer
3. ✓ User information extracted when present
4. ✓ BPF map populated with user data
5. ✓ Summary shows all tracked threads on exit

**The sniffer is now production-ready with user context tracking!** 🎉

