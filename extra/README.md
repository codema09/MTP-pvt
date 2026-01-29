# 🔐 HTTPS Server Sniffer - Complete Project

## 📦 What This Is

An **eBPF-based HTTPS traffic analyzer** that captures and attributes decrypted HTTPS request headers with comprehensive context tracking.

---

## ✨ Features

### **1. Connection Attribution (Race-Free!)**
- Maps each HTTPS request to its TCP connection 4-tuple
- Tracks handling thread (TID) and process (PID)
- Zero race conditions using kernel structure walking

### **2. User Information Extraction**
- Extracts username from cookies, Basic auth, or custom headers
- Captures full Cookie and Authorization headers
- Stores in BPF map for cross-program access

### **3. Resource Usage Tracking**
- Measures duration (time taken) per request
- Tracks CPU cycles consumed
- Tagged by unique request ID

### **4. User Request History**
- Maintains list of ALL requests per user
- Up to 100 requests per user
- Live updates after each request
- Shows request ID, timestamp, TID, source IP:port

---

## 🗂️ Files Overview

### **Main Programs:**

| File | Purpose | Use When |
|------|---------|----------|
| `integrated_sniffer.py` | All features combined | Full monitoring |
| `new_server_sniffer.py` | Basic (connection + user) | Simple use case |
| `server-sniffer.py` | Old design | Reference only |

### **Modules (Standalone):**

| File | Purpose |
|------|---------|
| `resource_tracker.py` | Resource usage tracking module |
| `user_history_tracker.py` | User history tracking module |

### **Test Server:**

| File | Purpose |
|------|---------|
| `SERVER/server.py` | HTTPS server with threading & random delays |

### **Test Scripts:**

| File | Tests |
|------|-------|
| `test-all-features.sh` | Comprehensive: all 4 features |
| `concurrent-test.sh` | 10 concurrent requests |
| `test-user-info.sh` | User info extraction patterns |

### **Documentation:**

| File | Content |
|------|---------|
| `QUICK_START.md` | Get started in 30 seconds |
| `NEW_ARCHITECTURE.md` | Complete technical architecture |
| `INTEGRATED_FEATURES.md` | All features explained |
| `DESIGN_COMPARISON.md` | Old vs new design |
| `CONNECTION_ATTRIBUTION.md` | Race condition analysis |
| `TESTING.md` | Testing guide |

---

## 🚀 Quick Start

### **Terminal 1: Start Server**
```bash
cd SERVER
python3 server.py
```

### **Terminal 2: Start Integrated Sniffer**
```bash
sudo python3 integrated_sniffer.py
```

### **Terminal 3: Send Test Request**
```bash
curl -k \
  -H "Authorization: Bearer my_token" \
  -b "session=xyz; user=alice" \
  "https://localhost:8443/?id=TEST001"
```

---

## 📊 What You'll See

```
================================================================================
[HTTPS REQUEST INTERCEPTED]
================================================================================
Process ID (PID):        49473
Thread ID (TID):         49501
Process Name:            python3

Connection 4-tuple:
  Source:      127.0.0.1:54321 (client)
  Destination: 127.0.0.1:8443  (server)

HTTP Request Headers:
--------------------------------------------------------------------------------
GET /?id=TEST001 HTTP/1.1
Host: localhost:8443
Authorization: Bearer my_token
Cookie: session=xyz; user=alice
--------------------------------------------------------------------------------

📝 Request ID: TEST001

👤 User Information:
--------------------------------------------------------------------------------
  Username:      alice
  Cookie:        session=xyz; user=alice
  Authorization: Bearer my_token
--------------------------------------------------------------------------------

╔══════════════════════════════════════════════════════════════════════════════╗
║ 👤 USER: alice                                                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Total Requests: 1                                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ #  │ Request ID          │ Time     │ Thread  │ Source IP:Port               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  1 │ TEST001             │ 14:23:45 │   49501 │ 127.0.0.1      :54321       ║
╚══════════════════════════════════════════════════════════════════════════════╝

⏱ Processing Time: 5432.10 ms
  [⏱] Resource Usage for TEST001:
      Duration: 5432.10 ms
      CPU Cycles: 10,864,200
```

---

## 🧪 Run Comprehensive Test

```bash
./test-all-features.sh
```

This sends 10 requests from 3 different users (Alice, Bob, Charlie) plus anonymous requests.

**Watch the sniffer output to see:**
- ✅ Each request properly attributed to connection
- ✅ User histories updated live (Alice: 1, 2, 3, 4 requests)
- ✅ Resource usage calculated per request
- ✅ All maps populated correctly

**When you stop (Ctrl+C):**
```
📊 RESOURCE USAGE SUMMARY
  - All 10 requests listed with durations

👥 USER REQUEST HISTORIES
  - Alice: 4 requests with IDs and timestamps
  - Bob: 3 requests
  - Charlie: 2 requests
```

---

## 🗺️ BPF Maps Summary

| # | Map Name | Key | Value | Purpose |
|---|----------|-----|-------|---------|
| 1 | `fd_to_conn` | FD (u32) | Connection | TCP connection per FD |
| 2 | `tid_to_fd` | TID (u64) | FD | Which thread uses which FD |
| 3 | `tid_to_user_info` | TID (u32) | User info | User context per thread |
| 4 | `request_resources` | Request ID | Resource usage | Performance per request |
| 5 | `user_request_history` | Username | Request list | User's complete history |

---

## 🎯 Use Cases

### **Security Monitoring:**
```python
# Find all requests from admin users
user_history = bpf.get_table("user_request_history")
for username_key, history in user_history.items():
    user = username_key.name.decode('utf-8').rstrip('\x00')
    if 'admin' in user.lower():
        print(f"Admin user {user} made {history.request_count} requests")
```

### **Performance Analysis:**
```python
# Find slow requests
resources = bpf.get_table("request_resources")
for req_id_key, usage in resources.items():
    if usage.duration_ns > 5_000_000_000:  # >5 seconds
        req_id = req_id_key.id.decode('utf-8').rstrip('\x00')
        print(f"Slow request: {req_id}")
```

### **User Behavior Tracking:**
```python
# Correlate user's requests
user_history = bpf.get_table("user_request_history")
alice_key = user_history.Key()
alice_key.name = b'alice\x00'

alice_history = user_history[alice_key]
print(f"Alice made {alice_history.request_count} requests:")
for i in range(alice_history.request_count):
    req = alice_history.requests[i]
    print(f"  - {req.request_id.decode('utf-8').rstrip(chr(0))}")
```

---

## 📐 Architecture Highlights

### **Clean Design (Your Specification):**

```
Step 1: Do nothing at accept() time
        ✓ Avoids race conditions

Step 2: On first recv(FD):
        a) Walk kernel: FD → file → socket → struct sock
        b) Extract connection from sock->__sk_common
        c) Store: fd_to_conn[FD] = connection
        d) Store: tid_to_fd[TID] = FD

Step 3: On SSL_read:
        a) Lookup: TID → FD → Connection
        b) Capture decrypted headers
        c) Extract: Request ID, username, cookie, auth
        d) Update ALL maps:
           • tid_to_user_info
           • request_resources
           • user_request_history
```

### **Zero Race Conditions:**

```
✓ FD is unique per process
✓ Kernel walk is read-only
✓ Each thread independently extracts its FD's connection
✓ No shared state between accepts
✓ Maps updated atomically
```

---

## 📖 Documentation

- **Start here:** `QUICK_START.md`
- **Architecture:** `NEW_ARCHITECTURE.md`
- **All features:** `INTEGRATED_FEATURES.md`
- **Why this design:** `DESIGN_COMPARISON.md`

---

## 🎓 Technical Details

### **eBPF Probes Used:**

| Probe Type | Target | Purpose |
|------------|--------|---------|
| Tracepoint | `sys_enter_recvfrom` | Capture FD on first recv |
| Tracepoint | `sys_enter_read` | Track FD usage |
| Uprobe | `SSL_read` | Capture decrypted data |
| Uprobe | `SSL_read_ex` | Capture decrypted data (modern) |

### **Kernel Structures Walked:**

```c
task_struct → files_struct → fdtable → file → socket → sock

sock->__sk_common {
    .skc_daddr      // Client IP
    .skc_dport      // Client port
    .skc_rcv_saddr  // Server IP
    .skc_num        // Server port
}
```

---

## 🔧 Requirements

- **OS:** Linux (tested on 6.17.3)
- **Kernel:** 4.4+ (for eBPF support)
- **Python:** 3.8+ (for `os.gettid()`)
- **BCC:** Latest version
- **OpenSSL:** libssl.so.3 (auto-detected)
- **Permissions:** root (sudo)

---

## 🏆 Project Achievements

✅ **Race-free design** - Walks kernel structures directly
✅ **Complete attribution** - TID ↔ FD ↔ Connection ↔ User ↔ Resources
✅ **Modular architecture** - Features can be used separately
✅ **Production-ready** - Handles concurrent requests correctly
✅ **Well-documented** - Complete technical documentation
✅ **Fully tested** - Multiple test scripts included

---

## 📝 Files by Category

### **Core Implementation:**
```
integrated_sniffer.py          ← Use this! (All features)
new_server_sniffer.py          ← Basic version
resource_tracker.py            ← Module: Resource tracking
user_history_tracker.py        ← Module: User history
```

### **Testing:**
```
test-all-features.sh           ← Comprehensive test
concurrent-test.sh             ← Concurrent attribution test
test-user-info.sh              ← User extraction test
SERVER/server.py               ← Test HTTPS server
```

### **Documentation:**
```
README.md                      ← This file
QUICK_START.md                 ← 30-second guide
NEW_ARCHITECTURE.md            ← Complete architecture
INTEGRATED_FEATURES.md         ← All features explained
DESIGN_COMPARISON.md           ← Old vs new
CONNECTION_ATTRIBUTION.md      ← Race analysis
```

---

## 🎯 Next Steps

1. **Test it:** `./test-all-features.sh`
2. **Read architecture:** `cat NEW_ARCHITECTURE.md | less`
3. **Customize:** Modify display_request() to filter/log as needed
4. **Integrate:** Use BPF maps from other programs
5. **Extend:** Add IPv6 support, more resource metrics, etc.

---

## 📧 Credits

**Design Philosophy:** Based on the principle of reading kernel data structures directly on first use, eliminating event correlation races.

**Key Insight:** "A single thread may accept a bunch of FDs" - led to the race-free design.

---

## 🎉 Ready to Use!

```bash
# Terminal 1
cd SERVER && python3 server.py

# Terminal 2  
sudo python3 integrated_sniffer.py

# Terminal 3
./test-all-features.sh
```

**Watch the magic happen!** 🚀

