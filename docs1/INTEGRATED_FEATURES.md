# 🎯 Integrated Sniffer - All Features

## 📋 Overview

The integrated sniffer combines **4 tracking features**:

1. **Connection Attribution** - Maps threads to TCP connections
2. **User Information** - Extracts username, cookies, auth tokens
3. **Resource Usage** - Tracks CPU cycles, memory, time per request
4. **User Request History** - Maintains list of all requests per user

---

## 🗺️ All BPF Maps

### **Map 1: `fd_to_conn` (FD → Connection)**
```c
BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);

Purpose: Map file descriptor to connection 4-tuple
Example:
  fd_to_conn[5] = {src: 127.0.0.1:54321, dst: 127.0.0.1:8443}
```

### **Map 2: `tid_to_fd` (Thread → FD)**
```c
BPF_HASH(tid_to_fd, u64, u32);

Purpose: Track which thread uses which FD
Example:
  tid_to_fd[49501] = 5
```

### **Map 3: `tid_to_user_info` (Thread → User Info)**
```c
BPF_HASH(tid_to_user_info, u32, struct user_info_t);

struct user_info_t {
    char username[64];
    char cookie[256];
    char authorization[128];
    u8 has_username;
    u8 has_cookie;
    u8 has_authorization;
};

Purpose: Store extracted user information per thread
Example:
  tid_to_user_info[49501] = {
    username: "alice",
    cookie: "session=abc; user=alice",
    authorization: "Bearer token_xyz",
    has_username: 1,
    has_cookie: 1,
    has_authorization: 1
  }
```

### **Map 4: `request_resources` (Request ID → Resources) [NEW]**
```c
BPF_HASH(request_resources, char[64], struct resource_usage_t);

struct resource_usage_t {
    char request_id[64];         // Unique request identifier
    u32 tid;                     // Thread handling request
    u64 start_time_ns;           // Start timestamp
    u64 end_time_ns;             // End timestamp
    u64 duration_ns;             // Total time taken
    u64 cpu_cycles_start;        // CPU cycles at start
    u64 cpu_cycles_end;          // CPU cycles at end
    u64 cpu_cycles_used;         // Total CPU cycles consumed
    u8 is_complete;              // Completion flag
};

Purpose: Track resource usage for each request
Example:
  request_resources["REQ001"] = {
    request_id: "REQ001",
    tid: 49501,
    duration_ns: 7_320_000_000,  // 7.32 seconds
    cpu_cycles_used: 14_640_000,
    is_complete: 1
  }
```

### **Map 5: `user_request_history` (Username → History) [NEW]**
```c
BPF_HASH(user_request_history, char[64], struct user_history_t);

struct request_entry_t {
    char request_id[64];
    u64 timestamp_ns;
    u32 tid;
    u32 src_ip;
    u16 src_port;
};

struct user_history_t {
    char username[64];
    struct request_entry_t requests[100];  // List of requests
    u32 request_count;                     // Number in list
    u64 last_updated_ns;
};

Purpose: Maintain complete request history for each user
Example:
  user_request_history["alice"] = {
    username: "alice",
    request_count: 3,
    requests: [
      {request_id: "REQ001", timestamp: ..., tid: 49501, ...},
      {request_id: "REQ005", timestamp: ..., tid: 49503, ...},
      {request_id: "REQ009", timestamp: ..., tid: 49507, ...}
    ]
  }
```

---

## 🔄 Complete Flow with All Features

```
┌────────────────────────────────────────────────────────────────┐
│ 1. Client Connects                                            │
│    127.0.0.1:54321 → 127.0.0.1:8443                          │
└────────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────────┐
│ 2. Thread calls recv(FD=5)                                    │
│    → Walk kernel: FD 5 → struct sock                          │
│    → Extract: {127.0.0.1:54321 → 127.0.0.1:8443}            │
│    → Store: fd_to_conn[5] = connection                        │
│    → Store: tid_to_fd[49501] = 5                             │
└────────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────────┐
│ 3. SSL_read_ex() captures decrypted data                      │
│    Multiple chunks aggregated:                                 │
│    "GET /?id=REQ001 HTTP/1.1\r\n                              │
│     Cookie: session=xyz; user=alice\r\n                        │
│     Authorization: Bearer token_123\r\n\r\n"                   │
└────────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────────┐
│ 4. Python Processing (All Features!)                          │
│                                                                │
│  a) Extract Request ID:                                       │
│     → From X-Request-ID header, OR                            │
│     → From query param ?id=REQ001, OR                         │
│     → Auto-generate: AUTO_000001                              │
│                                                                │
│  b) Extract User Info:                                        │
│     → username = "alice" (from Cookie: user=alice)           │
│     → cookie = "session=xyz; user=alice"                      │
│     → authorization = "Bearer token_123"                       │
│                                                                │
│  c) Update tid_to_user_info map:                             │
│     → tid_to_user_info[49501] = {alice, cookie, auth}        │
│                                                                │
│  d) Start Resource Tracking:                                  │
│     → request_resources["REQ001"] = {                         │
│         tid: 49501,                                            │
│         start_time: <now>,                                     │
│         is_complete: 0                                         │
│       }                                                         │
│                                                                │
│  e) Update User History:                                      │
│     → user_request_history["alice"].requests.append({         │
│         request_id: "REQ001",                                  │
│         tid: 49501,                                            │
│         src_ip: 127.0.0.1,                                     │
│         src_port: 54321,                                       │
│         timestamp: <now>                                       │
│       })                                                        │
│     → Display updated history for alice                        │
│                                                                │
│  f) Complete Resource Tracking:                               │
│     → request_resources["REQ001"].is_complete = 1             │
│     → Calculate duration and CPU cycles                        │
└────────────────────────────────────────────────────────────────┘
```

---

## 📊 Example Output

### **Single Request Display:**

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
GET /?id=REQ001 HTTP/1.1
Host: localhost:8443
User-Agent: curl/8.5.0
Cookie: session_id=xyz789; user=alice; role=admin
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
--------------------------------------------------------------------------------

📝 Request ID: REQ001

👤 User Information:
--------------------------------------------------------------------------------
  Username:      alice
  Cookie:        session_id=xyz789; user=alice; role=admin
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
--------------------------------------------------------------------------------

╔══════════════════════════════════════════════════════════════════════════════╗
║ 👤 USER: alice                                                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Total Requests: 3                                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ #  │ Request ID          │ Time     │ Thread  │ Source IP:Port               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  1 │ AUTO_000001         │ 14:23:15 │   49499 │ 127.0.0.1      :54319       ║
║  2 │ AUTO_000003         │ 14:23:18 │   49500 │ 127.0.0.1      :54320       ║
║  3 │ REQ001              │ 14:23:22 │   49501 │ 127.0.0.1      :54321       ║
╚══════════════════════════════════════════════════════════════════════════════╝

⏱ Processing Time: 7320.45 ms
  [⏱] Resource Usage for REQ001:
      Duration: 7320.45 ms
      CPU Cycles: 14,640,900

```

---

## 🧪 Testing the Integrated Sniffer

### **Terminal 1: Server**
```bash
cd SERVER && python3 server.py
```

### **Terminal 2: Integrated Sniffer**
```bash
sudo python3 integrated_sniffer.py
```

### **Terminal 3: Send Test Requests**

**Test 1: Request with username in cookie**
```bash
curl -k \
  -b "session=abc; user=alice" \
  "https://localhost:8443/?id=REQ_ALICE_001"
```

**Test 2: Another request from same user**
```bash
curl -k \
  -b "session=xyz; user=alice" \
  "https://localhost:8443/?id=REQ_ALICE_002"
```

**Test 3: Request from different user**
```bash
curl -k \
  -H "Authorization: Basic Ym9iOnBhc3MxMjM=" \
  "https://localhost:8443/?id=REQ_BOB_001"
```
(Basic Ym9iOnBhc3MxMjM= = bob:pass123)

**Test 4: Request with Bearer token**
```bash
curl -k \
  -H "Authorization: Bearer admin_token_xyz" \
  -H "X-User: charlie" \
  "https://localhost:8443/?id=REQ_CHARLIE_001"
```

---

## 📊 Summary on Exit (Ctrl+C)

```
🛑 Stopping sniffer...

================================================================================
📊 RESOURCE USAGE SUMMARY
================================================================================
  Total requests tracked: 4

  Request ID           │ Duration     │ CPU Cycles      │ Status    
  ----------------------------------------------------------------------------
  REQ_ALICE_001        │    7320.45 ms │  14,640,900 │ Complete  
  REQ_ALICE_002        │    2150.23 ms │   4,300,460 │ Complete  
  REQ_BOB_001          │    9876.54 ms │  19,753,080 │ Complete  
  REQ_CHARLIE_001      │    1543.21 ms │   3,086,420 │ Complete  
================================================================================

================================================================================
👥 USER REQUEST HISTORIES
================================================================================
  Total users tracked: 3

╔══════════════════════════════════════════════════════════════════════════════╗
║ 👤 USER: alice                                                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Total Requests: 2                                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ #  │ Request ID          │ Time     │ Thread  │ Source IP:Port               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  1 │ REQ_ALICE_001       │ 14:23:15 │   49501 │ 127.0.0.1      :54321       ║
║  2 │ REQ_ALICE_002       │ 14:23:22 │   49503 │ 127.0.0.1      :54323       ║
╚══════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════╗
║ 👤 USER: bob                                                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Total Requests: 1                                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ #  │ Request ID          │ Time     │ Thread  │ Source IP:Port               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  1 │ REQ_BOB_001         │ 14:23:30 │   49505 │ 127.0.0.1      :54325       ║
╚══════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════╗
║ 👤 USER: charlie                                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Total Requests: 1                                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ #  │ Request ID          │ Time     │ Thread  │ Source IP:Port               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  1 │ REQ_CHARLIE_001     │ 14:23:45 │   49507 │ 127.0.0.1      :54327       ║
╚══════════════════════════════════════════════════════════════════════════════╝

================================================================================
```

---

## 🎯 Feature Details

### **Feature 1: Resource Usage Tracking**

**What it tracks:**
- ⏱️ **Duration**: Time from first SSL_read to request completion
- 🔄 **CPU Cycles**: Approximated from timestamps
- 🧵 **Thread ID**: Which thread handled the request
- 🏷️ **Request ID**: Unique identifier for correlation

**Request ID sources (priority order):**
1. `X-Request-ID` header
2. Query parameter: `?id=REQ001`
3. Auto-generated: `AUTO_000001`

**BPF Map:**
```c
request_resources["REQ001"] = {
  request_id: "REQ001",
  tid: 49501,
  start_time_ns: 1699876543000000000,
  end_time_ns:   1699876550320000000,
  duration_ns:   7320000000,  // 7.32 seconds
  cpu_cycles_used: 14640900,
  is_complete: 1
}
```

**Use cases:**
- Identify slow requests
- Track resource consumption per endpoint
- Performance monitoring
- Capacity planning

---

### **Feature 2: User Request History**

**What it tracks:**
- 👤 **All requests** made by each user
- 📝 **Request IDs** for each request
- ⏰ **Timestamps** when requests occurred
- 🧵 **Thread IDs** that handled each request
- 🌐 **Source IP:Port** for each request

**BPF Map:**
```c
user_request_history["alice"] = {
  username: "alice",
  request_count: 5,
  requests: [
    {request_id: "REQ001", timestamp: t1, tid: 49501, src: 127.0.0.1:54321},
    {request_id: "REQ003", timestamp: t2, tid: 49503, src: 127.0.0.1:54323},
    {request_id: "REQ007", timestamp: t3, tid: 49507, src: 127.0.0.1:54327},
    {request_id: "REQ009", timestamp: t4, tid: 49509, src: 127.0.0.1:54329},
    {request_id: "REQ012", timestamp: t5, tid: 49512, src: 127.0.0.1:54332}
  ],
  last_updated_ns: t5
}
```

**Features:**
- ✅ Maintains up to 100 requests per user
- ✅ FIFO: Oldest requests dropped when full
- ✅ Displays updated list after each new request
- ✅ Persistent across requests (until sniffer stops)

**Use cases:**
- User behavior tracking
- Session monitoring
- Security auditing
- Request correlation per user

---

## 📈 Data Flow Diagram

```
┌──────────────┐      ┌──────────────┐      ┌─────────────────┐
│  recv(FD)    │ ───> │  SSL_read()  │ ───> │ Python Parsing  │
└──────────────┘      └──────────────┘      └─────────────────┘
       │                     │                        │
       │                     │                        ├─> Extract Request ID
       ├─> FD→Connection     │                        ├─> Extract User Info
       └─> TID→FD            ├─> Capture Headers      ├─> Update Maps:
                             └─> Lookup Connection    │     • tid_to_user_info
                                                       │     • request_resources
                                                       │     • user_request_history
                                                       └─> Display All
```

---

## 🔍 Use Case Examples

### **1. Security Monitoring**
```python
# Query user_request_history to find suspicious patterns
user_history = bpf.get_table("user_request_history")

for username, history in user_history.items():
    user = username.value.decode('utf-8').rstrip('\x00')
    
    # Alert if admin user makes >10 requests
    if history.request_count > 10 and 'admin' in user.lower():
        print(f"⚠️  Suspicious: {user} made {history.request_count} requests")
```

### **2. Performance Analysis**
```python
# Find slow requests
resources = bpf.get_table("request_resources")

for req_id, usage in resources.items():
    duration_ms = usage.duration_ns / 1_000_000
    
    if duration_ms > 5000:  # Slower than 5 seconds
        req = req_id.value.decode('utf-8').rstrip('\x00')
        print(f"🐢 Slow request: {req} took {duration_ms:.2f}ms")
```

### **3. User Session Correlation**
```python
# Get all requests from user "alice"
user_history = bpf.get_table("user_request_history")
alice_key = (ctypes.c_char * 64)(b'alice\x00')
alice_history = user_history[alice_key]

print(f"Alice made {alice_history.request_count} requests:")
for i in range(alice_history.request_count):
    req = alice_history.requests[i]
    req_id = req.request_id.decode('utf-8').rstrip('\x00')
    print(f"  - {req_id} from TID {req.tid}")
```

---

## 🛠️ Module Architecture

### **File Organization:**

```
integrated_sniffer.py       ← Main program (all features combined)
├─ Connection tracking      (from new_server_sniffer.py)
├─ User info extraction     (built-in)
├─ Resource tracking        (new feature)
└─ User history tracking    (new feature)

resource_tracker.py         ← Standalone module (if needed separately)
user_history_tracker.py     ← Standalone module (if needed separately)
new_server_sniffer.py       ← Basic sniffer (connection + user info only)
```

### **Integration Points:**

```python
# You can also load modules separately:

from resource_tracker import RESOURCE_TRACKER_BPF
from user_history_tracker import USER_HISTORY_BPF

# Combine with main sniffer
combined_bpf = MAIN_BPF + RESOURCE_TRACKER_BPF + USER_HISTORY_BPF
bpf = BPF(text=combined_bpf)
```

---

## 📝 Summary

### **5 Primary BPF Maps:**

| Map | Key | Value | Purpose |
|-----|-----|-------|---------|
| `fd_to_conn` | FD (u32) | Connection 4-tuple | Connect FD to TCP connection |
| `tid_to_fd` | TID (u64) | FD (u32) | Track which thread uses which FD |
| `tid_to_user_info` | TID (u32) | User info | Store user context per thread |
| `request_resources` | Request ID | Resource usage | Track performance per request |
| `user_request_history` | Username | Request list | Maintain user's request history |

### **Complete Attribution Chain:**

```
Request comes in:
  ├─ recv() → Establish: TID ↔ FD ↔ Connection
  ├─ SSL_read() → Capture: Decrypted headers
  ├─ Parse → Extract: Request ID, Username, Cookie, Auth
  ├─ Update Maps:
  │    ├─ tid_to_user_info[TID] = user info
  │    ├─ request_resources[Request ID] = resource usage
  │    └─ user_request_history[Username].append(request)
  └─ Display: Complete request with all context
```

**Every HTTPS request is now fully tracked with:**
- ✅ TCP connection (4-tuple)
- ✅ Handling thread (TID)
- ✅ User identity (username, auth)
- ✅ Resource consumption (time, CPU)
- ✅ User's complete request history

**Perfect for security monitoring, performance analysis, and user behavior tracking!** 🎯

