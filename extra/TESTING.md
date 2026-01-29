# HTTPS Server Sniffer - Testing Guide

## Setup

### Terminal 1: Start the HTTPS Server
```bash
cd SERVER
python3 server.py
```

The server will:
- Listen on `https://localhost:8443`
- Add random delays (1-10 seconds) to simulate processing time
- Print detailed info for each request including TID and request ID

### Terminal 2: Start the Sniffer
```bash
sudo python3 server-sniffer.py
```

The sniffer will:
- Capture all HTTPS requests
- Show connection 4-tuple (src/dst IP and ports)
- Display HTTP headers including custom headers
- Map each request to the correct thread (TID)

---

## Test 1: Quick Concurrent Test

**Terminal 3:**
```bash
./quick-test.sh
```

**What it does:**
- Sends 10 concurrent requests
- Each request has a unique ID (REQ001 - REQ010)
- Each request uses a different source port

**Expected Output:**

**Sniffer should show:**
```
[HTTPS REQUEST INTERCEPTED]
PID: 49473
TID: 49501
Process: python3

Connection 4-tuple:
  Source:      127.0.0.1:54321
  Destination: 127.0.0.1:8443

HTTP Headers:
--------------------------------------------------------------------------------
GET /?id=REQ001 HTTP/1.1
Host: localhost:8443
X-Request-ID: REQ001
User-Agent: Test-1
Cookie: session=sess_1
--------------------------------------------------------------------------------

[HTTPS REQUEST INTERCEPTED]
PID: 49473
TID: 49502  ← Different TID!
...
Connection 4-tuple:
  Source:      127.0.0.1:54322  ← Different source port!
  ...
GET /?id=REQ002 HTTP/1.1  ← Different request ID!
X-Request-ID: REQ002
```

---

## Test 2: Full Stress Test

**Terminal 3:**
```bash
./stress-test.sh
```

**What it does:**
- Sends 10 concurrent requests with random delays
- Creates detailed logs in `./stress-test-results/`
- Shows timing for each request
- Verifies all requests completed successfully

**Verification Checklist:**

✅ **1. Unique Source Ports**
Each request should have a different source port:
- REQ001 → 127.0.0.1:**54321**
- REQ002 → 127.0.0.1:**54322**
- etc.

✅ **2. Correct TID Mapping**
Compare server logs with sniffer output:
```bash
# Server shows:
[REQUEST] GET /?id=REQ001
Kernel Thread ID (TID): 49501

# Sniffer should show same TID:
TID: 49501
GET /?id=REQ001
X-Request-ID: REQ001
```

✅ **3. One-to-One Mapping**
Even with overlapping requests:
- Each TID handles exactly one connection
- Each source port maps to exactly one request ID
- No confusion between concurrent requests

---

## Test 3: Custom Request

Send your own request with custom headers:

```bash
curl -k \
  -H "X-Request-ID: CUSTOM123" \
  -H "Authorization: Bearer mytoken" \
  -H "X-Custom: test" \
  -b "session=xyz; user=admin" \
  "https://localhost:8443/?id=CUSTOM123"
```

**Verify:**
- All headers appear in sniffer output
- Connection 4-tuple is captured
- TID matches between server and sniffer

---

## Troubleshooting

### No connection info in sniffer output

If you see `[Tracking in progress...]`:

1. Make sure `inet_csk_accept` probe attached:
   ```
   ✓ Attached to inet_csk_accept (connection tracking)
   ```

2. Check sniffer is running as root:
   ```bash
   sudo python3 server-sniffer.py
   ```

3. Verify sys_enter_read tracepoint is working:
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe | grep sys_enter_read
   ```

### Mismatched TIDs

If TIDs don't match:
- Check that server is using `get_kernel_tid()` (not `threading.get_ident()`)
- Verify Python version is 3.8+ for `os.gettid()`

### Missing requests

If sniffer misses requests:
- Check that both `SSL_read` and `SSL_read_ex` probes attached
- Verify `/usr/lib/libssl.so.3` exists

---

## Understanding the Output

### Server Output Explained
```
======================================================================
[REQUEST] GET /?id=REQ001 | RESPONSE: 200
======================================================================
  Process ID (PID):         49473         ← Server process
  Kernel Thread ID (TID):   49501         ← Handler thread
  Client Address:           127.0.0.1:54321  ← Unique per request
  Active Threads in Server: 11            ← Concurrent handlers
  [DELAY] Sleeping for 7.32s (Request ID: REQ001)
  [RESUME] Processing request ID: REQ001
======================================================================
```

### Sniffer Output Explained
```
================================================================================
[HTTPS REQUEST INTERCEPTED]
PID: 49473      ← Same PID as server
TID: 49501      ← Same TID as server ✓

Connection 4-tuple:
  Source:      127.0.0.1:54321  ← Client (unique ephemeral port)
  Destination: 127.0.0.1:8443   ← Server

HTTP Headers:
--------------------------------------------------------------------------------
GET /?id=REQ001 HTTP/1.1        ← Request line
Host: localhost:8443
X-Request-ID: REQ001            ← Custom header for identification
User-Agent: Test-1
Cookie: session=sess_1
--------------------------------------------------------------------------------
```

---

## Success Criteria

✅ **Test passes if:**
1. All 10 requests captured by sniffer
2. Each request has unique source port
3. TIDs match between server and sniffer
4. Request IDs (REQ001-REQ010) all present
5. No mixing of requests (correct 1-to-1 attribution)

❌ **Test fails if:**
1. Some requests missing from sniffer
2. Connection info shows `[Tracking in progress...]`
3. TIDs don't match between server and sniffer
4. Request IDs appear in wrong connections
5. Multiple requests share same source port

---

## Advanced Testing

### Test with 50 concurrent requests:
```bash
for i in {1..50}; do
    curl -k -H "X-ID: REQ$(printf '%03d' $i)" \
    "https://localhost:8443/?id=$i" &
done
wait
```

### Test with POST requests:
```bash
for i in {1..10}; do
    curl -k -X POST \
        -H "Content-Type: application/json" \
        -d "{\"id\":$i,\"data\":\"test$i\"}" \
        "https://localhost:8443" &
done
wait
```

---

## Cleanup

```bash
# Stop server: Ctrl+C in Terminal 1
# Stop sniffer: Ctrl+C in Terminal 2
# Clean test results:
rm -rf stress-test-results/
```

