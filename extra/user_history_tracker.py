#!/usr/bin/env python3
"""
User History Tracker - eBPF Module
===================================
Maintains a list of all requests made by each user across different HTTPS requests.
Tracks request history per user with unique request IDs.

Can be loaded independently or integrated with main sniffer.
"""

# eBPF program for user history tracking
USER_HISTORY_BPF = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_USERNAME_LEN 64
#define MAX_REQUEST_ID_LEN 64
#define MAX_REQUESTS_PER_USER 100

// Key structures
struct username_key_t {
    char name[MAX_USERNAME_LEN];
};

struct request_id_key_t {
    char id[MAX_REQUEST_ID_LEN];
};

// Single request entry
struct request_entry_t {
    char request_id[MAX_REQUEST_ID_LEN];
    u64 timestamp_ns;
    u32 tid;
    u32 src_ip;
    u16 src_port;
};

// User request history (list of requests for one user)
struct user_history_t {
    char username[MAX_USERNAME_LEN];
    struct request_entry_t requests[MAX_REQUESTS_PER_USER];
    u32 request_count;  // Number of requests in the list
    u64 last_updated_ns;
};

// PRIMARY MAP: Username → Request History
BPF_HASH(user_request_history, struct username_key_t, struct user_history_t);

// Helper to add request to user's history
int add_request_to_user_history(char username[MAX_USERNAME_LEN], 
                                 char request_id[MAX_REQUEST_ID_LEN],
                                 u32 tid, u32 src_ip, u16 src_port) {
    
    struct user_history_t *history = user_request_history.lookup(&username);
    struct user_history_t new_history;
    
    if (history == NULL) {
        // First request for this user - initialize
        __builtin_memset(&new_history, 0, sizeof(new_history));
        bpf_probe_read_kernel_str(new_history.username, MAX_USERNAME_LEN, username);
        new_history.request_count = 0;
        history = &new_history;
    } else {
        // Copy existing history
        bpf_probe_read_kernel(&new_history, sizeof(new_history), history);
    }
    
    // Check if we have space for more requests
    if (new_history.request_count >= MAX_REQUESTS_PER_USER) {
        // Shift array left to make room (drop oldest)
        #pragma unroll
        for (int i = 0; i < MAX_REQUESTS_PER_USER - 1; i++) {
            new_history.requests[i] = new_history.requests[i + 1];
        }
        new_history.request_count = MAX_REQUESTS_PER_USER - 1;
    }
    
    // Add new request
    u32 idx = new_history.request_count;
    bpf_probe_read_kernel_str(new_history.requests[idx].request_id, 
                             MAX_REQUEST_ID_LEN, request_id);
    new_history.requests[idx].timestamp_ns = bpf_ktime_get_ns();
    new_history.requests[idx].tid = tid;
    new_history.requests[idx].src_ip = src_ip;
    new_history.requests[idx].src_port = src_port;
    
    new_history.request_count++;
    new_history.last_updated_ns = bpf_ktime_get_ns();
    
    // Update map
    user_request_history.update(&username, &new_history);
    
    return 0;
}
"""

import ctypes
import time


class UserHistoryTracker:
    """Manages user request history tracking"""
    
    def __init__(self, bpf_instance):
        """Initialize with existing BPF instance"""
        self.bpf = bpf_instance
    
    def add_request(self, username, request_id, tid, src_ip, src_port):
        """Add a request to user's history"""
        if not username:
            return  # No username, can't track
        
        try:
            # Get or create history for this user
            user_history_map = self.bpf.get_table("user_request_history")
            
            username_key = (ctypes.c_char * 64)()
            username_key.value = username.encode('utf-8')[:63] + b'\x00'
            
            try:
                history = user_history_map[username_key]
                request_count = history.request_count
            except KeyError:
                # First request for this user
                history = user_history_map.Leaf()
                history.username = username.encode('utf-8')[:63] + b'\x00'
                history.request_count = 0
                request_count = 0
            
            # Check if we have space
            idx = request_count
            if idx >= 100:
                # Shift array (drop oldest)
                for i in range(99):
                    history.requests[i] = history.requests[i + 1]
                idx = 99
            else:
                history.request_count += 1
            
            # Add new request
            req_id_bytes = request_id.encode('utf-8')[:63] + b'\x00'
            history.requests[idx].request_id = req_id_bytes
            history.requests[idx].timestamp_ns = int(time.time() * 1_000_000_000)
            history.requests[idx].tid = tid
            history.requests[idx].src_ip = src_ip
            history.requests[idx].src_port = src_port
            history.last_updated_ns = int(time.time() * 1_000_000_000)
            
            # Update map
            user_history_map[username_key] = history
            
            # Display updated history
            self.display_user_history(username, history)
            
        except Exception as e:
            print(f"  [⚠] Error adding to user history: {e}")
    
    def display_user_history(self, username, history):
        """Display complete request history for a user"""
        print("\n" + "╔" + "═" * 78 + "╗")
        print(f"║ USER REQUEST HISTORY: {username:60} ║")
        print("╠" + "═" * 78 + "╣")
        
        count = history.request_count
        print(f"║ Total Requests: {count:63} ║")
        print("╠" + "═" * 78 + "╣")
        
        if count == 0:
            print("║ No requests yet" + " " * 62 + "║")
        else:
            for i in range(min(count, 100)):
                req_entry = history.requests[i]
                req_id = req_entry.request_id.decode('utf-8', errors='ignore').rstrip('\x00')
                
                if not req_id:
                    continue
                
                # Format timestamp
                ts_sec = req_entry.timestamp_ns / 1_000_000_000
                time_str = time.strftime('%H:%M:%S', time.localtime(ts_sec))
                
                # Format source
                src_ip_str = self._ip_to_str(req_entry.src_ip)
                
                print(f"║ [{i+1:2}] {req_id:20} │ {time_str} │ TID:{req_entry.tid:6} │ {src_ip_str:15}:{req_entry.src_port:5} ║")
        
        print("╚" + "═" * 78 + "╝")
    
    def display_all_user_histories(self):
        """Display request history for ALL users"""
        print("\n" + "=" * 80)
        print("COMPLETE USER REQUEST HISTORIES")
        print("=" * 80)
        
        user_history_map = self.bpf.get_table("user_request_history")
        
        if len(user_history_map) == 0:
            print("  No user histories tracked yet.")
            print("=" * 80)
            return
        
        print(f"  Total users tracked: {len(user_history_map)}\n")
        
        for username_key, history in user_history_map.items():
            username = username_key.value.decode('utf-8', errors='ignore').rstrip('\x00')
            
            if not username:
                continue
            
            self.display_user_history(username, history)
        
        print("\n" + "=" * 80)
    
    def _ip_to_str(self, ip):
        """Convert IP integer to string"""
        import socket
        import struct
        return socket.inet_ntoa(struct.pack("I", ip))


# Standalone testing
if __name__ == "__main__":
    from bcc import BPF
    
    print("User History Tracker - Standalone Test")
    print("=" * 80)
    print("Loading eBPF program...")
    
    bpf = BPF(text=USER_HISTORY_BPF)
    tracker = UserHistoryTracker(bpf)
    
    print("✓ User history tracker loaded")
    print("\nThis module is meant to be integrated with the main sniffer.")
    print("Use: from user_history_tracker import USER_HISTORY_BPF, UserHistoryTracker")

