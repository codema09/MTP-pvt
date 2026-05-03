
import os
import sys

import threading
import time

def allocate_small_objects():
    print("Allocating many small objects (should trigger pymalloc arenas)...")
    # Small objects < 512 bytes are handled by pymalloc
    # It allocates 256KB arenas from the system
    # We need enough of them to force a system allocation
    l = []
    for i in range(100000):
        l.append((i, i)) # Tuples are small

def allocate_large_object():
    print("Allocating a large object (should trigger direct system allocation)...")
    # Large objects are routed to system malloc
    # Large enough mallocs use mmap directly
    # 10MB string
    s = "a" * (10 * 1024 * 1024)

def allocate_in_thread():
    def thread_task():
        print(f"Thread {threading.get_ident()} allocating 1MB object...")
        s = "b" * (1024)
        # s = "b" * (  1024)

        print(f"Thread {threading.get_ident()} finished allocation.")
        
    print("Spawning a thread...")
    t = threading.Thread(target=thread_task)
    t.start()
    t.join()
    print("Thread joined.")

if __name__ == "__main__":
    print(f"PID: {os.getpid()}")
    allocate_small_objects()
    # allocate_large_object()
    allocate_in_thread()
    allocate_in_thread()
