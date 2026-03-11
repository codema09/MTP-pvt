import pandas as pd
import numpy as np
import time
import os
import psutil

def get_process_memory():
    process = psutil.Process(os.getpid())
    # memory_info().rss gives the "Resident Set Size" in bytes
    return process.memory_info().rss

def monitor_memory():
    # 1. Baseline Memory (Python runtime overhead)
    base_memory = get_process_memory()
    print(f"PID: {os.getpid()}")
    print(f"Baseline Memory (Python Overhead): {base_memory / 1024:.2f} KB")

    # 2. Create the 100KB DataFrame
    rows = 1024
    cols = 10000
    df = pd.DataFrame(np.random.randn(rows, cols))
    
    # Force a small calculation to ensure allocation happens immediately
    _ = df.sum()

    # 3. Check Memory Increase
    current_memory = get_process_memory()
    increment = current_memory - base_memory
    
    print(f"Memory after DataFrame creation: {current_memory / 1024:.2f} KB")
    print(f"Approximate Increase: {increment / 1024:.2f} KB")
    print("-" * 30)

    # 4. Monitor Loop
    start_time = time.time()
    while (time.time() - start_time) < 60:
        # "Touch" the data to keep it active
        _ = df.sum()
        
        # Check actual physical memory again
        live_rss = get_process_memory()
        print(f"Live Physical RAM (RSS): {live_rss / 1024:.2f} KB", end='\r')
        
        time.sleep(1)

    print("\nDone.")

if __name__ == "__main__":
    monitor_memory()