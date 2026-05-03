import pandas as pd
import numpy as np
import time
import os
import sys
import psutil
import threading

# Global stats map and lock
thread_stats = {}
stats_lock = threading.Lock()

# --- Helper function to get kernel TID ---
def get_kernel_tid():
    """Get the actual kernel Thread ID that eBPF sees (not pthread ID)"""
    try:
        # Python 3.8+ has os.gettid() - this is the CORRECT way
        return os.gettid()
    except AttributeError:
        # Fallback for Python < 3.8: use ctypes to call gettid syscall directly
        import ctypes
        libc = ctypes.CDLL('libc.so.6')
        SYS_gettid = 186  # syscall number for gettid on x86_64
        return libc.syscall(SYS_gettid)

def get_process_memory_mb():
    process = psutil.Process(os.getpid())
    # memory_info().rss gives the "Resident Set Size" in bytes
    rss_bytes = process.memory_info().rss
    return rss_bytes / (1024 * 1024)

def allocate_pandas_dataframe(size_multiplier=1):
    # Target sizes: 100 Bytes to 100 MB (scaled by multiplier)
    min_size = 100 * size_multiplier
    max_size = 100 * 1024 * 1024 * size_multiplier
    steps = 10
    
    # Generate geometric progression of sizes
    target_sizes = np.geomspace(min_size, max_size, steps, dtype=int)
    
    dataframes = []
    
    pid = get_kernel_tid()
    print(f"[{pid}] Process ID: {pid}")
    print(f"[{pid}] Starting memory allocation in {steps} steps.")
    
    initial_rss = get_process_memory_mb()
    print(f"[{pid}] Initial RSS: {initial_rss:.2f} MB")
    
    for i, target_size in enumerate(target_sizes):
        prev_rss = get_process_memory_mb()
        
        # Calculate number of float64 elements (8 bytes each)
        num_elements = max(1, int(target_size // 8))
        
        # Create DataFrame
        # np.random.randn generates float64 by default
        df = pd.DataFrame(np.random.randn(num_elements, 1), columns=['data'])
        
        # Keep reference to prevent garbage collection
        dataframes.append(df)
        
        current_rss = get_process_memory_mb()
        rss_increase = current_rss - prev_rss
        total_rss_increase = current_rss - initial_rss
        
        current_target_mb = target_size / (1024 * 1024)
        actual_df_size = sys.getsizeof(df)
        actual_df_size_mb = actual_df_size / (1024 * 1024)
        
        print(f"[{pid}] Step {i+1}/{steps}: Current RSS:    {current_rss:.2f} MB (Step Increase: {rss_increase:+.2f} MB, Total Increase: {total_rss_increase:+.2f} MB)")
        
        with stats_lock:
            thread_stats[pid] = total_rss_increase

        # Wait 15 seconds between allocations
        print(f"[{pid}] Sleeping for 10 seconds...")
        time.sleep(10)

    print(f"[{pid}] Allocation complete.")

if __name__ == "__main__":
    try:
        print("[Main] Creating allocation thread...")
        
        # Create the thread
        # daemon=True ensures the thread dies if the main program exits
        print(f"PID={os.getpid()}")
        time.sleep(30)
        alloc_thread = threading.Thread(target=allocate_pandas_dataframe, args=(1,), daemon=True)
        
        # Start the thread
        alloc_thread.start()
        print("[Main] Thread started. Main thread is waiting...")

        time.sleep(25)
        thread2 = threading.Thread(target=allocate_pandas_dataframe, args=(10,), daemon=True)
        thread2.start() 
        
        # Keep the main thread alive while the child thread runs
        while alloc_thread.is_alive():
            alloc_thread.join(timeout=1.0)

        while thread2.is_alive():
            thread2.join(timeout=1.0)

        print("[Main] Thread finished execution.")
        
        print("\n--- Final RSS Increases per Thread ---")
        with stats_lock:
            for t_pid, increase in thread_stats.items():
                print(f"[{t_pid}] Total RSS Increase: {increase:+.2f} MB")
        
        print("[Main] Exiting.")

    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user. Exiting.")