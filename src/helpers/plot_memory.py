#!/usr/bin/env python3

import os
import sys
import argparse
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt

def main():
    parser = argparse.ArgumentParser(description="Plot memory usage per req_id_param")
    parser.add_argument("--log", default="memory_debug_annotated.log", help="Path to annotated memory log")
    parser.add_argument("--outdir", default="plots", help="Directory to save the plots")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # memory_history[req_param] = [(time_offset, current_held_kb), ...]
    memory_history = defaultdict(list)
    
    # memory_held tracks the current allocated memory for each req_param
    memory_held = defaultdict(float)

    # discrete event index instead of time

    print(f"Reading log file: {args.log} ...")
    try:
        with open(args.log, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('---') or line.startswith('TIMESTAMP'):
                    continue
                
                parts = [p.strip() for p in line.split('|')]
                # Parts expected: [TIMESTAMP, TID, EVENT, SIZE, RSS, PFN, Req-ID, Req-Param]
                if len(parts) < 8:
                    continue
                
                timestamp_str = parts[0]
                event = parts[2]
                
                try:
                    size_kb = float(parts[3])
                except ValueError:
                    continue
                
                req_param = parts[7]
                
                # Ignore entries with no req_param
                if req_param == '-':
                    continue
                
                # We do not use time offset anymore
                
                # Update holding
                if event == 'ALLOC':
                    memory_held[req_param] += size_kb
                elif event == 'FREE':
                    memory_held[req_param] -= size_kb
                
                # Append to history
                memory_history[req_param].append(memory_held[req_param])
                
    except FileNotFoundError:
        print(f"Error: Log file {args.log} not found.")
        sys.exit(1)

    print("Generating combined plot for the first 5 Request Parameters...")

    plt.figure(figsize=(12, 8))
    
    count = 0
    valid_params = [rp for rp, h in memory_history.items() if h][:5]
    
    for i, req_param in enumerate(valid_params, 1):
        history = memory_history[req_param]
        # Add an initial point with 0 memory before the first event
        sizes = [0.0] + history
        steps = list(range(len(sizes)))
        
        # Plot utilizing step function: memory allocation holds until it's changed
        plt.step(steps, sizes, where='post', linewidth=2, label=f'REQ{i}')
        count += 1
        
    plt.title('Physical Memory held vs Event Sequence Index')
    plt.xlabel('Event Sequence Index')
    plt.ylabel('Memory Held (KB)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.tight_layout()
    
    plot_filepath = os.path.join(args.outdir, "combined_memory_plot_top5.png")
    
    try:
        plt.savefig(plot_filepath)
        print(f"Successfully generated combined plot at {plot_filepath}")
    except Exception as e:
        print(f"Failed to save {plot_filepath}: {e}")
        
    plt.close()

if __name__ == "__main__":
    main()
