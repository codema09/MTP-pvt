import re
import sys
from collections import defaultdict

def main():
    ansi_file = "/home/khr/homefr/MTP/ebpf/bcc-latest/src/logs/first.ansi"
    mem_file = "/home/khr/homefr/MTP/ebpf/bcc-latest/src/memory_debug.log"
    out_file = "/home/khr/homefr/MTP/ebpf/bcc-latest/src/tagged_memory_debug.log"

    if len(sys.argv) > 2:
        ansi_file = sys.argv[1]
        mem_file = sys.argv[2]
        
    if len(sys.argv) > 3:
        out_file = sys.argv[3]

    tid_to_reqs = defaultdict(set)
    
    # Parse ansi file for mapping
    try:
        with open(ansi_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Strip ANSI escape sequences just in case
                plain_line = re.sub(r'\x1b\[.*?m', '', line)
                match = re.search(r'tid=\s*(\d+).*?req_id_param:\s*(\d+)', plain_line)
                if match:
                    tid = match.group(1)
                    req_id = match.group(2)
                    tid_to_reqs[tid].add(req_id)
    except Exception as e:
        print(f"Error reading {ansi_file}: {e}")
        return

    print(f"Loaded mappings for {len(tid_to_reqs)} distinct TIDs from {ansi_file}")

    # Tag memory_debug.log
    try:
        with open(mem_file, "r") as infile, open(out_file, "w") as outfile:
            for line in infile:
                original_line = line.rstrip('\n')
                if original_line.startswith("TIMESTAMP"):
                    outfile.write(original_line + " | REQ_ID_PARAM\n")
                    continue
                if original_line.startswith("---"):
                    outfile.write(original_line + "----------------------\n")
                    continue
                
                parts = original_line.split('|')
                if len(parts) >= 2:
                    tid_str = parts[1].strip()
                    reqs = tid_to_reqs.get(tid_str, set())
                    req_val = ",".join(reqs) if reqs else "N/A"
                    outfile.write(original_line + f" | {req_val:>18}\n")
                else:
                    outfile.write(original_line + "\n")
                    
        print(f"Successfully tagged memory data into {out_file}")
    except Exception as e:
        print(f"Error processing {mem_file}: {e}")

if __name__ == "__main__":
    main()
