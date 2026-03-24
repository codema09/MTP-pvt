#!/usr/bin/env python3

import re
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Annotate memory_debug.log with req_id_param from ansi log.")
    parser.add_argument("--ansi", default="logs/first.ansi", help="Path to ansi log file")
    parser.add_argument("--mem", default="memory_debug.log", help="Path to memory_debug.log")
    parser.add_argument("--out", default="memory_debug_annotated.log", help="Path to output log file")
    args = parser.parse_args()

    mapping = {}

    req_id_pattern = re.compile(r'([a-zA-Z]+_seq[0-9]+_[a-f0-9]{8,})')
    param_pattern = re.compile(r'req_id_param:\s*(\d+)')

    try:
        with open(args.ansi, 'r') as f:
            for line in f:
                line_clean = re.sub(r'\x1b\[[0-9;]*[mK]', '', line)
                param_match = param_pattern.search(line_clean)
                if param_match:
                    param = param_match.group(1)
                    req_matches = req_id_pattern.findall(line_clean)
                    for req_id in req_matches:
                        mapping[req_id] = param
    except FileNotFoundError:
        print(f"ANSI log file {args.ansi} not found.")
        sys.exit(1)

    print(f"Extracted {len(mapping)} unique Request-ID to req_id_param mappings.")

    try:
        with open(args.mem, 'r') as fin, open(args.out, 'w') as fout:
            for line in fin:
                line = line.rstrip('\n')
                if line.startswith("TIMESTAMP"):
                    fout.write(line + " | Req-Param\n")
                elif line.startswith("---"):
                    fout.write(line + "--------------\n")
                else:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 7:
                        req_id = parts[6]
                        param = mapping.get(req_id, "-")
                        # Format symmetrically 
                        fout.write(line + f" | {param}\n")
                    else:
                        fout.write(line + "\n")
    except FileNotFoundError:
        print(f"Memory log file {args.mem} not found.")
        sys.exit(1)

    print(f"Annotated log written to {args.out}")

if __name__ == "__main__":
    main()
