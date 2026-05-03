import os
try:
    from bcc import BPF
except ImportError:
    print("BCC not installed")
    exit(1)

from src.ebpf.loader import load_bpf_program

print("Compiling BPF...")
try:
    num_cpus = os.cpu_count() or 128
    bpf_source = load_bpf_program(num_cpus)
    bpf = BPF(text=bpf_source, cflags=["-Wno-array-bounds"])
    print("Compilation successful!")
except Exception as e:
    print(f"Compilation failed: {e}")
    exit(1)
