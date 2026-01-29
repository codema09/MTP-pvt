#!/usr/bin/python3
from bcc import BPF

# 1. Define the eBPF C program
# This program will be compiled and loaded into the kernel.
bpf_program = """
/*
 * kprobe__sys_clone is a special naming convention used by bcc.
 * It automatically creates a kprobe on the kernel function
 * 'sys_clone' and attaches this C function to it.
 */
int kprobe__sys_clone(void *ctx) {
    
    /*
     * bpf_trace_printk() is a simple helper for debugging.
     * It prints a message to the kernel's trace pipe.
     * NOTE: It's limited (e.g., max 3 args) and slow.
     * For real tools, we use BPF_PERF_OUTPUT (see Example 2).
     */
    bpf_trace_printk("Hello,    new process!\\n");
    return 0;
}
"""

# 2. Load the BPF program
# This compiles the C code and loads the eBPF bytecode into the kernel.
b = BPF(text=bpf_program)

# 3. Read and print output
print("Tracing new processes... Ctrl-C to exit.")

# b.trace_print() is a bcc helper that reads /sys/kernel/debug/tracing/trace_pipe
# and prints any messages from bpf_trace_printk().
try:
    b.trace_print()
except KeyboardInterrupt:
    pass