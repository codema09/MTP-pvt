from bcc import BPF
from time import sleep

bpf_text = """
BPF_HASH(syscall_counts, u32, u64);

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 key = 1;
    syscall_counts.increment(key);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u32 key = 2;
    syscall_counts.increment(key);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
    u32 key = 3;
    syscall_counts.increment(key);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
    u32 key = 4;
    syscall_counts.increment(key);
    return 0;
}
"""

b = BPF(text=bpf_text)
print("Tracing... Hit Ctrl-C to end.")
try:
    sleep(10)
except KeyboardInterrupt:
    pass

counts = b.get_table("syscall_counts")
names = {1: "write", 2: "sendto", 3: "writev", 4: "sendmsg"}
for k, v in counts.items():
    print("%-10s %d" % (names.get(k.value, "unknown"), v.value))
