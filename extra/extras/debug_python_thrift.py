from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>

struct evt_t {
    u32 pid;
    char comm[16];
    u8 bytes[32];
    u32 count;
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h') {
        struct evt_t evt = {};
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        
        evt.count = args->len;
        if (evt.count >= 8) {
            bpf_probe_read_user(&evt.bytes, 32, args->buff);
            events.perf_submit(args, &evt, sizeof(evt));
        }
    }
    return 0;
}
"""

b = BPF(text=bpf_text)

print("Tracing Python sendto... Hit Ctrl-C to end")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    hex_str = " ".join([f"{x:02x}" for x in event.bytes])
    print(f"PID {event.pid} ({event.comm.decode()}) len {event.count}: {hex_str}")

b["events"].open_perf_buffer(print_event)

try:
    # Read for a short time
    for _ in range(50):
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass
