import os, ctypes, multiprocessing, re
from bcc import BPF

EBPF_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ebpf")

BPF_SOURCE_FILES = [
    "include/common.h",
    "include/maps.h",
    "include/helpers.h",
    "tracepoints/cpu_tracking.c",
    "tracepoints/io_tracking.c",
    "tracepoints/conn_tracking.c",
    "uprobes/ssl_interception.c",
    "tracepoints/lifecycle.c",
    "tracepoints/memory_tracking.c",
]

bpf_text = ""
for relpath in BPF_SOURCE_FILES:
    filepath = os.path.join(EBPF_SRC_DIR, relpath)
    with open(filepath, "r") as f:
        bpf_text += f"// === {relpath} ===\n"
        bpf_text += f.read() + "\n"

bpf_text = bpf_text.replace("__NUM_CPUS__", str(multiprocessing.cpu_count()))
bpf = BPF(text=bpf_text)

print("EBPF_MAP_SIZES = {")
map_names = re.findall(r'BPF_HASH\(([a-zA-Z0-9_]+)', bpf_text)
for name in map_names:
    try:
        table = bpf[name]
        item_size = ctypes.sizeof(table.Key) + ctypes.sizeof(table.Leaf)
        print(f"    '{name}': {item_size},")
    except Exception as e:
        print(f"    # Failed to get size for {name}: {e}")
print("}")
