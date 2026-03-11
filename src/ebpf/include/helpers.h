// ═══════════════════════════════════════════════════════════════
// helpers.h — Common helper functions
// ═══════════════════════════════════════════════════════════════

static inline int is_target_process() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;
    return 1;
}

static struct sock* get_sock_from_fd(u32 fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = task->files;
    if (files == NULL) return NULL;
    struct fdtable *fdt = files->fdt;
    if (fdt == NULL) return NULL;
    if (fd >= fdt->max_fds) return NULL;
    struct file **fd_array;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (file == NULL) return NULL;
    struct socket *sock_obj;
    bpf_probe_read_kernel(&sock_obj, sizeof(sock_obj), &file->private_data);
    if (sock_obj == NULL) return NULL;
    struct sock *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), &sock_obj->sk);
    return sk;
}
