#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

SEC("raw_tracepoint/task_rename")
int raw_tracepoint__task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    bpf_printk("Raw tracepoint\n");
    
    char *e;
    e = bpf_ringbuf_reserve(&events, sizeof(char)*7, 0);
    if (!e) {
        bpf_printk("Failed rtp");
        return 0;
    }

    bpf_probe_read_user(e, sizeof(char)*7, (void*)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(fentry__do_unlinkat, int dfd, char *name)
{
    bpf_printk("Fentry program: dfd: %d Filename: %s\n", dfd, name);
    
    char *e;
    e = bpf_ringbuf_reserve(&events, sizeof(char)*7, 0);
    if (!e) {
        bpf_printk("Failed fentry");
        return 0;
    }

    bpf_probe_read(e, sizeof(char)*7, name);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
