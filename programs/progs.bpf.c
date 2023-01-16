#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "maps.bpf.h"

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    int *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed");
        return 0;
    }
    *e = ctx->args[1];
    bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tracepoint/task_rename")
int raw_tracepoint__task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    char *e;
	e = bpf_ringbuf_reserve(&events, sizeof(char)*5, 0);
    if (!e) {
        bpf_printk("Failed");
        return 0;
    }

    bpf_probe_read_user(e, sizeof(char)*5, (void*)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(fentry__do_unlinkat, int dfd, struct filename *name)
{
    int *e;
	e = bpf_ringbuf_reserve(&events, sizeof(int), 0);
    if (!e) {
        bpf_printk("Failed");
        return 0;
    }
    *e = dfd;
    bpf_ringbuf_submit(e, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
