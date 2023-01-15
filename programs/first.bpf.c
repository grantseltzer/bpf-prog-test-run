#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    int id = ctx->args[1];
    const char fmt_str[] = "raw_tracepoint ran: %ld";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), id);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
