#include "first.skel.h"
#include "maps.skel.h"
#include <signal.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <linux/ptrace.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main()
{
    signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    int err;    
    struct first_bpf *first_skel;

    first_skel = first_bpf__open_and_load();
    if (!first_skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    int rawtp_prog_fd = bpf_program__fd(first_skel->progs.raw_tracepoint__sys_enter);

	__u64 args[2] = {0x1234ULL, 0x0045ULL};

    struct bpf_test_run_opts test_run_opts = { 
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = args,
        .ctx_size_in = sizeof(args),
		.flags = BPF_F_TEST_RUN_ON_CPU,
    };

    err = bpf_prog_test_run_opts(rawtp_prog_fd, &test_run_opts);
    if (err != 0) {
        fprintf(stderr, "failed to test run rawtp: %d\n", err);
		return 1;
    }
}
