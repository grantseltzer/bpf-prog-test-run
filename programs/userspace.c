#include "progs.skel.h"
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	int *e = data;
    printf("> %d\n", *e);
	return 0;
}

int main()
{
    signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    int err;    
	struct ring_buffer *rb = NULL;
    struct progs_bpf *progs_skel;

    progs_skel = progs_bpf__open_and_load();
    if (!progs_skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    int rawtp_prog_fd = bpf_program__fd(progs_skel->progs.fentry__do_unlinkat);
    rb = ring_buffer__new(bpf_map__fd(progs_skel->maps.events), handle_event, NULL, NULL);

    // char test[5] = "AAAA\n";
	__u64 args[2] = {0x00000045,  0x00000000};

  	LIBBPF_OPTS(bpf_test_run_opts, test_run_opts,
		.ctx_in = args,
		.ctx_size_in = sizeof(args),
	);

    err = bpf_prog_test_run_opts(rawtp_prog_fd, &test_run_opts);
    if (err != 0) {
        fprintf(stderr, "failed to test run rawtp: %d\n", err);
        return 1;
    }

    err = ring_buffer__poll(rb, 100);
    if (err < 0) {
        printf("Error polling ring buffer: %d\n", err);
    }
}
