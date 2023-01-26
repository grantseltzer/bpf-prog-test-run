#include "progs.skel.h"
#include "maps.skel.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <linux/ptrace.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_string_event(void *ctx, void *data, size_t data_sz)
{
	char e[7] = data;
    printf("> %s\n", e);
	return 0;
}

int main(int argc, char** argv)
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

    if (argc != 2) {
        printf("must specify program to test run, `./example fentry or raw_tp`\n");
        return 1;
    }

    char *raw_tp_str = "raw_tp", *fentry_str = "fentry";
    if (!strcmp(raw_tp_str, argv[1])) {
        int raw_tp_prog_fd = bpf_program__fd(progs_skel->progs.raw_tracepoint__task_rename);
        rb = ring_buffer__new(bpf_map__fd(progs_skel->maps.events), handle_event, NULL, NULL);

        __u64 args[2] = {0x1234ULL, (__u64)raw_tp_str};

        LIBBPF_OPTS(bpf_test_run_opts, test_run_opts,
            .ctx_in = args,
            .ctx_size_in = sizeof(args),
        );

        err = bpf_prog_test_run_opts(raw_tp_prog_fd, &test_run_opts);
        if (err != 0) {
            fprintf(stderr, "failed to test run rawtp: %d\n", err);
            return 1;
        }

        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
        }
    } else if (!strcmp(fentry_str, argv[1])) {

        int fentry_prog_fd = bpf_program__fd(progs_skel->progs.fentry__do_unlinkat);
        rb = ring_buffer__new(bpf_map__fd(progs_skel->maps.events), handle_event, NULL, NULL);

        __u64 args[2] = {0x1234ULL, (__u64)fentry_str};

        LIBBPF_OPTS(bpf_test_run_opts, test_run_opts,
            .ctx_in = args,
            .ctx_size_in = sizeof(args),
        );

        err = bpf_prog_test_run_opts(fentry_prog_fd, &test_run_opts);
        if (err != 0) {
            fprintf(stderr, "failed to test run rawtp: %d\n", err);
            return 1;
        }

        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
        }
    } else {
        printf("invalid input, specify fentry or raw_tp\n");
    }
}
