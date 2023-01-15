# bpf-prog-test-run-experiment

Testing how to use the `BPF_PROG_TEST_RUN`/`BPF_PROG_RUN` bpf command (via libbpf) for potentially unit testing bpf programs.

This runs a raw tracepoint program for sys_enter and sets the id parameter, it prints it to trace_pipe to confirm that setting/running it works.