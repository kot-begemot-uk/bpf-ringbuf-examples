// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "ringbuf-output.skel.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;
static char *pin = NULL;

static void sig_handler(int sig)
{
    if (pin) {
        unlink(pin);
    }
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct ringbuf_output_bpf *skel;
	int err;

	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = ringbuf_output_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint */
	err = ringbuf_output_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    if (argc > 1) {
        bpf_map__pin(skel->maps.rb, argv[1]);
        pin = argv[1];
    }

	while (!exiting) {
        select(0, NULL, NULL, NULL, NULL); /* wait until interrupted */
	}

cleanup:
	ring_buffer__free(rb);
	ringbuf_output_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
