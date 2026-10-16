// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "compact_ext_default.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

static int parse_node(const char *arg, int *node_id)
{
    char *end;
    long val;

    errno = 0;
    val = strtol(arg, &end, 10);
    if (errno || end == arg || *end || val < 0 || val > INT_MAX)
        return -1;

    *node_id = val;
    return 0;
}

int main(int argc, char **argv)
{
    struct compact_ext_default_bpf *skel;
    struct bpf_link *link;
    int node_id = 0;
    int err;

    if (argc > 2 || (argc == 2 && parse_node(argv[1], &node_id))) {
        fprintf(stderr, "Usage: %s [node_id]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = compact_ext_default_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    err = compact_ext_default_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(-err));
        goto cleanup;
    }

    link = bpf_map__attach_compact_ext_ops(skel->maps.default_ops, node_id);
    if (!link) {
        err = -errno;
        fprintf(stderr, "Failed to attach compact_ext ops to node %d: %s\n",
            node_id, strerror(-err));
        goto cleanup;
    }

    printf("compact_ext default policy attached to node %d\n", node_id);
    printf("Press Ctrl-C to detach and exit.\n");

    while (running)
        sleep(1);

    printf("\nDetaching...\n");
    bpf_link__destroy(link);

cleanup:
    compact_ext_default_bpf__destroy(skel);
    return err ? 1 : 0;
}
