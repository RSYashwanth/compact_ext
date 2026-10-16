// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "compact_ext_default.skel.h"

static int expect_busy(const char *what, struct bpf_map *map, int node_id)
{
    struct bpf_link *link;
    int err;

    link = bpf_map__attach_compact_ext_ops(map, node_id);
    if (link) {
        printf("FAIL: %s: attach succeeded, expected EBUSY\n", what);
        bpf_link__destroy(link);
        return -1;
    }
    err = errno;
    if (err != EBUSY) {
        printf("FAIL: %s: attach failed with %s, expected EBUSY\n",
               what, strerror(err));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct compact_ext_default_bpf *first, *second = NULL;
    struct bpf_link *link1, *link2 = NULL;
    int node_id = argc > 1 ? atoi(argv[1]) : 0;
    int ret = 1;

    first = compact_ext_default_bpf__open_and_load();
    second = compact_ext_default_bpf__open_and_load();
    if (!first || !second) {
        printf("FAIL: cannot load default policy: %s\n", strerror(errno));
        goto out;
    }

    link1 = bpf_map__attach_compact_ext_ops(first->maps.default_ops, node_id);
    if (!link1) {
        printf("FAIL: first attach to node %d failed: %s\n",
               node_id, strerror(errno));
        goto out;
    }

    if (expect_busy("same map", first->maps.default_ops, node_id) ||
        expect_busy("second copy", second->maps.default_ops, node_id) ||
        expect_busy("second copy, retry", second->maps.default_ops, node_id)) {
        bpf_link__destroy(link1);
        goto out;
    }

    bpf_link__destroy(link1);

    link2 = bpf_map__attach_compact_ext_ops(second->maps.default_ops, node_id);
    if (!link2) {
        printf("FAIL: attach after detaching the first policy failed: %s\n",
               strerror(errno));
        goto out;
    }

    printf("PASS: second attach failed with EBUSY, node %d freed on detach\n",
           node_id);
    ret = 0;

out:
    bpf_link__destroy(link2);
    compact_ext_default_bpf__destroy(second);
    compact_ext_default_bpf__destroy(first);
    return ret;
}
