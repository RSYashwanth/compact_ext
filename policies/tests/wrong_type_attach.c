// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "wrong_type_attach.skel.h"

#define CA_NAME "cext_wrong_type"
#define CA_LIST "/proc/sys/net/ipv4/tcp_available_congestion_control"

static int ca_registered(void)
{
    char buf[4096];
    char *tok;
    FILE *f;

    f = fopen(CA_LIST, "r");
    if (!f)
        return -1;
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    for (tok = strtok(buf, " \n"); tok; tok = strtok(NULL, " \n"))
        if (!strcmp(tok, CA_NAME))
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    struct wrong_type_attach_bpf *skel;
    struct bpf_link *link;
    int node_id = argc > 1 ? atoi(argv[1]) : 0;
    int ret = 1;
    int err, reg;

    skel = wrong_type_attach_bpf__open_and_load();
    if (!skel) {
        printf("FAIL: cannot load tcp_congestion_ops: %s\n", strerror(errno));
        return 1;
    }

    link = bpf_map__attach_compact_ext_ops(skel->maps.wrong_type_ops, node_id);
    err = link ? 0 : errno;
    reg = ca_registered();

    if (link)
        printf("FAIL: tcp_congestion_ops attached to node %d\n", node_id);
    else if (err != EINVAL)
        printf("FAIL: attach failed with %s, expected EINVAL\n", strerror(err));
    else if (reg < 0)
        printf("FAIL: cannot read %s\n", CA_LIST);
    else if (reg)
        printf("FAIL: %s was registered as a congestion control\n", CA_NAME);
    else {
        printf("PASS: attach failed with EINVAL, %s not registered\n", CA_NAME);
        ret = 0;
    }

    bpf_link__destroy(link);
    wrong_type_attach_bpf__destroy(skel);
    return ret;
}
