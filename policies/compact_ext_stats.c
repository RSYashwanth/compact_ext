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
#include "compact_ext_stats.h"
#include "compact_ext_stats.skel.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const char *const hook_names[NR_HOOKS] = {
    [HOOK_INIT] = "init",
    [HOOK_EXIT] = "exit",
    [HOOK_SHOULD_COMPACT_ZONE] = "should_compact_zone",
    [HOOK_SHOULD_PROACTIVE_COMPACT] = "should_proactive_compact",
    [HOOK_FRAGMENTATION_SCORE] = "fragmentation_score",
    [HOOK_SELECT_MIGRATION_SOURCE] = "select_migration_source",
    [HOOK_SELECT_MIGRATION_TARGET] = "select_migration_target",
    [HOOK_FIND_MIGRATE_PFN] = "find_migrate_pfn",
    [HOOK_FIND_FREE_PFN] = "find_free_pfn",
    [HOOK_SHOULD_MIGRATE_FOLIO] = "should_migrate_folio",
    [HOOK_SHOULD_EVICT_FOLIO] = "should_evict_folio",
    [HOOK_COMPACTION_FINISHED] = "compaction_finished",
    [HOOK_MIGRATION_COMPLETED] = "migration_completed",
    [HOOK_COMPACTION_COMPLETED] = "compaction_completed",
};

static const char *const trigger_names[NR_TRIGGERS] = {
    "direct", "kcompactd", "proactive", "manual",
};

static const char *const result_names[] = {
    "not_suitable_zone", "skipped", "deferred", "no_suitable_page",
    "continue", "complete", "partial_skipped", "contended", "success",
};

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

static int parse_int(const char *arg, long min, int *out)
{
    char *end;
    long val;

    errno = 0;
    val = strtol(arg, &end, 10);
    if (errno || end == arg || *end || val < min || val > INT_MAX)
        return -1;

    *out = val;
    return 0;
}

static const char *trigger_name(int trigger)
{
    if (trigger < 0 || trigger >= NR_TRIGGERS)
        return "?";
    return trigger_names[trigger];
}

static const char *result_name(int result)
{
    if (result < 0 || result >= (int)ARRAY_SIZE(result_names))
        return "?";
    return result_names[result];
}

static void print_stats(struct compact_ext_stats_bpf *skel)
{
    struct compact_ext_stats_bpf__bss *bss = skel->bss;
    unsigned long long calls[NR_HOOKS] = {};
    __u32 i;
    int err;

    for (i = 0; i < NR_HOOKS; i++) {
        __u64 val;

        err = bpf_map__lookup_elem(skel->maps.hook_calls, &i, sizeof(i),
                                   &val, sizeof(val), 0);
        if (err) {
            fprintf(stderr, "Failed to read hook_calls[%u]: %s\n",
                    i, strerror(-err));
            continue;
        }
        calls[i] = val;
    }

    printf("=== node %d ===\n", bss->node_id);
    printf("hook calls:\n");
    for (i = 0; i < NR_HOOKS; i++)
        printf("  %-26s %llu\n", hook_names[i], calls[i]);

    printf("should_compact_zone by trigger:");
    for (i = 0; i < NR_TRIGGERS; i++)
        printf(" %s=%llu", trigger_names[i],
               (unsigned long long)bss->trigger_calls[i]);
    printf("\n");
    if (calls[HOOK_SHOULD_COMPACT_ZONE])
        printf("  last: trigger=%s order=%d default=%s free_blocks=%lld\n",
               trigger_name(bss->last_trigger), bss->last_order,
               bss->last_default ? "compact" : "skip",
               (long long)bss->last_free_blocks);

    if (calls[HOOK_SHOULD_PROACTIVE_COMPACT])
        printf("proactive: last node_score=%u\n", bss->last_node_score);
    if (calls[HOOK_FRAGMENTATION_SCORE])
        printf("fragmentation: last score=%lld extfrag_index=%lld\n",
               (long long)bss->last_frag_score,
               (long long)bss->last_extfrag_index);
    if (calls[HOOK_SELECT_MIGRATION_TARGET])
        printf("target: last pageblock migratetype=%d\n",
               bss->last_target_migratetype);

    printf("source pageblocks with skip bit: %llu\n",
           (unsigned long long)bss->nr_source_skip);
    printf("folios the kernel would not migrate: %llu\n",
           (unsigned long long)bss->nr_folio_default_no);
    printf("pages migrated: %llu (failed: %llu)\n",
           (unsigned long long)bss->total_migrated,
           (unsigned long long)bss->total_migrate_failed);
    if (calls[HOOK_COMPACTION_COMPLETED])
        printf("last compaction result: %s (%d)\n",
               result_name(bss->last_result), bss->last_result);

    if (bss->map_idx < 0) {
        printf("map: create(%u entries) failed: %s\n",
               bss->map_entries, strerror(-bss->map_idx));
    } else {
        printf("map: index %d, %u of %llu pageblocks (order %u, kfunc says %u), map_size=%lld\n",
               bss->map_idx, bss->map_entries,
               (unsigned long long)bss->nr_pageblocks, bss->pb_order,
               bss->kfunc_pb_order, (long long)bss->map_size);
        if (calls[HOOK_COMPACTION_COMPLETED] &&
            calls[HOOK_SELECT_MIGRATION_SOURCE])
            printf("  pageblock %llu selected as source %lld times\n",
                   (unsigned long long)bss->last_source_key,
                   (long long)bss->last_source_count);
    }
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct compact_ext_stats_bpf *skel;
    struct bpf_link *link;
    int node_id = 0;
    int interval = 5;
    int err;

    if (argc > 3 ||
        (argc > 1 && parse_int(argv[1], 0, &node_id)) ||
        (argc > 2 && parse_int(argv[2], 1, &interval))) {
        fprintf(stderr, "Usage: %s [node_id] [interval_s]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = compact_ext_stats_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton: %s\n",
            strerror(errno));
        return 1;
    }

    err = compact_ext_stats_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n",
            strerror(-err));
        goto cleanup;
    }

    link = bpf_map__attach_compact_ext_ops(skel->maps.stats_ops, node_id);
    if (!link) {
        err = -errno;
        fprintf(stderr, "Failed to attach compact_ext ops to node %d: %s\n",
            node_id, strerror(-err));
        goto cleanup;
    }

    printf("compact_ext stats policy attached to node %d, reporting every %ds\n",
           node_id, interval);
    printf("Press Ctrl-C to detach and exit.\n\n");

    while (running) {
        sleep(interval);
        if (running)
            print_stats(skel);
    }

    printf("\nDetaching...\n");
    bpf_link__destroy(link);
    print_stats(skel);

cleanup:
    compact_ext_stats_bpf__destroy(skel);
    return err ? 1 : 0;
}
