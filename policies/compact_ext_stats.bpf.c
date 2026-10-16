// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"
#include "compact_ext_stats.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_HOOKS);
	__type(key, __u32);
	__type(value, __u64);
} hook_calls SEC(".maps");

int node_id;
__u64 node_start_pfn;
__u32 pb_order;
__u32 kfunc_pb_order;
__u64 nr_pageblocks;
__u32 map_entries;
__s32 map_idx;

__u64 trigger_calls[NR_TRIGGERS];
int last_trigger;
int last_order;
int last_default;
__s64 last_free_blocks;

__u32 last_node_score;

__s64 last_frag_score;
__s64 last_extfrag_index;

__u64 nr_source_skip;
__u64 last_source_key;

int last_target_migratetype;

__u64 nr_folio_default_no;

__u64 total_migrated;
__u64 total_migrate_failed;

int last_result;
__s64 map_size;
__s64 last_source_count;

static __always_inline void count(enum stats_hook hook)
{
	__u32 key = hook;
	__u64 *cnt;

	cnt = bpf_map_lookup_elem(&hook_calls, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(stats_init, struct compact_ext_node_ctx *node_ctx)
{
	__u64 nr = node_ctx->nr_pageblocks;

	count(HOOK_INIT);
	node_id = node_ctx->nid;
	node_start_pfn = node_ctx->node_start_pfn;
	pb_order = node_ctx->pb_order;
	kfunc_pb_order = bpf_compact_ext_pageblock_order();
	nr_pageblocks = nr;

	if (nr > COMPACT_EXT_MAP_MAX_ENTRIES)
		nr = COMPACT_EXT_MAP_MAX_ENTRIES;
	map_entries = nr;

	map_idx = bpf_compact_ext_map_create(node_id, nr);
	return 0;
}

void BPF_STRUCT_OPS(stats_exit, struct compact_ext_node_ctx *node_ctx)
{
	count(HOOK_EXIT);
}

bool BPF_STRUCT_OPS(stats_should_compact_zone,
		    struct compact_ext_trigger_ctx *trigger_ctx)
{
	__u32 trigger = trigger_ctx->trigger;
	int order = trigger_ctx->order;

	count(HOOK_SHOULD_COMPACT_ZONE);
	if (trigger < NR_TRIGGERS)
		__sync_fetch_and_add(&trigger_calls[trigger], 1);
	last_trigger = trigger;
	last_order = order;
	last_default = trigger_ctx->default_result;
	if (order >= 0)
		last_free_blocks =
			bpf_compact_ext_zone_free_pages(trigger_ctx->zone, order);
	return trigger_ctx->default_result;
}

bool BPF_STRUCT_OPS(stats_should_proactive_compact,
		    struct compact_ext_proactive_ctx *proactive_ctx)
{
	count(HOOK_SHOULD_PROACTIVE_COMPACT);
	last_node_score = proactive_ctx->node_score;
	return proactive_ctx->default_result;
}

s64 BPF_STRUCT_OPS(stats_fragmentation_score,
		   struct compact_ext_frag_ctx *frag_ctx)
{
	count(HOOK_FRAGMENTATION_SCORE);
	last_frag_score = frag_ctx->default_score;
	last_extfrag_index =
		bpf_compact_ext_extfrag_index(frag_ctx->zone,
					      frag_ctx->target_order);
	return frag_ctx->default_score;
}

bool BPF_STRUCT_OPS(stats_select_migration_source,
		    struct compact_ext_source_ctx *source_ctx)
{
	unsigned long pfn = source_ctx->pfn;
	__s32 idx = map_idx;
	__u64 key;

	count(HOOK_SELECT_MIGRATION_SOURCE);
	if (bpf_compact_ext_pageblock_skip(source_ctx->zone, pfn))
		__sync_fetch_and_add(&nr_source_skip, 1);

	if (idx >= 0 && pfn >= node_start_pfn) {
		key = (pfn - node_start_pfn) >> pb_order;
		if (key < map_entries) {
			bpf_compact_ext_map_add(source_ctx->nid, idx, key, 1);
			last_source_key = key;
		}
	}
	return source_ctx->default_result;
}

bool BPF_STRUCT_OPS(stats_select_migration_target,
		    struct compact_ext_target_ctx *target_ctx)
{
	count(HOOK_SELECT_MIGRATION_TARGET);
	last_target_migratetype =
		bpf_compact_ext_pageblock_migratetype(target_ctx->zone,
						      target_ctx->pfn);
	return target_ctx->default_result;
}

unsigned long BPF_STRUCT_OPS(stats_find_migrate_pfn,
			     struct compact_ext_scanner_ctx *scanner_ctx)
{
	count(HOOK_FIND_MIGRATE_PFN);
	return scanner_ctx->default_pfn;
}

unsigned long BPF_STRUCT_OPS(stats_find_free_pfn,
			     struct compact_ext_scanner_ctx *scanner_ctx)
{
	count(HOOK_FIND_FREE_PFN);
	return scanner_ctx->default_pfn;
}

bool BPF_STRUCT_OPS(stats_should_migrate_folio,
		    struct compact_ext_folio_ctx *folio_ctx)
{
	count(HOOK_SHOULD_MIGRATE_FOLIO);
	if (!folio_ctx->default_decision)
		__sync_fetch_and_add(&nr_folio_default_no, 1);
	return folio_ctx->default_decision;
}

bool BPF_STRUCT_OPS(stats_should_evict_folio,
		    struct compact_ext_folio_ctx *folio_ctx)
{
	count(HOOK_SHOULD_EVICT_FOLIO);
	return false;
}

enum compact_ext_finish BPF_STRUCT_OPS(stats_compaction_finished,
				       struct compact_ext_finish_ctx *finish_ctx)
{
	count(HOOK_COMPACTION_FINISHED);
	return COMPACT_EXT_FINISH_DEFAULT;
}

void BPF_STRUCT_OPS(stats_migration_completed,
		    struct compact_ext_migration_ctx *migration_ctx)
{
	count(HOOK_MIGRATION_COMPLETED);
	__sync_fetch_and_add(&total_migrated, migration_ctx->nr_succeeded);
	__sync_fetch_and_add(&total_migrate_failed, migration_ctx->nr_failed);
}

void BPF_STRUCT_OPS(stats_compaction_completed,
		    struct compact_ext_result_ctx *result_ctx)
{
	__s32 idx = map_idx;

	count(HOOK_COMPACTION_COMPLETED);
	last_result = result_ctx->result;
	if (idx >= 0) {
		map_size = bpf_compact_ext_map_size(result_ctx->nid, idx);
		last_source_count =
			bpf_compact_ext_map_get(result_ctx->nid, idx,
						last_source_key);
	}
}

SEC(".struct_ops.link")
struct compact_ext_ops stats_ops = {
	.init = (void *)stats_init,
	.exit = (void *)stats_exit,
	.should_compact_zone = (void *)stats_should_compact_zone,
	.should_proactive_compact = (void *)stats_should_proactive_compact,
	.fragmentation_score = (void *)stats_fragmentation_score,
	.select_migration_source = (void *)stats_select_migration_source,
	.select_migration_target = (void *)stats_select_migration_target,
	.find_migrate_pfn = (void *)stats_find_migrate_pfn,
	.find_free_pfn = (void *)stats_find_free_pfn,
	.should_migrate_folio = (void *)stats_should_migrate_folio,
	.should_evict_folio = (void *)stats_should_evict_folio,
	.compaction_finished = (void *)stats_compaction_finished,
	.migration_completed = (void *)stats_migration_completed,
	.compaction_completed = (void *)stats_compaction_completed,
};
