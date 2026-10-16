// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 reserve_blocks = 64;
const volatile __u64 demand_ms = 10000;
const volatile __u64 backoff_ms = 5000;

__u64 nr_run_low_memory;
__u64 nr_run_deferred;
__u64 nr_demand_passes;
__u64 nr_reserve_full;
__u64 nr_continued;
__u64 nr_evicted;
__u64 nr_not_copied;
__u64 nr_pinned_sources;
__u64 nr_pinned_targets;
__u64 nr_backoffs;

static bool demand_pass;
static u64 last_demand_ns;
static u64 backoff_until_ns;
static u64 pass_evicted;
static u64 pass_migrated;

static __always_inline bool pinned_block(int mt)
{
	return mt == MIGRATE_UNMOVABLE || mt == MIGRATE_RECLAIMABLE;
}

static __always_inline bool on_demand(enum compact_ext_trigger t, int order)
{
	return t == COMPACT_EXT_TRIGGER_DIRECT && order >= HPAGE_PMD_ORDER;
}

static __always_inline bool holds_reserve(struct zone *zone)
{
	return zone->present_pages >=
	       2 * ((u64)reserve_blocks << HPAGE_PMD_ORDER);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(contig_init, struct compact_ext_node_ctx *c)
{
	bpf_printk("compact_ext: contig policy attached to node %d", c->nid);
	return 0;
}

void BPF_STRUCT_OPS(contig_exit, struct compact_ext_node_ctx *c)
{
	bpf_printk("compact_ext: contig policy detached from node %d", c->nid);
}

enum compact_ext_run BPF_STRUCT_OPS(contig_should_compact_zone,
				    struct compact_ext_trigger_ctx *c)
{
	if (!on_demand(c->trigger, c->order) || c->watermark_ok)
		return c->default_result;
	last_demand_ns = bpf_ktime_get_ns();
	if (!c->suitable)
		COUNT(nr_run_low_memory);
	else if (c->is_deferred)
		COUNT(nr_run_deferred);
	return COMPACT_EXT_RUN_IGNORE_SKIP;
}

bool BPF_STRUCT_OPS(contig_should_proactive_compact,
		    struct compact_ext_proactive_ctx *c)
{
	u64 now = bpf_ktime_get_ns();

	demand_pass = last_demand_ns &&
		      now - last_demand_ns < demand_ms * NSEC_PER_MSEC &&
		      now >= backoff_until_ns;
	if (demand_pass) {
		COUNT(nr_demand_passes);
		pass_evicted = nr_evicted;
		pass_migrated = 0;
	}
	return demand_pass;
}

bool BPF_STRUCT_OPS(contig_select_migration_source,
		    struct compact_ext_source_ctx *c)
{
	if (c->trigger == COMPACT_EXT_TRIGGER_DIRECT &&
	    c->alloc_migratetype == c->pageblock_migratetype)
		return c->default_result;
	if (pinned_block(c->pageblock_migratetype)) {
		COUNT(nr_pinned_sources);
		return false;
	}
	return c->default_result;
}

bool BPF_STRUCT_OPS(contig_select_migration_target,
		    struct compact_ext_target_ctx *c)
{
	if (pinned_block(c->pageblock_migratetype)) {
		COUNT(nr_pinned_targets);
		return true;
	}
	return c->default_result;
}

bool BPF_STRUCT_OPS(contig_should_evict_folio,
		    struct compact_ext_folio_ctx *c)
{
	if (!on_demand(c->trigger, c->order) &&
	    !(c->trigger == COMPACT_EXT_TRIGGER_PROACTIVE && demand_pass))
		return false;
	COUNT(nr_evicted);
	return true;
}

bool BPF_STRUCT_OPS(contig_should_migrate_folio,
		    struct compact_ext_folio_ctx *c)
{
	if (on_demand(c->trigger, c->order)) {
		COUNT(nr_not_copied);
		return false;
	}
	return c->default_decision;
}

enum compact_ext_finish BPF_STRUCT_OPS(contig_compaction_finished,
				       struct compact_ext_finish_ctx *c)
{
	if (c->trigger != COMPACT_EXT_TRIGGER_PROACTIVE)
		return COMPACT_EXT_FINISH_DEFAULT;
	if (!holds_reserve(c->zone))
		return COMPACT_EXT_FINISH_SUCCESS;
	if (zone_free_blocks(c->zone, HPAGE_PMD_ORDER) >= reserve_blocks) {
		COUNT(nr_reserve_full);
		return COMPACT_EXT_FINISH_SUCCESS;
	}
	if (c->default_result == COMPACT_SUCCESS) {
		COUNT(nr_continued);
		return COMPACT_EXT_FINISH_CONTINUE;
	}
	return COMPACT_EXT_FINISH_DEFAULT;
}

void BPF_STRUCT_OPS(contig_compaction_completed,
		    struct compact_ext_result_ctx *c)
{
	if (c->trigger != COMPACT_EXT_TRIGGER_PROACTIVE || !demand_pass)
		return;
	pass_migrated += c->total_migrated;
	if (c->result != COMPACT_COMPLETE || !holds_reserve(c->zone) ||
	    pass_migrated || nr_evicted != pass_evicted)
		return;
	backoff_until_ns = bpf_ktime_get_ns() + backoff_ms * NSEC_PER_MSEC;
	COUNT(nr_backoffs);
}

SEC(".struct_ops.link")
struct compact_ext_ops contig_ops = {
	.init			= (void *)contig_init,
	.exit			= (void *)contig_exit,
	.should_compact_zone	= (void *)contig_should_compact_zone,
	.should_proactive_compact = (void *)contig_should_proactive_compact,
	.select_migration_source = (void *)contig_select_migration_source,
	.select_migration_target = (void *)contig_select_migration_target,
	.should_evict_folio	= (void *)contig_should_evict_folio,
	.should_migrate_folio	= (void *)contig_should_migrate_folio,
	.compaction_finished	= (void *)contig_compaction_finished,
	.compaction_completed	= (void *)contig_compaction_completed,
};
