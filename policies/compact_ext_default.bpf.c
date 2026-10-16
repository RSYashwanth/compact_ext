// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

s32 BPF_STRUCT_OPS_SLEEPABLE(default_init, struct compact_ext_node_ctx *node_ctx)
{
	bpf_printk("compact_ext: default policy initialized for node %d",
		   node_ctx->nid);
	return 0;
}

void BPF_STRUCT_OPS(default_exit, struct compact_ext_node_ctx *node_ctx)
{
	bpf_printk("compact_ext: default policy detached from node %d",
		   node_ctx->nid);
}

bool BPF_STRUCT_OPS(default_should_compact_zone,
		    struct compact_ext_trigger_ctx *trigger_ctx)
{
	return trigger_ctx->default_result;
}

bool BPF_STRUCT_OPS(default_should_proactive_compact,
		    struct compact_ext_proactive_ctx *proactive_ctx)
{
	return proactive_ctx->default_result;
}

s64 BPF_STRUCT_OPS(default_fragmentation_score,
		   struct compact_ext_frag_ctx *frag_ctx)
{
	return frag_ctx->default_score;
}

bool BPF_STRUCT_OPS(default_select_migration_source,
		    struct compact_ext_source_ctx *source_ctx)
{
	return source_ctx->default_result;
}

bool BPF_STRUCT_OPS(default_select_migration_target,
		    struct compact_ext_target_ctx *target_ctx)
{
	return target_ctx->default_result;
}

unsigned long BPF_STRUCT_OPS(default_find_migrate_pfn,
			     struct compact_ext_scanner_ctx *scanner_ctx)
{
	return scanner_ctx->default_pfn;
}

unsigned long BPF_STRUCT_OPS(default_find_free_pfn,
			     struct compact_ext_scanner_ctx *scanner_ctx)
{
	return scanner_ctx->default_pfn;
}

bool BPF_STRUCT_OPS(default_should_migrate_folio,
		    struct compact_ext_folio_ctx *folio_ctx)
{
	return folio_ctx->default_decision;
}

bool BPF_STRUCT_OPS(default_should_evict_folio,
		    struct compact_ext_folio_ctx *folio_ctx)
{
	return false;
}

enum compact_ext_finish BPF_STRUCT_OPS(default_compaction_finished,
				       struct compact_ext_finish_ctx *finish_ctx)
{
	return COMPACT_EXT_FINISH_DEFAULT;
}

void BPF_STRUCT_OPS(default_migration_completed,
		    struct compact_ext_migration_ctx *migration_ctx)
{
}

void BPF_STRUCT_OPS(default_compaction_completed,
		    struct compact_ext_result_ctx *result_ctx)
{
}

SEC(".struct_ops.link")
struct compact_ext_ops default_ops = {
	.init = (void *)default_init,
	.exit = (void *)default_exit,
	.should_compact_zone = (void *)default_should_compact_zone,
	.should_proactive_compact = (void *)default_should_proactive_compact,
	.fragmentation_score = (void *)default_fragmentation_score,
	.select_migration_source = (void *)default_select_migration_source,
	.select_migration_target = (void *)default_select_migration_target,
	.find_migrate_pfn = (void *)default_find_migrate_pfn,
	.find_free_pfn = (void *)default_find_free_pfn,
	.should_migrate_folio = (void *)default_should_migrate_folio,
	.should_evict_folio = (void *)default_should_evict_folio,
	.compaction_finished = (void *)default_compaction_finished,
	.migration_completed = (void *)default_migration_completed,
	.compaction_completed = (void *)default_compaction_completed,
};
