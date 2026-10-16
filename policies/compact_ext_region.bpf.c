// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define PAGES_PER_MB	256

const volatile __u64 start_mb = 4096;
const volatile __u64 size_mb = 256;

__u64 nr_jumps;
__u64 nr_blocks_emptied;
__u64 nr_targets_refused;

static __always_inline unsigned long pageblock_pages(void)
{
	return 1UL << bpf_compact_ext_pageblock_order();
}

static __always_inline unsigned long range_start(void)
{
	return (start_mb * PAGES_PER_MB) & ~(pageblock_pages() - 1);
}

static __always_inline unsigned long range_end(void)
{
	unsigned long pb = pageblock_pages();

	return ((start_mb + size_mb) * PAGES_PER_MB + pb - 1) & ~(pb - 1);
}

static __always_inline bool in_range(unsigned long pfn)
{
	return pfn >= range_start() && pfn < range_end();
}

unsigned long BPF_STRUCT_OPS(region_find_migrate_pfn,
			     struct compact_ext_scanner_ctx *c)
{
	unsigned long start = range_start();

	if (c->trigger != COMPACT_EXT_TRIGGER_MANUAL ||
	    c->default_pfn >= start || start > c->max_pfn)
		return c->default_pfn;
	COUNT(nr_jumps);
	return start;
}

bool BPF_STRUCT_OPS(region_select_migration_source,
		    struct compact_ext_source_ctx *c)
{
	if (c->trigger != COMPACT_EXT_TRIGGER_MANUAL)
		return c->default_result;
	if (!in_range(c->pfn))
		return false;
	COUNT(nr_blocks_emptied);
	return true;
}

bool BPF_STRUCT_OPS(region_select_migration_target,
		    struct compact_ext_target_ctx *c)
{
	if (!in_range(c->pfn))
		return c->default_result;
	COUNT(nr_targets_refused);
	return false;
}

SEC(".struct_ops.link")
struct compact_ext_ops region_ops = {
	.find_migrate_pfn		= (void *)region_find_migrate_pfn,
	.select_migration_source	= (void *)region_select_migration_source,
	.select_migration_target	= (void *)region_select_migration_target,
};
