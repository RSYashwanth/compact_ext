// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

__u64 nr_hot_skipped;
__u64 nr_cold_moved;

bool BPF_STRUCT_OPS(coldskip_should_migrate_folio,
		    struct compact_ext_folio_ctx *c)
{
	if (!background(c->trigger) || !c->default_decision)
		return c->default_decision;
	if (c->is_lru && (c->is_active || c->is_referenced)) {
		COUNT(nr_hot_skipped);
		return false;
	}
	COUNT(nr_cold_moved);
	return true;
}

SEC(".struct_ops.link")
struct compact_ext_ops coldskip_ops = {
	.should_migrate_folio	= (void *)coldskip_should_migrate_folio,
};
