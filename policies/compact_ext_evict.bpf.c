// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile bool background_only = false;
const volatile bool keep_referenced = false;

__u64 nr_dropped;
__u64 nr_kept;

bool BPF_STRUCT_OPS(evict_should_evict_folio, struct compact_ext_folio_ctx *c)
{
	if (background_only && !background(c->trigger))
		return false;
	if (c->is_active || (keep_referenced && c->is_referenced)) {
		COUNT(nr_kept);
		return false;
	}
	COUNT(nr_dropped);
	return true;
}

SEC(".struct_ops.link")
struct compact_ext_ops evict_ops = {
	.should_evict_folio	= (void *)evict_should_evict_folio,
};
