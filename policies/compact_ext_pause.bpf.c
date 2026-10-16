// SPDX-License-Identifier: GPL-2.0

#include "compact_ext_lib.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cext_pause SEC(".maps");

__u64 nr_refused;
__u64 nr_stopped;

static __always_inline bool paused(void)
{
	__u32 key = 0;
	__u32 *val = bpf_map_lookup_elem(&cext_pause, &key);

	return val && *val;
}

enum compact_ext_run BPF_STRUCT_OPS(pause_should_compact_zone,
				    struct compact_ext_trigger_ctx *c)
{
	if (background(c->trigger) && c->default_result && paused()) {
		COUNT(nr_refused);
		return COMPACT_EXT_RUN_NO;
	}
	return c->default_result;
}

bool BPF_STRUCT_OPS(pause_should_proactive_compact,
		    struct compact_ext_proactive_ctx *c)
{
	if (c->default_result && paused()) {
		COUNT(nr_refused);
		return false;
	}
	return c->default_result;
}

enum compact_ext_finish BPF_STRUCT_OPS(pause_compaction_finished,
				       struct compact_ext_finish_ctx *c)
{
	if (c->trigger != COMPACT_EXT_TRIGGER_PROACTIVE ||
	    c->default_result != COMPACT_CONTINUE || !paused())
		return COMPACT_EXT_FINISH_DEFAULT;
	COUNT(nr_stopped);
	return COMPACT_EXT_FINISH_ABORT;
}

SEC(".struct_ops.link")
struct compact_ext_ops pause_ops = {
	.should_compact_zone		= (void *)pause_should_compact_zone,
	.should_proactive_compact	= (void *)pause_should_proactive_compact,
	.compaction_finished		= (void *)pause_compaction_finished,
};
