/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __COMPACT_EXT_LIB_BPF_H
#define __COMPACT_EXT_LIB_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name)              \
	BPF_PROG(name, ##args)

#define COMPACT_EXT_MAX_MAPS		4
#define COMPACT_EXT_MAP_MAX_ENTRIES	(1U << 22)

#define HPAGE_PMD_ORDER			9
#define PAGE_ALLOC_COSTLY_ORDER		3
#define MAX_ORDER			10
#define NSEC_PER_MSEC			1000000ULL

extern s64 bpf_compact_ext_zone_free_pages(struct zone *zone,
					    int order) __ksym;
extern int bpf_compact_ext_pageblock_migratetype(struct zone *zone,
						  unsigned long pfn) __ksym;
extern bool bpf_compact_ext_pageblock_skip(struct zone *zone,
					    unsigned long pfn) __ksym;
extern s64 bpf_compact_ext_extfrag_index(struct zone *zone,
					  int order) __ksym;
extern u32 bpf_compact_ext_pageblock_order(void) __ksym;

extern s32 bpf_compact_ext_map_create(int nid, u32 nr_entries) __ksym;
extern s64 bpf_compact_ext_map_size(int nid, s32 map_idx) __ksym;
extern s64 bpf_compact_ext_map_get(int nid, s32 map_idx, u64 key) __ksym;
extern int bpf_compact_ext_map_set(int nid, s32 map_idx, u64 key,
				    s64 value) __ksym;
extern s64 bpf_compact_ext_map_add(int nid, s32 map_idx, u64 key,
				    s64 delta) __ksym;

#define COUNT(counter)	__sync_fetch_and_add(&(counter), 1)

static __always_inline s64 zone_free_blocks(struct zone *zone, int order)
{
	s64 total = 0;
	int o;

	if (order < 0 || order > MAX_ORDER)
		return 0;
	for (o = order; o <= MAX_ORDER; o++) {
		s64 n = bpf_compact_ext_zone_free_pages(zone, o);

		if (n > 0)
			total += n << (o - order);
	}
	return total;
}

static __always_inline bool background(enum compact_ext_trigger trigger)
{
	return trigger == COMPACT_EXT_TRIGGER_KCOMPACTD ||
	       trigger == COMPACT_EXT_TRIGGER_PROACTIVE;
}

#endif
