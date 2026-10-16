/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_COMPACT_EXT_H
#define _LINUX_COMPACT_EXT_H

#include <linux/errno.h>
#include <linux/mmzone.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

union bpf_attr;

enum compact_ext_trigger {
	COMPACT_EXT_TRIGGER_DIRECT = 0,
	COMPACT_EXT_TRIGGER_KCOMPACTD = 1,
	COMPACT_EXT_TRIGGER_PROACTIVE = 2,
	COMPACT_EXT_TRIGGER_MANUAL = 3,
};

enum compact_ext_run {
	COMPACT_EXT_RUN_NO = 0,
	COMPACT_EXT_RUN_YES = 1,
	COMPACT_EXT_RUN_IGNORE_SKIP = 3,
};

enum compact_ext_finish {
	COMPACT_EXT_FINISH_DEFAULT = 0,
	COMPACT_EXT_FINISH_CONTINUE = 1,
	COMPACT_EXT_FINISH_SUCCESS = 2,
	COMPACT_EXT_FINISH_ABORT = 3,
};

struct compact_ext_node_ctx {
	struct pglist_data *pgdat;
	int nid;
	unsigned long node_start_pfn;
	unsigned long node_spanned_pages;
	unsigned long node_present_pages;
	unsigned int pb_order;
	unsigned long nr_pageblocks;
};

struct compact_ext_trigger_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	int highest_zoneidx;
	int priority;
	int mode;
	unsigned long free_pages;
	unsigned long watermark;
	bool watermark_ok;
	bool suitable;
	int fragindex;
	bool is_deferred;
	unsigned int compact_defer_shift;
	unsigned int compact_considered;
	int compact_order_failed;
	bool default_result;
};

struct compact_ext_proactive_ctx {
	int nid;
	unsigned int node_score;
	unsigned int wmark_high;
	unsigned int wmark_low;
	unsigned int proactiveness;
	bool kswapd_running;
	bool default_result;
};

struct compact_ext_frag_ctx {
	struct zone *zone;
	int nid;
	int target_order;
	unsigned long free_pages;
	unsigned long zone_present;
	s64 default_score;
};

struct compact_ext_source_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	unsigned long pfn;
	int pageblock_migratetype;
	int alloc_migratetype;
	int mode;
	bool default_result;
};

struct compact_ext_target_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	unsigned long pfn;
	int pageblock_migratetype;
	int largest_buddy_order;
	bool default_result;
};

struct compact_ext_scanner_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	int mode;
	unsigned long zone_start_pfn;
	unsigned long zone_end_pfn;
	unsigned long cached_migrate_pfn;
	unsigned long cached_free_pfn;
	unsigned long migrate_pfn;
	unsigned long free_pfn;
	unsigned long min_pfn;
	unsigned long max_pfn;
	unsigned long default_pfn;
	unsigned short fast_search_fail;
};

struct compact_ext_folio_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	unsigned long pfn;
	int folio_order;
	int mode;
	bool is_lru;
	bool is_movable;
	bool is_anonymous;
	bool is_dirty;
	bool is_writeback;
	bool is_unevictable;
	bool is_pinned;
	bool is_mapped;
	bool is_active;
	bool is_referenced;
	bool default_decision;
};

struct compact_ext_finish_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	unsigned long free_pages;
	unsigned long nr_migrated;
	unsigned long nr_migrate_scanned;
	unsigned long nr_free_scanned;
	bool scanners_met;
	int default_result;
};

struct compact_ext_migration_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	int mode;
	unsigned long nr_attempted;
	unsigned long nr_succeeded;
	unsigned long nr_failed;
	int err;
	unsigned long total_migrated;
};

struct compact_ext_result_ctx {
	struct zone *zone;
	int nid;
	enum compact_ext_trigger trigger;
	int order;
	int result;
	int priority;
	int mode;
	unsigned long total_migrated;
	unsigned long total_migrate_scanned;
	unsigned long total_free_scanned;
};

struct compact_ext_ops {
	s32  (*init)(struct compact_ext_node_ctx *ctx);
	void (*exit)(struct compact_ext_node_ctx *ctx);

	enum compact_ext_run (*should_compact_zone)(struct compact_ext_trigger_ctx *ctx);
	bool (*should_proactive_compact)(struct compact_ext_proactive_ctx *ctx);
	s64  (*fragmentation_score)(struct compact_ext_frag_ctx *ctx);

	bool (*select_migration_source)(struct compact_ext_source_ctx *ctx);
	bool (*select_migration_target)(struct compact_ext_target_ctx *ctx);
	unsigned long (*find_migrate_pfn)(struct compact_ext_scanner_ctx *ctx);
	unsigned long (*find_free_pfn)(struct compact_ext_scanner_ctx *ctx);

	bool (*should_migrate_folio)(struct compact_ext_folio_ctx *ctx);
	bool (*should_evict_folio)(struct compact_ext_folio_ctx *ctx);

	enum compact_ext_finish (*compaction_finished)(struct compact_ext_finish_ctx *ctx);

	void (*migration_completed)(struct compact_ext_migration_ctx *ctx);
	void (*compaction_completed)(struct compact_ext_result_ctx *ctx);
};

#define COMPACT_EXT_MAX_MAPS		4
#define COMPACT_EXT_MAP_MAX_ENTRIES	(1U << 22)

struct compact_ext_map {
	struct rcu_head rcu;
	u32 nr_entries;
	s64 data[] __aligned(8);
};

struct compact_ext_ds_registry {
	struct compact_ext_map __rcu *maps[COMPACT_EXT_MAX_MAPS];
	bool init_in_progress;
};

#ifdef CONFIG_COMPACT_EXT

static inline struct compact_ext_ops *compact_ext_ops_rcu(pg_data_t *pgdat)
{
	return rcu_dereference(pgdat->compact_ext_ops);
}

int bpf_compact_ext_ops_link_create(union bpf_attr *attr);

int compact_ext_ds_registry_init(struct pglist_data *pgdat);
void compact_ext_ds_registry_reset(struct pglist_data *pgdat);

#else

static inline struct compact_ext_ops *compact_ext_ops_rcu(pg_data_t *pgdat)
{
	return NULL;
}

static inline int bpf_compact_ext_ops_link_create(union bpf_attr *attr)
{
	return -EOPNOTSUPP;
}

#endif

s64  bpf_compact_ext_zone_free_pages(struct zone *zone, int order);
int  bpf_compact_ext_pageblock_migratetype(struct zone *zone,
					    unsigned long pfn);
bool bpf_compact_ext_pageblock_skip(struct zone *zone, unsigned long pfn);
s64  bpf_compact_ext_extfrag_index(struct zone *zone, int order);
u32  bpf_compact_ext_pageblock_order(void);
s32  bpf_compact_ext_map_create(int nid, u32 nr_entries);
s64  bpf_compact_ext_map_size(int nid, s32 map_idx);
s64  bpf_compact_ext_map_get(int nid, s32 map_idx, u64 key);
int  bpf_compact_ext_map_set(int nid, s32 map_idx, u64 key, s64 value);
s64  bpf_compact_ext_map_add(int nid, s32 map_idx, u64 key, s64 delta);

#endif
