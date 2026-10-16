// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "compact_ext: " fmt

#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/compact_ext.h>
#include <linux/compaction.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/memory_hotplug.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/nodemask.h>
#include <linux/nospec.h>
#include <linux/overflow.h>
#include <linux/pageblock-flags.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

int compact_ext_ds_registry_init(struct pglist_data *pgdat)
{
	struct compact_ext_ds_registry *registry;

	if (pgdat->compact_ext_registry)
		return 0;

	registry = kzalloc(sizeof(*registry), GFP_KERNEL);
	if (!registry)
		return -ENOMEM;

	smp_store_release(&pgdat->compact_ext_registry, registry);
	return 0;
}

void compact_ext_ds_registry_reset(struct pglist_data *pgdat)
{
	struct compact_ext_ds_registry *registry = pgdat->compact_ext_registry;
	struct compact_ext_map *m;
	int i;

	if (!registry)
		return;

	for (i = 0; i < COMPACT_EXT_MAX_MAPS; i++) {
		m = rcu_dereference_protected(registry->maps[i], true);
		if (!m)
			continue;
		RCU_INIT_POINTER(registry->maps[i], NULL);
		kvfree_rcu(m, rcu);
	}
	registry->init_in_progress = false;
}

static struct compact_ext_ds_registry *compact_ext_registry(int nid)
{
	pg_data_t *pgdat;

	if (nid < 0 || nid >= MAX_NUMNODES)
		return NULL;
	nid = array_index_nospec(nid, MAX_NUMNODES);
	if (!node_online(nid))
		return NULL;

	pgdat = NODE_DATA(nid);
	if (!pgdat)
		return NULL;

	return READ_ONCE(pgdat->compact_ext_registry);
}

static struct compact_ext_map *compact_ext_map_lookup(int nid, s32 map_idx)
{
	struct compact_ext_ds_registry *registry = compact_ext_registry(nid);
	struct compact_ext_map *m;

	if (!registry || map_idx < 0 || map_idx >= COMPACT_EXT_MAX_MAPS)
		return ERR_PTR(-EINVAL);
	map_idx = array_index_nospec(map_idx, COMPACT_EXT_MAX_MAPS);

	m = rcu_dereference(registry->maps[map_idx]);
	return m ?: ERR_PTR(-ENOENT);
}

static s64 *compact_ext_map_elem(int nid, s32 map_idx, u64 key)
{
	struct compact_ext_map *m = compact_ext_map_lookup(nid, map_idx);

	if (IS_ERR(m))
		return ERR_CAST(m);
	if (key >= m->nr_entries)
		return ERR_PTR(-EINVAL);

	return &m->data[array_index_nospec((u32)key, m->nr_entries)];
}

__bpf_kfunc s64 bpf_compact_ext_zone_free_pages(struct zone *zone, int order)
{
	if (!zone)
		return -1;

	if (order < 0 || order > MAX_ORDER)
		return -1;
	order = array_index_nospec(order, MAX_ORDER + 1);

	return READ_ONCE(zone->free_area[order].nr_free);
}

__bpf_kfunc int bpf_compact_ext_pageblock_migratetype(struct zone *zone,
						       unsigned long pfn)
{
	struct page *page;

	if (!zone)
		return -1;

	if (pfn < zone->zone_start_pfn || pfn >= zone_end_pfn(zone))
		return -1;

	page = pfn_to_online_page(pfn);
	if (!page)
		return -1;

	return get_pageblock_migratetype(page);
}

__bpf_kfunc bool bpf_compact_ext_pageblock_skip(struct zone *zone,
						 unsigned long pfn)
{
	struct page *page;

	if (!zone)
		return true;

	if (pfn < zone->zone_start_pfn || pfn >= zone_end_pfn(zone))
		return true;

	page = pfn_to_online_page(pfn);
	if (!page)
		return true;

	return get_pageblock_skip(page);
}

__bpf_kfunc s64 bpf_compact_ext_extfrag_index(struct zone *zone, int order)
{
	if (!zone)
		return -1;

	if (order < 0 || order > MAX_ORDER)
		return -1;

	return extfrag_for_order(zone, order);
}

__bpf_kfunc u32 bpf_compact_ext_pageblock_order(void)
{
	return pageblock_order;
}

__bpf_kfunc s32 bpf_compact_ext_map_create(int nid, u32 nr_entries)
{
	struct compact_ext_ds_registry *registry;
	struct compact_ext_map *m;
	int i;

	registry = compact_ext_registry(nid);
	if (!registry)
		return -EINVAL;

	if (!registry->init_in_progress)
		return -EPERM;

	if (!nr_entries || nr_entries > COMPACT_EXT_MAP_MAX_ENTRIES)
		return -EINVAL;

	m = kvzalloc(struct_size(m, data, nr_entries), GFP_KERNEL_ACCOUNT);
	if (!m)
		return -ENOMEM;
	m->nr_entries = nr_entries;

	for (i = 0; i < COMPACT_EXT_MAX_MAPS; i++) {
		if (!rcu_access_pointer(registry->maps[i])) {
			rcu_assign_pointer(registry->maps[i], m);
			return i;
		}
	}

	kvfree(m);
	return -ENOSPC;
}

__bpf_kfunc s64 bpf_compact_ext_map_size(int nid, s32 map_idx)
{
	struct compact_ext_map *m;
	s64 ret;

	rcu_read_lock();
	m = compact_ext_map_lookup(nid, map_idx);
	if (IS_ERR(m))
		ret = PTR_ERR(m);
	else
		ret = m->nr_entries;
	rcu_read_unlock();

	return ret;
}

__bpf_kfunc s64 bpf_compact_ext_map_get(int nid, s32 map_idx, u64 key)
{
	s64 *elem, val = 0;

	rcu_read_lock();
	elem = compact_ext_map_elem(nid, map_idx, key);
	if (!IS_ERR(elem))
		val = READ_ONCE(*elem);
	rcu_read_unlock();

	return val;
}

__bpf_kfunc int bpf_compact_ext_map_set(int nid, s32 map_idx, u64 key,
					s64 value)
{
	s64 *elem;

	rcu_read_lock();
	elem = compact_ext_map_elem(nid, map_idx, key);
	if (!IS_ERR(elem))
		WRITE_ONCE(*elem, value);
	rcu_read_unlock();

	return PTR_ERR_OR_ZERO(elem);
}

__bpf_kfunc s64 bpf_compact_ext_map_add(int nid, s32 map_idx, u64 key,
					s64 delta)
{
	s64 *elem, val = 0;

	rcu_read_lock();
	elem = compact_ext_map_elem(nid, map_idx, key);
	if (!IS_ERR(elem))
		val = atomic64_add_return(delta, (atomic64_t *)elem);
	rcu_read_unlock();

	return val;
}

BTF_SET8_START(compact_ext_kfunc_ids)
BTF_ID_FLAGS(func, bpf_compact_ext_zone_free_pages)
BTF_ID_FLAGS(func, bpf_compact_ext_pageblock_migratetype)
BTF_ID_FLAGS(func, bpf_compact_ext_pageblock_skip)
BTF_ID_FLAGS(func, bpf_compact_ext_extfrag_index)
BTF_ID_FLAGS(func, bpf_compact_ext_pageblock_order)
BTF_ID_FLAGS(func, bpf_compact_ext_map_create, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_compact_ext_map_size)
BTF_ID_FLAGS(func, bpf_compact_ext_map_get)
BTF_ID_FLAGS(func, bpf_compact_ext_map_set)
BTF_ID_FLAGS(func, bpf_compact_ext_map_add)
BTF_SET8_END(compact_ext_kfunc_ids)

BTF_ID_LIST_SINGLE(compact_ext_ops_btf_ids, struct, compact_ext_ops)

static int compact_ext_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&compact_ext_kfunc_ids, kfunc_id))
		return 0;

	if (prog->type == BPF_PROG_TYPE_STRUCT_OPS &&
	    prog->aux->attach_btf_id == compact_ext_ops_btf_ids[0])
		return 0;

	return -EACCES;
}

static const struct btf_kfunc_id_set compact_ext_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &compact_ext_kfunc_ids,
	.filter = compact_ext_kfunc_filter,
};

static int __init compact_ext_ds_init(void)
{
	int nid, ret;

	for_each_online_node(nid) {
		if (compact_ext_ds_registry_init(NODE_DATA(nid)))
			pr_warn("node %d: failed to allocate the map registry\n",
				nid);
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&compact_ext_kfunc_set);
	if (ret)
		pr_err("failed to register kfunc set (%d)\n", ret);

	return ret;
}
late_initcall(compact_ext_ds_init);
