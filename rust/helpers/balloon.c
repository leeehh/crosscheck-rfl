// SPDX-License-Identifier: GPL-2.0

/*
 * Helpers for the Rust memory-balloon abstractions.
 *
 * Keep policy and virtio protocol decisions in the Rust driver.  These
 * helpers only bridge C-only MM APIs, callback registrations, and inline
 * page-list operations.
 */

#include <linux/balloon_compaction.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/page_reporting.h>
#include <linux/poison.h>
#include <linux/shrinker.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/virtio_balloon.h>
#include <linux/vmstat.h>

#if IS_ENABLED(CONFIG_MEMORY_BALLOON)

struct rust_balloon_pages {
	struct balloon_dev_info info;
	void *context;
	int (*migrate)(void *context, void *pages, void *new_page,
		       void *old_page);
	bool deflate_on_oom;
};

#if IS_ENABLED(CONFIG_BALLOON_COMPACTION)
static int rust_balloon_migrate_page(struct balloon_dev_info *info,
				     struct page *new_page,
				     struct page *old_page,
				     enum migrate_mode mode)
{
	struct rust_balloon_pages *pages =
		container_of(info, struct rust_balloon_pages, info);

	(void)mode;
	if (!pages->migrate)
		return -EAGAIN;

	return pages->migrate(pages->context, pages, new_page, old_page);
}
#endif

void *rust_helper_balloon_pages_alloc(bool deflate_on_oom)
{
	struct rust_balloon_pages *pages;

	pages = kzalloc(sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return NULL;

	balloon_devinfo_init(&pages->info);
	pages->deflate_on_oom = deflate_on_oom;
#if IS_ENABLED(CONFIG_BALLOON_COMPACTION)
	pages->info.migratepage = rust_balloon_migrate_page;
#endif
	return pages;
}

void rust_helper_balloon_pages_set_migration(
	void *raw_pages, void *context,
	int (*migrate)(void *context, void *pages, void *new_page,
		       void *old_page))
{
	struct rust_balloon_pages *pages = raw_pages;

	pages->context = context;
	pages->migrate = migrate;
}

void rust_helper_balloon_pages_free(void *raw_pages)
{
	struct rust_balloon_pages *pages = raw_pages;
	struct page *page;

	if (!pages)
		return;

	while ((page = balloon_page_dequeue(&pages->info))) {
		if (!pages->deflate_on_oom)
			adjust_managed_page_count(page, 1);
		put_page(page);
	}
	kfree(pages);
}

void *rust_helper_balloon_page_alloc(void)
{
	return balloon_page_alloc();
}

void rust_helper_balloon_page_enqueue(void *raw_pages, void *raw_page)
{
	struct rust_balloon_pages *pages = raw_pages;
	struct page *page = raw_page;

	balloon_page_enqueue(&pages->info, page);
}

void *rust_helper_balloon_page_dequeue(void *raw_pages)
{
	struct rust_balloon_pages *pages = raw_pages;

	return balloon_page_dequeue(&pages->info);
}

unsigned long rust_helper_balloon_page_pfn(void *raw_page)
{
	return page_to_pfn((struct page *)raw_page);
}

void rust_helper_balloon_page_adjust_managed(void *raw_page, long delta)
{
	adjust_managed_page_count(raw_page, delta);
}

void rust_helper_balloon_page_put(void *raw_page)
{
	put_page(raw_page);
}

#if IS_ENABLED(CONFIG_BALLOON_COMPACTION)
void rust_helper_balloon_migration_prepare(void *raw_pages,
					   void *raw_new_page,
					   void *raw_old_page)
{
	struct rust_balloon_pages *pages = raw_pages;
	struct page *new_page = raw_new_page;
	struct page *old_page = raw_old_page;
	unsigned long flags;

	get_page(new_page);
	if (!pages->deflate_on_oom &&
	    page_zone(old_page) != page_zone(new_page)) {
		adjust_managed_page_count(old_page, 1);
		adjust_managed_page_count(new_page, -1);
	}

	spin_lock_irqsave(&pages->info.pages_lock, flags);
	balloon_page_insert(&pages->info, new_page);
	pages->info.isolated_pages--;
	__count_vm_event(BALLOON_MIGRATE);
	spin_unlock_irqrestore(&pages->info.pages_lock, flags);
}

void rust_helper_balloon_migration_finish(void *raw_old_page)
{
	struct page *old_page = raw_old_page;

	balloon_page_finalize(old_page);
	put_page(old_page);
}
#endif

#endif /* CONFIG_MEMORY_BALLOON */

struct rust_balloon_free_pool {
	spinlock_t lock;
	struct list_head pages;
	unsigned long blocks;
};

void *rust_helper_balloon_free_pool_alloc(void)
{
	struct rust_balloon_free_pool *pool;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;
	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->pages);
	return pool;
}

unsigned long rust_helper_balloon_hint_block_pages(void)
{
	return 1UL << MAX_PAGE_ORDER;
}

unsigned long rust_helper_balloon_hint_block_bytes(void)
{
	return PAGE_SIZE << MAX_PAGE_ORDER;
}

void *rust_helper_balloon_hint_block_alloc(void)
{
	gfp_t flags = __GFP_NORETRY | __GFP_NOWARN | __GFP_NOMEMALLOC;

	return alloc_pages(flags, MAX_PAGE_ORDER);
}

void *rust_helper_balloon_hint_block_address(void *raw_page)
{
	return page_address(raw_page);
}

void rust_helper_balloon_hint_block_free(void *raw_page)
{
	__free_pages(raw_page, MAX_PAGE_ORDER);
}

void rust_helper_balloon_free_pool_store(void *raw_pool, void *raw_page)
{
	struct rust_balloon_free_pool *pool = raw_pool;
	struct page *page = raw_page;
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	balloon_page_push(&pool->pages, page);
	pool->blocks++;
	spin_unlock_irqrestore(&pool->lock, flags);
}

unsigned long rust_helper_balloon_free_pool_return(void *raw_pool,
						   unsigned long requested)
{
	struct rust_balloon_free_pool *pool = raw_pool;
	unsigned long flags;
	unsigned long returned;

	spin_lock_irqsave(&pool->lock, flags);
	for (returned = 0; returned < requested; returned++) {
		struct page *page = balloon_page_pop(&pool->pages);

		if (!page)
			break;
		__free_pages(page, MAX_PAGE_ORDER);
	}
	pool->blocks -= returned;
	spin_unlock_irqrestore(&pool->lock, flags);
	return returned;
}

unsigned long rust_helper_balloon_free_pool_count(void *raw_pool)
{
	struct rust_balloon_free_pool *pool = raw_pool;
	unsigned long flags;
	unsigned long blocks;

	spin_lock_irqsave(&pool->lock, flags);
	blocks = pool->blocks;
	spin_unlock_irqrestore(&pool->lock, flags);
	return blocks;
}

void rust_helper_balloon_free_pool_free(void *raw_pool)
{
	struct rust_balloon_free_pool *pool = raw_pool;

	if (!pool)
		return;
	rust_helper_balloon_free_pool_return(pool, ULONG_MAX);
	kfree(pool);
}

struct rust_balloon_stat_value {
	u16 tag;
	u64 value;
};

static void rust_balloon_add_stat(struct rust_balloon_stat_value *values,
				  size_t capacity, size_t *count,
				  u16 tag, u64 value)
{
	if (*count >= capacity)
		return;
	values[*count].tag = tag;
	values[*count].value = value;
	(*count)++;
}

size_t rust_helper_balloon_collect_stats(void *raw_values, size_t capacity)
{
	struct rust_balloon_stat_value *values = raw_values;
	struct sysinfo info;
	unsigned long events[NR_VM_EVENT_ITEMS];
	unsigned long stall = 0;
	unsigned long caches;
	long available;
	size_t count = 0;
	unsigned int zid;

#ifdef CONFIG_VM_EVENT_COUNTERS
	all_vm_events(events);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_SWAP_IN,
			      (u64)events[PSWPIN] << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_SWAP_OUT,
			      (u64)events[PSWPOUT] << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_MAJFLT, events[PGMAJFAULT]);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_MINFLT, events[PGFAULT]);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_OOM_KILL, events[OOM_KILL]);
	for (zid = 0; zid < MAX_NR_ZONES; zid++)
		stall += events[ALLOCSTALL_NORMAL - ZONE_NORMAL + zid];
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_ALLOC_STALL, stall);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_ASYNC_SCAN,
			      (u64)events[PGSCAN_KSWAPD] << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_DIRECT_SCAN,
			      (u64)events[PGSCAN_DIRECT] << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_ASYNC_RECLAIM,
			      (u64)events[PGSTEAL_KSWAPD] << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_DIRECT_RECLAIM,
			      (u64)events[PGSTEAL_DIRECT] << PAGE_SHIFT);
#ifdef CONFIG_HUGETLB_PAGE
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_HTLB_PGALLOC,
			      events[HTLB_BUDDY_PGALLOC]);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_HTLB_PGFAIL,
			      events[HTLB_BUDDY_PGALLOC_FAIL]);
#endif
#endif

	si_meminfo(&info);
	available = si_mem_available();
	caches = global_node_page_state(NR_FILE_PAGES);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_MEMFREE,
			      (u64)info.freeram << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_MEMTOT,
			      (u64)info.totalram << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_AVAIL,
			      (u64)available << PAGE_SHIFT);
	rust_balloon_add_stat(values, capacity, &count,
			      VIRTIO_BALLOON_S_CACHES,
			      (u64)caches << PAGE_SHIFT);
	return count;
}

bool rust_helper_balloon_can_report_free_pages(void)
{
	return want_init_on_free() || page_poisoning_enabled_static();
}

u32 rust_helper_balloon_page_poison_value(void)
{
	u32 poison = 0;

	if (!want_init_on_free())
		memset(&poison, PAGE_POISON, sizeof(poison));
	return poison;
}

struct rust_balloon_shrinker {
	struct shrinker *shrinker;
	void *context;
	unsigned long (*count)(void *context);
	unsigned long (*scan)(void *context, unsigned long nr_to_scan);
};

static unsigned long rust_balloon_shrinker_count(struct shrinker *shrinker,
						  struct shrink_control *sc)
{
	struct rust_balloon_shrinker *state = shrinker->private_data;

	(void)sc;
	return state->count(state->context);
}

static unsigned long rust_balloon_shrinker_scan(struct shrinker *shrinker,
						 struct shrink_control *sc)
{
	struct rust_balloon_shrinker *state = shrinker->private_data;

	return state->scan(state->context, sc->nr_to_scan);
}

void *rust_helper_balloon_shrinker_register(
	void *context, unsigned long (*count)(void *context),
	unsigned long (*scan)(void *context, unsigned long nr_to_scan))
{
	struct rust_balloon_shrinker *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;
	state->shrinker = shrinker_alloc(0, "rust-virtio-balloon");
	if (!state->shrinker) {
		kfree(state);
		return NULL;
	}
	state->context = context;
	state->count = count;
	state->scan = scan;
	state->shrinker->private_data = state;
	state->shrinker->count_objects = rust_balloon_shrinker_count;
	state->shrinker->scan_objects = rust_balloon_shrinker_scan;
	shrinker_register(state->shrinker);
	return state;
}

void rust_helper_balloon_shrinker_unregister(void *raw_state)
{
	struct rust_balloon_shrinker *state = raw_state;

	if (!state)
		return;
	shrinker_free(state->shrinker);
	kfree(state);
}

struct rust_balloon_oom_notifier {
	struct notifier_block notifier;
	void *context;
	unsigned long (*reclaim)(void *context);
};

static int rust_balloon_oom_notify(struct notifier_block *notifier,
				   unsigned long action, void *data)
{
	struct rust_balloon_oom_notifier *state =
		container_of(notifier, struct rust_balloon_oom_notifier,
			     notifier);
	unsigned long *freed = data;

	(void)action;
	*freed += state->reclaim(state->context);
	return NOTIFY_OK;
}

void *rust_helper_balloon_oom_register(
	void *context, unsigned long (*reclaim)(void *context), int priority)
{
	struct rust_balloon_oom_notifier *state;
	int error;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;
	state->context = context;
	state->reclaim = reclaim;
	state->notifier.notifier_call = rust_balloon_oom_notify;
	state->notifier.priority = priority;
	error = register_oom_notifier(&state->notifier);
	if (error) {
		kfree(state);
		return NULL;
	}
	return state;
}

void rust_helper_balloon_oom_unregister(void *raw_state)
{
	struct rust_balloon_oom_notifier *state = raw_state;

	if (!state)
		return;
	unregister_oom_notifier(&state->notifier);
	kfree(state);
}

#if IS_ENABLED(CONFIG_PAGE_REPORTING)

struct rust_balloon_page_reporter {
	struct page_reporting_dev_info info;
	void *context;
	int (*report)(void *context, void *scatterlist, unsigned int entries);
};

static int rust_balloon_page_report(struct page_reporting_dev_info *info,
				    struct scatterlist *scatterlist,
				    unsigned int entries)
{
	struct rust_balloon_page_reporter *state =
		container_of(info, struct rust_balloon_page_reporter, info);

	return state->report(state->context, scatterlist, entries);
}

void *rust_helper_balloon_page_reporter_register(
	void *context,
	int (*report)(void *context, void *scatterlist, unsigned int entries),
	unsigned int order)
{
	struct rust_balloon_page_reporter *state;
	int error;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;
	state->context = context;
	state->report = report;
	state->info.report = rust_balloon_page_report;
	state->info.order = order;
	error = page_reporting_register(&state->info);
	if (error) {
		kfree(state);
		return NULL;
	}
	return state;
}

void rust_helper_balloon_page_reporter_unregister(void *raw_state)
{
	struct rust_balloon_page_reporter *state = raw_state;

	if (!state)
		return;
	page_reporting_unregister(&state->info);
	kfree(state);
}

#endif /* CONFIG_PAGE_REPORTING */
