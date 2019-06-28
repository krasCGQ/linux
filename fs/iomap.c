// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (c) 2016-2018 Christoph Hellwig.
 */
#include <linux/module.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/dax.h>
#include <linux/sched/signal.h>

#include "internal.h"
#include "iomap/iomap_internal.h"

/*
 * Execute a iomap write on a segment of the mapping that spans a
 * contiguous range of pages that have identical block mapping state.
 *
 * This avoids the need to map pages individually, do individual allocations
 * for each page and most importantly avoid the need for filesystem specific
 * locking per page. Instead, all the operations are amortised over the entire
 * range of pages. It is assumed that the filesystems will lock whatever
 * resources they require in the iomap_begin call, and release them in the
 * iomap_end call.
 */
loff_t
iomap_apply(struct inode *inode, loff_t pos, loff_t length, unsigned flags,
		const struct iomap_ops *ops, void *data, iomap_actor_t actor)
{
	struct iomap iomap = { 0 };
	loff_t written = 0, ret;

	/*
	 * Need to map a range from start position for length bytes. This can
	 * span multiple pages - it is only guaranteed to return a range of a
	 * single type of pages (e.g. all into a hole, all mapped or all
	 * unwritten). Failure at this point has nothing to undo.
	 *
	 * If allocation is required for this range, reserve the space now so
	 * that the allocation is guaranteed to succeed later on. Once we copy
	 * the data into the page cache pages, then we cannot fail otherwise we
	 * expose transient stale data. If the reserve fails, we can safely
	 * back out at this point as there is nothing to undo.
	 */
	ret = ops->iomap_begin(inode, pos, length, flags, &iomap);
	if (ret)
		return ret;
	if (WARN_ON(iomap.offset > pos))
		return -EIO;
	if (WARN_ON(iomap.length == 0))
		return -EIO;

	/*
	 * Cut down the length to the one actually provided by the filesystem,
	 * as it might not be able to give us the whole size that we requested.
	 */
	if (iomap.offset + iomap.length < pos + length)
		length = iomap.offset + iomap.length - pos;

	/*
	 * Now that we have guaranteed that the space allocation will succeed.
	 * we can do the copy-in page by page without having to worry about
	 * failures exposing transient data.
	 */
	written = actor(inode, pos, length, data, &iomap);

	/*
	 * Now the data has been copied, commit the range we've copied.  This
	 * should not fail unless the filesystem has had a fatal error.
	 */
	if (ops->iomap_end) {
		ret = ops->iomap_end(inode, pos, length,
				     written > 0 ? written : 0,
				     flags, &iomap);
	}

	return written ? written : ret;
}

sector_t
iomap_sector(struct iomap *iomap, loff_t pos)
{
	return (iomap->addr + pos - iomap->offset) >> SECTOR_SHIFT;
}

struct iomap_page *
iomap_page_create(struct inode *inode, struct page *page)
{
	struct iomap_page *iop = to_iomap_page(page);

	if (iop || i_blocksize(inode) == PAGE_SIZE)
		return iop;

	iop = kmalloc(sizeof(*iop), GFP_NOFS | __GFP_NOFAIL);
	atomic_set(&iop->read_count, 0);
	atomic_set(&iop->write_count, 0);
	bitmap_zero(iop->uptodate, PAGE_SIZE / SECTOR_SIZE);

	/*
	 * migrate_page_move_mapping() assumes that pages with private data have
	 * their count elevated by 1.
	 */
	get_page(page);
	set_page_private(page, (unsigned long)iop);
	SetPagePrivate(page);
	return iop;
}

static void
iomap_page_release(struct page *page)
{
	struct iomap_page *iop = to_iomap_page(page);

	if (!iop)
		return;
	WARN_ON_ONCE(atomic_read(&iop->read_count));
	WARN_ON_ONCE(atomic_read(&iop->write_count));
	ClearPagePrivate(page);
	set_page_private(page, 0);
	put_page(page);
	kfree(iop);
}

void
iomap_set_range_uptodate(struct page *page, unsigned off, unsigned len)
{
	struct iomap_page *iop = to_iomap_page(page);
	struct inode *inode = page->mapping->host;
	unsigned first = off >> inode->i_blkbits;
	unsigned last = (off + len - 1) >> inode->i_blkbits;
	unsigned int i;
	bool uptodate = true;

	if (iop) {
		for (i = 0; i < PAGE_SIZE / i_blocksize(inode); i++) {
			if (i >= first && i <= last)
				set_bit(i, iop->uptodate);
			else if (!test_bit(i, iop->uptodate))
				uptodate = false;
		}
	}

	if (uptodate && !PageError(page))
		SetPageUptodate(page);
}

/*
 * iomap_is_partially_uptodate checks whether blocks within a page are
 * uptodate or not.
 *
 * Returns true if all blocks which correspond to a file portion
 * we want to read within the page are uptodate.
 */
int
iomap_is_partially_uptodate(struct page *page, unsigned long from,
		unsigned long count)
{
	struct iomap_page *iop = to_iomap_page(page);
	struct inode *inode = page->mapping->host;
	unsigned len, first, last;
	unsigned i;

	/* Limit range to one page */
	len = min_t(unsigned, PAGE_SIZE - from, count);

	/* First and last blocks in range within page */
	first = from >> inode->i_blkbits;
	last = (from + len - 1) >> inode->i_blkbits;

	if (iop) {
		for (i = first; i <= last; i++)
			if (!test_bit(i, iop->uptodate))
				return 0;
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(iomap_is_partially_uptodate);

int
iomap_releasepage(struct page *page, gfp_t gfp_mask)
{
	/*
	 * mm accommodates an old ext3 case where clean pages might not have had
	 * the dirty bit cleared. Thus, it can send actual dirty pages to
	 * ->releasepage() via shrink_active_list(), skip those here.
	 */
	if (PageDirty(page) || PageWriteback(page))
		return 0;
	iomap_page_release(page);
	return 1;
}
EXPORT_SYMBOL_GPL(iomap_releasepage);

void
iomap_invalidatepage(struct page *page, unsigned int offset, unsigned int len)
{
	/*
	 * If we are invalidating the entire page, clear the dirty state from it
	 * and release it to avoid unnecessary buildup of the LRU.
	 */
	if (offset == 0 && len == PAGE_SIZE) {
		WARN_ON_ONCE(PageWriteback(page));
		cancel_dirty_page(page);
		iomap_page_release(page);
	}
}
EXPORT_SYMBOL_GPL(iomap_invalidatepage);

#ifdef CONFIG_MIGRATION
int
iomap_migrate_page(struct address_space *mapping, struct page *newpage,
		struct page *page, enum migrate_mode mode)
{
	int ret;

	ret = migrate_page_move_mapping(mapping, newpage, page, mode, 0);
	if (ret != MIGRATEPAGE_SUCCESS)
		return ret;

	if (page_has_private(page)) {
		ClearPagePrivate(page);
		get_page(newpage);
		set_page_private(newpage, page_private(page));
		set_page_private(page, 0);
		put_page(page);
		SetPagePrivate(newpage);
	}

	if (mode != MIGRATE_SYNC_NO_COPY)
		migrate_page_copy(newpage, page);
	else
		migrate_page_states(newpage, page);
	return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL_GPL(iomap_migrate_page);
#endif /* CONFIG_MIGRATION */

int
iomap_set_page_dirty(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	int newly_dirty;

	if (unlikely(!mapping))
		return !TestSetPageDirty(page);

	/*
	 * Lock out page->mem_cgroup migration to keep PageDirty
	 * synchronized with per-memcg dirty page counters.
	 */
	lock_page_memcg(page);
	newly_dirty = !TestSetPageDirty(page);
	if (newly_dirty)
		__set_page_dirty(page, mapping, 0);
	unlock_page_memcg(page);

	if (newly_dirty)
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
	return newly_dirty;
}
EXPORT_SYMBOL_GPL(iomap_set_page_dirty);

int
iomap_truncate_page(struct inode *inode, loff_t pos, bool *did_zero,
		const struct iomap_ops *ops)
{
	unsigned int blocksize = i_blocksize(inode);
	unsigned int off = pos & (blocksize - 1);

	/* Block boundary? Nothing to do */
	if (!off)
		return 0;
	return iomap_zero_range(inode, pos, blocksize - off, did_zero, ops);
}
EXPORT_SYMBOL_GPL(iomap_truncate_page);
