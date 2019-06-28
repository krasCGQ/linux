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

/*
 * Calculate the range inside the page that we actually need to read.
 */
void
iomap_adjust_read_range(struct inode *inode, struct iomap_page *iop,
		loff_t *pos, loff_t length, unsigned *offp, unsigned *lenp)
{
	loff_t orig_pos = *pos;
	loff_t isize = i_size_read(inode);
	unsigned block_bits = inode->i_blkbits;
	unsigned block_size = (1 << block_bits);
	unsigned poff = offset_in_page(*pos);
	unsigned plen = min_t(loff_t, PAGE_SIZE - poff, length);
	unsigned first = poff >> block_bits;
	unsigned last = (poff + plen - 1) >> block_bits;

	/*
	 * If the block size is smaller than the page size we need to check the
	 * per-block uptodate status and adjust the offset and length if needed
	 * to avoid reading in already uptodate ranges.
	 */
	if (iop) {
		unsigned int i;

		/* move forward for each leading block marked uptodate */
		for (i = first; i <= last; i++) {
			if (!test_bit(i, iop->uptodate))
				break;
			*pos += block_size;
			poff += block_size;
			plen -= block_size;
			first++;
		}

		/* truncate len if we find any trailing uptodate block(s) */
		for ( ; i <= last; i++) {
			if (test_bit(i, iop->uptodate)) {
				plen -= (last - i + 1) * block_size;
				last = i - 1;
				break;
			}
		}
	}

	/*
	 * If the extent spans the block that contains the i_size we need to
	 * handle both halves separately so that we properly zero data in the
	 * page cache for blocks that are entirely outside of i_size.
	 */
	if (orig_pos <= isize && orig_pos + length > isize) {
		unsigned end = offset_in_page(isize - 1) >> block_bits;

		if (first <= end && last > end)
			plen -= (last - end) * block_size;
	}

	*offp = poff;
	*lenp = plen;
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

static void
iomap_read_finish(struct iomap_page *iop, struct page *page)
{
	if (!iop || atomic_dec_and_test(&iop->read_count))
		unlock_page(page);
}

static void
iomap_read_page_end_io(struct bio_vec *bvec, int error)
{
	struct page *page = bvec->bv_page;
	struct iomap_page *iop = to_iomap_page(page);

	if (unlikely(error)) {
		ClearPageUptodate(page);
		SetPageError(page);
	} else {
		iomap_set_range_uptodate(page, bvec->bv_offset, bvec->bv_len);
	}

	iomap_read_finish(iop, page);
}

static void
iomap_read_end_io(struct bio *bio)
{
	int error = blk_status_to_errno(bio->bi_status);
	struct bio_vec *bvec;
	struct bvec_iter_all iter_all;

	bio_for_each_segment_all(bvec, bio, iter_all)
		iomap_read_page_end_io(bvec, error);
	bio_put(bio);
}

struct iomap_readpage_ctx {
	struct page		*cur_page;
	bool			cur_page_in_bio;
	bool			is_readahead;
	struct bio		*bio;
	struct list_head	*pages;
};

void
iomap_read_inline_data(struct inode *inode, struct page *page,
		struct iomap *iomap)
{
	size_t size = i_size_read(inode);
	void *addr;

	if (PageUptodate(page))
		return;

	BUG_ON(page->index);
	BUG_ON(size > PAGE_SIZE - offset_in_page(iomap->inline_data));

	addr = kmap_atomic(page);
	memcpy(addr, iomap->inline_data, size);
	memset(addr + size, 0, PAGE_SIZE - size);
	kunmap_atomic(addr);
	SetPageUptodate(page);
}

static loff_t
iomap_readpage_actor(struct inode *inode, loff_t pos, loff_t length, void *data,
		struct iomap *iomap)
{
	struct iomap_readpage_ctx *ctx = data;
	struct page *page = ctx->cur_page;
	struct iomap_page *iop = iomap_page_create(inode, page);
	bool is_contig = false;
	loff_t orig_pos = pos;
	unsigned poff, plen;
	sector_t sector;

	if (iomap->type == IOMAP_INLINE) {
		WARN_ON_ONCE(pos);
		iomap_read_inline_data(inode, page, iomap);
		return PAGE_SIZE;
	}

	/* zero post-eof blocks as the page may be mapped */
	iomap_adjust_read_range(inode, iop, &pos, length, &poff, &plen);
	if (plen == 0)
		goto done;

	if (iomap->type != IOMAP_MAPPED || pos >= i_size_read(inode)) {
		zero_user(page, poff, plen);
		iomap_set_range_uptodate(page, poff, plen);
		goto done;
	}

	ctx->cur_page_in_bio = true;

	/*
	 * Try to merge into a previous segment if we can.
	 */
	sector = iomap_sector(iomap, pos);
	if (ctx->bio && bio_end_sector(ctx->bio) == sector) {
		if (__bio_try_merge_page(ctx->bio, page, plen, poff, true))
			goto done;
		is_contig = true;
	}

	/*
	 * If we start a new segment we need to increase the read count, and we
	 * need to do so before submitting any previous full bio to make sure
	 * that we don't prematurely unlock the page.
	 */
	if (iop)
		atomic_inc(&iop->read_count);

	if (!ctx->bio || !is_contig || bio_full(ctx->bio)) {
		gfp_t gfp = mapping_gfp_constraint(page->mapping, GFP_KERNEL);
		int nr_vecs = (length + PAGE_SIZE - 1) >> PAGE_SHIFT;

		if (ctx->bio)
			submit_bio(ctx->bio);

		if (ctx->is_readahead) /* same as readahead_gfp_mask */
			gfp |= __GFP_NORETRY | __GFP_NOWARN;
		ctx->bio = bio_alloc(gfp, min(BIO_MAX_PAGES, nr_vecs));
		ctx->bio->bi_opf = REQ_OP_READ;
		if (ctx->is_readahead)
			ctx->bio->bi_opf |= REQ_RAHEAD;
		ctx->bio->bi_iter.bi_sector = sector;
		bio_set_dev(ctx->bio, iomap->bdev);
		ctx->bio->bi_end_io = iomap_read_end_io;
	}

	bio_add_page(ctx->bio, page, plen, poff);
done:
	/*
	 * Move the caller beyond our range so that it keeps making progress.
	 * For that we have to include any leading non-uptodate ranges, but
	 * we can skip trailing ones as they will be handled in the next
	 * iteration.
	 */
	return pos - orig_pos + plen;
}

int
iomap_readpage(struct page *page, const struct iomap_ops *ops)
{
	struct iomap_readpage_ctx ctx = { .cur_page = page };
	struct inode *inode = page->mapping->host;
	unsigned poff;
	loff_t ret;

	for (poff = 0; poff < PAGE_SIZE; poff += ret) {
		ret = iomap_apply(inode, page_offset(page) + poff,
				PAGE_SIZE - poff, 0, ops, &ctx,
				iomap_readpage_actor);
		if (ret <= 0) {
			WARN_ON_ONCE(ret == 0);
			SetPageError(page);
			break;
		}
	}

	if (ctx.bio) {
		submit_bio(ctx.bio);
		WARN_ON_ONCE(!ctx.cur_page_in_bio);
	} else {
		WARN_ON_ONCE(ctx.cur_page_in_bio);
		unlock_page(page);
	}

	/*
	 * Just like mpage_readpages and block_read_full_page we always
	 * return 0 and just mark the page as PageError on errors.  This
	 * should be cleaned up all through the stack eventually.
	 */
	return 0;
}
EXPORT_SYMBOL_GPL(iomap_readpage);

static struct page *
iomap_next_page(struct inode *inode, struct list_head *pages, loff_t pos,
		loff_t length, loff_t *done)
{
	while (!list_empty(pages)) {
		struct page *page = lru_to_page(pages);

		if (page_offset(page) >= (u64)pos + length)
			break;

		list_del(&page->lru);
		if (!add_to_page_cache_lru(page, inode->i_mapping, page->index,
				GFP_NOFS))
			return page;

		/*
		 * If we already have a page in the page cache at index we are
		 * done.  Upper layers don't care if it is uptodate after the
		 * readpages call itself as every page gets checked again once
		 * actually needed.
		 */
		*done += PAGE_SIZE;
		put_page(page);
	}

	return NULL;
}

static loff_t
iomap_readpages_actor(struct inode *inode, loff_t pos, loff_t length,
		void *data, struct iomap *iomap)
{
	struct iomap_readpage_ctx *ctx = data;
	loff_t done, ret;

	for (done = 0; done < length; done += ret) {
		if (ctx->cur_page && offset_in_page(pos + done) == 0) {
			if (!ctx->cur_page_in_bio)
				unlock_page(ctx->cur_page);
			put_page(ctx->cur_page);
			ctx->cur_page = NULL;
		}
		if (!ctx->cur_page) {
			ctx->cur_page = iomap_next_page(inode, ctx->pages,
					pos, length, &done);
			if (!ctx->cur_page)
				break;
			ctx->cur_page_in_bio = false;
		}
		ret = iomap_readpage_actor(inode, pos + done, length - done,
				ctx, iomap);
	}

	return done;
}

int
iomap_readpages(struct address_space *mapping, struct list_head *pages,
		unsigned nr_pages, const struct iomap_ops *ops)
{
	struct iomap_readpage_ctx ctx = {
		.pages		= pages,
		.is_readahead	= true,
	};
	loff_t pos = page_offset(list_entry(pages->prev, struct page, lru));
	loff_t last = page_offset(list_entry(pages->next, struct page, lru));
	loff_t length = last - pos + PAGE_SIZE, ret = 0;

	while (length > 0) {
		ret = iomap_apply(mapping->host, pos, length, 0, ops,
				&ctx, iomap_readpages_actor);
		if (ret <= 0) {
			WARN_ON_ONCE(ret == 0);
			goto done;
		}
		pos += ret;
		length -= ret;
	}
	ret = 0;
done:
	if (ctx.bio)
		submit_bio(ctx.bio);
	if (ctx.cur_page) {
		if (!ctx.cur_page_in_bio)
			unlock_page(ctx.cur_page);
		put_page(ctx.cur_page);
	}

	/*
	 * Check that we didn't lose a page due to the arcance calling
	 * conventions..
	 */
	WARN_ON_ONCE(!ret && !list_empty(ctx.pages));
	return ret;
}
EXPORT_SYMBOL_GPL(iomap_readpages);

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

