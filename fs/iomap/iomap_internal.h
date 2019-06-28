// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (c) 2016-2018 Christoph Hellwig.
 */
#ifndef _IOMAP_INTERNAL_H_
#define _IOMAP_INTERNAL_H_

sector_t iomap_sector(struct iomap *iomap, loff_t pos);
void iomap_set_range_uptodate(struct page *page, unsigned off, unsigned len);
struct iomap_page *iomap_page_create(struct inode *inode, struct page *page);
void iomap_adjust_read_range(struct inode *inode, struct iomap_page *iop,
		loff_t *pos, loff_t length, unsigned *offp, unsigned *lenp);
void iomap_read_inline_data(struct inode *inode, struct page *page,
		struct iomap *iomap);

#endif /* _IOMAP_INTERNAL_H_ */
