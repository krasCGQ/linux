/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012-2016 Eric Biggers
 *
 * Adapted for linux kernel by Alexander Mamaev:
 * - remove implementations of get_unaligned_
 * - remove SSE and AVX instructions
 * - assume GCC is always defined
 * - inlined aligned_malloc/aligned_free
 * - ISO C90
 * - linux kernel code style
 */

#ifndef _COMMON_DEFS_H
#define _COMMON_DEFS_H

#include <linux/string.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <asm/unaligned.h>


/* ========================================================================== */
/*				Type definitions			      */
/* ========================================================================== */

/*
 * Type of a machine word.  'u32 long' would be logical, but that is only
 * 32 bits on x86_64 Windows.  The same applies to 'uint_fast32_t'.  So the best
 * we can do without a bunch of #ifdefs appears to be 'size_t'.
 */

#define WORDBYTES	sizeof(size_t)
#define WORDBITS	(8 * WORDBYTES)

/* ========================================================================== */
/*			   Compiler-specific definitions		      */
/* ========================================================================== */

#  define forceinline		__always_inline
#  define _aligned_attribute(n) __aligned(n)
#  define bsr32(n)		(31 - __builtin_clz(n))
#  define bsr64(n)		(63 - __builtin_clzll(n))
#  define bsf32(n)		__builtin_ctz(n)
#  define bsf64(n)		__builtin_ctzll(n)

/* STATIC_ASSERT() - verify the truth of an expression at compilation time */
#define STATIC_ASSERT(expr)	((void)sizeof(char[1 - 2 * !(expr)]))

/* STATIC_ASSERT_ZERO() - verify the truth of an expression at compilation time
 * and also produce a result of value '0' to be used in constant expressions
 */
#define STATIC_ASSERT_ZERO(expr) ((int)sizeof(char[-!(expr)]))

/* UNALIGNED_ACCESS_IS_FAST should be defined to 1 if unaligned memory accesses
 * can be performed efficiently on the target platform.
 */
#if defined(__x86_64__) || defined(__i386__) || defined(__ARM_FEATURE_UNALIGNED)
#  define UNALIGNED_ACCESS_IS_FAST 1
#else
#  define UNALIGNED_ACCESS_IS_FAST 0
#endif

/* ========================================================================== */
/*			    Unaligned memory accesses			      */
/* ========================================================================== */

#define load_word_unaligned(p) get_unaligned((const size_t *)(p))
#define store_word_unaligned(v, p) put_unaligned((v), (size_t *)(p))


/* ========================================================================== */
/*			       Bit scan functions			      */
/* ========================================================================== */

/*
 * Bit Scan Reverse (BSR) - find the 0-based index (relative to the least
 * significant end) of the *most* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

#ifndef bsr32
static forceinline u32
bsr32(u32 v)
{
	u32 bit = 0;

	while ((v >>= 1) != 0)
		bit++;
	return bit;
}
#endif

#ifndef bsr64
static forceinline u32
bsr64(u64 v)
{
	u32 bit = 0;

	while ((v >>= 1) != 0)
		bit++;
	return bit;
}
#endif

static forceinline u32
bsrw(size_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return bsr32(v);
	else
		return bsr64(v);
}

/*
 * Bit Scan Forward (BSF) - find the 0-based index (relative to the least
 * significant end) of the *least* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

#ifndef bsf32
static forceinline u32
bsf32(u32 v)
{
	u32 bit;

	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
}
#endif

#ifndef bsf64
static forceinline u32
bsf64(u64 v)
{
	u32 bit;

	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
}
#endif

static forceinline u32
bsfw(size_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return bsf32(v);
	else
		return bsf64(v);
}

/* Return the log base 2 of 'n', rounded up to the nearest integer. */
static forceinline u32
ilog2_ceil(size_t n)
{
	if (n <= 1)
		return 0;
	return 1 + bsrw(n - 1);
}

/* ========================================================================== */
/*			    Aligned memory allocation			      */
/* ========================================================================== */

static forceinline void *
aligned_malloc(size_t size, size_t alignment)
{
	const uintptr_t mask = alignment - 1;
	char *ptr = NULL;
	char *raw_ptr;

	raw_ptr = kmalloc(mask + sizeof(size_t) + size, GFP_NOFS);
	if (raw_ptr) {
		ptr = (char *)raw_ptr + sizeof(size_t);
		ptr = (void *)(((uintptr_t)ptr + mask) & ~mask);
		*((size_t *)ptr - 1) = ptr - raw_ptr;
	}
	return ptr;
}

static forceinline void
aligned_free(void *ptr)
{
	if (ptr)
		kfree((char *)ptr - *((size_t *)ptr - 1));
}

extern void *aligned_malloc(size_t size, size_t alignment);
extern void aligned_free(void *ptr);

#endif /* _COMMON_DEFS_H */
