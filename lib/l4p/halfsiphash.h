/*
 * SipHash reference C implementation

 * Copyright (c) 2016 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>

 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.

 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef _SIPHASH_
#define _SIPHASH_

#ifdef __cplusplus
extern "C" {
#endif

/* The below siphash logic is taken from the source
 * https://github.com/veorq/SipHash
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_debug.h>

#define STATE_V2 0x6c796765
#define STATE_V3 0x74656462

#define ROTL(x, b) (uint32_t)(((x) << (b)) | ((x) >> (32 - (b))))

/*
 * Siphash hash functionality logically divided into different
 * phases and the functions are named based on the same.
 * SipHash-2-4 is used i.e: 2 compression rounds and 4 finalization rounds.
 */
static inline void
sipround(rte_xmm_t *v)
{
	v->u32[0] += v->u32[1];
	v->u32[1] = ROTL(v->u32[1], 5);
	v->u32[1] ^= v->u32[0];
	v->u32[0] = ROTL(v->u32[0], 16);
	v->u32[2] += v->u32[3];
	v->u32[3] = ROTL(v->u32[3], 8);
	v->u32[3] ^= v->u32[2];
	v->u32[0] += v->u32[3];
	v->u32[3] = ROTL(v->u32[3], 7);
	v->u32[3] ^= v->u32[0];
	v->u32[2] += v->u32[1];
	v->u32[1] = ROTL(v->u32[1], 13);
	v->u32[1] ^= v->u32[2];
	v->u32[2] = ROTL(v->u32[2], 16);
}

static inline void
siphash_initialization(rte_xmm_t *v, const rte_xmm_t *k)
{
	uint32_t k0 = k->u32[0];
	uint32_t k1 = k->u32[1];

	v->u32[0] = k0;
	v->u32[1] = k1;
	v->u32[2] = STATE_V2 ^ k0;
	v->u32[3] = STATE_V3 ^ k1;
}

static inline void
siphash_compression(const uint32_t *in, size_t len, rte_xmm_t *v)
{
	uint32_t i;

	for (i = 0; i < len; i++) {
		v->u32[3] ^= in[i];
		sipround(v);
		sipround(v);
		v->u32[0] ^= in[i];
	}
}

static inline void
siphash_finalization(rte_xmm_t *v)
{
	v->u32[2] ^= 0xff;
	sipround(v);
	sipround(v);
	sipround(v);
	sipround(v);
}

#ifdef __cplusplus
}
#endif

#endif /* __SIPHASH__ */
