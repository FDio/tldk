/*
 * Copyright (c) 2016-2017  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _SYNCOOKIE_H_
#define _SYNCOOKIE_H_

#include <rte_jhash.h>

#include "tcp_misc.h"
#include <tle_ctx.h>
#include <halfsiphash.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sync_in4 {
	uint32_t seq;
	union l4_ports port;
	union ipv4_addrs addr;
};

static const rte_xmm_t mss4len = {
	.u32 = {
		TCP4_MIN_MSS, /* 536 */
		1300,
		TCP4_OP_MSS,  /* 1440 */
		TCP4_NOP_MSS, /* 1460 */
	},
};

static const rte_xmm_t mss6len = {
	.u32 = {
		TCP6_MIN_MSS, /* 1220 */
		TCP6_OP_MSS,  /* 1420 */
		TCP6_NOP_MSS, /* 1440 */
		8940,
	},
};

#define	SYNC_MSS_BITS	2
#define	SYNC_MSS_MASK	((1 << SYNC_MSS_BITS) - 1)

#define	SYNC_TMS_WSCALE_BITS	4
#define	SYNC_TMS_WSCALE_MASK	((1 << SYNC_TMS_WSCALE_BITS) - 1)

#define	SYNC_TMS_RESERVE_BITS	2

#define	SYNC_TMS_OPT_BITS	(SYNC_TMS_WSCALE_BITS + SYNC_TMS_RESERVE_BITS)
#define	SYNC_TMS_OPT_MASK	((1 << SYNC_TMS_OPT_BITS) - 1)

/* allow around 2 minutes for 3-way handshake. */
#define	SYNC_MAX_TMO	0x20000

/* ??? use SipHash as FreeBSD does. ??? */
static inline uint32_t
sync_hash4(const union pkt_info *pi, uint32_t seq, rte_xmm_t *secret_key,
		uint32_t hash_alg)
{
	struct sync_in4 in4;
	rte_xmm_t state;
	uint32_t v0, v1;

	in4.seq = seq;
	in4.port = pi->port;
	in4.addr = pi->addr4;

	if (hash_alg == TLE_JHASH) {
		v0 = secret_key->u32[0];
		v1 = secret_key->u32[1];
		rte_jhash_32b_2hashes(&in4.seq, sizeof(in4) / sizeof(uint32_t),
				&v0, &v1);
		return v0 + v1;
	} else {
		state = *secret_key;
		siphash_compression(&in4.seq, sizeof(in4) / sizeof(uint32_t),
				&state);
		siphash_finalization(&state);
		return (state.u32[0] ^ state.u32[1] ^
			state.u32[2] ^ state.u32[3]);
	}
}

static inline uint32_t
sync_hash6(const union pkt_info *pi, uint32_t seq, rte_xmm_t *secret_key,
		uint32_t hash_alg)
{
	uint32_t port_seq[2];
	rte_xmm_t state;
	uint32_t v0, v1;

	if (hash_alg == TLE_JHASH) {
		v0 = secret_key->u32[0];
		v1 = secret_key->u32[1];
		rte_jhash_32b_2hashes(pi->addr6->raw.u32,
				sizeof(*pi->addr6) / sizeof(uint32_t),
				&v0, &v1);
		return rte_jhash_3words(v0, seq, pi->port.raw, v1);
	} else {
		state = *secret_key;
		siphash_compression(pi->addr6->raw.u32,
				sizeof(*pi->addr6) / sizeof(uint32_t), &state);
		port_seq[0] = pi->port.raw;
		port_seq[1] = seq;
		siphash_compression(port_seq, RTE_DIM(port_seq), &state);
		siphash_finalization(&state);
		return (state.u32[0] ^ state.u32[1] ^
			state.u32[2] ^ state.u32[3]);
	}
}

static inline uint32_t
sync_mss2idx(uint16_t mss, const rte_xmm_t *msl)
{
	if (mss >= msl->u32[2])
		return (mss >= msl->u32[3]) ? 3 : 2;
	else
		return (mss >= msl->u32[1]) ? 1 : 0;
}

static inline uint32_t
sync_gen_seq(const union pkt_info *pi, uint32_t seq, uint32_t ts, uint16_t mss,
		uint32_t hash_alg, rte_xmm_t *secret_key)
{
	uint32_t h, mi;

	if (pi->tf.type == TLE_V4) {
		h = sync_hash4(pi, seq, secret_key, hash_alg);
		mi = sync_mss2idx(mss, &mss4len);
	} else {
		h = sync_hash6(pi, seq, secret_key, hash_alg);
		mi = sync_mss2idx(mss, &mss6len);
	}

	h += (ts & ~SYNC_MSS_MASK) | mi;
	return h;
}

static inline uint32_t
sync_gen_ts(uint32_t ts, uint32_t wscale)
{
	ts = (ts - (SYNC_TMS_OPT_MASK + 1)) & ~SYNC_TMS_OPT_MASK;
	ts |= wscale;
	return ts;
}

static inline int
sync_check_ack(const union pkt_info *pi, uint32_t seq, uint32_t ack,
	uint32_t ts, uint32_t hash_alg, rte_xmm_t *secret_key)
{
	uint32_t h, mi, pts;

	if (pi->tf.type == TLE_V4)
		h = sync_hash4(pi, seq, secret_key, hash_alg);
	else
		h = sync_hash6(pi, seq, secret_key, hash_alg);

	h = ack - h;
	pts = h & ~SYNC_MSS_MASK;
	mi = h & SYNC_MSS_MASK;

	if (ts - pts > SYNC_MAX_TMO)
		return -ERANGE;

	return (pi->tf.type == TLE_V4) ? mss4len.u32[mi] : mss6len.u32[mi];
}

static inline void
sync_fill_tcb(struct tcb *tcb, const union seg_info *si, const union tsopt *to)
{
	uint32_t ack, mss, seq, wscale;

	seq = si->seq;

	tcb->rcv.nxt = seq;
	tcb->rcv.irs = seq - 1;
	tcb->snd.wu.wl1 = seq;

	ack = si->ack;

	tcb->snd.nxt = ack;
	tcb->snd.una = ack;
	tcb->snd.iss = ack - 1;
	tcb->snd.rcvr = ack - 1;
	tcb->snd.wu.wl2 = ack;

	mss = si->mss;

	tcb->snd.mss = mss;
	tcb->so.mss = mss;

	tcb->snd.ts = to->ecr;
	tcb->rcv.ts = to->val;
	tcb->so.ts.raw = to->raw;

	wscale = to->ecr & SYNC_TMS_WSCALE_MASK;

	tcb->snd.wscale = wscale;
	tcb->snd.wnd = si->wnd << wscale;
	tcb->so.wscale = wscale;

	tcb->rcv.wscale = (wscale == TCP_WSCALE_NONE) ?
		TCP_WSCALE_NONE : TCP_WSCALE_DEFAULT;
}

#ifdef __cplusplus
}
#endif

#endif /* _STREAM_TABLE_H_ */
