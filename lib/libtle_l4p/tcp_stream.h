/*
 * Copyright (c) 2016  Intel Corporation.
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

#ifndef _TCP_STREAM_H_
#define _TCP_STREAM_H_

#include <rte_vect.h>
#include <tle_dring.h>
#include <tle_tcp.h>
#include <tle_event.h>

#include "stream.h"
#include "misc.h"
#include "tcp_misc.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	TCP_ST_CLOSED,
	TCP_ST_LISTEN,
	TCP_ST_SYN_SENT,
	TCP_ST_SYN_RCVD,
	TCP_ST_ESTABLISHED,
	TCP_ST_FIN_WAIT_1,
	TCP_ST_FIN_WAIT_2,
	TCP_ST_CLOSE_WAIT,
	TCP_ST_CLOSING,
	TCP_ST_LAST_ACK,
	TCP_ST_TIME_WAIT,
	TCP_ST_NUM
};

struct tcb {
	volatile uint16_t state;
	struct {
		uint32_t nxt;
		uint32_t irs; /* initial received sequence */
		uint32_t wnd;
		uint32_t ts;
		uint16_t mss;
		uint8_t  wscale;
		uint8_t  dupack;
	} rcv;
	struct {
		uint32_t nxt;
		uint32_t una;
		uint32_t iss; /* initial send sequence */
		uint32_t wnd;
		uint32_t ack; /* last sent ack */
		uint32_t ts;
		uint16_t mss;
		uint8_t  wscale;
	} snd;
	struct syn_opts so; /* initial syn options. */
};


struct tle_tcp_stream {
	
	struct tle_stream s;

	struct stbl_entry *ste;     /* entry in streams table. */
	struct tcb tcb;

	struct {
		struct tle_event *ev;
		struct tle_stream_cb cb;
	} err;

	struct {
		rte_atomic32_t use;
		struct rte_ring *lq;     /* listen (syn) queue */
		struct tle_event *ev;    /* user provided recv event. */
		struct tle_stream_cb cb; /* user provided recv callback. */
	} rx __rte_cache_aligned;

	struct {
		rte_atomic32_t use;
		struct {
			uint32_t nb_elem;  /* number of obects per drb. */
			uint32_t nb_max;   /* number of drbs per stream. */
			struct rte_ring *r;
		} drb;
		struct rte_ring *q;  /* (re)tx queue */
		struct tle_event *ev;
		struct tle_stream_cb cb;
		struct tle_dest dst;
	} tx __rte_cache_aligned;

} __rte_cache_aligned;

#define TCP_STREAM(p)	\
((struct tle_tcp_stream *)((uintptr_t)(p) - offsetof(struct tle_tcp_stream, s)))

#define TCP_STREAM_TX_PENDING(s)	\
	((s)->tx.drb.nb_max != rte_ring_count((s)->tx.drb.r))

#define TCP_STREAM_TX_FINISHED(s)	\
	((s)->tx.drb.nb_max == rte_ring_count((s)->tx.drb.r))

#include "stream_table.h"

struct tcp_streams {
	struct stbl st;
	struct tle_tcp_stream s[];  /* array of allocated streams. */
};

#define CTX_TCP_STREAMS(ctx)	((struct tcp_streams *)(ctx)->streams.buf)
#define CTX_TCP_STLB(ctx)	(&CTX_TCP_STREAMS(ctx)->st)


static inline void
tcp_stream_down(struct tle_tcp_stream *s)
{
	rwl_down(&s->rx.use);
	rwl_down(&s->tx.use);
}

static inline void
tcp_stream_up(struct tle_tcp_stream *s)
{
	rwl_up(&s->rx.use);
	rwl_up(&s->tx.use);
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_STREAM_H_ */
