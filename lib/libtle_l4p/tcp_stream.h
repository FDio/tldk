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

enum {
	TCP_OP_LISTEN =  0x1,
	TCP_OP_ACCEPT =  0x2,
	TCP_OP_CONNECT = 0x4,
	TCP_OP_CLOSE =   0x8,
};

struct tcb {
	volatile uint16_t state;
	volatile uint16_t uop; /* operations by user performed */
	struct {
		uint32_t nxt;
		uint32_t irs; /* initial received sequence */
		uint32_t wnd;
		uint32_t ts;
		struct {
			uint32_t seq;
			uint32_t on;
		} frs;
		uint32_t srtt;   /* smoothed round trip time (scaled by >> 3) */
		uint32_t rttvar; /* rtt variance */
		uint16_t mss;
		uint8_t  wscale;
		uint8_t  dupack;
	} rcv;
	struct {
		uint64_t nxt;
		uint64_t una;
		uint64_t rcvr; /* recover RFC 6582 */
		uint64_t fss;  /* FIN sequence # */
		uint32_t fastack; /* # of partial acks in fast retransmit */
		uint32_t wnd;
		union wui wu; /* window update */
		uint32_t ack; /* last sent ack */
		uint32_t ts;
		uint32_t cwnd;     /* congestion window */
		uint32_t ssthresh; /* slow start threshold */
		uint32_t rto;      /* retransmission timeout */
		uint32_t iss;      /* initial send sequence */
		uint16_t mss;
		uint8_t  wscale;
		uint8_t nb_retx; /* number of retransmission */
		uint8_t nb_retm; /**< max number of retx attempts. */
	} snd;
	struct syn_opts so; /* initial syn options. */
};


struct tle_tcp_stream {

	struct tle_stream s;

	struct stbl_entry *ste;     /* entry in streams table. */
	struct tcb tcb;

	struct {
		void *handle;
	} timer;

	struct {
		struct tle_event *ev;
		struct tle_stream_cb cb;
	} err;

	struct {
		rte_atomic32_t use;
		struct rte_ring *q;     /* listen (syn) queue */
		struct ofo *ofo;
		struct tle_event *ev;    /* user provided recv event. */
		struct tle_stream_cb cb; /* user provided recv callback. */
	} rx __rte_cache_aligned;

	struct {
		rte_atomic32_t use;
		rte_atomic32_t arm;  /* when > 0 stream is in to-send queue */
		struct {
			uint32_t nb_elem;  /* number of objects per drb. */
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

struct sdr {
	rte_spinlock_t lock;
	STAILQ_HEAD(, tle_stream) fe;
	STAILQ_HEAD(, tle_stream) be;
};

struct tcp_streams {
	struct stbl st;
	struct tle_timer_wheel *tmr; /* timer wheel */
	struct rte_ring *tsq;        /* to-send streams queue */
	struct sdr dr;               /* death row for zombie streams */
	struct tle_tcp_stream s[];   /* array of allocated streams. */
};

#define CTX_TCP_STREAMS(ctx)	((struct tcp_streams *)(ctx)->streams.buf)
#define CTX_TCP_STLB(ctx)	(&CTX_TCP_STREAMS(ctx)->st)
#define CTX_TCP_TMWHL(ctx)	(CTX_TCP_STREAMS(ctx)->tmr)
#define CTX_TCP_TSQ(ctx)	(CTX_TCP_STREAMS(ctx)->tsq)
#define CTX_TCP_SDR(ctx)	(&CTX_TCP_STREAMS(ctx)->dr)

#ifdef __cplusplus
}
#endif

#endif /* _TCP_STREAM_H_ */
