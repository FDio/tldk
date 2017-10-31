/*
 * Copyright (c) 2017  Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ngx_tldk.h>
#include <tldk_sock.h>

#include <rte_cycles.h>

#include "be.h"
#include "debug.h"

#define	EVENT_BULK	32

enum {
	EV_ACCEPT,
	EV_RECV,
	EV_SEND,
	EV_ERR,
	EV_NUM
};

struct tldk_event_stat {
	uint64_t nb_get[EV_NUM];
	uint64_t nb_post[EV_NUM];
};

static struct tldk_event_stat event_stat;

extern ngx_event_module_t tldk_event_module;

/*
 * TLDK event module implementation
 */

static ngx_int_t
tldk_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
	struct tldk_sock *ts;
	ngx_connection_t *c;

	c = ev->data;

	FE_TRACE("%s(ev=%p,event=%#lx,flags=%#lx): fd=%d;\n",
		__func__, ev, event, flags, c->fd);

	ts = sd_to_sock(c->fd);
	if (ts == NULL)
		return NGX_OK;

	if (event == NGX_READ_EVENT) {
		tle_event_active(ts->rxev, TLE_SEV_DOWN);
		tle_event_active(ts->erev, TLE_SEV_DOWN);
		ts->rev = ev;
	} else if (event == NGX_WRITE_EVENT) {
		tle_event_active(ts->txev, TLE_SEV_DOWN);
		tle_event_active(ts->erev, TLE_SEV_DOWN);
		ts->wev = ev;
	}

	ev->active = 1;
	return NGX_OK;
}

static ngx_int_t
tldk_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
	struct tldk_sock *ts;
	ngx_connection_t *c;

	c = ev->data;

	FE_TRACE("%s(ev=%p,event=%#lx,flags=%#lx): fd=%d;\n",
		__func__, ev, event, flags, c->fd);

	ev->active = 0;
	if ((flags & NGX_CLOSE_EVENT) != 0)
		return NGX_OK;

	ts = sd_to_sock(c->fd);
	if (ts == NULL)
		return NGX_OK;

	if (event == NGX_READ_EVENT) {
		tle_event_down(ts->rxev);
		tle_event_down(ts->erev);
		ts->rev = NULL;
	} else if (event == NGX_WRITE_EVENT) {
		tle_event_down(ts->txev);
		tle_event_down(ts->erev);
		ts->wev = NULL;
	}

	return NGX_OK;
}

static inline void
post_event(ngx_event_t *ev, ngx_queue_t *q, ngx_uint_t flags, uint32_t type)
{
	if (ev != NULL && ev->active == 1) {
		ev->ready = 1;
		event_stat.nb_post[type]++;
		if ((flags & NGX_POST_EVENTS) != 0) {
			ngx_post_event(ev, q);
		} else
			ev->handler(ev);
	}
}

static ngx_int_t
tldk_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
	uint32_t i, n, ne, nr, ns, nt;
	uint64_t tme, tms, tmw;
	struct tldk_sock *te[EVENT_BULK];
	struct tldk_sock *tr[EVENT_BULK];
	struct tldk_sock *ts[EVENT_BULK];
	struct tldk_sock *tt[EVENT_BULK];
	struct tldk_ctx *tcx;

	FE_TRACE("%s(cycle=%p,timer=%lu,flags=%#lx);\n",
		__func__, cycle, timer, flags);

	tcx =  wrk2ctx + ngx_worker;

	tms = rte_get_tsc_cycles();
	tme = (timer == NGX_TIMER_INFINITE) ? timer :
		timer * (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S;
	tmw = 0;
	n = 0;

	do {
		if (tcx->cf->be_in_worker != 0)
			be_lcore_tcp(tcx);

		ns = tle_evq_get(stbl.syneq, (const void **)(uintptr_t)ts,
			RTE_DIM(ts));
		nr = tle_evq_get(stbl.rxeq, (const void **)(uintptr_t)tr,
			RTE_DIM(tr));
		nt = tle_evq_get(stbl.txeq, (const void **)(uintptr_t)tt,
			RTE_DIM(tt));
		ne = tle_evq_get(stbl.ereq, (const void **)(uintptr_t)te,
			RTE_DIM(te));
		n = ne + nr + ns + nt;

		if (n != 0) {
			event_stat.nb_get[EV_ACCEPT] += ns;
			event_stat.nb_get[EV_RECV] += nr;
			event_stat.nb_get[EV_SEND] += nt;
			event_stat.nb_get[EV_ERR] += ne;
			break;
		}

		if (tcx->cf->be_in_worker == 0)
			//sched_yield();
			rte_delay_us(1);

		tmw += rte_get_tsc_cycles() - tms;

	} while (tmw < tme && ngx_quit == 0 && ngx_terminate == 0);

	if ((flags & NGX_UPDATE_TIME) != 0 || ngx_event_timer_alarm)
		ngx_time_update();

	if (n == 0)
		return NGX_OK;

	for (i = 0; i != ns; i++)
		post_event(ts[i]->rev, &ngx_posted_accept_events, flags,
			EV_ACCEPT);

	for (i = 0; i != nr; i++)
		post_event(tr[i]->rev, &ngx_posted_events, flags, EV_RECV);

	for (i = 0; i != nt; i++)
		post_event(tt[i]->wev, &ngx_posted_events, flags, EV_SEND);

	for (i = 0; i != ne; i++) {
		te[i]->posterr++;
		post_event(te[i]->rev, &ngx_posted_events, flags, EV_ERR);
		post_event(te[i]->wev, &ngx_posted_events, flags, EV_ERR);
	}

	return NGX_OK;
}

static ngx_int_t
tldk_init_events(ngx_cycle_t *cycle, ngx_msec_t timer)
{
	FE_TRACE("%s(cycle=%p,timer=%lu);\n",
		__func__, cycle, timer);

	/* overwrite event actions for worker process */
	ngx_event_actions = tldk_event_module.actions;
	ngx_event_flags = NGX_USE_LEVEL_EVENT;

	ngx_io = ngx_os_io;
	return NGX_OK;
}

void
tldk_dump_event_stats(void)
{
	static const char * const name[EV_NUM] = {
		"ACCEPT",
		"RECV",
		"SEND",
		"ERR",
	};

	uint32_t i;

	RTE_LOG(NOTICE, USER1, "%s(worker=%lu)={\n", __func__, ngx_worker);
	for (i = 0; i != RTE_DIM(name); i++)
		RTE_LOG(NOTICE, USER1,
			"%s[GET, POST]={%" PRIu64 ", %" PRIu64 "};\n",
			name[i], event_stat.nb_get[i], event_stat.nb_post[i]);
	RTE_LOG(NOTICE, USER1, "};\n");
}

static void
tldk_done_events(ngx_cycle_t *cycle)
{
}

static ngx_str_t tldk_name = ngx_string("tldk");

ngx_event_module_t tldk_event_module = {
	.name = &tldk_name,
	.actions = {
		.add = tldk_add_event,
		.del = tldk_del_event,
		.enable = tldk_add_event,
		.disable = tldk_del_event,
		.process_events = tldk_process_events,
		.init = tldk_init_events,
		.done = tldk_done_events,
	},
};

ngx_module_t ngx_tldk_event_module = {
	NGX_MODULE_V1,
	&tldk_event_module,    /* module context */
	NULL,                  /* module directives */
	NGX_EVENT_MODULE,      /* module type */
	NULL,                  /* init master */
	NULL,                  /* init module */
	NULL,                  /* init process */
	NULL,                  /* init thread */
	NULL,                  /* exit thread */
	NULL,                  /* exit process */
	NULL,                  /* exit master */
	NGX_MODULE_V1_PADDING
};
