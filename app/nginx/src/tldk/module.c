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

#include <rte_ethdev.h>
#include <rte_lpm6.h>
#include <rte_lpm.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_tldk.h"
#include "be.h"
#include "tldk_sock.h"

extern ngx_module_t ngx_tldk_module;

/* map from ngx_worker to corresponding TLDK ctx */
struct tldk_ctx wrk2ctx[RTE_MAX_LCORE] = {};

/* per be lcore tldk_ctx(s) */
static struct lcore_ctxs_list lc_ctxs[RTE_MAX_LCORE];

volatile int force_quit;

static void *
tldk_module_create_conf(ngx_cycle_t *cycle)
{
	tldk_conf_t *cf;

	cf = ngx_pcalloc(cycle->pool, sizeof(*cf));
	if (cf == NULL)
		return NULL;
	return cf;
}

static char *
tldk_module_init_conf(ngx_cycle_t *cycle, void *conf)
{
	tldk_conf_t *cf;

	cf = conf;
	(void)cf;
	return NGX_CONF_OK;
}

static void
fini_context(struct tldk_ctx *tcx)
{
	tle_ctx_destroy(tcx->ctx);
	rte_lpm_free(tcx->lpm4);
	rte_lpm6_free(tcx->lpm6);
	rte_mempool_free(tcx->mpool);
	rte_mempool_free(tcx->frag_mpool);
	memset(tcx, 0, sizeof(*tcx));
}

static int
init_context(struct tldk_ctx *tcx, const struct tldk_ctx_conf *cf,
		tldk_conf_t *cft)
{
	uint32_t lc, rc, sid;
	struct tle_ctx_param cprm;

	lc = cf->lcore;
	sid = rte_lcore_to_socket_id(lc);
	rc = be_lcore_lpm_init(tcx, sid, cf);
	if (rc != 0)
		return rc;

	memset(&cprm, 0, sizeof(cprm));
	cprm.socket_id = sid;
	cprm.proto = TLE_PROTO_TCP;
	cprm.max_streams = cf->nb_stream;
	cprm.max_stream_rbufs = cf->nb_rbuf;
	cprm.max_stream_sbufs = cf->nb_sbuf;
	if (cf->be_in_worker != 0)
		cprm.flags |= TLE_CTX_FLAG_ST;
	cprm.timewait = cf->tcp_timewait;
	cprm.lookup4 = be_lpm4_dst_lookup;
	cprm.lookup4_data = tcx;
	cprm.lookup6 = be_lpm6_dst_lookup;
	cprm.lookup6_data = tcx;
	cprm.secret_key.u64[0] = rte_rand();
	cprm.secret_key.u64[1] = rte_rand();

	tcx->ctx = tle_ctx_create(&cprm);
	RTE_LOG(NOTICE, USER1,
		"%s: tle_ctx_create(lcore=%u) for worker=%lu returns %p;\n",
		__func__, lc, cf->worker, tcx->ctx);
	if (tcx->ctx == NULL) {
		rte_lpm_free(tcx->lpm4);
		rte_lpm6_free(tcx->lpm6);
		return -ENOMEM;
	}

	tcx->cf = cf;

	/* create mempool for the context */
	rc = be_mpool_init(tcx);
	if (rc != 0)
		return rc;

	/* initialize queues of the device given in the context */
	rc = be_queue_init(tcx, cft);
	if (rc != 0)
		return rc;

	/* create devices of the context */
	rc = be_add_dev(tcx, cft);
	if (rc != 0)
		return rc;

	/*
	 *1.create LPMs and add to the context
	 *2.add routes for the given destinations to the context
	 */
	rc = be_dst_init(tcx, cft);
	if (rc != 0)
		return rc;

	return 0;
}

void
tldk_module_fini(ngx_cycle_t *cycle)
{
	tldk_conf_t *cf;
	uint32_t i, wrk;

	cf = (tldk_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_tldk_module);

	/* signal all launched slave lcores to stop */
	force_quit = 1;

	/* wait all slave lcores to be stopped */
	for (i = 0; i != cf->nb_ctx; i++)
		rte_eal_wait_lcore(cf->ctx[i].lcore);

	/* finish all TLDK contexts */
	for (i = 0; i != cf->nb_ctx; i++) {
		wrk = cf->ctx[i].worker;
		/* free up all tx pkt buffers of the tldk_dev 'ses
		 * of the tldk_ctx
		 */
		be_lcore_clear(wrk2ctx + wrk);
		fini_context(wrk2ctx + wrk);
	}

	/* stop all ports */
	for (i = 0; i != cf->nb_port; i++)
		be_stop_port(cf->port[i].id);
}

/* configuration sanity check */
static int
process_conf(tldk_conf_t *cf)
{
	uint32_t i, j, port_id, mask;
	uint16_t queue_id;
	const struct tldk_ctx_conf *ctx;
	struct tldk_port_conf *pcf;

	/*
	 * count the number of queues associated
	 * with each port by iterating through all tldk_ctx'ses.
	 * if same queue of the port is used in multiple tldk_ctx'ses
	 * error will be returned.
	 */
	for (i = 0; i < cf->nb_ctx; i++) {
		ctx = &cf->ctx[i];
		for (j = 0; j < ctx->nb_dev; j++) {
			port_id = ctx->dev[j].port;
			queue_id = ctx->dev[j].queue;
			pcf = &cf->port[port_id];

			if (queue_id >= MAX_PORT_QUEUE)
				return -EINVAL;

			mask = 1 << queue_id;

			if (pcf->queue_map & mask)
				/* tldk_port_conf already has the queue */
				return -EEXIST;

			pcf->queue_map |= mask;
			if (pcf->nb_queues <= queue_id)
				pcf->nb_queues = queue_id + 1;
		}
	}

	return 0;
}

static ngx_int_t
tldk_module_init(ngx_cycle_t *cycle)
{
	int32_t rc;
	uint32_t i, j, wrk, num, lc, ctx_lim;
	tldk_conf_t *cf;
	struct tldk_ctx *tcx;

	cf = (tldk_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_tldk_module);

	rc = rte_eal_init(cf->eal_argc, cf->eal_argv);
	if (rc < 0) {
		RTE_LOG(ERR, USER1,
			"%s: rte_eal_init failed with error code: %d\n",
			__func__, rc);
		return NGX_ERROR;
	}

	rc = process_conf(cf);
	if (rc < 0) {
		RTE_LOG(ERR, USER1,
			"%s: process_conf failed with error code: %d\n",
			__func__, rc);
		return NGX_ERROR;
	}

	/* port initialization */
	rc = be_port_init(cf);
	if (rc != 0) {
		RTE_LOG(ERR, USER1,
			"%s: be_port_init failed with error code: %d\n",
			__func__, rc);

		return NGX_ERROR;
	}

	/* initialise TLDK contexts */
	for (i = 0; i != cf->nb_ctx; i++) {
		wrk = cf->ctx[i].worker;
		rc = init_context(wrk2ctx + wrk, cf->ctx + i, cf);
		if (rc != 0)
			break;
	}

	if (i != cf->nb_ctx) {
		for (j = 0; j != i; j++) {
			wrk = cf->ctx[j].worker;
			fini_context(wrk2ctx + wrk);
		}
		RTE_LOG(ERR, USER1,
			"%s: init_context failed with error code: %d\n",
			__func__, rc);
		return NGX_ERROR;
	}

	/* start the ports */
	for (i = 0; i != cf->nb_port; i++) {
		RTE_LOG(NOTICE, USER1, "%s: starting port %u\n",
			__func__, cf->port[i].id);

		rc = rte_eth_dev_start(cf->port[i].id);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s: rte_eth_dev_start(%u) returned "
				"error code: %d\n",
				__func__, cf->port[i].id, rc);
			goto freectx;
		}
	}

	/* accumulate all tldk_ctx(s) that belongs to one be lcore */
	for (i = 0; i != cf->nb_ctx; i++) {
		tcx = &wrk2ctx[cf->ctx[i].worker];
		/* setup rx callbacks */
		rc = be_lcore_setup(tcx);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
					"%s: be_lcore_setup failed with error "
					"code: %d\n", __func__, rc);
			goto freectx;
		}

		if (tcx->cf->be_in_worker)
			continue;

		lc = cf->ctx[i].lcore;
		num = lc_ctxs[lc].nb_ctxs;
		ctx_lim = RTE_DIM(lc_ctxs[lc].ctxs);

		if (num < ctx_lim) {
			lc_ctxs[lc].ctxs[num] = tcx;
			lc_ctxs[lc].nb_ctxs++;
		} else {
			RTE_LOG(ERR, USER1,
				"%s: cannot assign more than supported %u "
				"ctx(s) for the given lcore %u\n",
				__func__, ctx_lim, lc);
			goto freectx;
		}
	}

	/*
	 * launch slave lcores with lcore_main_tcp to handle
	 * multiple tldk_ctx(s) of that lcore.
	 */
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (lc_ctxs[i].nb_ctxs != 0) {
			if (be_check_lcore(i) != 0 ||
					rte_eal_remote_launch(be_lcore_main,
						&lc_ctxs[i], i) != 0) {
				RTE_LOG(ERR, USER1,
						"%s: failed to launch "
						"be_lcore_main for core =%u\n",
						__func__, i);
				goto freectx;
			}
		}
	}

	return NGX_OK;

freectx:
	tldk_module_fini(cycle);
	return NGX_ERROR;
}

static int
tldk_open_listening(ngx_cycle_t *cycle, struct tldk_ctx *tcx)
{
	uint32_t i;
	ngx_listening_t *ls;
	char host[NI_MAXHOST];
	char srv[NI_MAXSERV];

	ls = cycle->listening.elts;
	for (i = 0; i != cycle->listening.nelts; i++) {

		if (ls[i].ignore != 0 || ls[i].listen == 0)
			continue;

		ngx_close_socket(ls[i].fd);
		ls[i].fd = -1;

		getnameinfo(ls[i].sockaddr, ls[i].socklen,
			host, sizeof(host), srv, sizeof(srv),
			NI_NUMERICHOST | NI_NUMERICSERV);

		ls[i].fd = tldk_open_bind_listen(tcx,
			ls[i].sockaddr->sa_family, ls[i].type,
			ls[i].sockaddr, ls[i].socklen,
			ls[i].backlog);

		RTE_LOG(NOTICE, USER1, "%s(worker=%lu): "
			"listen() for %s:%s returns %d, errno=%d;\n",
			__func__, ngx_worker, host, srv, ls[i].fd, errno);

		if (ls[i].fd == -1)
			return NGX_ERROR;
	}

	return NGX_OK;
}

static void
tldk_process_fini(ngx_cycle_t *cycle)
{
	struct tldk_ctx *tcx;
	tcx =  wrk2ctx + ngx_worker;

	tldk_stbl_fini();
	if (tcx->cf->be_in_worker != 0)
		be_lcore_clear(tcx);
}


static ngx_int_t
tldk_process_init(ngx_cycle_t *cycle)
{
	ngx_event_conf_t  *ecf;
	int32_t rc;

	if (ngx_process != NGX_PROCESS_WORKER)
		return NGX_OK;

	rc = tldk_stbl_init(cycle, wrk2ctx + ngx_worker);
	if (rc != 0)
		return NGX_ERROR;

	rc = tldk_open_listening(cycle, wrk2ctx + ngx_worker);
	if (rc != 0)
		return NGX_ERROR;

	/* use tldk event module from now on*/
	ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);
	ecf->use = ngx_tldk_event_module.ctx_index;

	return NGX_OK;
}

static char *
tldk_conf_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *rv;
	ngx_conf_t save;

	save = *cf;
	cf->handler = tldk_block_parse;
	cf->handler_conf = conf;
	rv = ngx_conf_parse(cf, NULL);
	*cf = save;

	return rv;
}

static char *
tldk_ctx_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *rv;
	tldk_conf_t *tcf;
	struct tldk_ctx_conf *tcx;
	ngx_conf_t save;

	tcf = (tldk_conf_t *)((void **)conf)[0];
	if (tcf->nb_ctx >= RTE_DIM(tcf->ctx))
		return NGX_CONF_ERROR;

	/* setup default non-zero values, if any */
	tcx = tcf->ctx + tcf->nb_ctx;
	tcx->tcp_timewait = TLE_TCP_TIMEWAIT_DEFAULT;

	save = *cf;
	cf->handler = tldk_ctx_parse;
	cf->handler_conf = conf;
	rv = ngx_conf_parse(cf, NULL);
	*cf = save;

	if (rv == NGX_CONF_OK)
		tcf->nb_ctx++;

	return rv;
}

/*
 * define NGX TLDK module.
 */

static ngx_command_t tldk_commands[] = {

	{
		.name = ngx_string("tldk_main"),
		.type = NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
		.set = tldk_conf_block,
	},
	{
		.name = ngx_string("tldk_ctx"),
		.type = NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
		.set = tldk_ctx_block,
	},
	ngx_null_command,
};

static ngx_core_module_t tldk_module_ctx = {
	ngx_string("tldk"),
	tldk_module_create_conf,
	tldk_module_init_conf
};

ngx_module_t ngx_tldk_module = {
	NGX_MODULE_V1,
	&tldk_module_ctx,             /* module context */
	tldk_commands,                /* module directives */
	NGX_CORE_MODULE,              /* module type */
	NULL,                         /* init master */
	tldk_module_init,             /* init module */
	tldk_process_init,            /* init process */
	NULL,                         /* init thread */
	NULL,                         /* exit thread */
	tldk_process_fini,            /* exit process */
	tldk_module_fini,             /* exit master */
	NGX_MODULE_V1_PADDING
};
