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

#include <rte_malloc.h>
#include <rte_errno.h>

struct tldk_sock_stat {
	uint64_t nb_accept;
	uint64_t nb_close;
	uint64_t nb_readv;
	uint64_t nb_recv;
	uint64_t nb_setopts;
	uint64_t nb_shutdown;
	uint64_t nb_writev;
};

static struct tldk_sock_stat sock_stat;

/* One socket/file table per worker */
struct tldk_stbl stbl = {
	.snum = 0,
};

static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
static int (*real_close)(int);
static ssize_t (*real_readv)(int, const struct iovec *, int);
static ssize_t (*real_recv)(int, void *, size_t, int);
static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
static int (*real_shutdown)(int, int);
static ssize_t (*real_writev)(int, const struct iovec *, int);

static inline uint32_t
get_socks(struct tldk_sock_list *list, struct tldk_sock *rs[],
	uint32_t num)
{
	struct tldk_sock *s;
	uint32_t i, n;

	n = RTE_MIN(list->num, num);
	for (i = 0, s = LIST_FIRST(&list->head);
			i != n;
			i++, s = LIST_NEXT(s, link)) {
		rs[i] = s;
	}

	/* we retrieved all free entries */
	if (s == NULL)
		LIST_INIT(&list->head);
	else
		LIST_FIRST(&list->head) = s;

	list->num -= n;
	return n;
}

static inline struct tldk_sock *
get_sock(struct tldk_sock_list *list)
{
	struct tldk_sock *s;

	if (get_socks(list, &s, 1) != 1)
		return NULL;

	return s;
}

static inline void
put_socks(struct tldk_sock_list *list, struct tldk_sock *fs[], uint32_t num)
{
	uint32_t i;

	for (i = 0; i != num; i++)
		LIST_INSERT_HEAD(&list->head, fs[i], link);
	list->num += num;
}

static inline void
put_sock(struct tldk_sock_list *list, struct tldk_sock *s)
{
	put_socks(list, &s, 1);
}

static inline void
rem_sock(struct tldk_sock_list *list, struct tldk_sock *s)
{
	LIST_REMOVE(s, link);
	list->num--;
}

static void
term_sock(struct tldk_sock *ts)
{
	tle_event_idle(ts->erev);
	tle_event_idle(ts->rxev);
	tle_event_idle(ts->txev);
	tle_tcp_stream_close(ts->s);
	ts->s = NULL;
	ts->posterr = 0;
}

static int32_t
close_sock(struct tldk_sock *ts)
{
	if (ts->s == NULL)
		return EBADF;
	term_sock(ts);
	rem_sock(&stbl.use, ts);
	put_sock(&stbl.free, ts);
	return 0;
}

static void
dump_sock_stats(void)
{
	RTE_LOG(NOTICE, USER1, "%s(worker=%lu)={\n"
		"nb_accept=%" PRIu64 ";\n"
		"nb_close=%" PRIu64 ";\n"
		"nb_readv=%" PRIu64 ";\n"
		"nb_recv=%" PRIu64 ";\n"
		"nb_setopts=%" PRIu64 ";\n"
		"nb_shutdown=%" PRIu64 ";\n"
		"nb_writev=%" PRIu64 ";\n"
		"};\n",
		__func__,
		ngx_worker,
		sock_stat.nb_accept,
		sock_stat.nb_close,
		sock_stat.nb_readv,
		sock_stat.nb_recv,
		sock_stat.nb_setopts,
		sock_stat.nb_shutdown,
		sock_stat.nb_writev);
}

void
tldk_stbl_fini(void)
{
	dump_sock_stats();
	tldk_dump_event_stats();
	rte_free(stbl.sd);
	tle_evq_destroy(stbl.txeq);
	tle_evq_destroy(stbl.rxeq);
	tle_evq_destroy(stbl.ereq);
	tle_evq_destroy(stbl.syneq);
}

#define INIT_FUNC(func) do { \
	real_##func = dlsym(RTLD_NEXT, #func); \
	RTE_ASSERT(real_##func); \
} while (0)

static void __attribute__((constructor))
stub_init(void)
{
	INIT_FUNC(accept4);
	INIT_FUNC(close);
	INIT_FUNC(readv);
	INIT_FUNC(recv);
	INIT_FUNC(setsockopt);
	INIT_FUNC(shutdown);
	INIT_FUNC(writev);
}

#undef INIT_FUNC

int
tldk_stbl_init(const ngx_cycle_t *cycle, const struct tldk_ctx *tc)
{
	uint32_t i, lc, sid, sn;
	size_t sz;
	struct tle_evq_param eprm;
	struct rlimit rlim;

	lc = tc->cf->lcore;
	sn = tc->cf->nb_stream;
	sid = rte_lcore_to_socket_id(lc);

	if (sn < cycle->listening.nelts + cycle->connection_n)
		return -EINVAL;

	if (getrlimit(RLIMIT_NOFILE, &rlim) != 0)
		return -errno;

	stbl.nosd = rlim.rlim_max;

	/* allocate event queues */

	memset(&eprm, 0, sizeof(eprm));
	eprm.socket_id = sid;
	eprm.max_events = sn;

	stbl.syneq = tle_evq_create(&eprm);
	stbl.ereq = tle_evq_create(&eprm);
	stbl.rxeq = tle_evq_create(&eprm);
	stbl.txeq = tle_evq_create(&eprm);

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u, worker=%lu): "
		"synevq=%p, erevq=%p, rxevq=%p, txevq=%p\n",
		__func__, lc, ngx_worker,
		stbl.syneq, stbl.ereq, stbl.rxeq, stbl.txeq);
	if (stbl.syneq == NULL || stbl.ereq == NULL || stbl.rxeq == NULL ||
			stbl.txeq == NULL)
		return -ENOMEM;

	LIST_INIT(&stbl.lstn.head);
	LIST_INIT(&stbl.free.head);
	LIST_INIT(&stbl.use.head);

	sz = sn * sizeof(*stbl.sd);
	stbl.sd = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		rte_lcore_to_socket_id(lc));

	if (stbl.sd == NULL) {
		RTE_LOG(ERR, USER1, "%s(lcore=%u, worker=%lu): "
			"failed to allocate %zu bytes\n",
			__func__, lc, ngx_worker, sz);
		return -ENOMEM;
	}

	stbl.snum = sn;

	/* init listen socks */
	for (i = 0; i != cycle->listening.nelts; i++) {
		stbl.sd[i].rxev = tle_event_alloc(stbl.syneq, stbl.sd + i);
		stbl.sd[i].txev = tle_event_alloc(stbl.txeq, stbl.sd + i);
		stbl.sd[i].erev = tle_event_alloc(stbl.ereq, stbl.sd + i);
		put_sock(&stbl.lstn, stbl.sd + i);
	}

	/* init worker connection socks */
	for (; i != sn; i++) {
		stbl.sd[i].rxev = tle_event_alloc(stbl.rxeq, stbl.sd + i);
		stbl.sd[i].txev = tle_event_alloc(stbl.txeq, stbl.sd + i);
		stbl.sd[i].erev = tle_event_alloc(stbl.ereq, stbl.sd + i);
		put_sock(&stbl.free, stbl.sd + i);
	}

	return 0;
}

int
tldk_open_bind_listen(struct tldk_ctx *tcx, int domain, int type,
	const struct sockaddr *addr, socklen_t addrlen, int backlog)
{
	int32_t rc;
	struct tldk_sock *ts;
	struct tle_tcp_stream_param sprm;

	ts = get_sock(&stbl.lstn);
	if (ts == NULL) {
		errno = ENOBUFS;
		return -1;
	}

	tle_event_active(ts->erev, TLE_SEV_DOWN);
	tle_event_active(ts->rxev, TLE_SEV_DOWN);
	tle_event_active(ts->txev, TLE_SEV_DOWN);

	/* setup stream parameters */

	memset(&sprm, 0, sizeof(sprm));

	sprm.cfg.err_ev = ts->erev;
	sprm.cfg.recv_ev = ts->rxev;
	sprm.cfg.send_ev = ts->txev;

	memcpy(&sprm.addr.local, addr, addrlen);
	sprm.addr.remote.ss_family = sprm.addr.local.ss_family;

	ts->s = tle_tcp_stream_open(tcx->ctx, &sprm);
	if (ts->s != NULL)
		rc = tle_tcp_stream_listen(ts->s);
	else
		rc = -rte_errno;

	if (rc != 0) {
		term_sock(ts);
		put_sock(&stbl.lstn, ts);
		errno = -rc;
		return -1;
	}

	return SOCK_TO_SD(ts);
}

/*
 * socket API
 */

int
close(int sd)
{
	int32_t rc;
	struct tldk_sock *ts;

	FE_TRACE("worker#%lu: %s(%d);\n",
		ngx_worker, __func__, sd);

	ts = sd_to_sock(sd);
	if (ts == NULL)
		return real_close(sd);

	sock_stat.nb_close++;

	rc = close_sock(ts);
	if (rc != 0) {
		errno =-rc;
		return -1;
	}
	return 0;
}

int
shutdown(int sd, int how)
{
	struct tldk_sock *ts;

	FE_TRACE("worker#%lu: %s(%d, %#x);\n",
		ngx_worker, __func__, sd, how);

	ts = sd_to_sock(sd);
	if (ts == NULL)
		return real_shutdown(sd, how);

	sock_stat.nb_shutdown++;

	errno = ENOTSUP;
	return -1;
}


int
accept4(int sd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	uint32_t n, slen;
	struct tle_stream *s;
	struct tldk_sock *cs, *ts;
	struct tle_tcp_stream_cfg prm;
	struct tle_tcp_stream_addr sa;

	FE_TRACE("worker#%lu: %s(%d, %p, %p, %#x);\n",
		ngx_worker, __func__, sd, addr, addrlen, flags);

	ts = sd_to_sock(sd);
	if (ts == NULL)
		return real_accept4(sd, addr, addrlen, flags);
	else if (ts->s == NULL) {
		errno = EBADF;
		return -1;
	}

	sock_stat.nb_accept++;

	n = ts->acpt.num;
	if (n == 0) {
		n = tle_tcp_stream_accept(ts->s, ts->acpt.buf,
			RTE_DIM(ts->acpt.buf));
		if (n == 0) {
			errno = EAGAIN;
			return -1;
		}
	}

	s = ts->acpt.buf[n - 1];
	ts->acpt.num = n - 1;

	tle_event_raise(ts->rxev);

	cs = get_sock(&stbl.free);
	if (cs == NULL) {
		tle_tcp_stream_close(s);
		errno = ENOBUFS;
		return -1;
	}

	cs->s = s;
	put_sock(&stbl.use, cs);

	tle_event_active(cs->erev, TLE_SEV_DOWN);
	tle_event_active(cs->rxev, TLE_SEV_DOWN);
	tle_event_active(cs->txev, TLE_SEV_DOWN);

	memset(&prm, 0, sizeof(prm));
	prm.recv_ev = cs->rxev;
	prm.send_ev = cs->txev;
	prm.err_ev = cs->erev;
	tle_tcp_stream_update_cfg(&s, &prm, 1);

	if (tle_tcp_stream_get_addr(s, &sa) == 0) {

		if (sa.remote.ss_family == AF_INET)
			slen = sizeof(struct sockaddr_in);
		else if (sa.remote.ss_family == AF_INET6)
			slen = sizeof(struct sockaddr_in6);
		else
			slen = 0;

		slen = RTE_MIN(slen, *addrlen);
		memcpy(addr, &sa.remote, slen);
		*addrlen = slen;
	}

	return SOCK_TO_SD(cs);
}

ssize_t
recv(int sd, void *buf, size_t len, int flags)
{
	ssize_t sz;
	struct tldk_sock *ts;
	struct iovec iv;

	FE_TRACE("worker#%lu: %s(%d, %p, %zu, %#x);\n",
		ngx_worker, __func__, sd, buf, len, flags);

	ts = sd_to_sock(sd);
	if (ts == NULL)
		return real_recv(sd, buf, len, flags);
	else if (ts->s == NULL) {
		errno = EBADF;
		return -1;
	}

	sock_stat.nb_recv++;

	iv.iov_base = buf;
	iv.iov_len = len;

	sz = tle_tcp_stream_readv(ts->s, &iv, 1);
	if (sz < 0)
		errno = rte_errno;
	else if (sz == 0 && ts->posterr == 0) {
		errno = EAGAIN;
		sz = -1;
	}

	FE_TRACE("worker#%lu: %s(%d, %p, %zu, %#x) returns %zd;\n",
		ngx_worker, __func__, sd, buf, len, flags, sz);
	return sz;
}

ssize_t
readv(int sd, const struct iovec *iov, int iovcnt)
{
	ssize_t sz;
	struct tldk_sock *ts;
	struct tldk_ctx *tcx;

	FE_TRACE("worker#%lu: %s(%d, %p, %d);\n",
		ngx_worker, __func__, sd, iov, iovcnt);

	tcx =  wrk2ctx + ngx_worker;
	ts = sd_to_sock(sd);
	if (ts == NULL)
		return real_readv(sd, iov, iovcnt);
	else if (ts->s == NULL || tcx == NULL) {
		errno = EBADF;
		return -1;
	}

	sock_stat.nb_readv++;

	sz = tle_tcp_stream_readv(ts->s, iov, iovcnt);
	if (sz < 0)
		errno = rte_errno;
	else if (sz == 0 && ts->posterr == 0) {
		errno = EAGAIN;
		sz = -1;
	}

	FE_TRACE("worker#%lu: %s(%d, %p, %d) returns %zd;\n",
		ngx_worker, __func__, sd, iov, iovcnt, sz);
	return sz;
}

ssize_t
writev(int sd, const struct iovec *iov, int iovcnt)
{
	ssize_t sz;
	struct tldk_sock *ts;
	struct tldk_ctx *tcx;

	FE_TRACE("worker#%lu: %s(%d, %p, %d);\n",
		ngx_worker, __func__, sd, iov, iovcnt);

	tcx =  wrk2ctx + ngx_worker;
	ts = sd_to_sock(sd);
	if (ts == NULL)
		return real_writev(sd, iov, iovcnt);
	else if (ts->s == NULL || tcx == NULL) {
		errno = EBADF;
		return -1;
	}

	sock_stat.nb_writev++;

	sz = tle_tcp_stream_writev(ts->s, tcx->mpool, iov, iovcnt);
	if (sz < 0)
		errno = rte_errno;

	FE_TRACE("worker#%lu: %s(%d, %p, %d) returns %zd;\n",
		ngx_worker, __func__, sd, iov, iovcnt, sz);
	return sz;
}

int
setsockopt(int sd, int level, int optname, const void *optval, socklen_t optlen)
{
	struct tldk_sock *ts;

	FE_TRACE("worker#%lu: %s(%d, %#x, %#x, %p, %d);\n",
		ngx_worker, __func__, sd, level, optname, optval, optlen);

	ts = sd_to_sock(sd);
	if (ts == NULL)
		return real_setsockopt(sd, level, optname, optval, optlen);
	else if (ts->s == NULL) {
		errno = EBADF;
		return -1;
	}

	return 0;
}
