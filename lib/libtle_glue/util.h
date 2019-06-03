/*
 * Copyright (c) 2018 Ant Financial Services Group.
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

#ifndef _TLE_GLUE_UTIL_H_
#define _TLE_GLUE_UTIL_H_

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tle_tcp.h>
#include <tle_udp.h>

#include "../libtle_l4p/tcp_stream.h"

#include "fd.h"
#include "ctx.h"
#include "sock.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void *
xstrdup(const void *old)
{
	void *new = strdup(old);
	if (unlikely(new == NULL))
		rte_panic("Failed to strdup");
	return new;
}

static inline void *
xmalloc(size_t size)
{
	void *p = malloc(size ? size : 1);
	if (p == NULL)
		rte_panic("Failed to malloc");
	return p;
}

static inline char *
xvasprintf(const char *format, va_list args)
{
	va_list args2;
	size_t needed;
	char *s;

	va_copy(args2, args);
	needed = vsnprintf(NULL, 0, format, args);

	s = xmalloc(needed + 1);

	vsnprintf(s, needed + 1, format, args2);
	va_end(args2);

	return s;
}

static inline char *
xasprintf(const char *format, ...)
{
    va_list args;
    char *s;

    va_start(args, format);
    s = xvasprintf(format, args);
    va_end(args);

    return s;
}

static inline char **
grow_argv(char **argv, size_t cur_siz, size_t grow_by)
{
	char **p;

	p = realloc(argv, sizeof(char *) * (cur_siz + grow_by));
	if (unlikely(p == NULL))
		rte_panic("Failed to grow argv");
	return p;
}

static inline void
release_argv(int argc, char **argv_to_release, char **argv)
{
	int i;

	for (i = 0; i < argc; ++i)
		free(argv_to_release[i]);

	free(argv_to_release);
	free(argv);
}

static inline void
sock_alloc_events(struct sock *so)
{
	so->erev = tle_event_alloc(CTX(so)->ereq, so);
	so->rxev = tle_event_alloc(CTX(so)->rxeq, so);
	so->txev = tle_event_alloc(CTX(so)->txeq, so);
	tle_event_active(so->erev, TLE_SEV_DOWN);
	tle_event_active(so->rxev, TLE_SEV_DOWN);
	tle_event_active(so->txev, TLE_SEV_DOWN);
}

static inline void
sock_active_events(struct sock *so)
{
	tle_event_active(so->erev, TLE_SEV_DOWN);
	tle_event_active(so->rxev, TLE_SEV_DOWN);
	tle_event_active(so->txev, TLE_SEV_DOWN);
}

static inline const struct in6_addr*
select_local_addr_v6(const struct sockaddr *remote, struct glue_ctx *ctx)
{
	/* todo: implement route table to decide local address */

	if (IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)remote)
			->sin6_addr))
		return &in6addr_loopback;
	else
		return &ctx->ipv6;
}

static inline in_addr_t
select_local_addr(const struct sockaddr *remote, struct glue_ctx *ctx)
{
	/* todo: implement route table to decide local address */
	in_addr_t remote_addr;

	remote_addr = ((const struct sockaddr_in*)remote)->sin_addr.s_addr;
	if (remote_addr == htonl(INADDR_LOOPBACK))
		return htonl(INADDR_LOOPBACK);
	else
		return ctx->ipv4;
}

/* transform an IPv4 address(in struct sockaddr_in) to
 * an IPv4 mapped IPv6 address(in struct sockaddr_in6) */
static inline void
trans_4mapped6_addr(struct sockaddr *addr)
{
	struct sockaddr_in6 *addr6;

	if (addr->sa_family != AF_INET)
		return;

	addr6 = (struct sockaddr_in6*)addr;
	addr6->sin6_family = AF_INET6;
	addr6->sin6_addr.s6_addr32[0] = 0;
	addr6->sin6_addr.s6_addr32[1] = 0;
	addr6->sin6_addr.s6_addr32[2] = 0xffff0000;
	addr6->sin6_addr.s6_addr32[3] = ((struct sockaddr_in*)addr)->sin_addr.s_addr;
}

/* transform an IPv4 mapped IPv6 address(in struct sockaddr_in6) to
 * an IPv4 address(in struct sockaddr_in) */
static inline void
retrans_4mapped6_addr(struct sockaddr_storage * addr)
{
	struct in6_addr* addr6;
	if (addr->ss_family == AF_INET)
		return;

	addr6 = &((struct sockaddr_in6*)addr)->sin6_addr;
	if(IN6_IS_ADDR_V4MAPPED(addr6)) {
		addr->ss_family = AF_INET;
		((struct sockaddr_in*)addr)->sin_addr.s_addr = addr6->__in6_u.__u6_addr32[3];
	}
}

static inline struct tle_stream *
open_bind(struct sock *so, const struct sockaddr *local,
	  const struct sockaddr *remote)
{
	struct tle_stream *s;
	struct sockaddr_storage *l, *r;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	struct tle_tcp_stream_param pt = {0};
	struct tle_udp_stream_param pu = {0};

	if (so->rxev == NULL)
		sock_alloc_events(so);
	else
		sock_active_events(so);

	if (IS_TCP(so)) {
		pt.option = so->option.raw;
		l = &pt.addr.local;
		r = &pt.addr.remote;
		pt.cfg.err_ev = so->erev;
		pt.cfg.recv_ev = so->rxev;
		pt.cfg.send_ev = so->txev;
	} else {
		pu.option = so->option.raw;
		l = &pu.local_addr;
		r = &pu.remote_addr;
		pu.recv_ev = so->rxev;
		pu.send_ev = so->txev;
	}

	if (remote) {
		memcpy(r, remote, get_sockaddr_len_family(remote->sa_family));
		retrans_4mapped6_addr(r);
		if(r->ss_family == AF_INET) {
			addr4 = (struct sockaddr_in*)r;
			if (addr4->sin_addr.s_addr == 0)
				addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		} else {
			addr6 = (struct sockaddr_in6*)r;
			if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr))
				rte_memcpy(&addr6->sin6_addr, &in6addr_loopback,
						sizeof(struct in6_addr));
		}
	}

	if (local) {
		memcpy(l, local, get_sockaddr_len_family(local->sa_family));
		retrans_4mapped6_addr(l);
	} else {
		l->ss_family = r->ss_family;
	}

	if (!remote)
		r->ss_family = l->ss_family;

	/* Endpoints of stream have different socket families */
	if (r->ss_family != l->ss_family) {
		if (l->ss_family == AF_INET) {
			errno = EINVAL;
			return NULL;
		} else {
			/* if local addr is unbound, convert into remote family */
			if (IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6*)l)->sin6_addr)) {
				l->ss_family = AF_INET;
				((struct sockaddr_in*)l)->sin_addr.s_addr = 0;
			} else {
				errno = ENETUNREACH;
				return NULL;
			}
		}
	}

	if (l->ss_family == AF_INET) {
		addr4 = (struct sockaddr_in*)l;
		if (addr4->sin_addr.s_addr == htonl(INADDR_ANY) && remote) {
			addr4->sin_addr.s_addr =
				select_local_addr((struct sockaddr*)r, CTX(so));
			if (addr4->sin_addr.s_addr == htonl(INADDR_ANY)) {
				errno = EADDRNOTAVAIL;
				return NULL;
			}
		}
		else if (addr4->sin_addr.s_addr != CTX(so)->ipv4 &&
				addr4->sin_addr.s_addr != htonl(INADDR_LOOPBACK) &&
				addr4->sin_addr.s_addr != htonl(INADDR_ANY)) {
			errno = EADDRNOTAVAIL;
			return NULL;
		}
	} else {
		addr6 = (struct sockaddr_in6 *)l;
		if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) && remote) {
			memcpy(&addr6->sin6_addr,
			       select_local_addr_v6((struct sockaddr*)r, CTX(so)),
			       sizeof(struct in6_addr));
			if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr)) {
				errno = EADDRNOTAVAIL;
				return NULL;
			}
		}
		else if (memcmp(&addr6->sin6_addr, &CTX(so)->ipv6,
				sizeof(struct in6_addr)) != 0 &&
				(!IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr)) &&
				(!IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr))) {
			errno = EADDRNOTAVAIL;
			return NULL;
		}
	}

	if (IS_TCP(so))
		s = tle_tcp_stream_open(CTX(so)->tcp_ctx, &pt);
	else {
		if (so->s == NULL)
			s = tle_udp_stream_open(CTX(so)->udp_ctx, &pu);
		else
			s = tle_udp_stream_set(so->s, CTX(so)->udp_ctx, &pu);
	}

	if (s == NULL)
		errno = rte_errno;

	return s;
}

static inline struct tle_stream *
open_bind_listen(struct sock *so, const struct sockaddr *local)
{
	struct tle_stream *s = open_bind(so, local, NULL);

	if (s == NULL)
		return NULL;

	if (tle_tcp_stream_listen(s) != 0) {
		tle_tcp_stream_close(s);
		return NULL;
	}

	return s;
}

uint32_t get_socket_id(void);

#ifdef __cplusplus
}
#endif

#endif /*_TLE_GLUE_UTIL_H_ */
