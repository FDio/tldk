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
#ifndef _SOCK_H_
#define _SOCK_H_

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tle_event.h>
#include <tle_ctx.h>

#include "ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned int def_sndbuf;
extern unsigned int def_rcvbuf;

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif

#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT	30
#endif

struct sock;

struct proto {
	int (*setsockopt)(struct sock *sk, int optname, const void *optval,
			  socklen_t optlen);
	int (*getsockopt)(struct sock *sk, int optname, void *optval,
			  socklen_t *option);
	int (*getname)(struct sock *sk, struct sockaddr *addr, int peer);

	int (*bind)(struct sock *sk, const struct sockaddr *addr);
	int (*listen)(struct sock *sk, int backlog);
	int (*connect)(struct sock *sk, const struct sockaddr *addr);
	int (*accept)(struct sock *sk, struct sockaddr *addr,
		      socklen_t *addrlen, int flags);

	ssize_t (*recv)(struct tle_stream *s, struct rte_mbuf *pkt[],
			uint16_t num, struct sockaddr *addr);
	ssize_t (*send)(struct sock *sk, struct rte_mbuf *pkt[],
			uint16_t num, const struct sockaddr *dst_addr);

	ssize_t (*readv)(struct tle_stream *s, struct msghdr *msg, int flags);
	ssize_t (*writev)(struct sock *sk, const struct iovec *iov,
			  int iovcnt, const struct sockaddr *dst_addr);

	int (*shutdown)(struct sock *sk, int how);
	int (*close)(struct tle_stream *s);

	void (*update_cfg)(struct sock *sk);

	char name[32];
};

enum {
	PROTO_TCP,
	PROTO_UDP
};

#define RECV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

extern struct proto udp_prot;
extern struct proto tcp_prot;
extern struct proto *supported_proto_ops[];

struct sock {
	int		    fd;
	uint32_t	    cid:8,     /* ctx id for indexing ctx_array */
			    domain:8,  /* for AF_INET, AF_INET6 */
			    proto:8,   /* PROTO_TCP, PROTO_UDP */
			    valid:1,
			    epoll:1,
			    ubind:1,
			    ubindany:1,
			    nonblock:1,
			    tcp_connected:1,
			    shutdown:2;
	struct tle_stream   *s;
	struct rte_mbuf     *rx_left;
	tle_stream_options_t option;
	union {
		struct epoll_event event;
		int	    shadow_efd;
	};
	struct tle_event    txev;
	struct tle_event    rxev;
	struct tle_event    erev;
} __rte_cache_aligned;

#define CTX(so)    (&ctx_array[so->cid])
#define OPS(so)    (supported_proto_ops[so->proto])
#define IS_TCP(so) (so->proto == PROTO_TCP)
#define IS_UDP(so) (so->proto == PROTO_UDP)

static inline int
is_nonblock(struct sock *so, int flags)
{
	return (flags & MSG_DONTWAIT) || so->nonblock;
}

static inline struct tle_ctx *
get_sock_ctx(struct sock *so)
{
	if (IS_TCP(so))
		return CTX(so)->tcp_ctx;
	else
		return CTX(so)->udp_ctx;
}

static inline size_t
get_sockaddr_len(sa_family_t family)
{
	switch (family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	case AF_UNSPEC:
		return sizeof(sa_family_t);
	default:
		return 0;
	}
}

#ifdef __cplusplus
}
#endif

#endif /*_SOCK_H_ */
