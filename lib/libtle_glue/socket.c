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

#include "sym.h"

#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "tle_glue.h"
#include "fd.h"
#include "log.h"
#include "util.h"
#include "internal.h"
#include "sock.h"

struct proto *supported_proto_ops[] = {
	[PROTO_TCP] = &tcp_prot,
	[PROTO_UDP] = &udp_prot,
};

/* for setup, settings, and destroy */
int PRE(socket)(int domain, int type, int protocol)
{
	int fd;
	struct sock *so;
	
	if ((domain != AF_INET && domain != AF_INET6) ||
	    (type != SOCK_STREAM && type != SOCK_DGRAM))
		return k_socket(domain, type, protocol);

	if (domain == AF_INET) {
		if (default_ctx->ipv4 == 0 && !default_ctx->lo4_enabled) {
			errno = EAFNOSUPPORT;
			return -1;
		}
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&default_ctx->ipv6) &&
		    !default_ctx->lo6_enabled) {
			errno = EAFNOSUPPORT;
			return -1;
		}
	}

	fd = get_unused_fd();
	if (fd < 0) {
		errno = ENFILE;
		return -1;
	}
	so = fd2sock(fd);
	so->cid = get_cid();
	if (type == SOCK_STREAM)
		so->proto = PROTO_TCP;
	else /* type == SOCK_DGRAM */
		so->proto = PROTO_UDP;

	so->domain = domain;
	so->option.raw = 0;
	so->option.mulloop = 1;
	so->option.multtl = 1;
	if (type == SOCK_STREAM) {
		so->option.tcpquickack = 1;
		/* linux default value: 2 hours */
		so->option.keepidle = 2 * 60 * 60;
		/* linux default value: 75seconds */
		so->option.keepintvl = 75;
		/* linux default value: 9 */
		so->option.keepcnt = 9;
	}

	sock_alloc_events(so);

	GLUE_DEBUG("socket fd = %d", fd);
	printf("socket fd = %d", fd);
	return fd;
}

int PRE(bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_bind(sockfd, addr, addrlen);

	so = fd2sock(sockfd);
	if (so->s) {
		/* The socket is already bound to an address */
		errno = EINVAL;
		return -1;
	}

	if (addrlen < get_sockaddr_len(addr->sa_family)) {
		errno = EINVAL;
		return -1;
	}

	so->cid = get_cid(); /* allow ctx reset as stream is null */
	if (OPS(so)->bind)
		return OPS(so)->bind(so, addr);

	errno = EOPNOTSUPP;
	return -1;
}

int PRE(listen)(int sockfd, int backlog)
{
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_listen(sockfd, backlog);

	so = fd2sock(sockfd);

	if (OPS(so)->listen)
		return OPS(so)->listen(so, backlog);

	errno = EOPNOTSUPP;
	return -1;
}

int PRE(accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_accept(sockfd, addr, addrlen);

	so = fd2sock(sockfd);
	if (OPS(so)->accept)
		return OPS(so)->accept(so, addr, addrlen, 0);

	errno = EOPNOTSUPP;
	return -1;
}

int PRE(accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int fd;
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_accept4(sockfd, addr, addrlen, flags);

	fd = PRE(accept)(sockfd, addr, addrlen);

	/* inherit NONBLOCK flag */
	if (fd >= 0 && (flags & SOCK_NONBLOCK)) {
		so = fd2sock(fd);
		so->nonblock = 1;
	}

	return fd;
}

int PRE(connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_connect(sockfd, addr, addrlen);

	if (addrlen < get_sockaddr_len(addr->sa_family)) {
		errno = EINVAL;
		return -1;
	}

	so = fd2sock(sockfd);
	so->cid = get_cid();

	if (!(is_nonblock(so, 0)))
		mac_check(CTX(so), addr);

	if (OPS(so)->connect)
		return OPS(so)->connect(so, addr);

	errno = EOPNOTSUPP;
	return -1;
}

unsigned int def_sndbuf = 212992;
unsigned int def_rcvbuf = 212992;
static struct linger ling;

int PRE(getsockopt)(int sockfd, int level, int optname,
		    void *optval, socklen_t *optlen)
{
	struct sock *so;
	union {
		int val;
		uint64_t val64;
		struct linger ling;
		struct timeval tm;
	} *p = optval;


	if (is_kernel_fd(sockfd))
		return k_getsockopt(sockfd, level, optname, optval, optlen);

	if (!optval && !optlen)
		return -1;

	so = fd2sock(sockfd);

	switch (level) {
	case IPPROTO_IP:
		switch (optname) {
		case IP_OPTIONS:
			*optlen = 0;
			return 0;
		case IP_MULTICAST_LOOP:
			p->val = so->option.mulloop;
			return 0;
		case IP_MULTICAST_TTL:
			p->val = so->option.multtl;
			return 0;
		}
		break;
	case IPPROTO_IPV6:
		switch (optname) {
		case IPV6_V6ONLY:
			p->val = so->option.ipv6only;
			return 0;
		}
		break;
	case SOL_SOCKET:
		/* man socket(7), see /usr/include/asm-generic/socket.h */
		switch (optname) {
		case SO_REUSEADDR:
			p->val = so->option.reuseaddr;
			return 0;
		case SO_REUSEPORT:
			p->val = so->option.reuseport;
			return 0;
		case SO_ERROR:
			if (TLE_SEV_DOWN == tle_event_state(&so->erev))
				p->val = 0;
			else
				p->val = ECONNREFUSED;
				/* fixe me: ETIMEDOUT */
			return 0;
		case SO_LINGER:
			p->ling.l_onoff = 0;
			return 0;
		case SO_SNDBUF:
			p->val = def_sndbuf;
			return 0;
		case SO_RCVBUF:
			p->val = def_rcvbuf;
			return 0;
		case SO_ACCEPTCONN:
			if (IS_TCP(so)
			    && TCP_STREAM(so->s)->tcb.state == TCP_ST_LISTEN)
				p->val = 1;
			else
				p->val = 0;
			return 0;
		case SO_KEEPALIVE:
			p->val = so->option.keepalive;
			return 0;
		case SO_TYPE:
			if (IS_TCP(so))
				p->val = SOCK_STREAM;
			else
				p->val = SOCK_DGRAM;
			return 0;
		case SO_OOBINLINE:
			p->val = so->option.oobinline;
			return 0;
		case SO_TIMESTAMP:
			p->val = so->option.timestamp;
			return 0;
		case SO_PROTOCOL:
			if (so->proto == PROTO_TCP)
				p->val = IPPROTO_TCP;
			else
				p->val = IPPROTO_UDP;
			return 0;
		default:
			break;
		}

		break;
	case SOL_TCP:
	case SOL_UDP:
		return OPS(so)->getsockopt(so, optname, optval, optlen);
	}

	GLUE_LOG(WARNING, "getsockopt(%d) with level = %d, optname = %d",
		 sockfd, level, optname);
	errno = EOPNOTSUPP;
	return -1;
}

int PRE(setsockopt)(int sockfd, int level, int optname,
		    const void *optval, socklen_t optlen)
{
	int val;
	struct sock *so;
	if (is_kernel_fd(sockfd))
		return k_setsockopt(sockfd, level, optname, optval, optlen);
	if (!optval && !optlen)
		return -1;

	val = 0; /* just to make compiler happy */
	switch (optlen) {
	case sizeof(char):
		val = *(const char *)optval;
		break;
	case sizeof(int):
		val = *(const int *)optval;
		break;
	}

	so = fd2sock(sockfd);

	switch (level) {
	case IPPROTO_IP:
		switch (optname) {
		case IP_RECVERR:
			/* needed by netperf */
			return 0;
		case IP_MULTICAST_LOOP:
			if (val == 0)
				so->option.mulloop = 0;
			else
				so->option.mulloop = 1;
			if (so->s != NULL)
				so->s->option.mulloop = so->option.mulloop;
			return 0;
		case IP_MULTICAST_TTL:
			if (val > 255 || val < -1) {
				errno = EINVAL;
				return -1;
			}
			if(val == -1) {
				val = 1;
			}
			so->option.multtl = val;
			if (so->s != NULL)
				so->s->option.multtl = so->option.multtl;
			return 0;
		case IP_ADD_MEMBERSHIP:
			if (optlen < sizeof(struct ip_mreq)) {
				errno = EINVAL;
				return -1;
			}
			const struct ip_mreq* mreq = (const struct ip_mreq*)optval;
			if (mreq->imr_multiaddr.s_addr == INADDR_ANY) {
				errno = EINVAL;
				return -1;
			}
			errno = EOPNOTSUPP;
			return -1;
		case IP_MTU_DISCOVER:
			return 0;
		case IP_TOS:
			return 0;
		case IP_RECVTOS:
			return 0;
		}
		break;
	case IPPROTO_IPV6:
		switch (optname) {
		case IPV6_V6ONLY:
			if (val == 0)
				so->option.ipv6only = 0;
			else
				so->option.ipv6only = 1;
			if (so->s != NULL)
				so->s->option.ipv6only = so->option.ipv6only;
			return 0;
		case IPV6_TCLASS:
			return 0;
		case IPV6_RECVTCLASS:
			return 0;
		}
		break;
	case SOL_SOCKET:
		switch (optname) {
		case SO_REUSEADDR:
			if (val == 0)
				so->option.reuseaddr = 0;
			else
				so->option.reuseaddr = 1;
			if (so->s != NULL)
				so->s->option.reuseaddr = so->option.reuseaddr;
			return 0;
		case SO_LINGER:
			ling = *(const struct linger *)optval;
			if (ling.l_onoff == 0)
				return 0;
			else {
				GLUE_LOG(ERR, "app is enabling SO_LINGER which is not really supported");
				return 0;
			}
			break;
		case SO_KEEPALIVE:
			if (val == 0)
				so->option.keepalive = 0;
			else
				so->option.keepalive = 1;
			if (so->s != NULL) {
				so->s->option.keepalive = so->option.keepalive;
				if (so->proto == PROTO_TCP)
					tle_tcp_stream_set_keepalive(so->s);
			}
			return 0;
		case SO_REUSEPORT:
			if (val == 0)
				so->option.reuseport = 0;
			else
				so->option.reuseport = 1;
			if (so->s != NULL)
				so->s->option.reuseport = so->option.reuseport;
			return 0;
		case SO_SNDBUF:
			def_sndbuf = val;
			return 0;
		case SO_RCVBUF:
			def_rcvbuf = val;
			return 0;
		case SO_DONTROUTE:
			/* needed by netperf */
			return 0;
		case SO_BROADCAST:
			/* needed by nc */
			/* todo: only supported for DGRAM */
			return 0;
		case SO_TIMESTAMP:
			so->option.timestamp = !!val;
			if (so->s != NULL)
				so->s->option.timestamp = so->option.timestamp;
			return 0;
		case SO_OOBINLINE:
			if (val == 0)
				so->option.oobinline = 0;
			else
				so->option.oobinline = 1;
			if (so->s != NULL)
				so->s->option.oobinline = so->option.oobinline;
			return 0;
		default:
			break;
		}
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		return OPS(so)->setsockopt(so, optname, optval, optlen);
	}

	GLUE_LOG(WARNING, "setsockopt(%d) with level = %d, optname = %d\n",
		 sockfd, level, optname);
	errno = EOPNOTSUPP;
	return -1;
}

/*
 * Refer to glibc/sysdeps/unix/sysv/linux/fcntl.c
 */
int PRE(fcntl)(int fd, int cmd, ...)
{
	int rc;
	void *arg;
	va_list ap;
	struct sock *so;

	va_start(ap, cmd);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (is_kernel_fd(fd))
		return k_fcntl(fd, cmd, arg);

	so = fd2sock(fd);
	switch (cmd) {
	case F_SETFL:
		if ((unsigned long)arg & O_NONBLOCK)
			so->nonblock = 1;
		else
			so->nonblock = 0;
		rc = 0;
		break;
	case F_GETFL:
		if (so->nonblock)
			rc = O_NONBLOCK | O_RDWR;
		else
			rc = O_RDWR;
		break;
	case F_SETFD:
		rc = 0;
		break;
	default:
		rc = -1;
		errno = EOPNOTSUPP;
		GLUE_LOG(WARNING, "fcntl(%d) with cmd = %d", fd, cmd);
	}

	return rc;
}

/*
 * Refer to musl/src/misc/ioctl.c
 */
int PRE(ioctl)(int fd,  unsigned long int request, ...)
{
	int rc;
	void *arg;
	va_list ap;
	uint16_t left;
	struct sock *so;
	struct rte_mbuf *m;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (is_kernel_fd(fd))
		return k_ioctl(fd, request, arg);

	so = fd2sock(fd);

	switch (request) {
	case FIONREAD: /* SIOCINQ */
		if (so->s == NULL)
			*(int *)arg = 0;
		else if (IS_TCP(so)) {
			left = tle_tcp_stream_inq(so->s);
			if (so->rx_left)
				left += rte_pktmbuf_pkt_len(so->rx_left);
			*(int *)arg = left;
		} else {
			if (so->rx_left)
				*(int *)arg = rte_pktmbuf_pkt_len(so->rx_left);
			else {
				if (tle_udp_stream_recv(so->s, &m , 1) == 0)
					*(int *)arg = 0;
				else {
					*(int *)arg = rte_pktmbuf_pkt_len(m);
					so->rx_left = m;
				}
			}
		}
		rc = 0;
		break;
	case FIONBIO:
		if (*(int *)arg)
			so->nonblock = 1;
		else
			so->nonblock = 0;
		rc = 0;
		break;
	case SIOCGSTAMP:
		if (so->s->timestamp == 0) {
			errno = ENOENT;
			rc = -1;
		} else {
			((struct timeval*)arg)->tv_sec = so->s->timestamp >> 20;
			((struct timeval*)arg)->tv_usec = so->s->timestamp & 0xFFFFFUL;
			rc = 0;
		}
		break;
	default:
		errno = EOPNOTSUPP;
		rc = -1;
		GLUE_LOG(WARNING, "ioctl(%d) with request = %ld", fd, request);
	}

	return rc;
}

int PRE(shutdown)(int sockfd, int how)
{
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_shutdown(sockfd, how);

	so = fd2sock(sockfd);
	switch (how) {
	case SHUT_RD:
		so->shutdown |= RECV_SHUTDOWN;
		break;
	case SHUT_WR:
		so->shutdown |= SEND_SHUTDOWN;
		break;
	case SHUT_RDWR:
		so->shutdown = RECV_SHUTDOWN | SEND_SHUTDOWN;
		break;
	}
	if (OPS(so)->shutdown)
		return OPS(so)->shutdown(so, how);

	errno = EOPNOTSUPP;
	return -1;
}

static inline int
getname(int sockfd, struct sockaddr *uaddr, socklen_t *addrlen, int peer)
{
	struct sock *so;
	size_t socklen;
	int rc;

	so = fd2sock(sockfd);

	/* This is ugly, but netperf ask for local addr (before any
	 * connect or bind) to check family.
	 *
	 * To formally fix this, we shall bind a local address in advance
	 */
	socklen = get_sockaddr_len(so->domain);
	/* fixme: It is not conform to linux standard, fix it later. */
	if (*addrlen < socklen) {
		errno = EINVAL;
		return -1;
	}
	*addrlen = socklen;

	if (so->s == NULL) {
		if (peer) {
			errno = ENOTCONN;
			return -1;
		} else {
			memset(uaddr, 0, socklen);
			uaddr->sa_family = so->domain;
			return 0;
		}
	}

	if (OPS(so)->getname) {
		rc = OPS(so)->getname(so, uaddr, peer);
		if (rc < 0)
			return rc;
		if (peer) {
			if ((uaddr->sa_family == AF_INET &&
			     ((struct sockaddr_in*)uaddr)->sin_addr.s_addr == 0) ||
			    (uaddr->sa_family == AF_INET6 &&
			     IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6*)
						       uaddr)->sin6_addr))) {
				errno = ENOTCONN;
				return -1;
			}
		}
		if (uaddr->sa_family == AF_INET && so->domain == AF_INET6)
			trans_4mapped6_addr(uaddr);
		return rc;
	}

	errno = EOPNOTSUPP;
	return -1;
}

int PRE(getsockname)(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (is_kernel_fd(sockfd))
		return k_getsockname(sockfd, addr, addrlen);

	return getname(sockfd, addr, addrlen, 0);
}

int PRE(getpeername)(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (is_kernel_fd(sockfd))
		return k_getpeername(sockfd, addr, addrlen);

	return getname(sockfd, addr, addrlen, 1);
}

int PRE(close)(int fd)
{
	struct sock *so;

	if (is_kernel_fd(fd))
		return k_close(fd);

	GLUE_DEBUG("close fd = %d", fd);

	so = fd2sock(fd);
	if (unlikely(so->valid == 0)) {
		errno = EBADF;
		return -1;
	} else if (unlikely(so->epoll)) {
		k_close(so->shadow_efd);
		glue_ctx_free(CTX(so));
	} else if (so->s) {
		if (OPS(so)->close)
			OPS(so)->close(so->s);

		if (IS_TCP(so))
			be_tx_with_lock(CTX(so));

		if (so->rx_left)
			rte_pktmbuf_free(so->rx_left);
	}
	
	tle_event_idle_err(&so->erev);
	tle_event_idle(&so->rxev);
	tle_event_idle(&so->txev);

	memset(((int*)so) + 1, 0, sizeof(*so) - sizeof(int));
	put_free_fd(fd);
	return 0;
}
