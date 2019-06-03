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

#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <tle_tcp.h>

#include "sym.h"
#include "fd.h"
#include "log.h"
#include "util.h"
#include "internal.h"
#include "sock.h"

#define MAX_TCP_KEEPIDLE 32767
#define MAX_TCP_KEEPINTVL 32767

static inline void
foo_support(const char *msg)
{
	GLUE_LOG(WARNING, "%s, return ok without really supporting it", msg);
}

static int tcp_setsockopt(struct sock *sk, int optname,
			  const void *optval, socklen_t optlen)
{
	int val;

	val = 0; /* just to make compiler happy */
	if (optlen == sizeof(val))
		val = *(const int *)optval;

	/* man tcp(7) or  see /usr/include/netinet/tcp.h */
	switch (optname) {
	case TCP_NODELAY: /* antonym: TCP_CORK */
		if (val == 0)
			sk->option.tcpnodelay = 0;
		else
			sk->option.tcpnodelay = 1;
		if (sk->s != NULL)
			sk->s->option.tcpnodelay = sk->option.tcpnodelay;
		return 0;
	case TCP_CORK:
		if (val == 0)
			sk->option.tcpcork = 0;
		else
			sk->option.tcpcork = 1;
		if (sk->s != NULL)
			sk->s->option.tcpcork = sk->option.tcpcork;
		return 0;
	case TCP_KEEPIDLE:
		if (val <= 0 || val > MAX_TCP_KEEPIDLE) {
			errno = EINVAL;
			return -1;
		}
		sk->option.keepidle = val;
		if (sk->s != NULL)
			sk->s->option.keepidle = sk->option.keepidle;
		return 0;
	case TCP_KEEPINTVL:
		if (val <= 0 || val > MAX_TCP_KEEPINTVL) {
			errno = EINVAL;
			return -1;
		}
		sk->option.keepintvl = val;
		if (sk->s != NULL)
			sk->s->option.keepintvl = sk->option.keepintvl;
		return 0;
	case TCP_USER_TIMEOUT:
		foo_support("set TCP_USER_TIMEOUT");
		return 0;
	case TCP_DEFER_ACCEPT:
		if (val == 0)
			return 0;
		break;
	case TCP_FASTOPEN:
	case TCP_FASTOPEN_CONNECT:
		if (val == 0)
			return 0;
		break;
	case TCP_QUICKACK:
		/* Based on below info, it's safe to just return 0:
		 * "This flag is not permanent, it only enables a 
		 * switch to or from quickack mode.  Subsequent
		 * operationof the TCP protocol will once again ..."
		 */
		if (val == 0)
			sk->option.tcpquickack = 0;
		else
			sk->option.tcpquickack = 8;
		if (sk->s != NULL)
			sk->s->option.tcpquickack = sk->option.tcpquickack;
		return 0;
	case TCP_CONGESTION:
		/* only support NewReno; but we return success for
		 * any kind of setting.
		 */
		foo_support("set TCP_CONGESTION");
		return 0;
	default:
		break;
	}

	rte_panic("setsockopt(%d) with level = SOL_TCP, optname = %d\n",
		  sock2fd(sk), optname);
	return -1;
}

static int tcp_getsockopt(struct sock *sk, int optname,
			  void *optval, socklen_t *optlen)
{
	int rc;
	union {
		int val;
		uint64_t val64;
		struct linger ling;
		struct timeval tm;
	} *p = optval;

	RTE_SET_USED(optlen);

	/* man tcp(7) or  see /usr/include/netinet/tcp.h */
	switch (optname) {
	case TCP_MAXSEG:
		p->val = 64 * 1024;
		return 0;
	case TCP_FASTOPEN:
	case TCP_FASTOPEN_CONNECT:
		p->val = 0;
		return 0;
	case TCP_INFO:
		/* needed by netperf */
		rc = tle_tcp_stream_get_info(sk->s, optval, optlen);
		if (rc < 0) {
			errno = -rc;
			return -1;
		}
		return 0;
	case TCP_CONGESTION:
		strncpy(optval, "NewReno", *optlen);
		((char *)optval)[*optlen - 1] = '\0';
		return 0;
	case TCP_CORK:
		p->val = sk->option.tcpcork;
		return 0;
	case TCP_QUICKACK:
		p->val = sk->option.tcpquickack != 0 ? 1 : 0;
		return 0;
	case TCP_NODELAY:
		p->val = sk->option.tcpnodelay;
		return 0;
	case TCP_KEEPIDLE:
		p->val = sk->option.keepidle;
		return 0;
	case TCP_KEEPINTVL:
		p->val = sk->option.keepintvl;
		return 0;
	default:
		break;
	}

	rte_panic("getsockopt(%d) with level = SOL_TCP, optname = %d",
		  sock2fd(sk), optname);
	return -1;
}

static int tcp_getname(struct sock *sk, struct sockaddr *addr, int peer)
{
	int rc;
	int addrlen;
	struct tle_tcp_stream_addr a;

	rc = tle_tcp_stream_get_addr(sk->s, &a);
	if (rc) {
		errno = -rc;
		return -1;
	}

	if (a.local.ss_family == AF_INET)
		addrlen = sizeof(struct sockaddr_in);
	else
		addrlen = sizeof(struct sockaddr_in6);

	if (peer)
		memcpy(addr, &a.remote, addrlen);
	else
		memcpy(addr, &a.local, addrlen);

	addr->sa_family = a.local.ss_family;

	return 0;
}

static int tcp_bind(struct sock *sk, const struct sockaddr *addr)
{
	sk->s = open_bind(sk, addr, NULL);
	if (sk->s == NULL)
		return -1;
	return 0;
}

static int tcp_listen(struct sock *sk, int backlog)
{
	int32_t rc;

	if (backlog < 0) {
		errno = EINVAL;
		return -1;
	}

	rc = tle_tcp_stream_listen(sk->s);
	if (rc) {
		errno = -rc;
		return -1;
	}

	return 0;
}

static int tcp_connect(struct sock *sk, const struct sockaddr *addr)
{
	int rc;
	int rx;
	int ret;
	struct epoll_event event;
	struct sockaddr_storage laddr;
	struct sockaddr_storage raddr;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	struct sockaddr *local = NULL;

	/* TODO: For multi-thread case, we shall properly manage local
	 * L4 port so that packets coming back can be put into the same
	 * queue pair.
	 */
	if (sk->s) {
		struct tle_tcp_stream *ts = TCP_STREAM(sk->s);
		/* case 1: bind happens before connect;
		 * case 2: connect after a previous connect, failed
		 *	   or succeeded.
		 */
		if (ts->tcb.err != 0) {
			errno = ts->tcb.err;
			return -1;
		}

		if (sk->txev && tle_event_state(sk->txev) != TLE_SEV_DOWN)
			return 0; /* connect succeeds */

		int state = ts->tcb.state;

		if (state == TCP_ST_CLOSED) {
			if (tcp_getname(sk, (struct sockaddr *)&laddr, 0) == 0)
				local = (struct sockaddr *)&laddr;
			tle_tcp_stream_close(sk->s);
			sk->s = NULL;
			goto do_connect; /* case 1 */
		} else if (state >= TCP_ST_SYN_SENT &&
			   state < TCP_ST_ESTABLISHED)
			errno = EALREADY;
		else if (state >= TCP_ST_ESTABLISHED)
			errno = EISCONN;
		else
			errno = EINVAL;
		return -1;
	}

do_connect:
	sk->s = open_bind(sk, local, addr);
	if (sk->s == NULL) /* errno is set */
		return -1;

	if (sk->s->type == TLE_V4) {
		addr4 = (struct sockaddr_in*)&raddr;
		addr4->sin_family = AF_INET;
		addr4->sin_port = sk->s->port.src;
		addr4->sin_addr.s_addr = sk->s->ipv4.addr.src;
	} else {
		addr6 = (struct sockaddr_in6*)&raddr;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = sk->s->port.src;
		rte_memcpy(&addr6->sin6_addr, &sk->s->ipv6.addr.src,
				sizeof(struct in6_addr));
	}
	rc = tle_tcp_stream_connect(sk->s, (const struct sockaddr*)&raddr);
	if (rc < 0) {
		errno = -rc;
		return -1;
	}

	if (is_nonblock(sk, 0)) {
		be_tx_with_lock(CTX(sk));
		/* It could not be ready so fast */
		errno = EINPROGRESS;
		return -1;
	}

	do {
		be_process(CTX(sk));

		if (tle_event_state(sk->txev) == TLE_SEV_UP) {
			tle_event_down(sk->txev);
			ret = 0;
			break;
		}

		if (tle_event_state(sk->erev) == TLE_SEV_UP) {
			tle_event_down(sk->erev);
			errno = ECONNREFUSED;
			ret = -1;
			break;
		}

		/* fix me: timeout? */
		epoll_kernel_wait(CTX(sk), -1, &event, 1, 1, &rx);
	} while (1);
	
	return ret;
}

static void tcp_update_cfg(struct sock *sk);

static int tcp_accept(struct sock *sk, struct sockaddr *addr,
		socklen_t *addrlen, int flags)
{
	int fd;
	int rx;
	struct sock *newsk;
	struct tle_stream *rs;
	struct tle_tcp_stream_addr a;

	fd = get_unused_fd();
	if (fd < 0) {
		errno = ENFILE;
		return -1;
	}

	newsk = fd2sock(fd);
again:
	if (tle_tcp_stream_accept(sk->s, &rs, 1) == 0) {
		if (rte_errno != EAGAIN) {
			errno = rte_errno;
			return -1;
		}

		struct epoll_event event;

		if (is_nonblock(sk, flags)) {
			newsk->valid = 0;
			put_free_fd(fd);
			errno = EAGAIN;
			return -1;
		}

		epoll_kernel_wait(CTX(sk), -1, &event, 1, 1, &rx);

		be_process(CTX(sk));

		goto again;
	}

	newsk->s = rs;
	newsk->cid = sk->cid;
	newsk->type = sk->type;
	newsk->proto = sk->proto;
	newsk->option.raw = 0;
	newsk->option.tcpquickack = 1;
	newsk->option.mulloop = 1;
	newsk->option.multtl = 1;
	newsk->option.keepidle = 2 * 60 * 60;
	newsk->option.keepintvl = 75;
	newsk->s->option.raw = newsk->option.raw;
	sock_alloc_events(newsk);
	tcp_update_cfg(newsk);

	if (addr) {
		/* We assume this function never fails */
		tle_tcp_stream_get_addr(rs, &a);

		*addrlen = sizeof(struct sockaddr_in);
		memcpy(addr, &a.remote, *addrlen);
	}

	return fd;
}

static ssize_t tcp_send(struct sock *sk, struct rte_mbuf *pkt[],
			 uint16_t num, const struct sockaddr *dst_addr)
{
	uint16_t rc;
	RTE_SET_USED(dst_addr);

	rc = tle_tcp_stream_send(sk->s, pkt, num);
	if (rc == 0)
		errno = rte_errno;

	return rc;
}

static ssize_t tcp_recv(struct tle_stream *s, struct rte_mbuf *pkt[],
			 uint16_t num, struct sockaddr *addr)
{
	uint16_t rc;

	RTE_SET_USED(addr);

	/* optimize me: merge multiple mbufs into one */
	rc = tle_tcp_stream_recv(s, pkt, num);
	if (rc == 0)
		errno = rte_errno;

	return rc;
}

static ssize_t tcp_readv(struct tle_stream *ts, const struct iovec *iov,
	int iovcnt, struct msghdr *msg)
{
	ssize_t rc;

	rc = tle_tcp_stream_readv_msg(ts, iov, iovcnt, msg);
	if (rc < 0)
		errno = rte_errno;
	return rc;
}

static ssize_t tcp_writev(struct sock *sk, const struct iovec *iov,
			  int iovcnt, const struct sockaddr *dst_addr)
{
	ssize_t rc;
	struct rte_mempool *mp = get_mempool_by_socket(0); /* fix me */

	RTE_SET_USED(dst_addr);

	rc = tle_tcp_stream_writev(sk->s, mp, iov, iovcnt);
	if (rc < 0)
		errno = rte_errno;
	return rc;
}

static int tcp_shutdown(struct sock *sk, int how)
{
	int ret;

	ret = tle_tcp_stream_shutdown(sk->s, how);
	if (how == SHUT_RDWR)
		sk->s = NULL;

	be_tx_with_lock(CTX(sk));
	return ret;

}

static void tcp_update_cfg(struct sock *sk)
{
	struct tle_tcp_stream_cfg prm;
	memset(&prm, 0, sizeof(prm));

	prm.recv_ev = sk->rxev;
	prm.send_ev = sk->txev;
	prm.err_ev = sk->erev;

	tle_tcp_stream_update_cfg(&sk->s, &prm, 1);
}

struct proto tcp_prot = {
	.name			= "TCP",
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.getname		= tcp_getname,
	.bind			= tcp_bind,
	.listen			= tcp_listen,
	.connect		= tcp_connect,
	.accept			= tcp_accept,
	.recv			= tcp_recv,
	.send			= tcp_send,
	.readv			= tcp_readv,
	.writev			= tcp_writev,
	.shutdown		= tcp_shutdown,
	.close			= tle_tcp_stream_close,
	.update_cfg		= tcp_update_cfg,
};
