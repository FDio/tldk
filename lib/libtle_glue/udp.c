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
#include <netinet/in.h>

#include <rte_ethdev.h>
#include <tle_udp.h>

#include "sym.h"
#include "fd.h"
#include "log.h"
#include "util.h"
#include "internal.h"
#include "sock.h"

static int
udp_setsockopt(__rte_unused struct sock *sk, __rte_unused int optname,
	       __rte_unused const void *optval, __rte_unused socklen_t optlen)
{
	return 0;
}

static int
udp_getsockopt(__rte_unused struct sock *sk, __rte_unused int optname,
	       __rte_unused void *optval, __rte_unused socklen_t *optlen)
{
	return 0;
}

static int
udp_getname(struct sock *sk, struct sockaddr *addr, int peer)
{
	struct tle_udp_stream_param p;
	size_t addrlen;
	int rc;

	rc = tle_udp_stream_get_param(sk->s, &p);
	if (rc) {
		errno = -rc;
		return -1;
	}

	addrlen = get_sockaddr_len(sk->domain);
	if (peer)
		memcpy(addr, &p.remote_addr, addrlen);
	else
		memcpy(addr, &p.local_addr, addrlen);
	addr->sa_family = p.local_addr.ss_family;
	return 0;
}

static int
udp_bind(struct sock *sk, const struct sockaddr *addr)
{
	if (sk->ubind) {
		errno = EINVAL;
		return -1;
	}

	sk->s = open_bind(sk, addr, NULL);
	if (sk->s != NULL) {
		sk->ubind = 1;
		if (is_any_addr(addr))
			sk->ubindany = 1;
		return 0;
	}

	return -1;
}

static int
udp_connect(struct sock *sk, const struct sockaddr *addr)
{
	struct sockaddr_storage laddr;

	/* According to linux manual, connectionless sockets may dissolve the
	 * association by connecting to an address with the sa_family member of
	 * sockaddr set to AF_UNSPEC (supported on Linux since kernel 2.2).
	 */
	if (sk->ubind) {
		if (udp_getname(sk, (struct sockaddr *)&laddr, 0))
			return -1;
		if (addr->sa_family == AF_UNSPEC) {
			addr = NULL;
			if (sk->ubindany)
				set_any_addr((struct sockaddr *)&laddr);
		}
		sk->s = open_bind(sk, (const struct sockaddr *)&laddr, addr);
	} else {
		if (addr->sa_family == AF_UNSPEC) {
			tle_udp_stream_close(sk->s);
			sk->s = NULL;
			return 0;
		}
		sk->s = open_bind(sk, NULL, addr);
	}

	if (sk->s)
		return 0;

	return -1;
}

static int
udp_addr_prepare(struct sock *sk, const struct sockaddr **p_dst_addr,
		 struct sockaddr_storage *addr)
{
	const struct sockaddr *dst_addr = *p_dst_addr;

	if (dst_addr != NULL &&
	    dst_addr->sa_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((const struct sockaddr_in6 *)dst_addr)->sin6_addr)) {
		rte_memcpy(addr, dst_addr, sizeof(struct sockaddr_in6));
		dst_addr = (const struct sockaddr*)(addr);
		*p_dst_addr = dst_addr;
		retrans_4mapped6_addr((struct sockaddr_storage*)(addr));
	}

	if (sk->s == NULL) {
		if (dst_addr == NULL) {
			errno = EDESTADDRREQ;
			return -1;
		}

		sk->s = open_bind(sk, NULL, dst_addr);
		if (sk->s == NULL) /* errno is set */
			return -1;
	} else if (dst_addr != NULL) {
		if (dst_addr->sa_family == AF_INET6 && sk->domain == AF_INET) {
			errno = EINVAL;
			return -1;
		}
		if (dst_addr->sa_family == AF_INET && sk->domain == AF_INET6) {
			if (IN6_IS_ADDR_UNSPECIFIED(&sk->s->ipv6.addr.dst)) {
				sk->s->type = TLE_V4;
				sk->s->ipv4.addr.dst = 0;
			} else {
				errno = ENETUNREACH;
				return -1;
			}
		}
	}

	return 0;
}

/* abstract client info from mbuf into s */
static inline void
udp_pkt_addr(const struct rte_mbuf *m, struct sockaddr *addr,
	     __rte_unused uint16_t family)
{
	const struct ipv4_hdr *ip4h;
	const struct ipv6_hdr *ip6h;
	const struct udp_hdr *udph;
	struct sockaddr_in *in4;
	struct sockaddr_in6 *in6;
	int off = -(m->l4_len + m->l3_len);

	udph = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, -m->l4_len);
	ip4h = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, off);
	if ((ip4h->version_ihl>>4) == 4) {
		addr->sa_family = AF_INET;
		in4 = (struct sockaddr_in *)addr;
		in4->sin_port = udph->src_port;
		in4->sin_addr.s_addr = ip4h->src_addr;
	} else {
		addr->sa_family = AF_INET6;
		ip6h = (const struct ipv6_hdr*)ip4h;
		in6 = (struct sockaddr_in6 *)addr;
		in6->sin6_port = udph->src_port;
		rte_memcpy(&in6->sin6_addr, ip6h->src_addr,
			   sizeof(in6->sin6_addr));
	}
}

static ssize_t
udp_send(struct sock *sk, struct rte_mbuf *pkt[],
	 uint16_t num, const struct sockaddr *dst_addr)
{
	uint16_t i;
	struct sockaddr_storage addr;

	if (udp_addr_prepare(sk, &dst_addr, &addr) != 0)
		return 0;

	/* chain them together as *one* message */
	for (i = 1; i < num; ++i) {
		pkt[i-1]->next = pkt[i];
		pkt[0]->pkt_len += pkt[i]->pkt_len;
	}
	pkt[0]->nb_segs = num;

	if (tle_udp_stream_send(sk->s, &pkt[0], 1, dst_addr) == 0) {
		errno = rte_errno;
		return 0;
	}

	return num;
}

static ssize_t
udp_readv(struct tle_stream *s, struct msghdr *msg, int flags)
{
	int i;
	ssize_t sz;
	uint16_t rc;
	uint32_t fin;
	struct iovec iv;
	struct rte_mbuf *m;
	const struct iovec *iov = msg->msg_iov;
	int iovcnt = msg->msg_iovlen;

	rc = tle_udp_stream_recv(s, &m, 1);
	if (rc == 0) {
		errno = rte_errno;
		return -1;
	}

	if (!s->option.timestamp)
		s->timestamp = m->timestamp;
	if (msg != NULL && msg->msg_control != NULL) {
		if (s->option.timestamp)
			tle_set_timestamp(msg, m);
		else
			msg->msg_controllen = 0;
	}

	if (msg != NULL && msg->msg_name != NULL) {
		udp_pkt_addr(m, (struct sockaddr*)msg->msg_name, 0);
		if (((struct sockaddr *)msg->msg_name)->sa_family == AF_INET)
			msg->msg_namelen = sizeof(struct sockaddr_in);
		else
			msg->msg_namelen = sizeof(struct sockaddr_in6);
	}

	for (i = 0, sz = 0; i != iovcnt; i++) {
		iv = iov[i];
		sz += iv.iov_len;
		fin = _mbus_to_iovec(&iv, &m, 1);
		if (fin == 1) {
			sz -= iv.iov_len;
			break;
		}
	}
	if (fin == 0) {
		if (flags & MSG_TRUNC)
			sz += m->pkt_len;
		rte_pktmbuf_free_seg(m);
		msg->msg_flags |= MSG_TRUNC;
	}
	return sz;
}

static ssize_t
udp_writev(struct sock *sk, const struct iovec *iov,
	   int iovcnt, const struct sockaddr *dst_addr)
{
	struct rte_mempool *mp = get_mempool_by_socket(0); /* fix me */
	struct sockaddr_storage addr;
	uint32_t slen, left_m, left_b, copy_len, left;
	uint16_t i, rc, nb_mbufs;
	char *dst, *src;
	uint64_t ufo;
	size_t total;
	int j;

	if (udp_addr_prepare(sk, &dst_addr, &addr) != 0)
		return -1;

	for (j = 0, total = 0; j < iovcnt; ++j)
		total += iov[j].iov_len;

	ufo = tx_offload & DEV_TX_OFFLOAD_UDP_TSO;
	if (ufo)
		slen = RTE_MBUF_DEFAULT_DATAROOM;
	else
		slen = 1500 - 20; /* mtu - ip_hdr_len */

	nb_mbufs = (total + 8 + slen - 1) / slen;
	struct rte_mbuf *mbufs[nb_mbufs];
	if (unlikely(rte_pktmbuf_alloc_bulk(mp, mbufs, nb_mbufs) != 0)) {
		errno = ENOMEM;
		return -1;
	}

	left_b = iov[0].iov_len;
	for (i = 0, j = 0; i < nb_mbufs && j < iovcnt; ++i) {
		/* first frag has udp hdr, its payload is 8 bytes less */
		if (i == 0)
			slen -= 8;
		else if (i == 1)
			slen += 8;
		left_m = slen;
		while (left_m > 0 && j < iovcnt) {
			copy_len = RTE_MIN(left_m, left_b);
			dst = rte_pktmbuf_mtod_offset(mbufs[i], char *,
						      slen - left_m);
			src = (char *)iov[j].iov_base + iov[j].iov_len - left_b;
			rte_memcpy(dst, src, copy_len);
	
			left_m -= copy_len;
			left_b -= copy_len;
			if (left_b == 0) {
				j++;
				left_b = iov[j].iov_len;
			}
		}
		mbufs[i]->data_len = slen;
		mbufs[i]->pkt_len = slen;
	}

	/* last seg */
	if (nb_mbufs == 1) {
		mbufs[nb_mbufs - 1]->data_len = total;
		mbufs[nb_mbufs - 1]->pkt_len = total;
	} else {
		mbufs[nb_mbufs - 1]->data_len = total - (nb_mbufs - 1) * slen + 8;
		mbufs[nb_mbufs - 1]->pkt_len = total - (nb_mbufs - 1) * slen + 8;
	}

	/* chain as *one* message */
	for (i = 1; i < nb_mbufs; ++i)
		mbufs[i-1]->next = mbufs[i];
	mbufs[0]->nb_segs = nb_mbufs;
	mbufs[0]->pkt_len = total;
	nb_mbufs = 1;

	rc = tle_udp_stream_send(sk->s, mbufs, nb_mbufs, dst_addr);
	for (i = rc, left = 0; i < nb_mbufs; ++i) {
		left += mbufs[i]->pkt_len;
		rte_pktmbuf_free(mbufs[i]);
	}

	if (rc == 0) {
		errno = rte_errno;
		return -1;
	}

	return total - left;
}

static ssize_t
udp_recv(struct tle_stream *s, struct rte_mbuf *pkt[], uint16_t num,
	 struct sockaddr *addr)
{
	uint16_t rc;

	rc = tle_udp_stream_recv(s, pkt, num);
	if (addr && num == 1 && rc == 1)
		udp_pkt_addr(pkt[0], addr, 0);

	if (rc == 0)
		errno = rte_errno;
	return rc;
}

static void
udp_update_cfg(struct sock *sk)
{
	struct tle_udp_stream_param prm;
	memset(&prm, 0, sizeof(prm));

	prm.recv_ev = &sk->rxev;
	prm.send_ev = &sk->txev;

	tle_udp_stream_update_cfg(&sk->s, &prm, 1);
}

static int
udp_shutdown(struct sock *sk, int how)
{
	int rc;

	if (sk->s == NULL) {
		errno = ENOTCONN;
		return -1;
	}

	rc = tle_udp_stream_shutdown(sk->s, how);
	if (rc < 0) {
		errno = -rc;
		return -1;
	}
	return 0;
}

struct proto udp_prot = {
	.name		= "UDP",
	.setsockopt	= udp_setsockopt,
	.getsockopt	= udp_getsockopt,
	.getname	= udp_getname,
	.bind		= udp_bind,
	.connect	= udp_connect,
	.recv		= udp_recv,
	.send		= udp_send,
	.readv		= udp_readv,
	.writev		= udp_writev,
	.shutdown	= udp_shutdown,
	.close		= tle_udp_stream_close,
	.update_cfg	= udp_update_cfg,
};
