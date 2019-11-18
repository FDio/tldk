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

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_atomic.h>

#include <tle_tcp.h>

#include <stddef.h>
#include <fcntl.h>

#include "tle_glue.h"
#include "fd.h"
#include "util.h"
#include "internal.h"

rte_atomic32_t thr_cnt;

#define MAX_UDP_PKT_LEN ((2 << 16) - 1 - sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr))

static inline struct rte_mbuf *
from_mbuf_to_buf(struct rte_mbuf *m, char *buf,
		 size_t len, int ispeek, int needcpy)
{
	void *src;
	uint32_t done = 0;
	uint32_t left = len, orig_pkt_len;
	uint16_t copy_len, seg_len, segs;
	struct rte_mbuf *m_next, *orig_pkt;

	if (len == 0)
		return m;

	orig_pkt = m;
	orig_pkt_len = m->pkt_len;
	segs = m->nb_segs;

	do {
		seg_len = rte_pktmbuf_data_len(m);
		copy_len = RTE_MIN(seg_len, left);
		src = rte_pktmbuf_mtod(m, void *);
		if (needcpy)
			rte_memcpy(buf + done, src, copy_len);
		done += copy_len;
		left -= copy_len;
		if (copy_len < seg_len) {
			if (!ispeek)
				rte_pktmbuf_adj(m, copy_len);
			break;
		}
		m_next = m->next;
		if (!ispeek) {
			rte_pktmbuf_free_seg(m);
			segs--;
		}
		m = m_next;
	} while (left && m);

	if (m && !ispeek) {
		m->nb_segs = segs;
		m->pkt_len = orig_pkt_len - done;
	}

	if(ispeek)
		return orig_pkt;
	else
		return m;
}

static inline bool
is_peer_closed(struct sock *so)
{
	if (errno == EAGAIN && tle_event_state(&so->erev) == TLE_SEV_UP)
		return true;

	return false;
}

static ssize_t
_recv(int sockfd, void *buf, size_t len, struct sockaddr *src_addr, int flags)
{
	int rx;
	ssize_t rc;
	ssize_t recvlen;
	size_t tmplen;
	struct sock *so;
	struct rte_mbuf *m;
	struct epoll_event event;
	int needcpy;

	if (RTE_PER_LCORE(_lcore_id) == LCORE_ID_ANY) {
		RTE_PER_LCORE(_lcore_id) = rte_atomic32_add_return(&thr_cnt, 1);
	}

	so = fd2sock(sockfd);

	if (so->s == NULL) {
		if (IS_UDP(so) && is_nonblock(so, flags))
			errno = EAGAIN;
		else
			errno = ENOTCONN;
		return -1;
	}

	if (so->rx_left) {
		m = so->rx_left;
		so->rx_left = NULL;
		if (src_addr) {
			OPS(so)->getname(so, src_addr, 1);
			/* fixme: cannot get addr for UDP in this way */
		}
	} else {
		rc = OPS(so)->recv(so->s, &m, 1, src_addr);
		if (rc == 0) {
			if (is_nonblock(so, flags)) {
				/* socket closed, return 0 */
				if (is_peer_closed(so)) {
					GLUE_DEBUG("peer closed: %d", sockfd);
					return 0;
				}

				/* According to linux stack,
				 * receive from shutdown tcp socket returns 0.
				 * And receive from shutdown udp socket generate
				 * EAGAIN. In special case, we return ESHUTDOWN
				 * to notify upper application.
				 */
				if (so->shutdown & RECV_SHUTDOWN) {
					if (so->proto == PROTO_TCP)
						return 0;
					else {
#ifdef LOOK_ASIDE_BACKEND
						errno = ESHUTDOWN;
#else
						errno = EAGAIN;
#endif
						return -1;
					}
				}
				return -1;
			}

			do {
				/* in blocking mode, recv from shutdown socket
				 * return 0 immediately */
				if (so->shutdown & RECV_SHUTDOWN)
					return 0;

				/* some error occured, return -1 */
				if (errno != EAGAIN)
					return -1;

				/* socket closed, return 0 */
				if (is_peer_closed(so)) {
					GLUE_DEBUG("peer closed: %d", sockfd);
					return 0;
				}

				epoll_kernel_wait(CTX(so), -1, &event, 1, 1, &rx);

				be_process(CTX(so));
			} while((rc = OPS(so)->recv(so->s, &m, 1, src_addr)) == 0);
		}
	}

	/* get one pkt */
	if (!so->option.timestamp)
		so->s->timestamp = m->timestamp;

	needcpy = 1;
	recvlen = RTE_MIN(m->pkt_len, len);
	if (flags & MSG_TRUNC) {
		if (IS_UDP(so))
			recvlen = m->pkt_len;
		else
			/* According to linux manual, data will be discarded
			 * if recv TCP stream with MSG_TRUNC flag */
			needcpy = 0;
	}

	so->rx_left = from_mbuf_to_buf(m, buf, len, flags & MSG_PEEK, needcpy);

	if (((flags & MSG_PEEK) == 0) && IS_UDP(so) && so->rx_left) {
		rte_pktmbuf_free(so->rx_left);
		so->rx_left = NULL;
	}

	/* UDP socket only receive one pkt at one time */
	if (IS_UDP(so) || (flags & MSG_PEEK)) {
		return recvlen;
	}
	/* TCP socket: try best to fill buf */
	len -= recvlen;
	buf = (char*)buf + recvlen;
	while (len) {
		if (OPS(so)->recv(so->s, &m, 1, src_addr) == 0)
			break;

		tmplen = (m->pkt_len < len) ? m->pkt_len : len;
		so->rx_left = from_mbuf_to_buf(m, buf, tmplen, 0, needcpy);
		len -= tmplen;
		recvlen += tmplen;
		buf = (char*)buf + tmplen;
	}

	if (so->rx_left)
		tle_event_raise(&so->rxev);

	/* may send window increase ACK after receive*/
	if (recvlen > 0)
		be_tx_with_lock(CTX(so));

	return recvlen;
}

ssize_t PRE(recv)(int sockfd, void *buf, size_t len, int flags)
{
	if (is_kernel_fd(sockfd))
		return k_read(sockfd, buf, len);

	return _recv(sockfd, buf, len, NULL, flags);
}

ssize_t PRE(recvfrom)(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen)
{
	ssize_t rc;
 	if (is_kernel_fd(sockfd))
 		return k_recv(sockfd, buf, len, flags);

	if (src_addr && !addrlen) {
		errno = EINVAL;
		return -1;
	}
	rc = _recv(sockfd, buf, len, src_addr, flags);
	if (rc >= 0 && src_addr) {
		if (src_addr->sa_family == AF_INET) {
			*addrlen = sizeof(struct sockaddr_in);
		} else {
			*addrlen = sizeof(struct sockaddr_in6);
 		}
 	}
	return rc;
}

#define RECV_CONTINUE	(-2)
static inline ssize_t
try_recvmsg(struct sock *so, struct msghdr *msg, int flags)
{
	ssize_t sz;

	if (so->s == NULL) {
		if (IS_UDP(so) && is_nonblock(so, flags))
			errno = EAGAIN;
		else
			errno = ENOTCONN;
		return -1;
	}

	sz = OPS(so)->readv(so->s, msg, flags);
	if (sz >= 0) { /* get data */
		/* may send window increase ACK after receive*/
		if (sz > 0)
			be_tx_with_lock(CTX(so));
		return sz;
	}
	else if (errno != EAGAIN) /* error occurred */
		return -1;
	else if (is_peer_closed(so)) {
		GLUE_DEBUG("peer closed: %d", so->fd);
		return 0;
	} else if (is_nonblock(so, flags))
		return -1;

	return RECV_CONTINUE;
}

ssize_t PRE(recvmsg)(int sockfd, struct msghdr *msg, int flags)
{
	ssize_t sz;
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_recvmsg(sockfd, msg, flags);

	so = fd2sock(sockfd);

	if (so->rx_left == NULL && OPS(so)->readv &&
	    (flags & MSG_PEEK) == 0 &&
	    ((flags & MSG_TRUNC) == 0 || so->proto == PROTO_UDP)) {
		/* udp_readv supports MSG_TRUNC, tcp_readv not yet.
		 * so only udp socket implement with readv interface.
		 */
		sz = try_recvmsg(so, msg, flags);
		if (sz != RECV_CONTINUE)
			return sz;
	}

	/* 1. rx_left != NULL; 2. get no data, fall back to blocking read */

	if (so->rx_left != NULL && msg != NULL && msg->msg_control != NULL) {
		if (so->option.timestamp)
			tle_set_timestamp(msg, so->rx_left);
		else
			msg->msg_controllen = 0;
	}

	sz = PRE(recvfrom)(sockfd, msg->msg_iov[0].iov_base,
			   msg->msg_iov[0].iov_len, flags,
			   (struct sockaddr *)msg->msg_name,
			   &msg->msg_namelen);

	return sz;
}

ssize_t PRE(read)(int fd, void *buf, size_t count)
{
	if (is_kernel_fd(fd))
		return k_read(fd, buf, count);

	return _recv(fd, buf, count, NULL, 0);
}

#define DECONST(type, var) ((type)(uintptr_t)(const void *)(var))

ssize_t PRE(readv)(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t sz;
	struct sock *so;
	struct msghdr msg;

	if (is_kernel_fd(fd))
		return k_readv(fd, iov, iovcnt);

	if (RTE_PER_LCORE(_lcore_id) == LCORE_ID_ANY) {
		RTE_PER_LCORE(_lcore_id) = rte_atomic32_add_return(&thr_cnt, 1);
	}

	so = fd2sock(fd);

	if (so->rx_left == NULL && OPS(so)->readv) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = DECONST(struct iovec *, iov);
		msg.msg_iovlen = iovcnt;
		sz = try_recvmsg(so, &msg, 0);
		if (sz != RECV_CONTINUE)
			return sz;
	}

	/* 1. rx_left != NULL; 2. get no data, fall back to blocking read */

	/* fixme: when so->rx_left != NULL, also needs readv.
	 * maybe need to modify readv interface args of ops */
	return _recv(fd, iov[0].iov_base, iov[0].iov_len, NULL, 0);
}

static ssize_t
_send(int sockfd, const void *buf, size_t len,
	const struct sockaddr *peer, int flags)
{
	struct sock *so = fd2sock(sockfd);
	struct rte_mempool *mp = get_mempool_by_socket(0); /* fix me */
	uint16_t nb_mbufs = (len + RTE_MBUF_DEFAULT_DATAROOM - 1)
			    / RTE_MBUF_DEFAULT_DATAROOM;
	uint16_t i, cnt, copy_len;
	int rc;
	struct rte_mbuf *mbufs[nb_mbufs + 1];
	size_t done = 0;
	uint32_t left = 0;
	char *dst;
	int blocking = !is_nonblock(so, flags);

	if (RTE_PER_LCORE(_lcore_id) == LCORE_ID_ANY) {
		RTE_PER_LCORE(_lcore_id) = rte_atomic32_add_return(&thr_cnt, 1);
	}

	if (!blocking && len > def_sndbuf && so->proto == PROTO_TCP) {
		len = def_sndbuf;
		nb_mbufs = (len + RTE_MBUF_DEFAULT_DATAROOM - 1)
			   / RTE_MBUF_DEFAULT_DATAROOM;
	}

	if (unlikely(len == 0)) {
		if (so->proto == PROTO_TCP)
			return 0;
		else
			nb_mbufs = 1;
	}

	if (unlikely(len > MAX_UDP_PKT_LEN && IS_UDP(so))) {
		errno = EMSGSIZE;
		return -1;
	}

	if (blocking)
		be_process(get_ctx());

	if (unlikely(rte_pktmbuf_alloc_bulk(mp, mbufs, nb_mbufs) < 0)) {
		errno = ENOMEM;
		return -1;
	}

	for (i = 0; i < nb_mbufs; ++i) {
		copy_len = RTE_MIN((size_t)RTE_MBUF_DEFAULT_DATAROOM,
				   len - done);
		dst = rte_pktmbuf_mtod(mbufs[i], char *);
		rte_memcpy(dst, (const char *)buf + done, copy_len);
		done += copy_len;
		mbufs[i]->data_len = copy_len;
		mbufs[i]->pkt_len = copy_len;
	}

	cnt = 0;
do_send:
	rc = OPS(so)->send(so, mbufs + cnt, nb_mbufs - cnt, peer);

	cnt += rc;

	if (cnt > 0)
		be_tx_with_lock(CTX(so));

	if (cnt > 0 && blocking)
		be_process(get_ctx());

	if (blocking &&
	    cnt < nb_mbufs &&
	    (rc > 0 || errno == EAGAIN) &&
	    tle_event_state(&so->erev) != TLE_SEV_UP) {
		be_process(get_ctx());
		goto do_send;
	}

	for (i = cnt; i < nb_mbufs; ++i) {
		left += mbufs[i]->pkt_len;
		rte_pktmbuf_free_seg(mbufs[i]);
	}

	if (cnt == 0)
		return -1;
	else
		return len - left;
}

ssize_t PRE(send)(int sockfd, const void *buf, size_t len, int flags)
{
	if (is_kernel_fd(sockfd))
		return k_write(sockfd, buf, len);

	/* MSG_NOSIGNAL means "Do not generate SIGPIPE". Ignore this flag */
	flags &= ~MSG_NOSIGNAL;

	return _send(sockfd, buf, len, NULL, flags);
}

ssize_t PRE(sendto)(int sockfd, const void *buf, size_t len, int flags,
		    const struct sockaddr *dest_addr, socklen_t addrlen)
{
	if (is_kernel_fd(sockfd))
		return k_sendto(sockfd, buf, len, flags, dest_addr, addrlen);

	/* MSG_NOSIGNAL means "Do not generate SIGPIPE". Ignore this flag */
	flags &= ~MSG_NOSIGNAL;

	return _send(sockfd, buf, len, dest_addr, flags);
}

ssize_t PRE(sendmsg)(int sockfd, const struct msghdr *msg, int flags)
{
	ssize_t ret;
	struct sock *so;

	if (is_kernel_fd(sockfd))
		return k_sendmsg(sockfd, msg, flags);

	/* MSG_NOSIGNAL means "Do not generate SIGPIPE". Ignore this flag */
	flags &= ~MSG_NOSIGNAL;

	so = fd2sock(sockfd);
	if (OPS(so)->writev) {
		ret = OPS(so)->writev(so, msg->msg_iov, msg->msg_iovlen,
				      msg->msg_name);
		if (ret < 0) {
			if (errno != EAGAIN || is_nonblock(so, flags))
				return -1;
		} else {
			/* TODO: blocking && ret < total length */
			be_tx_with_lock(CTX(so));
			return ret;
		}

		/* fall through to blocking send */
	}

	return _send(sockfd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len,
		     (struct sockaddr *)msg->msg_name, flags);
}

ssize_t PRE(write)(int fd, const void *buf, size_t count)
{
	if (is_kernel_fd(fd))
		return k_write(fd, buf, count);

	return _send(fd, buf, count, NULL, 0);
}

ssize_t PRE(writev)(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t ret;
	struct sock *so;

	if (is_kernel_fd(fd))
		return k_writev(fd, iov, iovcnt);

	if (RTE_PER_LCORE(_lcore_id) == LCORE_ID_ANY) {
		RTE_PER_LCORE(_lcore_id) = rte_atomic32_add_return(&thr_cnt, 1);
	}

	so = fd2sock(fd);
	if (OPS(so)->writev) {
		ret = OPS(so)->writev(so, iov, iovcnt, NULL);
		if (ret < 0) {
			if (errno != EAGAIN || is_nonblock(so, 0))
				return -1;
		} else {
			/* TODO: blocking && ret < total length */
			be_tx_with_lock(CTX(so));
			return ret;
		}

		/* fall through to blocking send */
	}

	return _send(fd, iov[0].iov_base, iov[0].iov_len, NULL, 0);
}

/* advanced functions */
ssize_t PRE(splice)(int fd_in, loff_t *off_in, int fd_out,
		loff_t *off_out, size_t len, unsigned int flags)
{
	if (is_kernel_fd(fd_in) && is_kernel_fd(fd_out))
		return k_splice(fd_in, off_in, fd_out, off_out, len, flags);

	rte_panic("splice is not supported yet");
	errno = EOPNOTSUPP;
	return -1;
}

ssize_t PRE(sendfile)(int out_fd, int in_fd, off_t *offset, size_t count)
{
	if (is_kernel_fd(out_fd) && is_kernel_fd(in_fd))
		return k_sendfile(out_fd, in_fd, offset, count);

	rte_panic("sendfile is not supported yet");
	errno = EOPNOTSUPP;
	return -1;
}
