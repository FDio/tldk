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
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "packetdrill.h"
#include "tle_glue.h"
#include "internal.h"
#include "fd.h"

#include <rte_arp.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_vhost.h>

static int vhost_vid;
enum {VIRTIO_RXQ, VIRTIO_TXQ, VIRTIO_QNUM};
static const char *sockname = "/tmp/sock0";

static int
new_device(int vid)
{
	vhost_vid = vid;

	/* Disable notifications. */
	rte_vhost_enable_guest_notification(vid, VIRTIO_RXQ, 0);
	rte_vhost_enable_guest_notification(vid, VIRTIO_TXQ, 0);

	return 0;
}

static void
destroy_device(int vid)
{
	RTE_SET_USED(vid);
}

static const struct vhost_device_ops device_ops =
{
	.new_device =  new_device,
	.destroy_device = destroy_device,
};

static void
vhost_init(void)
{
	unlink(sockname);

	if (rte_vhost_driver_register(sockname, 0) != 0)
		rte_exit(EXIT_FAILURE, "failed to register vhost driver \n");

	if (rte_vhost_driver_callback_register(sockname, &device_ops) != 0)
		rte_exit(EXIT_FAILURE, "failed to register vhost driver callbacks.\n");

	if (rte_vhost_driver_start(sockname) < 0)
		rte_exit(EXIT_FAILURE, "failed to start vhost driver.\n");

	rte_log_set_level(RTE_LOGTYPE_USER1, RTE_LOG_NOTICE);
}

static uint64_t
now_usecs(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;
}

static void
pd_free(void *userdata)
{
	RTE_SET_USED(userdata);
}

static int
pd_socket(void *userdata, int domain, int type, int protocol)
{
	RTE_SET_USED(userdata);
	return PRE(socket)(domain, type, protocol);
}

static int
pd_bind(void *userdata, int sockfd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	RTE_SET_USED(userdata);
	return PRE(bind)(sockfd, addr, addrlen);
}

static int
pd_listen(void *userdata, int sockfd, int backlog)
{
	RTE_SET_USED(userdata);
	return PRE(listen)(sockfd, backlog);
}

static int
pd_accept(void *userdata, int sockfd, struct sockaddr *addr,
	  socklen_t *addrlen)
{
	RTE_SET_USED(userdata);
	return PRE(accept)(sockfd, addr, addrlen);
}

static int
pd_connect(void *userdata, int sockfd, const struct sockaddr *addr,
	   socklen_t addrlen)
{
	RTE_SET_USED(userdata);
	return PRE(connect)(sockfd, addr, addrlen);
}

static ssize_t
pd_read(void *userdata, int fd, void *buf, size_t count)
{
	RTE_SET_USED(userdata);
	return PRE(read)(fd, buf, count);
}

static ssize_t
pd_readv(void *userdata, int fd, const struct iovec *iov, int iovcnt)
{
	RTE_SET_USED(userdata);
	return PRE(readv)(fd, iov, iovcnt);
}

static ssize_t
pd_recv(void *userdata, int sockfd, void *buf, size_t len, int flags)
{
	RTE_SET_USED(userdata);
	return PRE(recv)(sockfd, buf, len, flags);
}

static ssize_t
pd_recvfrom(void *userdata, int sockfd, void *buf, size_t len,
	    int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	RTE_SET_USED(userdata);
	return PRE(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}

static ssize_t
pd_recvmsg(void *userdata, int sockfd, struct msghdr *msg, int flags)
{
	RTE_SET_USED(userdata);
	return PRE(recvmsg)(sockfd, msg, flags);
}

static ssize_t
pd_write(void *userdata, int fd, const void *buf, size_t count)
{
	RTE_SET_USED(userdata);
	return PRE(write)(fd, buf, count);
}

static ssize_t
pd_writev(void *userdata, int fd, const struct iovec *iov, int iovcnt)
{
	RTE_SET_USED(userdata);
	return PRE(writev)(fd, iov, iovcnt);
}

static ssize_t
pd_send(void *userdata, int sockfd, const void *buf, size_t len, int flags)
{
	RTE_SET_USED(userdata);
	return PRE(send)(sockfd, buf, len, flags);
}

static ssize_t
pd_sendto(void *userdata, int sockfd, const void *buf, size_t len, int flags,
	  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	RTE_SET_USED(userdata);
	return PRE(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t
pd_sendmsg(void *userdata, int sockfd, const struct msghdr *msg, int flags)
{
	RTE_SET_USED(userdata);
	return PRE(sendmsg)(sockfd, msg, flags);
}

static int
pd_fcntl(void *userdata, int fd, int cmd, ...)
{
	void *arg;
	va_list ap;

	va_start(ap, cmd);
	arg = va_arg(ap, void *);
	va_end(ap);

	RTE_SET_USED(userdata);
	return PRE(fcntl)(fd, cmd, arg);
}

static int
pd_ioctl(void *userdata, int fd, unsigned long request, ...)
{
	void *arg;
	va_list ap;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	RTE_SET_USED(userdata);
	return PRE(ioctl)(fd, request, arg);
}

static int
pd_close(void *userdata, int fd)
{
	RTE_SET_USED(userdata);
	return PRE(close)(fd);
}

static int
pd_shutdown(void *userdata, int sockfd, int how)
{
	RTE_SET_USED(userdata);
	return PRE(shutdown)(sockfd, how); 
}

static int
pd_getsockopt(void *userdata, int sockfd, int level, int optname,
	      void *optval, socklen_t *optlen)
{
	RTE_SET_USED(userdata);
	return PRE(getsockopt)(sockfd, level, optname, optval, optlen);
}

static int
pd_setsockopt(void *userdata, int sockfd, int level, int optname,
	      const void *optval, socklen_t optlen)
{
	RTE_SET_USED(userdata);
	return PRE(setsockopt)(sockfd, level, optname, optval, optlen);
}

static int
pd_poll(void *userdata, struct pollfd *fds, nfds_t nfds, int timeout)
{
	RTE_SET_USED(userdata);
	return PRE(poll)(fds, nfds, timeout);
}

static struct rte_mbuf *
from_buf_to_mbuf(const void *buf, size_t count)
{
	struct rte_mempool *mp = get_mempool_by_socket(0);
	uint16_t nb_mbufs = (count + RTE_MBUF_DEFAULT_DATAROOM - 1) /
			    RTE_MBUF_DEFAULT_DATAROOM;
	struct rte_mbuf *mbufs[nb_mbufs + 1];
	uint16_t i, copy_len;
	size_t done = 0;
	char *dst;

	if (unlikely(rte_pktmbuf_alloc_bulk(mp, mbufs, nb_mbufs) < 0))
		rte_exit(EXIT_FAILURE, "allocate mbuf fails\n");

	for (i = 0; i < nb_mbufs; ++i) {
		copy_len = RTE_MIN((size_t)RTE_MBUF_DEFAULT_DATAROOM,
				   count - done);
		dst = rte_pktmbuf_mtod(mbufs[i], char *);
		rte_memcpy(dst, (const char *)buf + done, copy_len);
		done += copy_len;
		mbufs[i]->data_len = copy_len;
		if (i > 0)
			mbufs[i-1]->next = mbufs[i];
	}

	mbufs[0]->pkt_len = count;
	mbufs[0]->nb_segs = nb_mbufs;

	return mbufs[0];
}

/* Send @count bytes of data starting from @buf to the TCP stack.
 * Return 0 on success or -1 on error.
 */
static int
pd_netdev_send(void *userdata, const void *buf, size_t count)
{
	struct ether_hdr *hdr;
	struct rte_mbuf *m;

	RTE_SET_USED(userdata);

	m = from_buf_to_mbuf(buf, count);

	// add l2 header
	hdr = (struct ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
	hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	
	if (rte_vhost_enqueue_burst(vhost_vid, VIRTIO_RXQ, &m, 1) == 1)
		return 0;

	return -1;
}

static inline struct rte_mbuf *
from_mbuf_to_buf(struct rte_mbuf *m, char *buf, size_t len, int ispeek, int needcpy)
{
	void *src;
	uint32_t done = 0;
	uint32_t left = len, orig_pkt_len;
	uint16_t copy_len, seg_len;
	struct rte_mbuf *m_next, *orig_pkt;

	if (len == 0)
		return m;

	orig_pkt = m;
	orig_pkt_len = m->pkt_len;

	do {
		seg_len = rte_pktmbuf_data_len(m);
		copy_len = RTE_MIN(seg_len, left);
		src = rte_pktmbuf_mtod(m, void *);
		if (needcpy)
			rte_memcpy(buf + done, src, copy_len);
		done += copy_len;
		left -= copy_len;
		if (copy_len < seg_len) {
			if (!ispeek) {
				rte_pktmbuf_adj(m, copy_len);
			}
			break;
		}
		m_next = m->next;
		if (!ispeek) {
			rte_pktmbuf_free_seg(m);
		}
		m = m_next;
	} while (left && m);

	if (m && !ispeek)
		m->pkt_len = orig_pkt_len - done;

	if(ispeek)
		return orig_pkt;
	else
		return m;
}

/* Sniff the next packet leaving the TCP stack.
 * Put packet data in @buf.  @count is passed in as the buffer size.
 * The actual number of bytes received should be put in @count.
 * Set @count to 0 if received nothing.
 * Set @time_usecs to the receive timestamp.
 * Return 0 on success or -1 on error. */
static int
pd_netdev_recv(void *userdata, void *buf, size_t *count, long long *time_usecs)
{
	struct rte_mbuf *m;
	struct rte_mempool *mp = get_mempool_by_socket(0);

	RTE_SET_USED(userdata);

	while (rte_vhost_dequeue_burst(vhost_vid, VIRTIO_TXQ, mp, &m, 1) == 0);

	// remove l2 header
	rte_pktmbuf_adj(m, sizeof(struct ether_hdr));

	*count = m->pkt_len;
	from_mbuf_to_buf(m, buf, *count, 0, 1);

	*time_usecs = now_usecs();
	return 0;
}

static int
pd_usleep(void *userdata, useconds_t usec)
{
	RTE_SET_USED(userdata);
	return usleep(usec);
}

static int
pd_gettimeofday(void *userdata, struct timeval *tv, struct timezone *tz)
{
	RTE_SET_USED(userdata);
	return gettimeofday(tv, tz);
}

static int
pd_epoll_create(void *userdata, int size)
{
	RTE_SET_USED(userdata);
	return PRE(epoll_create)(size);
}

static int
pd_epoll_ctl(void *userdata, int epfd, int op, int fd,
	     struct epoll_event *event)
{
	RTE_SET_USED(userdata);
	return PRE(epoll_ctl)(epfd, op, fd, event);
}

static int
pd_epoll_wait(void *userdata, int epfd, struct epoll_event *events,
	      int maxevents, int timeout)
{
	RTE_SET_USED(userdata);
	return PRE(epoll_wait)(epfd, events, maxevents, timeout);
}

static int
pd_pipe(void *userdata, int pipefd[2])
{
	RTE_SET_USED(userdata);
	return pipe(pipefd);
}

static int
pd_splice(void *userdata, int fd_in, loff_t *off_in, int fd_out,
	  loff_t *off_out, size_t len, unsigned int flags)
{
	RTE_SET_USED(userdata);
	return PRE(splice)(fd_in, off_in, fd_out, off_out, len, flags);
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void *
io(void *arg)
{
	int epfd;
	struct in_addr ipv4;
	struct ether_addr mac = { .addr_bytes = { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff}, };
	struct epoll_event events[128];

	RTE_SET_USED(arg);

	setenv(DPDK_IP, "192.168.0.2", 1);
	setenv(DPDK_IP_MASK, "16", 1);
	setenv(DPDK_IP_GATEWAY, "192.168.0.1", 1);

	setenv(DPDK_IPV6, "fd3d:fa7b:d17d::0", 1);
	setenv(DPDK_IPV6_MASK, "48", 1);
	setenv(DPDK_IPV6_GATEWAY, "fd3d:fa7b:d17d:8888::0", 1);

	epfd = PRE(epoll_create)(0);

	inet_pton(AF_INET, "192.168.0.1", &ipv4);

	ipv4_dst_add(default_ctx, &ipv4, &mac);

	pthread_mutex_unlock(&lock);

	while (1) {
		PRE(epoll_wait)(epfd, events, 128, 0);
	}

	return NULL;
}

void
packetdrill_interface_init(const char *flags,
			   struct packetdrill_interface *ifc)
{
	int argc = 0;
	char *argv[16];
	pthread_t tid;

	RTE_SET_USED(flags);

	argv[argc++] = strdup("test");
	argv[argc++] = strdup("-l");
	argv[argc++] = strdup("0");
	argv[argc++] = strdup("--no-pci");
	argv[argc++] = strdup("--in-memory");
	argv[argc++] = strdup("--single-file-segments");
	argv[argc++] = strdup("--");

	if (rte_eal_init(argc, argv) < 0)
		rte_exit(EXIT_FAILURE, "Failed to init DPDK\n");

	fd_init();

	vhost_init();

	if (rte_eal_hotplug_add("vdev", "virtio_user0", "path=/tmp/sock0") < 0)
		rte_exit(EXIT_FAILURE, "hot plug virtio-user failed\n");

	pthread_mutex_lock(&lock);

	pthread_create(&tid, NULL, io, NULL);

	pthread_mutex_lock(&lock);

	ifc->free = pd_free;
	ifc->socket = pd_socket;
	ifc->bind = pd_bind;
	ifc->listen = pd_listen;
	ifc->accept = pd_accept;
	ifc->connect = pd_connect;
	ifc->read = pd_read;
	ifc->readv = pd_readv;
	ifc->recv = pd_recv;
	ifc->recvfrom = pd_recvfrom;
	ifc->recvmsg = pd_recvmsg;
	ifc->write = pd_write;
	ifc->writev = pd_writev;
	ifc->send = pd_send;
	ifc->sendto = pd_sendto;
	ifc->sendmsg = pd_sendmsg;
	ifc->fcntl = pd_fcntl;
	ifc->ioctl = pd_ioctl;
	ifc->close = pd_close;
	ifc->shutdown = pd_shutdown;
	ifc->getsockopt = pd_getsockopt;
	ifc->setsockopt = pd_setsockopt;
	ifc->poll = pd_poll;
	ifc->netdev_send = pd_netdev_send;
	ifc->netdev_receive = pd_netdev_recv;
	ifc->usleep = pd_usleep;
	ifc->gettimeofday = pd_gettimeofday;
	ifc->epoll_create = pd_epoll_create;
	ifc->epoll_ctl = pd_epoll_ctl;
	ifc->epoll_wait = pd_epoll_wait;
	ifc->pipe = pd_pipe;
	ifc->splice = pd_splice;
}
