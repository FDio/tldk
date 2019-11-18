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

#ifndef _TLE_GLUE_H_
#define _TLE_GLUE_H_

#include <sys/types.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <poll.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PRELOAD

#define PRE(name) name

#else

#define PRE(name) tle_ ## name

#endif

void glue_init1(int argc, char **argv);

/* epoll */
int PRE(epoll_create)(int size);
int PRE(epoll_create1)(int flags);
int PRE(epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
int PRE(epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
int PRE(epoll_pwait)(int epfd, struct epoll_event *events,
		int maxevents, int timeout, const sigset_t *sigmask);

/* for setup, settings, and destroy */
int PRE(socket)(int domain, int type, int protocol);
int PRE(listen)(int sockfd, int backlog);
int PRE(bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int PRE(accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int PRE(accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int PRE(connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int PRE(getsockopt)(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen);
int PRE(setsockopt)(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen);
int PRE(getsockname)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int PRE(getpeername)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int PRE(fcntl)(int fd, int cmd, ... /* arg */ );
int PRE(ioctl)(int d,  unsigned long int request, ...);
int PRE(shutdown)(int sockfd, int how);
int PRE(close)(int fd);

/* for recv */
ssize_t PRE(recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t PRE(recvfrom)(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t PRE(recvmsg)(int sockfd, struct msghdr *msg, int flags);
ssize_t PRE(read)(int fd, void *buf, size_t count);
ssize_t PRE(readv)(int fd, const struct iovec *iov, int iovcnt);

/* for send */
ssize_t PRE(send)(int sockfd, const void *buf, size_t len, int flags);
ssize_t PRE(sendto)(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t PRE(sendmsg)(int sockfd, const struct msghdr *msg, int flags);
ssize_t PRE(write)(int fd, const void *buf, size_t count);
ssize_t PRE(writev)(int fd, const struct iovec *iov, int iovcnt);

/* advanced functions */
ssize_t PRE(splice)(int fd_in, loff_t *off_in, int fd_out,
		loff_t *off_out, size_t len, unsigned int flags);
ssize_t PRE(sendfile)(int out_fd, int in_fd, off_t *offset, size_t count);

/* poll */
int PRE(poll)(struct pollfd *fds, nfds_t nfds, int timeout);
int PRE(ppoll)(struct pollfd *fds, nfds_t nfds,
		const struct timespec *tmo_p, const sigset_t *sigmask);

/* select */
int PRE(select)(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout);
int PRE(pselect)(int nfds, fd_set *readfds, fd_set *writefds,
		 fd_set *exceptfds, const struct timespec *timeout,
		 const sigset_t *sigmask);

/* non-posix APIs */
int fd_ready(int fd, int events);
void v_get_stats_snmp(unsigned long mibs[]);

#ifdef __cplusplus
}
#endif

#endif /* _TLE_GLUE_H_ */
