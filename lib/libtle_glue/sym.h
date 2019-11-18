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

#ifndef _TLE_KSYM_H_
#define _TLE_KSYM_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/socket.h>

#include <sys/epoll.h>
#include <unistd.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <sys/select.h>
#include <sys/time.h>

#include "tle_glue.h"

#ifdef __cplusplus
extern "C" {
#endif

void symbol_init(void);

#ifdef PRELOAD
int (*k_epoll_create)(int size);
int (*k_epoll_create1)(int flags);
int (*k_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
int (*k_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
int (*k_epoll_pwait)(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
int (*k_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*k_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int (*k_pselect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);

int (*k_socket)(int domain, int type, int protocol);
int (*k_listen)(int sockfd, int backlog);
int (*k_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen); 
int (*k_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int (*k_accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int (*k_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*k_getsockopt)(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int (*k_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int (*k_fcntl)(int fd, int cmd, ... /* arg */ );
int (*k_ioctl)(int d, int request, ...);
int (*k_shutdown)(int sockfd, int how);
int (*k_close)(int fd);
ssize_t (*k_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t (*k_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t (*k_recvmsg)(int sockfd, struct msghdr *msg, int flags);
ssize_t (*k_read)(int fd, void *buf, size_t count);
ssize_t (*k_readv)(int fd, const struct iovec *iov, int iovcnt);
ssize_t (*k_send)(int sockfd, const void *buf, size_t len, int flags);
ssize_t (*k_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t (*k_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
ssize_t (*k_write)(int fd, const void *buf, size_t count);
ssize_t (*k_writev)(int fd, const struct iovec *iov, int iovcnt);
ssize_t (*k_splice)(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
ssize_t (*k_sendfile)(int out_fd, int in_fd, off_t *offset, size_t count);
int (*k_getsockname)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int (*k_getpeername)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
#else
#define k_epoll_create epoll_create
#define k_epoll_create1 epoll_create1
#define k_epoll_ctl epoll_ctl
#define k_epoll_wait epoll_wait
#define k_epoll_pwait epoll_pwait
#define k_poll poll
#define k_select select
#define k_pselect pselect
#define k_socket socket
#define k_listen listen
#define k_bind bind
#define k_accept accept
#define k_accept4 accept4
#define k_connect connect
#define k_getsockopt getsockopt
#define k_setsockopt setsockopt
#define k_fcntl fcntl
#define k_ioctl ioctl
#define k_shutdown shutdown
#define k_close close
#define k_recv recv
#define k_recvfrom recvfrom
#define k_recvmsg recvmsg
#define k_read read
#define k_readv readv
#define k_send send
#define k_sendto sendto
#define k_sendmsg sendmsg
#define k_write write
#define k_writev writev
#define k_splice splice
#define k_sendfile sendfile
#define k_getsockname getsockname
#define k_getpeername getpeername
#endif

#ifdef __cplusplus
}
#endif

#endif /* _TLE_KSYM_H_ */
