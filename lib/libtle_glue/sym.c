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

#include <stdio.h>
#include <stdlib.h>
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <dlfcn.h>

#include <rte_debug.h>

#include "sym.h"
#include "log.h"

#ifdef PRELOAD
int (*k_epoll_create)(int size);
int (*k_epoll_create1)(int flags);
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

#define INIT_FUNC(func, handle) do {		\
	k_##func = dlsym(handle, #func);	\
	if ((error = dlerror()) != NULL)  {	\
		rte_panic(#func "is not init");	\
	}					\
	RTE_ASSERT(k_##func);			\
} while (0)

#endif

void
symbol_init(void)
{
#ifdef PRELOAD
	void *handle;
	char *error;

	TRACE("in %s", __func__);

	handle = dlopen("libc.so.6", RTLD_NOW);
	error = dlerror();
	if (!handle) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}

	INIT_FUNC(epoll_create, handle);
	INIT_FUNC(epoll_create1, handle);
	INIT_FUNC(epoll_create1, handle);
	INIT_FUNC(epoll_ctl, handle);
	INIT_FUNC(epoll_wait, handle);
	INIT_FUNC(epoll_pwait, handle);
	INIT_FUNC(socket, handle);
	INIT_FUNC(listen, handle);
	INIT_FUNC(bind, handle);
	INIT_FUNC(accept, handle);
	INIT_FUNC(accept4, handle);
	INIT_FUNC(connect, handle);
	INIT_FUNC(getsockopt, handle);
	INIT_FUNC(setsockopt, handle);
	INIT_FUNC(fcntl, handle);
	INIT_FUNC(ioctl, handle);
	INIT_FUNC(shutdown, handle);
	INIT_FUNC(close, handle);
	INIT_FUNC(recv, handle);
	INIT_FUNC(recvfrom, handle);
	INIT_FUNC(recvmsg, handle);
	INIT_FUNC(read, handle);
	INIT_FUNC(readv, handle);
	INIT_FUNC(send, handle);
	INIT_FUNC(sendto, handle);
	INIT_FUNC(sendmsg, handle);
	INIT_FUNC(write, handle);
	INIT_FUNC(writev, handle);
	INIT_FUNC(splice, handle);
	INIT_FUNC(sendfile, handle);
	INIT_FUNC(poll, handle);
	INIT_FUNC(getsockname, handle);
	INIT_FUNC(getpeername, handle);
	INIT_FUNC(select, handle);
	INIT_FUNC(pselect, handle);

	dlclose(handle);
#endif
}
