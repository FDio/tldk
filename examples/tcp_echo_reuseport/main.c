#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h> 
#include <errno.h> 
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAXLINE 4096
#define OPEN_MAX 100
#define LISTENQ 20
#define INFTIM 1000 
#define MAX_EVENT 10000

static char line[MAXLINE];

static void set_nonblocking(int sock)
{
	int opts;
	opts = fcntl(sock, F_GETFL);

	if (opts < 0) {
		perror("fcntl(sock,GETFL)");
		exit(1);
	}

	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
		perror("fcntl(sock, SETFL, opts)");
		exit(1);
	}
}

static int create_and_bind(char *addr, char *port)
{
	int s, sfd;
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(addr);
	sin.sin_port = htons(atoi(port));

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd == -1) {
		perror("socket failed");
		return -1;
	}
	printf("AF_INET = %d SOCK_STREAM socket, sfd = %d\n", AF_INET, sfd);

	set_nonblocking(sfd);

	s = bind(sfd, (struct sockaddr *)&sin, sizeof(sin));
	if (s < 0) {
		perror("bind failed");
		close(sfd);
		return -1;
	}

	return sfd;
}

#define NB_SOCK	8
static int sfds[NB_SOCK];

static int
sfd_lookup(int fd)
{
	int i;

	for (i = 0; i < NB_SOCK; i++)
		if (fd == sfds[i])
			return i;
	return -1;
}

int main(int argc, char *argv[])
{
	int i, j, cfd, sockfd, epfd, nfds;
	int ret;
	ssize_t n = 0;
	char szAddr[1024] = "\0";
	struct sockaddr_in caddr;
	socklen_t addrlen = sizeof(caddr);
	struct epoll_event ev, events[20];

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	epfd = epoll_create(256);
	printf("epoll_create(256) return %d\n", epfd);

	for (i = 0; i < NB_SOCK; i++) {
		sfds[i] = create_and_bind(argv[1], argv[2]);
		if (sfds[i] < 0) {
			perror("create_and_bind");
			exit(1);
		}

		listen(sfds[i], 256);

		ev.data.fd = sfds[i];
		ev.events = EPOLLIN | EPOLLET;
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sfds[i], &ev);
		if (ret < 0) {
			perror("epoll_ctl sfd");
			exit(1);
		}
		printf("server #%d: fd = %d\n", i, sfds[i]);
	}

	for ( ; ; ) {

		nfds = epoll_wait(epfd, events, MAX_EVENT, 1000);
		for (i = 0; i < nfds; ++i) {
			if (events[i].events & EPOLLIN) {
				sockfd = events[i].data.fd;
				if (sockfd < 0)
					continue;

				j = sfd_lookup(sockfd);
				if (j >= 0) {
					/* accept process */
					cfd = accept(sockfd, (struct sockaddr *)&caddr, &addrlen);
					if (cfd < 0)
						continue;

					set_nonblocking(cfd);

					ev.data.fd = cfd;
					ev.events = EPOLLIN | EPOLLET;
					ret = epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);

					char* p = (char *)&caddr.sin_addr;
					sprintf(szAddr, "%d.%d.%d.%d", *p, *(p + 1), *(p + 2), *(p + 3));
					printf("accept from #%d (fd = %d): ip=%s port=%u\n",
						j, sockfd, szAddr, ntohs(caddr.sin_port));
					printf("\tnow you can send \"close <index_of_fd>\" to close sfd\n");
				} else {
					/* cfd process */
					n = read(sockfd, line, MAXLINE);
					if (n < 0) {
						if (errno == ECONNRESET) {
							close(sockfd);
							events[i].data.fd = -1;
						} else {
							perror("read error");
							close(sockfd);
						}
					} else if (n == 0) {
						perror("connfd = 0\n");
						close(sockfd);
						events[i].data.fd = -1;
					} else {
						line[n] = '\0';
						printf("read len = %zi, data : %s\n", n, line);
					}

					ev.data.fd = sockfd;
					ev.events = EPOLLOUT | EPOLLET;
					epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);

					if (sscanf(line, "close %d", &j) == 1) {
						printf("will close #%d sfd = %d\n", j, sfds[j]);
						close(sfds[j]);
						sfds[j] = -1;
					}
				}
			} else if (events[i].events & EPOLLOUT) {
				sockfd = events[i].data.fd;
				n = write(sockfd, line, n);
				printf("write len = %zi, data : %s\n", n, line);

				ev.data.fd = sockfd;
				ev.events = EPOLLIN | EPOLLET;
				epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
			} else if (events[i].events & (EPOLLERR | EPOLLHUP)) {
				sockfd = events[i].data.fd;
				printf("peer closed\n");
				close(sockfd);
			}
		}
	}

	return 0;
}
