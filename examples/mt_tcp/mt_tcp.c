#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h> 
#include <pthread.h> 
#include <errno.h> 
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define WORKER 2

#define MAXLINE 1500
#define OPEN_MAX 100
#define LISTENQ 20
#define INFTIM 1000 
#define MAX_EVENT 10000

char *local;
char *lport;

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

	int val =1;
	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)) < 0)
		perror("setsockopt()");

	set_nonblocking(sfd);

	s = bind(sfd, (struct sockaddr *)&sin, sizeof(sin));
	if (s < 0) {
		perror("bind failed");
		close(sfd);
		return -1;
	}

	return sfd;
}

static void worker_handle(void *data)
{
	long w = (long)data;
	int i, sfd, cfd, sockfd, epfd, nfds;
	ssize_t n = 0;
	int ret = 0;
	char line[MAXLINE];
	char szAddr[1024] = "\0";
	struct sockaddr_in caddr;
	socklen_t addrlen = sizeof(caddr);
	struct epoll_event ev, events[20];

	epfd = epoll_create(256);	
	if (epfd < 0) {
		return;
	}

	sfd = create_and_bind(local, lport);
	if (sfd < 0) {
		return;
	}

	listen(sfd, 256);

	ev.data.fd = sfd;
	ev.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
	if (ret < 0) {
		return;
	}

	memset(line, 0, MAXLINE);

	for ( ; ; ) {

		nfds = epoll_wait(epfd, events, MAX_EVENT, 0);
		for (i = 0; i < nfds; ++i) {
			if (events[i].events & EPOLLIN) {

				sockfd = events[i].data.fd;
				if (sockfd < 0) {
					continue;
				}

				if (sockfd == sfd) {

					/* accept process */
					printf("i am worker %ld, begin to accept connection.\n", w);
					cfd = accept(sfd, (struct sockaddr *)&caddr, &addrlen);
					if (cfd != -1) {
						printf("worker %ld accept a connection sucess. ip:%s, port:%d\n", w, inet_ntoa(caddr.sin_addr), caddr.sin_port);
					} else {
						printf("worker %ld accept a connection failed, error: %s\n", w, strerror(errno));
					}
					if (cfd < 0) {
						continue;
					}

					set_nonblocking(cfd);

					ev.data.fd = cfd;
					ev.events = EPOLLIN | EPOLLET;
					ret = epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);


					char* p = (char *)&caddr.sin_addr;
					sprintf(szAddr, "%d.%d.%d.%d", *p, *(p + 1), *(p + 2), *(p + 3));
					printf("accept from %d:ip:%s port:%u\n", caddr.sin_family, szAddr, ntohs(caddr.sin_port));

				} else {

					/* cfd process */
					n = read(sockfd, line, MAXLINE);
					if (n < 0) {
						if (errno == ECONNRESET) {
							close(sockfd);
							events[i].data.fd = -1;
						} else {
							printf("readline error\n");
						}
					} else if (n == 0) {
						perror("connfd = 0\n");
						close(sockfd);
						events[i].data.fd = -1;
					}

					printf("read len = %zi\n", n);

					ev.data.fd = sockfd;
					ev.events = EPOLLOUT | EPOLLET;
					epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
				}
			} else if(events[i].events & EPOLLOUT) {

				sockfd = events[i].data.fd;
				if(sockfd < 0)
					continue;

				n = write(sockfd, line, n);
				printf("write len = %zi\n\n\n\n", n);

				ev.data.fd = sockfd;
				ev.events = EPOLLIN | EPOLLET;
				epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);

				close(sockfd);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf (stderr, "Usage: %s <ip> <port>\n", argv[0]);
		exit (EXIT_FAILURE);
	}

	local = argv[1];
	lport = argv[2];

	long i = 0;

	pthread_t th[WORKER];
	for (i = 0; i < WORKER; i++) {

		if (pthread_create(&th[i], NULL, (void *)worker_handle, (void *)i)) {
			perror("Failed to start all worker threads");
			return 1;
		}
	}

	for (i = 0; i < WORKER; i++) {
		pthread_join(th[i], NULL);
	}

	return 0;
}
