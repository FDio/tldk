#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netdb.h>
#include <assert.h>

#define ECHO_LEN	1025

#define MAXBUF		1024
#define MAXEPOLLSIZE	100

#define NI_MAXHOST	1025
#define NI_MAXSERV	32

char *laddr;
char *lport;

static void ipshow(struct sockaddr *addr)
{
	struct sockaddr_in *ina = (struct sockaddr_in *)addr;
	static char szAddr[20] = "\0";

	char* p = (char *)&ina->sin_addr;
	sprintf(szAddr, "%d.%d.%d.%d", *p, *(p + 1), *(p + 2), *(p + 3));
	printf("ip:%s port:%u\n", szAddr, ntohs(ina->sin_port));
}


static int setnonblocking(int sockfd)
{
	if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) == -1) {
		return -1;
	}

	return 0;
}

static int add_event(int epollfd, int fd, int state)
{
	struct epoll_event ev;

	ev.events = state;
	ev.data.fd = fd;
	return epoll_ctl(epollfd,EPOLL_CTL_ADD,fd,&ev);
} 

static int delete_event(int epollfd, int fd, int state)
{
	struct epoll_event ev;

	ev.events = state;
	ev.data.fd = fd;

	return epoll_ctl(epollfd,EPOLL_CTL_DEL,fd,&ev);
}

static void do_write(int epollfd, int fd, char *buf)
{
	int nwrite = 0;

	nwrite = write(fd, buf, strlen(buf));
	if (nwrite == -1) {
		perror("write error:");
		close(fd);
		delete_event(epollfd, fd, EPOLLOUT);
	}
}

static int udp_socket_connect(int epollfd, struct sockaddr_in *servaddr)
{
	struct sockaddr_in my_addr;
	int fd = 0;
	int opt = SO_REUSEADDR;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setnonblocking(fd);

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(atoi(lport));
	my_addr.sin_addr.s_addr = inet_addr(laddr);
	if (bind(fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		exit(1);
	} else {
		printf("IP and port bind success\n");
	}

	if (fd == -1) {
		return -1;
	}

	connect(fd, (struct sockaddr*)servaddr, sizeof(struct sockaddr_in));
	add_event(epollfd, fd, EPOLLIN);

	return fd;
}

static void accept_client(int epollfd,int fd)
{
	struct sockaddr_storage client_addr;
	socklen_t addr_size = sizeof(client_addr);
	char buf[1024];
	int new_sock;
	int ret = 0;

	ret = recvfrom(fd, buf, 1024, 0, (struct sockaddr *)&client_addr,
			&addr_size);
	if (ret > 0)
		printf("recvfrom len = %d\n", ret);
	else {
		perror("recvfrom");
		return;
	}

	buf[ret] = '\0';
	char type = buf[0];
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	ret = getnameinfo((struct sockaddr *)&client_addr, addr_size, hbuf,
			sizeof(hbuf), sbuf, sizeof(sbuf),
			NI_NUMERICHOST | NI_NUMERICSERV);

	ipshow((struct sockaddr *)&client_addr);
	printf("recvfrom client [%s:%s] : %c\n", hbuf, sbuf, buf[0]);

	if (type != '0') {
		return;
	}

	new_sock = udp_socket_connect(epollfd, (struct sockaddr_in*)&client_addr);
	buf[0] = '1';
	do_write(epollfd, new_sock, buf);
}

static void msg_process(int epollfd, int fd)
{
	int nread = 0;
	char buf[MAXBUF];
	char type;

	nread = read(fd, buf, MAXBUF);
	//check(nread > 0, "recvfrom error");
	if (nread < 2) {
		printf("prefix should be [0|1]\n");
	}

	buf[nread] = '\0';
	type = buf[0];

	if (type == '2') {
		printf("recv msg [len: %d]\n", nread - 1);
		do_write(epollfd, fd, buf);
	}

}
int main(int argc, char *argv[])
{
	int listener, kdpfd, nfds, n;
	struct sockaddr_in my_addr;
	struct epoll_event ev;
	struct epoll_event events[MAXEPOLLSIZE];

	if (argc != 3) {
		fprintf (stderr, "Usage: %s <ip> <port>\n", argv[0]);
		exit (EXIT_FAILURE);
	}

	laddr = argv[1];
	lport = argv[2];

	if ((listener = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket create failed");
		exit(1);
	} else {
		printf("socket create success\n");
	}

	int opt = SO_REUSEADDR;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt,sizeof(opt));

	setnonblocking(listener);

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(atoi(lport));
	my_addr.sin_addr.s_addr = inet_addr(laddr);
	if (bind(listener, (struct sockaddr *)&my_addr,
				sizeof(struct sockaddr)) == -1) {
		perror("bind");
		exit(1);
	} else {
		printf("IP and port bind success \n");
	}

	kdpfd = epoll_create(MAXEPOLLSIZE);
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = listener;
	if (epoll_ctl(kdpfd, EPOLL_CTL_ADD, listener, &ev) < 0) {
		fprintf(stderr, "epoll set insertion error: fd=%d\n", listener);
		return -1;
	} else {
		printf("listen socket added in epoll success\n");
	}

	while (1) {
		nfds = epoll_wait(kdpfd, events, MAXEPOLLSIZE, -1);
		if (nfds == -1 && errno != EINTR) {
			perror("epoll_wait");
			break;
		}

		for (n = 0; n < nfds; ++n) {
			if (events[n].data.fd == listener) {
				accept_client(kdpfd, listener);
			} else {
				msg_process(kdpfd, events[n].data.fd);
			}
		}
	}

	close(listener);
	return 0;
}
