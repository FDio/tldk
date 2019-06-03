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

#define MAXLINE 1400
#define OPEN_MAX 100
#define LISTENQ 20
#define INFTIM 1000 
#define MAX_EVENT 10000

char *laddr;
char *lport;

static void ip_show(const char *prefix, struct sockaddr_in *addr)
{
	char szAddr[20] = "\0";
	char* p = (char *)&addr->sin_addr;

	sprintf(szAddr, "%d.%d.%d.%d", *p, *(p + 1), *(p + 2), *(p + 3));
	printf("%s %d:ip:%s port:%u\n", prefix, addr->sin_family, szAddr, ntohs(addr->sin_port));
}

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

int main(int argc, char *argv[])
{
	int cfd;
	struct sockaddr_in sin;
	int i, sockfd, epfd, nfds;
	char send_data[1500];
	char recv_data[1500];
	ssize_t n;
	struct sockaddr_in caddr;
	socklen_t addrlen = sizeof(sin);
	struct epoll_event ev, events[20];

	if (argc != 3) {
		fprintf (stderr, "Usage: %s <ip> <port>\n", argv[0]);
		exit (EXIT_FAILURE);
	}

	laddr = argv[1];
	lport = argv[2];

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(laddr);
	sin.sin_port = htons(atoi(lport));;

	cfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (cfd == -1) {
		perror("socket failed");
		return -1;
	}
	printf("AF_INET = %d SOCK_DGRAM socket, cfd = %d\n", AF_INET, cfd);

	int opt = SO_REUSEADDR;
	setsockopt(cfd, SOL_SOCKET, SO_REUSEADDR, &opt,sizeof(opt));

	set_nonblocking(cfd);

	if (connect(cfd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
		perror("Connect");
		exit(1);
	}

	epfd = epoll_create(256);
	ev.data.fd = cfd;
	ev.events = EPOLLOUT | EPOLLET;  

	epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);
	for ( ; ; ) {

		nfds = epoll_wait(epfd, events, MAX_EVENT, 0);
		for (i = 0; i < nfds; ++i) {
			if (events[i].events & EPOLLIN) {

				sockfd = events[i].data.fd;
				if (sockfd < 0) {
					continue;
				}

				if (send_data[0] == '0') {
					n = recvfrom(sockfd, recv_data, MAXLINE, 0, (struct sockaddr *)&caddr, &addrlen);

					ip_show("0recvfrom pkt", &caddr);
				} else {
					n = read(sockfd, recv_data, MAXLINE);
					ip_show("read pkt", &sin);
				}

				if (n < 0) {
					if (errno == ECONNRESET) {
						close(sockfd);
						return 0;
					} else {
						printf("recv error\n");
					}
				} else if (n == 0) {
					printf("close");
				} else {
					recv_data[n] = '\0';
					printf("recv length = %zi data: [%s]\n", n, recv_data);
				}

				ev.data.fd = cfd;              
				ev.events = EPOLLOUT | EPOLLET;             
				epoll_ctl(epfd, EPOLL_CTL_MOD, cfd, &ev);
			} else if(events[i].events & EPOLLOUT) {    

				printf("\nSEND (q or Q to quit) : ");
				if (fgets(send_data, MAXLINE, stdin) == NULL) {
					perror("fgets");
					exit(1);
				}

				if (strcmp(send_data , "q") == 0 && strcmp(send_data , "Q") == 0) {
					return 0;
				}

				sockfd = events[i].data.fd;
				if (sockfd == -1) {
					continue;
				}

				if (send_data[0] == '0') {
					n = sendto(sockfd, send_data, strlen(send_data), 0, (struct sockaddr*)&sin, addrlen);
					ip_show("sendto pkt", &sin);
				} else {
					n = write(sockfd, send_data, strlen(send_data));
					ip_show("write pkt", &sin);
				}

				printf("send length = %zi data: [%s]\n", n, send_data);

				ev.data.fd = sockfd;
				ev.events = EPOLLIN | EPOLLET;
				epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
			}
		}
	}

	return 0;
}
