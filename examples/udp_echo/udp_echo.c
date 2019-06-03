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

#define MAXLINE 1500
#define OPEN_MAX 100
#define LISTENQ 20
#define INFTIM 1000 
#define MAX_EVENT 10000

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

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sfd == -1) {
		perror("socket failed");
		return -1;
	}

	set_nonblocking(sfd);

	s = bind(sfd, (struct sockaddr *)&sin, sizeof(sin));
	if (s < 0) {
		perror("bind failed");
		close(sfd);
		return -1;
	}

	return sfd;
}

int main(int argc, char *argv[])
{
    int i, sfd, sockfd, epfd, nfds;
    int ret;
    ssize_t n = 0;
    char line[MAXLINE];
    char szAddr[1024] = "\0";
	struct sockaddr_in caddr;
	socklen_t addrlen = sizeof(caddr);
    struct epoll_event ev, events[20];

	if (argc != 3) {
		fprintf (stderr, "Usage: %s <ip> <port>\n", argv[0]);
		exit (EXIT_FAILURE);
	}

    epfd = epoll_create(256);
    printf("epoll_create(256) return %d\n", epfd);

	sfd = create_and_bind(argv[1], argv[2]);
	if (sfd < 0) {
		return -1;
	}

	ev.data.fd = sfd;
    ev.events = EPOLLIN | EPOLLET;  
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
    printf("epoll_ctl return %d\n", ret);
   
    memset(line, 0, MAXLINE);

    for ( ; ; ) {

        nfds = epoll_wait(epfd, events, MAX_EVENT, 0);
        for (i = 0; i < nfds; ++i) {
            if (events[i].events & EPOLLIN) {

                if ((sockfd = events[i].data.fd) < 0)
                    continue;

                if ((n = recvfrom(sockfd, line, MAXLINE, 0, (struct sockaddr *)&caddr, &addrlen)) < 0) {
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

                char* p = (char *)&caddr.sin_addr;
				line[n] = '\0';
                sprintf(szAddr, "%d.%d.%d.%d", *p, *(p + 1), *(p + 2), *(p + 3));
                printf("recv %s from %d:ip:%s port:%u\n", line, caddr.sin_family, szAddr, ntohs(caddr.sin_port));

                ev.data.fd = sockfd;              
                ev.events = EPOLLOUT | EPOLLET;             
                epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);   

            } else if(events[i].events & EPOLLOUT) {    
            
                if(events[i].data.fd == -1) {
                    continue;
                }

                sockfd = events[i].data.fd;             
                printf("send %s\n", line);               
                ev.data.fd = sockfd;              
                ev.events = EPOLLIN | EPOLLET;      
                sendto(sockfd, line, n, 0, (struct sockaddr*)&caddr, addrlen);
                epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
            }
        }
    }

    return 0;
}

