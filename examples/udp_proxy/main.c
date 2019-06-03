#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <pthread.h> 
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h> 

#include "./libev/ev.h"

#define WORKER 3

char *local;
char *lport;

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CONNECTIONS 1024

#define upstream_ip "1.1.1.2"
#define upstream_port 9999

struct connection {
	struct ev_io *ev;
	struct ev_timer *timer;
	int fd;
	void *loop;

	struct ev_io *up_ev;
	int up_fd;
};

void udp_accept_callback(struct ev_loop *loop, struct ev_io *watcher, int revents);
int udp_socket_connect(struct sockaddr_in *peer, char *self_port, int isbind);

void udp_read_callback(struct ev_loop *loop, struct ev_io *watcher, int revents);

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

/*
   static void timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
   {
///time_t now;

///now = time(NULL);
///printf("in tiemr cb %ld , cur time is %s revents = %d EV_READ = %d EV_WRITE = %d\n", 
///	(long int)(w->data), ctime(&now), revents, EV_READ, EV_WRITE);
//ev_timer_init(w, timeout_cb, 5, 0);
//ev_timer_start(loop, w);
}
*/

int udp_socket_connect(struct sockaddr_in *peer, char *self_port, int isbind)
{
	int fd = 0;
	int opt = SO_REUSEADDR;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	set_nonblocking(fd);

	if (isbind) {
		struct sockaddr_in my_addr;
		bzero(&my_addr, sizeof(my_addr));
		my_addr.sin_family = PF_INET;
		my_addr.sin_port = htons(atoi(self_port));
		my_addr.sin_addr.s_addr = inet_addr(local);
		if (bind(fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
			perror("bind");
			exit(1);
		} else {
			printf("IP and port bind success\n");
		}
	}

	if (fd == -1)
		return  -1;

	connect(fd, (struct sockaddr*)peer, sizeof(struct sockaddr_in));

	return fd;
}

static int create_upstream_peer(struct connection *conn)
{
	struct sockaddr_in addr;
	struct ev_io *ev = NULL;

	addr.sin_family = PF_INET;
	addr.sin_port = htons(upstream_port);
	addr.sin_addr.s_addr = inet_addr(upstream_ip);
	conn->up_fd = udp_socket_connect((struct sockaddr_in*)&addr, NULL, 0);

	ev = (struct ev_io*)malloc(sizeof(struct ev_io));
	if (!ev) {
		return -1;
	}

	ev->data = conn;
	conn->up_ev = ev;

	ev_io_init(ev, udp_read_callback, conn->up_fd, EV_READ);
	ev_io_start(conn->loop, ev);

	return 0;
}

void udp_accept_callback(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	int client_sd;
	struct sockaddr_in addr;
	socklen_t client_len = sizeof(addr);
	struct ev_io *client_watcher = NULL;
	struct ev_timer *timeout_watcher = NULL;
	struct connection *conn = NULL;
	char buffer[BUFFER_SIZE];
	int ret = 0;

	if (EV_ERROR & revents) {
		printf("error event in accept\n");
		return;
	}

	conn = (struct connection *)malloc(sizeof(struct connection));
	if (!conn) {
		return;
	}

	ret = recvfrom(watcher->fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &client_len);

	client_sd = udp_socket_connect((struct sockaddr_in*)&addr, lport, 1);
	if (client_sd < 0) {
		printf("accept error\n");
		return;
	}

	client_watcher = (struct ev_io*)malloc(sizeof(struct ev_io));
	timeout_watcher = (struct ev_timer*)malloc(sizeof(struct ev_timer));

	if (!client_watcher) {
		return;
	}

	if (!timeout_watcher) {
		free(client_watcher);
		return;
	}

	printf("client connected, fd: %d\n", client_sd);

	// listen new client
	ev_io_init(client_watcher, udp_read_callback, client_sd, EV_READ);
	ev_io_start(loop, client_watcher);

	// add a timer for this fd
	/*
	   timeout_watcher->data = (void *)(long)client_sd;
	   ev_timer_init(timeout_watcher, timeout_cb, 5, 0);
	   ev_timer_start(loop, timeout_watcher);
	   */

	conn->ev = client_watcher;
	conn->timer = timeout_watcher;
	conn->fd = client_sd;
	conn->loop = loop;
	client_watcher->data = conn;

	create_upstream_peer(conn);

	ret = write(conn->up_fd, buffer, ret);

	bzero(buffer, BUFFER_SIZE);
}

static void conn_finish(struct connection *conn)
{
	struct ev_loop *loop = (struct ev_loop *)conn->loop;

	close(conn->fd);
	ev_io_stop(loop, conn->ev);
	ev_timer_stop(loop, conn->timer);

	close(conn->up_fd);
	ev_io_stop(loop, conn->up_ev);

	free(conn);
}

void udp_read_callback(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct connection *conn = NULL;
	char buffer[BUFFER_SIZE];
	ssize_t len;

	if (EV_ERROR & revents) {
		printf("error event in read\n");
		return;
	}

	// socket recv
	len = recv(watcher->fd, buffer, BUFFER_SIZE, 0); // read stream to buffer
	if (read < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			printf("read error\n");
			return;
		}
	}

	if(len <= 0) {
		printf("client closed.\n");
		goto conn_free;
	}

	conn= (struct connection *)watcher->data;
	if (watcher->fd == conn->fd) {
		// socket send to client
		len = send(conn->up_fd, buffer, len, 0);
	} else if (watcher->fd == conn->up_fd) {
		// socket send to upstream
		len = send(conn->fd, buffer, len, 0);
	}

	bzero(buffer, BUFFER_SIZE);

conn_free:
	if (watcher->data) {
		//conn_finish((struct connection *)watcher->data);
	}
}

int ev_cycle(void *data)
{
	long w = (long)data;
	int sd;
	struct sockaddr_in addr;
	struct ev_loop *loop = NULL;
	struct ev_io *socket_watcher = (struct ev_io*)malloc(sizeof(struct ev_io));

	signal(SIGPIPE, SIG_IGN);

	// socket
	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		printf("socket error\n");
		return -1;
	}
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(lport));
	addr.sin_addr.s_addr = inet_addr(local);

	set_nonblocking(sd);

	// bind
	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
		printf("bind error\n");
		return -1;
	}

	// set sd reuseful
	int bReuseaddr = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const char*) &bReuseaddr, sizeof(bReuseaddr)) != 0) {
		printf("setsockopt error in reuseaddr[%d]\n", sd);
		return -1;
	}

	loop = ev_loop_new(0);

	printf("worker: %ld loop: %p\n", w, loop);

	/* init ev_io */
	socket_watcher->data = NULL;
	ev_io_init(socket_watcher, udp_accept_callback, sd, EV_READ);
	ev_io_start(loop, socket_watcher);

	/* ev loop */
	while(1) {
		ev_run(loop, 1);
	}

	return 1;
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

		//sleep(2);
		if (pthread_create(&th[i], NULL, (void *)ev_cycle, (void *)i)) {
			perror("Failed to start all worker threads");
			return 1;
		}
	}

	for (i = 0; i < WORKER; i++) {
		pthread_join(th[i], NULL);
	}

	return 0;
}
