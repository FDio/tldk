#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include <rte_mbuf.h>
#include <rte_errno.h>

#define HUGE_2M "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages"
#define HUGE_1G "/sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages"

static long int
get_value(const char *path)
{
	int fd, len;
	long int value;
	char buf[1024];

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return ULONG_MAX;

	len = read(fd, buf, sizeof(buf));

	close(fd);

	if (len <= 0) {
		return ULONG_MAX;
	}

	value = strtol(buf, NULL, 10);
	return value;
}

static void
print_free_hugepages(void)
{
	printf("2M: %ld\t\t1G: %ld\n", get_value(HUGE_2M), get_value(HUGE_1G));
}

static int
make_socket_non_blocking(int sfd)
{
	int flags, s;

	flags = fcntl(sfd, F_GETFL, 0);
	if (flags == -1)
	{
		perror("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl(sfd, F_SETFL, flags);
	if (s == -1)
	{
		perror("fcntl");
		return -1;
	}

	return 0;
}

static int
create_and_bind(const char *addr, uint16_t port)
{
	int s, sfd;
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(addr);
	sin.sin_port = htons(port);


	sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd == -1) {
		perror("socket failed");
		return -1;
	}

	s = bind(sfd, (struct sockaddr *)&sin, sizeof(sin));
	if (s < 0) {
		perror("bind failed");
		close(sfd);
		return -1;
	}

	return sfd;
}

static int
create_server(const char *addr, uint16_t port)
{
	int sfd;

	sfd = create_and_bind(addr, port);
	if (sfd == -1)
		return -1;

	if (make_socket_non_blocking(sfd) < 0)
		abort();

	if (listen(sfd, SOMAXCONN) < 0) {
		perror("listen");
		return -1;
	}

	return sfd;
}

static int sock_idx = 0;

extern struct rte_mempool *get_mempool_by_socket(int32_t socket_id);

int
main(void)
{
	int i;
	int fd;
	int nb_socks = 1024 * 64 - 1;
	int nb_mbufs = 0x80000;
	int port_start = 1;
	struct rte_mbuf *m;
	struct rte_mempool *mp = get_mempool_by_socket(0);

	for (i = 0; i < nb_socks; i++) {
		sock_idx = i;
		fd = create_server("0.0.0.0", port_start + i);
		if (fd < 0) {
			printf("failed to create socket: %s\n", strerror(errno));
			break;
		}

		if ((i % 4096) == 1) {
			print_free_hugepages();
			usleep(100 * 1000);
		}
	}

	printf("We have successfully created %d sockets\n", i);

	for (i = 0; i < nb_mbufs; i++) {
		m = rte_pktmbuf_alloc(mp);
		if (m == NULL) {
			printf("failed to alloc mbuf: %s\n", strerror(rte_errno));
			break;
		}
		if ((i % 4096) == 1) {
			print_free_hugepages();
			usleep(100 * 1000);
		}
	}

	printf("We have successfully allocated %d mbufs\n", i);

	return EXIT_SUCCESS;
}
