#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>

int main(int argc, char *argv[]) {
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
#define BUF_SIZE 2000
	char buffer[BUF_SIZE];

	memset(buffer, 'a', sizeof(buffer));

	if (argc < 3) {
		fprintf(stderr,"usage %s hostname port\n", argv[0]);
		exit(0);
	}

	portno = atoi(argv[2]);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
#if 0
	struct hostent *server;
	server = gethostbyname(argv[1]);

	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}

	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
#else
	inet_aton(argv[1], &serv_addr.sin_addr);
#endif
	serv_addr.sin_port = htons(portno);

	/* Now connect to the server */
	if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR connecting");
		exit(1);
	}

	printf("Please enter how many bytes to send: ");
	if (scanf("%d", &n) < 0) {
		perror("scanf error");
		exit(1);
	}

	n = write(sockfd, buffer, n);

	if (n < 0) {
		perror("ERROR writing to socket");
		exit(1);
	}

	printf("Press any key to read: ");
	fgets(buffer, sizeof(buffer) - 1, stdin);

	bzero(buffer, sizeof(buffer));
	n = read(sockfd, buffer, sizeof(buffer) - 1);

	if (n < 0) {
		perror("ERROR reading from socket");
		exit(1);
	}

	printf("%s\n",buffer);
	return 0;
}
