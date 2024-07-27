#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hacking.h"
#include "hacking-net.h"

#define PORT 80

void The_connection(int, struct sockaddr_in *);
int get_file_size(int);

int main(void)	{
	int sockfd, new_sockfd, yes=1;
	struct sockaddr_in host_addr, client_addr;
	socklen_t sin_size;
	
	printf("---------------------------------------\n");
	printf(" Aceitando requisições web na porta %d\n", PORT);
	printf("---------------------------------------\n\n");

	if((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) fatal("No socket");
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) fatal("Setando opções do socket SO_REUSEADDR");

	host_addr.sin_family = AF_INET;
	host_addr.sin_port = htons(PORT);
	host_addr.sin_addr.s_addr = INADDR_ANY;
	memset(&(host_addr.sin_zero), '\0', 8);

	if(bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) == -1) fatal("Linkando ao socket");

	if(listen(sockfd, 20) == -1) fatal("Escutando no socket");

	while(1)	{
		sin_size = sizeof(struct sockaddr_in);
		new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);

		if(new_sockfd == -1) fatal("Aceitando conexão");
		The_connection(new_sockfd, &client_addr);
	}

	return 0;
}

