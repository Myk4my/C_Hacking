#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hacking.h"

#define PORT 3301

int main(void)	{
	int sockfd, new_sockfd; // socket e socket_aux
	struct sockaddr_in host_addr, client_addr;
	socklen_t sin_size;
	int recv_length=1, yes=1;
	char buffer[1024];

	if((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) fatal("Em criação de Socket");
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
		fatal("Iniciando opções do socket SO_REUSEADDR");

	host_addr.sin_family = AF_INET;
	host_addr.sin_port = htons(PORT);
	host_addr.sin_addr.s_addr = 0;
	memset(&(host_addr.sin_zero), '\0', 8);
	
	if(bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) == -1)
		fatal("Vinculando o socket");

	if(listen(sockfd, 5) == -1)
		fatal("Ouvindo no socket");

	while(1)	{
		sin_size = sizeof(struct sockaddr_in);
		new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);

		if(new_sockfd == -1) fatal("Ao aceitar a conexão");
		printf("Servidor: Recebeu uma conexão de %s porta %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		send(new_sockfd, "\nHACKING ALL THE THINGS!\n", 13, 0);
		recv_length = recv(new_sockfd, &buffer, 1024, 0);

		while(recv_length > 0)	{
			printf("RECEBEMOS: %d bytes\n\n", recv_length);
			dump(buffer, recv_length);
			recv_length = recv(new_sockfd, &buffer, 1024, 0);
		}
		close(new_sockfd);
	}
	return 0;
}