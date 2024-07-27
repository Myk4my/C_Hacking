#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/*
Um simples resolvedor de nomes DNS lindo!
Criar coisas em C é super COOL!!!

By: Myk4my
*/

int main(int argc, char **argv)	{
	struct hostent *host; // ponteiro de struct para o domínio
	struct in_addr *ip;	// ponteiro de struct para armazenar o IPv4 correspondente

	if(argc < 2)	{
		printf("Modo de usar: %s [Nome do site]\n", argv[0]);
		exit(1);
	}

	host = gethostbyname(argv[1]); // função que faz a mágica acontecer

	if(host == NULL) printf("Não foi possível econtrar o endereço correspondente a [%s]\n", argv[1]);

	else {
		ip = (struct in_addr *) (host->h_addr); // Casting para coletar somente o Ipv4
		printf("[%s] Corresponde ===> %s\n", argv[1], inet_ntoa(*ip)); // inet_ntoa converte o formato de rede Binário para um padrão
	}
	return 0;
}