#define WEBROOT "/var/www/html/pages" // Diretorio raiz do servidor
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#include <arpa/inet.h>

// Cabeçalho de funções e variáveis para o sniffer
// u_tipo = unsigned tipo

void pcap_fatal(const char *, const char *); // Função para lidar com erros
void decode_ethernet(const u_char *); // Função para decodificar o cabeçalho da Layer 2 OSI 
void decode_ip(const u_char *);		// Função para decodificar o cabeçalho da Layer 3 OSI
u_int decode_tcp(const u_char *); // Função para decodificar o cabeçlho da Layer 4 OSI
void pacote_pego(u_char *, const struct pcap_pkthdr *, const u_char *); // Função para tratar os pacotes individualmente

struct pcap_pkthdr cap_header; 
const u_char *pacote, *pkt_data;


/* Struct para o cabeçalho Ethernet */

struct ether_hdr	{
	unsigned char ether_dest_addr[ETHER_ADDR_LEN];
	unsigned char ether_src_addr[ETHER_ADDR_LEN];
	unsigned short ether_type;
};

/* Struct para o cabeçalho IP */

struct ip_hdr	{
	unsigned char uo_version_and_length;
	unsigned char ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_flag_offset;
	unsigned char ip_ttl;
	unsigned char ip_type;
	unsigned short up_checksum;
	unsigned int ip_src_addr;	
	unsigned int ip_dst_addr;
};

/* Struct para o cabeçalho TCP */

struct tcp_hdr	{
	unsigned short tcp_src_port;
	unsigned short tcp_dst_port;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned char reserved:4;
	unsigned char tcp_offset:4;
	unsigned tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
	unsigned short tcp_window;
	unsigned short tcp_checksum;
	unsigned short tcp_ungent;
};

/*
Esta função aceita um socket e um ponteiro e garante
que todos os bytes da string ssão enviados.
Retorna 1 se der certo e 0 errado.
*/

int send_string(int sockfd, unsigned char *buffer)	{
	int bytes_enviados, bytes_a_enviar;
	bytes_a_enviar = strlen(buffer);

	while(bytes_a_enviar > 0 )	{
		bytes_enviados = send(sockfd, buffer, bytes_a_enviar, 0);

		if(bytes_enviados == -1) return 0;

		bytes_a_enviar -= bytes_enviados;
		buffer += bytes_enviados;
	}

	return 1;
}

/*
Esta função aceita um socket e um ponteiro para o buffer de destino. 
ele ira receber do socket ate a sequência de byte EOL. 
O EOL bytes são lidos do socket, mas o buffer de destino é terminado depois deles. 
Retorna o tamanho da linha lida sem o EOL
*/

int recv_line(int sockfd, unsigned char *dbuffer)	{
#define EOL "\r\n" // Byte de fim de linha
#define EOL_SIZE 2
	unsigned char *ptr;
	int eol = 0;
	ptr = dbuffer;

	while(recv(sockfd, ptr, 1, 0) == 1)	{ // lê um único byte
		if(*ptr == EOL[eol])	{ // Final?
			eol++;

			if(eol == EOL_SIZE)	{
				*(ptr+1-EOL_SIZE) = '0';
				return strlen(dbuffer);
			}
		}
		else eol = 0;
		ptr++;
	}
	return 0;
}

/*
Esta função lida com a conexão vinda do socket e do cliente.
Ela é processada como um requisição web e essa função responde sobre o socket conectado. 
Finalmente, o socket é fechado no final da função. 
*/

void The_connection(int sockfd, struct sockaddr_in *cliente)	{
	unsigned char *ptr, request[500], resource[500];
	int fd, length;
	length = recv_line(sockfd, request);

	printf("Recebi uma requisição de [%s:%d] \"%s\"\n", 
	inet_ntoa(cliente->sin_addr), ntohs(cliente->sin_port), request);

	ptr = strstr(request, " HTTP/");
	if(ptr == NULL) printf("NÂO É UMA REQUISIÇÃO HTTP VÁLIDA!\n");
	else 	{
		*ptr = 0;
		ptr = NULL;

		if(strncmp(request, "GET ", 4) == 0)
			ptr = request+4;
		if(strncmp(request, "HEAD ", 5) == 0)
			ptr = request+5;
		if(ptr == NULL)	
			printf("REQUISIÇÃO DESCONHECIDA!\n");
		else   	{
			if(ptr[strlen(ptr) -1] == '/')
				strcat(ptr, "index.html");
			strcpy(resource, WEBROOT);
			strcat(resource, ptr);
			fd = open(resource, O_RDONLY, 0);
			printf("Abrindo \'%s\'\t", resource);

			if(fd == -1)	{
				printf(" 404 Not Found\n");
				send_string(sockfd, "HTTP/1.0 404 NOT FOUND\r\n");
				send_string(sockfd, "Server: Pequeno webserver\r\n\r\n");
				send_string(sockfd, "<html><head><title>404 Not Found</title></head>");
				send_string(sockfd, "<body><h1>URL not found</h1></body></html>\r\n");
			}
			else 	{
				printf(" 200 OK");
				send_string(sockfd, "HTTP 1.0 200 OK\r\n");
				send_string(sockfd, "Server: Pequeno webserver\r\n\r\n");
				
				if(ptr == request+4)	{
					if((length = get_file_size(fd)) == -1) fatal("Contando o tamanho do arquivo");
					if((ptr = (unsigned char *) malloc(length)) == NULL) fatal("Alocando memória para ler o arquivo");
					read(fd, ptr, length);
					send(sockfd, ptr, length, 0);
					free(ptr);
				}
				close(fd);
			}
		}
	}
	shutdown(sockfd, SHUT_RDWR);
}

/*
Esta função aceita um um decritor de arquivo aberto 
e retorna o seu tanamho.
*/

int get_file_size(int fd)	{
	struct stat stat_struct;

	if(fstat(fd, &stat_struct) == -1) return -1;
	return (int) stat_struct.st_size; 
}

/*
Função responsável por capturar pacotes.
decodificar as camadas Ethernet, IP e TCP
Extrair os dados úteis e imprimí-los.

	OBS = Ela é utilizada na função pcap_loop() como ponteiro de função 
para repetir o processo para cada pacote capturado.
*/

void pacote_pego(u_char *arg, const struct pcap_pkthdr *cap_header, const u_char *pacote)	{
	int tcp_header_len, total_header_size, pkt_data_len;
	u_char *pkt_data;

	printf("\n\n\t\t===== Capturei um pacote de %d Bytes =====\n", cap_header->len);
	printf("--------------------------------------------------------------------------------\n");

	decode_ethernet(pacote);
	decode_ip(pacote+ETHER_HDR_LEN);
	tcp_header_len = decode_tcp(pacote+ETHER_HDR_LEN+sizeof(struct ip_hdr));

	total_header_size = ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_len;
	pkt_data = (u_char *)pacote +total_header_size; // Ao somar o tamamho total dos Cabeçalhos, se aponta para os dados úteis
	pkt_data_len = cap_header->len - total_header_size;

	if(pkt_data_len > 0)	{
		printf("\n\n\t\t\t%u Bytes de dados no pacote\n\n", pkt_data_len);
		dump(pkt_data, pkt_data_len);
	}
	else printf("\t\t\tSEM DADOS NO PACOTE\n");
	printf("--------------------------------------------------------------------------------\n");
}

void pcap_fatal(const char *falhou_em, const char *errbuf)	{
	printf("[!#!] Erro fatal em %s => %s\n", falhou_em, errbuf);

}

void decode_ethernet(const u_char *header_start)	{
	int i;
	const struct ether_hdr *ether_header;
	ether_header = (const struct ether_hdr *) header_start;
	printf("\n[[  Layer 2  ]]\t{{  Ethernet Header  }}\n");
	
	printf("{  Origem: %02x", ether_header->ether_src_addr[0]);
	for(i=1;i<ETHER_ADDR_LEN;i++)	{
		printf(":%02x", ether_header->ether_src_addr[i]);
	}
	
	printf("\tDestino: %02x", ether_header->ether_dest_addr[0]);
	for(i=1;i<ETHER_ADDR_LEN;i++)	{
		printf(":%02x", ether_header->ether_dest_addr[i]);
	}
	printf("\tTipo ==> %hu  }\n", ether_header->ether_type);

}

void decode_ip(const u_char *header_start)	{
	const struct ip_hdr *ip_header;
	ip_header = (const struct ip_hdr *) header_start;
	struct in_addr ip_addr;
    ip_addr.s_addr = ip_header->ip_src_addr;

	printf("\t\n[[  Layer 3  ]]\t((  IP Header  ))\n");
	printf("\t( Origem: %s\t", inet_ntoa(ip_addr));
    ip_addr.s_addr = ip_header->ip_dst_addr;
	printf("Destino: %s)\n", inet_ntoa(ip_addr));
	printf("\t(  Tipo ==> %u\t", (u_int) ip_header->ip_type);
	printf("\t(  ID: %hu\t Tamanho: %hu  )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

u_int decode_tcp(const u_char *header_start)	{
	u_int header_size;
	const struct tcp_hdr *tcp_header;

	tcp_header = (const struct tcp_hdr *) header_start;
	header_size = 4*tcp_header->tcp_offset;

	printf("\n\t\t[[  Layer 4  ]]\t||  TCP Header  ||\n");
	printf("\t\t||  Porta de Origem: %hu\t", ntohs(tcp_header->tcp_src_port));
	printf("Porta de Destino: %hu  ||\n", ntohs(tcp_header->tcp_dst_port));
	printf("\t\t||  Seq =: %u\t", ntohl(tcp_header->tcp_seq));
	printf("Ack =: %u  ||\n", ntohl(tcp_header->tcp_ack));
	printf("\t\t|| Tamanho Cabeçalho: %u\tFlags: ", header_size);

	if(tcp_header->tcp_flags & TCP_FIN) printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN) printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST) printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH) printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK) printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG) printf("URG ");
	printf(" ||\n");

	return header_size;
}