// Funções para mostrar mensagens de erro

// Mensagem de erro
void fatal (char *mensagem)	{
	char mensagem_de_erro[100];

	strcpy(mensagem_de_erro, "[!!] Erro Fatal ");
	strncat(mensagem_de_erro, mensagem, 83);
	perror(mensagem_de_erro);
	exit(-1);
}

// Mensagem de erro para malloc (heap alocation)

void *ec_malloc(unsigned int size)	{
	void *ptr;
	ptr = malloc(size);
	if(ptr == NULL) fatal("Em malloc() na alocação de memória");
	return ptr;
}

// Mostra raw memory em hex byte e em formato printavel

void dump(const unsigned char *data_buffer, const unsigned int length)	{
	unsigned char byte;
	unsigned int i, j;

	for(i=0;i<length;i++)	{
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]); // mostra em hex
	
		if(((i%16)==15) || (i==length-1))	{
			for(j=0;j<15-(i%16);j++) printf("   ");
			printf("| ");

			for(j=(i-(i%16));j<=i;j++)	{
				byte = data_buffer[j];
				if((byte>31) && (byte <127)) printf("%c", byte);
				else printf(".");
			}

			printf("  |\n");
		}
	}
}