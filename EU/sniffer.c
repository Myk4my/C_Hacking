#include <pcap.h>
#include <stdio.h>
#include "hacking.h"
#include "hacking-net.h"


int main()	{

	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *pcap_handle;

	device = pcap_lookupdev(errbuf);
	if(device == NULL) pcap_fatal("Em pcap_lookupdev", errbuf);

	printf("\n\t\t-----------------------------------------\n");
	printf("\t\t|\tSnifando na interface %s  \t|", device);
	printf("\n\t\t-----------------------------------------\n\n");

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	if(pcap_handle == NULL) pcap_fatal("Em pcap_open_live", errbuf);
	pcap_loop(pcap_handle, 5, pacote_pego, NULL);
	pcap_close(pcap_handle);

	return 0;

}