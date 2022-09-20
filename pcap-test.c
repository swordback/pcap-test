#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

struct ethernet_hdr* eth_hdr;
struct ipv4_hdr* ip_hdr;
struct TCP_hdr* tcp_hdr;

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_result() {
	printf("Source MAC address: ");
	for (int num1 = 5; num1 >= 0; num1--) {
		printf("%x", eth_hdr->ether_shost[num1]);
	}
	printf("\n");

	printf("Destination MAC address: ");
	for (int num1 = 5; num1 >= 0; num1--) {
		printf("%x", eth_hdr->ether_dhost[num1]);
	}
	printf("\n");

	printf("Source IP address: ");
	printf("%x\n", ntohl(ip_hdr->ip_shost));

	printf("Destination IP address: ");
	printf("%x\n", ntohl(ip_hdr->ip_dhost));

	printf("Source port number: ");
	printf("%x\n", ntohs(tcp_hdr->tcp_sport));

	printf("Destination port number: ");
	printf("%x\n", ntohs(tcp_hdr->tcp_dport));
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		for (int num1 = 0; num1 < header->caplen; num1++) {
			printf("%x", packet[num1]);
		}
		printf("\n");


		////////// modify start //////////


		int offset = 0;

		// check length
		if (header->caplen < 54) {
			continue;
		}

		eth_hdr = packet;

		// check ethernet type is IPv4
		if (ntohs(eth_hdr->ether_type) != 0x0800) {
			continue;
		}

		offset += 14;

		ip_hdr = packet + offset;

		offset += (ip_hdr->ver_ihl / 16) * 4;
		
		// check IP protocol is TCP
		if (ip_hdr->protocol != 0x06) {
			continue;
		}

		tcp_hdr = packet + offset;

		offset += (tcp_hdr->data_offset_else / 0x0100);

		print_result();

		printf("payload's hexadecimal value (for 10 bytes): ");
		for (int idx = offset; idx < offset + 10; idx++) {
			if (idx < header->caplen) {
				printf("%x", *((char*)packet + idx));
			}
		}
		printf("\n");

		///////// modify end //////////
	}

	pcap_close(pcap);
}
 