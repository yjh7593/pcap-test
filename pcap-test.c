#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,     /* header length */
           ip_v:4;          /* version */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */

    u_int8_t   th_x2:4,         /* (unused) */
	    th_off:4;        /* data offset */
         
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
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

//Print MAC
void printMac(u_int8_t* m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x ",m[0], m[1], m[2], m[3], m[4], m[5]);
}

//Print IP
void printIp(uint32_t ip){
	printf("%d.%d.%d.%d", ip&0xFF, ip>>8&0xFF, ip>>16&0xFF, ip>>24);
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
		printf("\n%u bytes captured\n", header->caplen);
		
		//set the ethernet and ip header
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr* ip_hdr = packet+sizeof(struct libnet_ethernet_hdr);
		
		//Check the protocol(IP, TCP)
		if(eth_hdr -> ether_type !=ntohs(ETHERTYPE_IP) || ip_hdr->ip_p != 0x06){
			continue;
		}
		
		//Print MAC
		printf("MAC : ");
		printMac(eth_hdr->ether_shost);
		printf(" > ");
		printMac(eth_hdr->ether_dhost);
		printf("\n");

		//Print IP
		printf("IP : ");
		printIp(ip_hdr->ip_src.s_addr);
		printf(" > ");
		printIp(ip_hdr->ip_dst.s_addr);
		printf("\n");

		//set the tcp header
		struct libnet_tcp_hdr* tcp_hdr = packet+sizeof(struct libnet_ethernet_hdr)+(ip_hdr->ip_hl*4);		
		printf("port : %d > %d\n", htons(tcp_hdr->th_sport), htons(tcp_hdr->th_dport));
		
		//calculate the offset for data
		int data_offset = sizeof(struct libnet_ethernet_hdr)+(ip_hdr->ip_hl*4)+(tcp_hdr->th_off*4);
		if(header->len <= data_offset){
			continue;
		}
		//if packet has data
		else{
			//printf("header : %d data_off : %d\n", header->len, data_offset);
			char * data = packet+data_offset;
			int data_len = header->len - data_offset;
			//Check the ethernet padding
			if(data[0]!=0x00){
				printf("Application Data : ");
				//print the maximum 10 data
				for(int i = 0; i<(data_len >= 10 ? 10 : data_len) ;i++){
					printf("%c", data[i]);
				}
				printf("\n");	
			}
		}	
	}

	pcap_close(pcap);
}
