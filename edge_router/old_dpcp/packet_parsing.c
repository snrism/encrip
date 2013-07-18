#include <libipq.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include "datapath_functions.h"
#include "packet_header.h"
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include<sys/types.h>
#include<ctype.h>
#include "uthash.h"
#include<sys/socket.h>

#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<netinet/in.h>

#define BUFSIZE 2048

struct credential_cache {
	char fivetuple[50];             /* key */
	int id1;
   	int id2;
	int id3;
	int id4;

	UT_hash_handle hh;         /* makes this structure hashable */
};

struct credential_cache *cache = NULL;

void add_data(char *fivetuple, int index1, int index2, int index3, int index4)
{
	struct credential_cache *s;
	s = malloc(sizeof(struct credential_cache));
	strcpy(s->fivetuple, fivetuple);
	s->id1 = index1;
	s->id2 = index2;
	s->id3 = index3;
	s->id4 = index4;
	HASH_ADD_STR(cache, fivetuple, s);
}

void print_indices() {
    struct credential_cache *s;
    for(s=cache; s != NULL; s=s->hh.next) {
    }
}


int sd;//Socket descriptor declared as global variable
static void die(struct ipq_handle *h) {

    ipq_perror("passer");
    ipq_destroy_handle(h);

}

void PrintPacketInHex(unsigned char *packet, int len)
{
	unsigned char *p = packet;

	printf("\n\n---------Packet---Starts----\n\n");
	
	while(len--)
	{
		printf("%.2x ", *p);
		p++;
	}

	printf("\n\n--------Packet---Ends-----\n\n");

}

void PrintInHex(char *mesg, unsigned char *p, int len)
{
	printf(mesg);

	while(len--)
	{
		printf("%.2X ", *p);
		p++;
	}

}

void ParseEthernetHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;

	if(len > sizeof(struct ethhdr))
	{
		ethernet_header = (struct ethhdr *)packet;

		/* First set of 6 bytes are Destination MAC */

		PrintInHex("Destination MAC: ", ethernet_header->h_dest, 6);
		printf("\n");
		
		/* Second set of 6 bytes are Source MAC */

		PrintInHex("Source MAC: ", ethernet_header->h_source, 6);
		printf("\n");

		/* Last 2 bytes in the Ethernet header are the protocol it carries */

		PrintInHex("Protocol: ",(void *)&ethernet_header->h_proto, 2);
		printf("\n");

		
	}
	else
	{
		printf("Packet size too small !\n");
	}
}

void ParseIpHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;

	/* First Check if the packet contains an IP header using
	   the Ethernet header                                */

	ethernet_header = (struct ethhdr *)packet;

	if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
	{
		/* The IP header is after the Ethernet header  */
		
		if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
		{
			ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
			
			/* print the Source and Destination IP address */

			printf("Dest IP address: %s\n", inet_ntoa(ip_header->daddr));
			printf("Source IP address: %s\n", inet_ntoa(ip_header->saddr));
	

		}
		else
		{
			printf("IP packet does not have full header\n");
		}

	}
	else
	{
		/* Not an IP packet */

	}
}
void ParseTcpHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;

	/* Check if enough bytes are there for TCP Header */

	if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
		/* Do all the checks: 1. Is it an IP pkt ? 2. is it TCP ? */
		
		ethernet_header = (struct ethhdr *)packet;

		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

			if(ip_header->protocol == IPPROTO_TCP)
			{
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				/* Print the Dest and Src ports */

				printf("Source Port: %d\n", ntohs(tcp_header->source));
				printf("Dest Port: %d\n", ntohs(tcp_header->dest));

			}
			else
			{
				printf("Not a TCP packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
		
	}
	else
	{
		printf("TCP Header not present \n");

	} 
}
void start_packet_engine() {

	int status;
    	unsigned char buf[BUFSIZE];
	struct ipq_handle *h;

    	h = ipq_create_handle(0, PF_INET);

    	if (!h){
		 die(h);
	}

    	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);

	if (status < 0){
	
        	die(h);
	}	

    	do {
  
    		status = ipq_read(h, buf, BUFSIZE, 0);
        	if (status < 0){
			printf("2\n");
            		die(h);
		}

        	switch (ipq_message_type(buf)) {

            		case NLMSG_ERROR: {
                		fprintf(stderr, "Received error message %d\n",
                		ipq_get_msgerr(buf));
        	       		break;
            		}
            
			case IPQM_PACKET: /* got a packet */ {
                	 ipq_packet_msg_t *msg = ipq_get_packet(buf);
			
			/* Parse Ethernet Header */
			
			ParseEthernetHeader(buf,status);

			/* Parse IP Header */

			ParseIpHeader(buf,status);

			/* Parse TCP Header */

			ParseTcpHeader(buf,status);
	
	
                break;
            	}

            	default: {
                fprintf(stderr, "Unknown message type!\n");
                break;
            }
        }

    }

   while (1);


    ipq_destroy_handle(h);

}

int main() {

 
   	start_packet_engine();
    	return 0;
}

