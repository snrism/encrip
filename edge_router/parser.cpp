#include <linux/netfilter.h>
extern "C" {
#include <libipq.h>
}
#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <bitset>
#include<sys/time.h>

#define BUFSIZE 2048
#define DATA_SIZE	100

using namespace std; 
typedef struct PseudoHeader{

	unsigned long int source_ip;
	unsigned long int dest_ip;
	unsigned char reserved;
	unsigned char protocol;
	unsigned short int tcp_length;

}PseudoHeader;

static void die(struct ipq_handle *h)
{
    ipq_perror("passer");
    ipq_destroy_handle(h);
    exit(1);
}

unsigned short ComputeChecksum(unsigned char *data, int len)
{
         long sum = 0;  /* assume 32 bit long, 16 bit short */
	 unsigned short *temp = (unsigned short *)data;

         while(len > 1){
             sum += *temp++;
             if(sum & 0x80000000)   /* if high order bit set, fold */
               sum = (sum & 0xFFFF) + (sum >> 16);
             len -= 2;
         }

         if(len)       /* take care of left over byte */
             sum += (unsigned short) *((unsigned char *)temp);
          
         while(sum>>16)
             sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}

void CreatePseudoHeaderAndComputeTcpChecksum(struct tcphdr *tcp_header, struct iphdr *ip_header, unsigned char *data, int len)
{
	/*The TCP Checksum is calculated over the PseudoHeader + TCP header +Data*/

	/* Find the size of the TCP Header + Data */
	int segment_len = ntohs(ip_header->tot_len) - ip_header->ihl*4; 

	/* Total length over which TCP checksum will be computed */
	int header_len = sizeof(PseudoHeader) + segment_len;

	/* Allocate the memory */

	unsigned char *hdr = (unsigned char *)malloc(header_len);

	/* Fill in the pseudo header first */
	
	PseudoHeader *pseudo_header = (PseudoHeader *)hdr;

	pseudo_header->source_ip = ip_header->saddr;
	pseudo_header->dest_ip = ip_header->daddr;
	pseudo_header->reserved = 0;
	pseudo_header->protocol = ip_header->protocol;
	pseudo_header->tcp_length = htons(segment_len);

	
	/* Now copy TCP */

	memcpy((hdr + sizeof(PseudoHeader)), (void *)tcp_header, tcp_header->doff*4);

	/* Now copy the Data */

	memcpy((hdr + sizeof(PseudoHeader) + tcp_header->doff*4), data, len);

	/* Calculate the Checksum */

	tcp_header->check = ComputeChecksum(hdr, header_len);

	/* Free the PseudoHeader */
	free(hdr);
}
unsigned char *CreateData(int len)
{
	unsigned char *data = (unsigned char *)malloc(len);  
	struct timeval tv;
	struct timezone tz;
	int counter = len;	

	/* get time of the day */
	gettimeofday(&tv, &tz);

	/* seed the random number generator */

	srand(tv.tv_sec);
	
	/* Add random data for now */

	for(counter = 0  ; counter < len; counter++)
		data[counter] = 255.0 *rand()/(RAND_MAX +1.0);

	return data;
}

int main(int argc, char **argv)
{
    int status;
    unsigned char buf[BUFSIZE]; 
    unsigned char *data;
    struct ipq_handle *h;
    
    h = ipq_create_handle(0, PF_INET);
    if (!h)
        die(h);
        
    status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
    if (status < 0)
        die(h);
        
    do{
        status = ipq_read(h, buf, BUFSIZE, 0);
        if (status < 0)
            die(h);
            
        switch (ipq_message_type(buf)) {
            case NLMSG_ERROR:
                fprintf(stderr, "Received error message %d\n",
                        ipq_get_msgerr(buf));
                break;
                
            case IPQM_PACKET: {
 		
                 ipq_packet_msg_t *m = ipq_get_packet(buf);
               	 unsigned char *new_packet;		 
		 int new_packet_len=m->data_len;	 

//		 memcpy(new_packet,(unsigned char*)m,new_packet_len);	

		 struct iphdr *ip = (struct iphdr*) m->payload;
                 struct tcphdr *tcp = (struct tcphdr*) (m->payload + (4 * ip->ihl));
                 int port = htons(tcp->dest);       
		 int ip_length = ntohs(ip->tot_len);

	bitset<8> ssad1 = bitset<8>(10); 
        bitset<8> ssad2 = bitset<8>(1);
        bitset<8> ssad3 = bitset<8>(1);
        bitset<8> ssad4 = bitset<8>(1);
	string ssaddr;
	ssaddr += ssad1.to_string<char, char_traits<char> ,allocator<char> > () + ssad2.to_string<char, char_traits<char> ,allocator<char> > () + ssad3.to_string<char, char_traits<char> ,allocator<char> > () +ssad4.to_string<char, char_traits<char> ,allocator<char> > (); 


  	bitset<8> ddad1 = bitset<8>(10);
        bitset<8> ddad2 = bitset<8>(0);
        bitset<8> ddad3 = bitset<8>(2);
        bitset<8> ddad4 = bitset<8>(10);
        string ddaddr;
        ddaddr += ddad1.to_string<char, char_traits<char> ,allocator<char> > () + ddad2.to_string<char, char_traits<char> ,allocator<char> > () + ddad3.to_string<char, char_traits<char> ,allocator<char> > () +ddad4.to_string<char, char_traits<char> ,allocator<char> > ();
	

	struct iphdr *ip_header;
	ip_header = (struct iphdr *)malloc(sizeof(struct iphdr));

	ip_header = (struct iphdr*)new_packet;

	ip_header->version = ip->version;
	ip_header->ihl = ip->ihl;
	ip_header->tos = ip->tos;
	ip_header->tot_len = htons(ip_length);
	ip_header->id = htons(ip->id);
	ip_header->frag_off = ip->frag_off;
	ip_header->ttl = ip->ttl;
	ip_header->protocol = IPPROTO_TCP;
	ip_header->check = 0; /* We will calculate the checksum later */
	ip_header->saddr = htonl((bitset<32>(ssaddr)).to_ulong());
        ip_header->daddr = htonl((bitset<32>(ddaddr)).to_ulong());

	/* Calculate the IP checksum now : 
	   The IP Checksum is only over the IP header */

	ip_header->check = ComputeChecksum((unsigned char *)ip_header, ip_header->ihl*4);
	
	struct tcphdr *tcp_header;
	tcp_header = (struct tcphdr*)malloc(sizeof(struct tcphdr));
	tcp_header = (struct tcphdr*)(new_packet + ip_header->ihl*4);

	tcp_header->source = htons(tcp->source);
	tcp_header->dest = htons(tcp->dest);
	tcp_header->seq = htonl(tcp->seq);
	tcp_header->ack_seq = htonl(tcp->ack_seq);
	tcp_header->res1 = tcp->res1;
	tcp_header->doff = tcp->doff;
	tcp_header->syn = tcp->syn;
	tcp_header->window = htons(tcp->window);
	tcp_header->check = 0; /* Will calculate the checksum with pseudo-header later */
	tcp_header->urg_ptr = tcp->urg_ptr;

	/* Create Data */	
//	data = CreateData(ntohs(ip_header->tot_len) - ip_header->ihl*4 - tcp_header->doff*4);
        data = (unsigned char*)malloc(m->data_len +1 - ip_header->ihl*4 - tcp_header->doff*4);
	memcpy(data,m->payload + ip_header->ihl*4 + tcp_header->doff*4,m->data_len + 1- ip_header->ihl*4 - tcp_header->doff*4);

	memcpy(new_packet + ip_header->ihl*4 + tcp_header->doff*4, data, m->data_len + 1- ip_header->ihl*4 - tcp_header->doff*4);

	/* Create PseudoHeader and compute TCP Checksum  */
	CreatePseudoHeaderAndComputeTcpChecksum(tcp_header, ip_header, data ,m->data_len +1 - ip_header->ihl*4 - tcp_header->doff*4);

        cout << "Sending packet out..."<<endl;
        status = ipq_set_verdict(h, m->packet_id,NF_ACCEPT,new_packet_len,new_packet);

                if (status < 0)
                    die(h);
                break;
            }
            
            default:
                fprintf(stderr, "Unknown message type!\n");
                break;
        }
    } while (1);
    
    ipq_destroy_handle(h);
    return 0;
}
