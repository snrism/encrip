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
#define BUFSIZE 2048
using namespace std; 
static void die(struct ipq_handle *h)
{
    ipq_perror("passer");
    ipq_destroy_handle(h);
    exit(1);
}
int main(int argc, char **argv)
{
    int status;
    unsigned char buf[BUFSIZE];
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
   struct iphdr *ip = (struct iphdr*) m->payload;

            struct tcphdr *tcp = (struct tcphdr*) (m->payload + (4 * ip->ihl));
 
                int port = htons(tcp->dest);       
		bitset<32>src_addr(ntohl(ip->saddr));
		bitset<32>dst_addr(ntohl(ip->daddr));
		string sip = src_addr.to_string<char,char_traits<char> , allocator<char> > ();
		string dip = dst_addr.to_string<char,char_traits<char> , allocator<char> > ();

	bitset<8> sad1 = bitset<8>(sip.substr(0,8)); 
	bitset<8> sad2 = bitset<8>(sip.substr(8,8));
	bitset<8> sad3 = bitset<8>(sip.substr(16,8));
	bitset<8> sad4 = bitset<8>(sip.substr(24,8));

	bitset<8> dad1 = bitset<8>(dip.substr(0,8)); 
	bitset<8> dad2 = bitset<8>(dip.substr(8,8));
	bitset<8> dad3 = bitset<8>(dip.substr(16,8));
	bitset<8> dad4 = bitset<8>(dip.substr(24,8));

cout << "Source Address: "<< "\t"<<sad1.to_ulong()<< "\t"<<sad2.to_ulong()<< "\t"<<sad3.to_ulong() << "\t"<<sad4.to_ulong() << endl;
cout << "Destination Address: "<< "\t"<<dad1.to_ulong()<< "\t"<<dad2.to_ulong()<< "\t"<<dad3.to_ulong() << "\t"<<dad4.to_ulong() << endl;

		//printf("Destination Port Number: %d\n",port);
	//	cout << "Source IP Address: " << inet_ntoa(ip->saddr) <<endl;
	//	cout << "Destination IP Address: "<< inet_ntoa(ip->daddr) << endl;             
                status = ipq_set_verdict(h, m->packet_id,
                                         NF_ACCEPT, 0, NULL);
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
