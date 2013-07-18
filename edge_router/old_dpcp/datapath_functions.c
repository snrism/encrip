#include <string.h>
#include <libipq.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<features.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<arpa/inet.h>
#include<string.h>
//#include <netinet/cred.h>
#include "cred.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include<ctype.h>
#include<sys/types.h>






//Comapre strings for nonce comparison
int FindStr(FILE *f, char *str)
{
 int s_pos; //string position in the text
 int c_pos; //char position in the text
 char *string;
 char ccnt; //char count
 s_pos = -1;
 c_pos = 0;
 string = malloc(strlen(str));
 while (!feof(f))
  {
   
	if (c_pos == 0)
    for (ccnt = 1; ccnt <= strlen(str); ccnt++)
     if (!feof(f))
      string[ccnt - 1] = getc(f);
   if (c_pos != 0)
    if (!feof(f))
     {
      for (ccnt = 0; ccnt <= strlen(str) - 2; ccnt++)
       string[ccnt] = string[ccnt + 1];  
      string[strlen(str) - 1] = getc(f);
     }   
   if (strcmp(string, str) == 0)
    {
     s_pos = c_pos;
     break;
    }    
   c_pos++;
  }
printf("The s pos is %d\n",s_pos);
 return(s_pos);
}



//This function creates the nonce
 unsigned int get_nonce() {

unsigned int random_number;	
long ltime;
int stime;

	ltime = time(NULL);
        stime = (unsigned) ltime/2;
        srand(stime);
        random_number = rand();
	return(random_number);
}




//Gets the Bloom filter array
unsigned char *get_BFilter(ipq_packet_msg_t *msg, unsigned char *BloomFilter) {
int count;

struct iphdr *iph = ((struct iphdr *) msg->payload);

    /* Cast the TCP Header from the raw packet */
    struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl << 2));
for(count=0;count<16;count++) {

BloomFilter[count] = setup->Bfilter[count];
}
return BloomFilter;
}



/* This fuction identifies if the captured packet is TCP or UDP.
 Fuction will return: Protocol code e.g.  6 for TCP and 17 UDP.*/

int identify_ip_protocol(ipq_packet_msg_t *msg) {
    int protocol=0;  /* 6 = TCP, 16 = UDP */
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* get the protocol identifier from the ip header */
    protocol = iph->protocol;
    
    return(protocol);
    
}





/* This function gets src IP from captured packet.
 Returns source IP in inet_addr form */

unsigned int get_src_ip(ipq_packet_msg_t *msg) {
// char  get_src_ip(ipq_packet_msg_t *msg) {
//struct in_addr ipaddr;
 unsigned int src_ip_addr;
// char src_ip_addr; 
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
//ipaddr.s_addr = iph->saddr;
// src_ip_addr = inet_ntoa(ipaddr);
   
    /* get src address from iphdr */
src_ip_addr = iph->saddr;
    
    return(src_ip_addr);
    
}



/* This function gets dst IP from captured packet.
 Returns destination IP in inet_addr form */
unsigned int get_dst_ip(ipq_packet_msg_t *msg) {

    unsigned int dst_ip_addr;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* get dst address from iphdr */
    dst_ip_addr =iph->daddr;
    
    return(dst_ip_addr);
    
}



//Get Source POrt
int get_cred_src_port(ipq_packet_msg_t *msg) {
    int src_port=0;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl << 2));
    
    /* get the destination port of the packet */
    src_port = ntohs(setup->src);
    
    return(src_port);
    
}


//Gets Destination port

int get_cred_dst_port(ipq_packet_msg_t *msg) {
    int dst_port=0;

    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);

    /* Cast the TCP Header from the raw packet */
    struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl << 2));

    /* get the destination port of the packet */
    dst_port = ntohs(setup->dest);

    return(dst_port);

}


//Gets the Next Header Number

int get_cred_nexthdr(ipq_packet_msg_t *msg) {

	int header =0;
	
	struct iphdr *iph = ((struct iphdr *) msg->payload);

    /* Cast the TCP Header from the raw packet */
    struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl << 2));

    /* get the destination port of the packet */
    header = setup->nexthdr;

    return(header);

}
	







//gets signatures
unsigned char *get_Bfilter_array(ipq_packet_msg_t *msg, unsigned char *BitArray) {
int count;

struct iphdr *iph = ((struct iphdr *) msg->payload);

struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl <<2));

for(count=0;count<16;count++){
BitArray[count] = setup->Bfilter[count];
}
return BitArray;
}






//gets setup flag
unsigned int get_setup_setupflag(ipq_packet_msg_t *msg) {

unsigned int setupflag;

struct iphdr *iph = ((struct iphdr *) msg->payload);

struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl <<2));

setupflag = setup->request;
return(setupflag);
}



//Gets the response flag
unsigned int get_setup_responseflag(ipq_packet_msg_t *msg) {

unsigned int responseflag;

struct iphdr *iph = ((struct iphdr *) msg->payload);

struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl <<2));

responseflag = setup->response;
return(responseflag);
}


//gets challenge flag

unsigned int get_setup_challengeflag(ipq_packet_msg_t *msg) {

//unsigned int challengeflag;

struct iphdr *iph = ((struct iphdr *) msg->payload);

struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl <<2));

//challengeflag = setup->challenge;
return(setup->challenge);
}

//gets credential index flag

unsigned int get_setup_credentialsflag(ipq_packet_msg_t *msg) {

//unsigned int credentialflag;

struct iphdr *iph = ((struct iphdr *) msg->payload);

struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl <<2));

//challengeflag = setup->challenge;
return(setup->credentials);
}


void credentials_get_payload(ipq_packet_msg_t *msg, char *buffer) {

    int unsigned payload_length=0;

    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);

    /* Cast the TCP Header from the raw packet */
//	 struct setup_credhdr *setup = (struct setup_credhdr *) (msg->payload + (iph->ihl << 2));

    

    /* get the payload offset from within the raw packet */
    int unsigned payload_offset = (iph->ihl << 2) + 20;

    /* calculate the length of the payload */
    payload_length = (unsigned int) ntohs(iph->tot_len) - ((iph->ihl << 2) + 20);

    if(payload_length) {
        memcpy(buffer, msg->payload + payload_offset, payload_length);
    }
    else{
        //printf("ERROR: tcp_udp_parse->tcp_get_payload [payload is zero....]\n");
}
}






/* This function returns the destination port of the captured packet.
 returns destination port */
int get_tcp_dst_port(ipq_packet_msg_t *msg) {
    int dst_port=0;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
    
    /* get the destination port of the packet */
    dst_port = ntohs(tcp->dest);
    
    return(dst_port);
    
}

int get_udp_dst_port(ipq_packet_msg_t *msg) {
    int dst_port=0;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the UDP Header from the raw packet */
    struct udphdr *udp = (struct udphdr *) (msg->payload + (iph->ihl << 2));
    
    /* get the destination port of the packet */
    dst_port = ntohs(udp->dest);
    
    return(dst_port);
    
}


unsigned int get_seq_no(ipq_packet_msg_t *msg)

{

 struct iphdr *iph = ((struct iphdr *) msg->payload);

    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
return(ntohs(tcp->seq));
}

/* This fuction checks if the captured packet is a tcp conection request.  It checks for
 SYN flag within the tcp header.
 returns 0 for no, 1 for yes */
int tcp_connection_request_check(ipq_packet_msg_t *msg) {
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
    
    /* get syn flag and return it */
    return (tcp->syn);
    
}

/* This fuction checks if the captured packet is a tcp termination request.  It checks for
 FIN flag within the tcp header.
 returns 0 for no, 1 for yes */
int tcp_connection_termination_check(ipq_packet_msg_t *msg) {
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
    /* get syn flag and return it */
    return (tcp->fin);
    
}

int tcp_connection_ack_check(ipq_packet_msg_t *msg) {
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
    
    /* get syn flag and return it */
    return (tcp->ack);
    
}

int tcp_get_payload_size(ipq_packet_msg_t *msg) {
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
    
    /* calculate the length of the payload */
    int unsigned payload_length = (unsigned int) ntohs(iph->tot_len) - ((iph->ihl << 2) + (tcp->doff << 2));
    
    return(payload_length);
    
}

void get_tcp_connection_id(ipq_packet_msg_t *msg, char *connectid) {
    unsigned int src_ip;
    unsigned int src_port;
    char str_ip[25];
    char str_port[15];
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
    
    src_ip = get_src_ip(msg);
    src_port = ntohs(tcp->source);
    
    sprintf(str_ip, "%d", src_ip);
    strcat(connectid, str_ip );
    strcat(connectid, ":");
    sprintf(str_port, "%d", src_port);
    strcat(connectid, str_port);
    
}

void tcp_get_payload(ipq_packet_msg_t *msg, char *buffer) {
    
    int unsigned payload_length=0;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcp = (struct tcphdr *) (msg->payload + (iph->ihl << 2));
    
    /* get the payload offset from within the raw packet */
    int unsigned payload_offset = ((iph->ihl << 2) + (tcp->doff << 2));
    
    /* calculate the length of the payload */
    payload_length = (unsigned int) ntohs(iph->tot_len) - ((iph->ihl << 2) + (tcp->doff << 2));
    
    if(payload_length) {
        memcpy(buffer, msg->payload + payload_offset, payload_length);
    }
    else
        printf("ERROR: tcp_udp_parse->tcp_get_payload [payload is zero....]\n");
}

//Writes the nonce sent to a file with srcip,dst ip, src port, dest port, next header

void write_noncesent_to_file(unsigned long srcaddr, unsigned long dstaddr, unsigned int src_port, unsigned int dst_port, unsigned int nexthdr, unsigned int nonce_generated) {
	 
	// struct in_addr ipaddr;
	FILE *file;
        file = fopen("nonce_sent.txt", "a+");

        if (file == NULL) {
        //	printf("couldn't open nonces_send.txt file for writing.\n");
                exit(0);
        }
	 //ipaddr.s_addr = srcaddr;

        fprintf(file,"%lu", srcaddr);
	 //ipaddr.s_addr = dstaddr;

        fprintf(file,"%lu", dstaddr);
        fprintf(file,"%d", src_port);
        fprintf(file,"%d", dst_port);
        fprintf(file,"%d", nexthdr);
        fprintf(file, "%d\n", nonce_generated);
        fclose(file);
}

//writes the received encrypted data to file 

void write_encrypted_data_to_file(unsigned char *encrdata) {
	
	FILE *decr;
        int q;
        decr = fopen("encr.txt","wb");
	if (decr == NULL) {
       // 	printf("couldn't open encr.txt file for writing.\n");
                exit(0);
        }

	for(q=0; q<349; q++) {
		//printf("%c",data[q]);
                fprintf(decr,"%c",encrdata[q]);
        }
        fclose(decr);
}

//Read the nonce decrypted from the file 

unsigned char *read_nonce_decrypted_from_file(unsigned char *nonce_recv){
	 

	FILE *f_read;
        int n;
	f_read = fopen("noncereceived.txt","r");
        if (f_read == NULL) {
        //	printf("couldn't open noncereceived.txt file for reading.\n");
                exit(0);
        }
	n = fread(nonce_recv,1,11,f_read);
        nonce_recv[n] ='\0';
        fclose(f_read);
	return nonce_recv;
}

unsigned char *read_fivetuple_data_from_file(unsigned char *fivetuple){


        FILE *f_read;
        int n;
        f_read = fopen("fivetuple.txt","r");
        if (f_read == NULL) {
          //      printf("couldn't open fivetuple.txt file for reading.\n");
                exit(0);
        }
        n = fread(fivetuple,1,30,f_read);
        fivetuple[n] ='\0';
        fclose(f_read);
        return fivetuple;
}





//Write all data to the file (src ip, dst ip, src port, dst port, next hdr, decrypted nonce

void write_recvd_data_to_file_with_nonce(unsigned long srcaddr, unsigned long dstaddr, unsigned int src_port, unsigned int dst_port, unsigned int nexthdr, unsigned char *nonce_decrypted) {

//      struct in_addr ipaddr;
        FILE *file;
        file = fopen("nonce_recv.txt", "w");

        if (file == NULL) {
            //    printf("couldn't open nonces_recv.txt file for writing.\n");
                exit(0);
        }
    //     ipaddr.s_addr = srcaddr;

        fprintf(file,"%lu", dstaddr);
        // ipaddr.s_addr = dstaddr;

        fprintf(file,"%lu",srcaddr);
        fprintf(file,"%d", src_port);
        fprintf(file,"%d", dst_port);
        fprintf(file,"%d", nexthdr);
        fprintf(file, "%s\n", nonce_decrypted);
        fclose(file);
}

void write_recvd_data_to_file_without_nonce(unsigned long srcaddr, unsigned long dstaddr, unsigned int src_port, unsigned int dst_port, unsigned int nexthdr) {

        FILE *file;
        file = fopen("fivetuple.txt", "w");

        if (file == NULL) {
              //  printf("couldn't open fivetuple.txt file for writing.\n");
                exit(0);
        }
	
	if(srcaddr<=dstaddr)
	{
	//	printf("Src %lo is lesser than DST %lo\n", srcaddr, dstaddr);
	//	ipaddr.s_addr = srcaddr;	
//	        fprintf(file,"%s", inet_ntoa(ipaddr));
		fprintf(file,"%lu",srcaddr);

	     //   ipaddr.s_addr = dstaddr;
	        fprintf(file,"%lu", dstaddr);
	}
	else
	{
	//	printf("DST %lo is lesser than SRC %lo\n", dstaddr, srcaddr);
             //   ipaddr.s_addr = dstaddr;
                fprintf(file,"%lu",dstaddr);
               // ipaddr.s_addr = srcaddr;
                fprintf(file,"%lu",srcaddr);
	}
	
	if(src_port<=dst_port)
	{
		fprintf(file,"%d", src_port);
        	fprintf(file,"%d", dst_port);
	}
	else
	{
		fprintf(file,"%d", dst_port);
                fprintf(file,"%d", src_port);
	}
		
        fprintf(file,"%d", nexthdr);
        fclose(file);
}

//Compares the nonce

int compare_nonces() {

	FILE *f_noncerecv;
	//Compare The nonce recved and then decide
        unsigned char compare[41];
        int read_from_file;
        f_noncerecv = fopen("nonce_recv.txt","r");
        if (f_noncerecv == NULL) {
        //	printf("couldn't open nonce_recv.txt file for reading.\n");
        	exit(0);
        }

        read_from_file = fread(compare,1,40,f_noncerecv);
        compare[read_from_file] ='\0';
       //printf("Compare 1 is : %s\n", compare);
       fclose(f_noncerecv);

	FILE *f;
        int pos;
        f = fopen("nonce_sent.txt","r");
        if(f == NULL) {
        //	printf("Couldn't oppen file foe comparison\n");
                exit(0);
        }
        pos = FindStr(f,compare);
	fclose(f);
	return pos;	
}


/*char *compare_nonces() {
	char *result;
	FILE *fp1=fopen("nonce_sent.txt","r");
        char  tmp1[256]={0x0};
 	FILE *fp2=fopen("nonce_sent.txt","r");
        char  tmp2[256]={0x0};
	fgets(tmp2, sizeof(tmp2),fp2);	
        while(fp1!=NULL && fgets(tmp1, sizeof(tmp1),fp1)!=NULL)
        {
        result = strstr(tmp1, tmp2);
	//if(result!=NULL)
        //printf("%s", tmp1);
        //}
}
return result;

        fclose(fp1);
        fclose(fp2);

}
*/

//Gets the Indices generated from the file Cindex.txt

unsigned int *get_index(unsigned int *numbers) {

	FILE *Cindex_file;
        int i;
	Cindex_file = fopen("Cindex.txt", "r");
	if(Cindex_file==NULL) {
        //	printf("Error: can't open file.\n");
	}
        else {
        //	printf("File opened successfully.\n");
                i = 0 ;
                while(!feof(Cindex_file)) {
                	fscanf(Cindex_file, "%d", &numbers[i]);
                	i++;
                }
        //printf("Number of numbers read: %d\n\n", i);
        //printf("The numbers are:\n");
        //for(j=0 ; j<4 ; j++) {
	//printf("%d\n", numbers[j]);
        }
        fclose(Cindex_file);
	return numbers;
}

//This method prints data in hex
void PrintInHex(char *mesg, unsigned char *p, int len)
{
        printf(mesg);

        while(len--)
        {
                printf("%.2X ", *p);
                p++;
        }

}


//This function prints packet in hex
void PrintPacketInHex(unsigned char *packet, int len)
{
        unsigned char *p = packet;

       // printf("\n\n---------Packet---Starts----\n\n");



        while(len--)
        {
                printf("%.2x ", *p);
                p++;
        }

      //  printf("\n\n--------Packet---Ends-----\n\n");

}

//Check sum for Ip header

unsigned short in_cksum(unsigned short *addr, int len)
                                {
                                        int nleft = len;
                                        int sum = 0;
                                        unsigned short *w = addr;
                                        unsigned short answer = 0;

                                        while (nleft > 1) {
                                                sum += *w++;
                                                nleft -= 2;
                                        }

                                        if (nleft == 1) {
                                                *(unsigned char *) (&answer) = *(unsigned char *) w;
                                                sum += answer;
                                        }

                                sum = (sum >> 16) + (sum & 0xFFFF);
                                sum += (sum >> 16);
                                answer = ~sum;
                                return (answer);
                                }


/* Identifies the source interface(e.g. eth0, eth1, etc) that the packet came from */
void identify_incomimg_interface(ipq_packet_msg_t *msg, char *interface) {
    // just copy the interface name!
    strcpy(interface, msg->indev_name);

}



//Creates and send the Challenge Packet with the nonce 
void  Create_Send_ChallengePacket(unsigned long srcip, unsigned long dstip,  int srcport, int dstport, unsigned int nonce, unsigned char *Bloom_Filter) { 

	struct ip ip;
        struct setup_credhdr setup;
	int sock;
	const int on = 1;
        struct sockaddr_in sin;
        u_char *packet;
	int count;
        
	packet = (u_char *)malloc(100);
	
        ip.ip_hl = 0x5;
        ip.ip_v = 0x4;
        ip.ip_tos = 0x0;
        ip.ip_len = htons(60);
        ip.ip_id = htons(12830);
        ip.ip_off = 0x0;
        ip.ip_ttl = 10;
        ip.ip_p = 253;
        ip.ip_sum = 0x0;
        //ip.ip_src.s_addr = inet_addr("10.1.2.3");
        ip.ip_src.s_addr = srcip;
	ip.ip_dst.s_addr = dstip;

	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));

        memcpy(packet, &ip, sizeof(ip));

        //Consturct setup cred hdr with challenge flag and nonce
        setup.src = htons(srcport);
        setup.dest = htons(dstport);
        setup.nexthdr = 6;
        setup.request =0;
        setup.challenge = 1;
        setup.response=0;
        setup.nonce = htonl(nonce);
	
	for(count =0;count<16;count++)
        {
        setup.Bfilter[count] = Bloom_Filter[count];
        }

	//Copy the cred header after IP header
        memcpy(packet + sizeof(ip), &setup, sizeof(setup));
 //       printf("The size of the challenge pac is %d\n", sizeof(setup));
        if ((sock = socket(AF_INET, SOCK_RAW,IPPROTO_RAW)) < 0) {
 	       perror("raw socket");
               exit(1);
        }
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        	perror("setsockopt");
                exit(1);
        }
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = ip.ip_dst.s_addr;
        if (sendto(sock, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) > 0)  {
        printf("the nonce sent is %d\n",nonce);

                printf("Challenge Packet sent\n\n\n");
                free(packet);
        }
        else
        {
	        perror("sendto");
                exit(1);
        }

}



//Create and send the packet with Credential index
					
void Create_Send_Credential_IndexPacket(unsigned long srcip, unsigned long dstip,  int srcport, int dstport,int *indices, unsigned char *Bloom_Filter ) {

	struct ip ip;
        struct setup_credhdr setup;
        int sd;
        const int on = 1;
        struct sockaddr_in sin;
        u_char *packet;

        packet = (u_char *)malloc(100);

        ip.ip_hl = 0x5;
        ip.ip_v = 0x4;
        ip.ip_tos = 0x0;
        ip.ip_len = htons(60);
        ip.ip_id = htons(12830);
        ip.ip_off = 0x0;
        ip.ip_ttl = 10;
        ip.ip_p = 253;
        ip.ip_sum = 0x0;
	ip.ip_src.s_addr = srcip;
	//ip.ip_src.s_addr = inet_addr("10.1.3.2");
        ip.ip_dst.s_addr = dstip;
        ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));

        memcpy(packet, &ip, sizeof(ip));
        setup.src = htons(srcport);
        setup.dest = htons(dstport);
        setup.nexthdr = 6;
        setup.request =0;
        setup.challenge = 0;
        setup.response=0;
        setup.credentials=1;

	 
	setup.Cindex[0] = indices[0];
        setup.Cindex[1] = indices[1];
        setup.Cindex[2] = indices[2];
        setup.Cindex[3] = indices[3];
	
	int count =0;
	for(count =0;count<16;count++)
        {
        	setup.Bfilter[count] = Bloom_Filter[count];
        }
	
	

       //Copy the cred header after IP header
       memcpy(packet + sizeof(ip), &setup, sizeof(setup));
//       printf("The size of the Credential Index  packet is %d\n", sizeof(setup));
       if ((sd = socket(AF_INET, SOCK_RAW,IPPROTO_RAW)) < 0) {
	       perror("raw socket");
               exit(1);
       }
       if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
               perror("setsockopt");
               exit(1);
       }
       memset(&sin, 0, sizeof(sin));
       sin.sin_family = AF_INET;
       sin.sin_addr.s_addr = ip.ip_dst.s_addr;
       if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) > 0)  {
 	    //  printf("The packet with credential index is sent\n");
              free(packet);
       }
       else
       {
	       perror("sendto");
               exit(1);
       }
}



// setup request
void Create_Send_SetupRequestWithBitArray(unsigned long dstip, unsigned char *Bloom_Filter) {


int sd;
const int on = 1;

struct ip ip;
struct setup_credhdr setup;
struct sockaddr_in sin;
u_char *packet;
int count;

        ip.ip_hl = 0x5;
        ip.ip_v = 0x4;
        ip.ip_tos = 0x0;
        ip.ip_len = htons(sizeof(ip) + sizeof(setup));
        ip.ip_id = htons(12830);
        ip.ip_off = 0x0;
        ip.ip_ttl = 10;
        ip.ip_p = 253;
        ip.ip_sum = 0x0;
        ip.ip_src.s_addr = inet_addr("10.1.2.3");
        ip.ip_dst.s_addr = dstip;

        ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
        //memcpy(packet, &ip, sizeof(ip));

        //create Set up request header
        setup.src = htons(2100);
        setup.dest = htons(3100);
        setup.nexthdr = 6;
        setup.request=1;
        setup.challenge =0;
        setup.response =0;
	
	for(count =0;count<16;count++)
	{
	setup.Bfilter[count] = Bloom_Filter[count];
	}
	/*for (count=0; count<16; count++){

                                printf("%2d", count);

                        }
                         printf("\n");

                         for (count=0; count<16; count++){

                                printf("%02X", setup.Bfilter[count]);

                        }
*/

        //Allocate memory for packet
        packet = (u_char *)malloc(sizeof(ip)+ sizeof(setup));

        //Copy IP header First
        memcpy(packet, &ip, sizeof(ip));

        //Copy setup header afer IP
        memcpy(packet + sizeof(struct ip), &setup, sizeof(setup));





        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = ip.ip_dst.s_addr;

	if ((sd = socket(AF_INET, SOCK_RAW,IPPROTO_RAW)) < 0) {
               perror("raw socket");
               exit(1);
       }
       if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
               perror("setsockopt");
               exit(1);
       }
       memset(&sin, 0, sizeof(sin));
       sin.sin_family = AF_INET;
       sin.sin_addr.s_addr = ip.ip_dst.s_addr;
       if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) > 0)  {
             // printf("The 2nd setup to new node is sent\n");
              free(packet);
       }
       else
       {
               perror("sendto");
               exit(1);
       }
}

