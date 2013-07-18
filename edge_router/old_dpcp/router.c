#include <linux/netfilter.h>
#include <libipq.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <syslog.h>
#include <string.h>
#include "datapath_functions.h"
#include "packet_header.h"
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include<sys/types.h>
#include<ctype.h>
#include "uthash.h"
#define BUFSIZE 2048

struct credential_cache {
	unsigned int key;             /* key */
	int id1;
   	int id2;
	int id3;
	int id4;

	UT_hash_handle hh;         /* makes this structure hashable */
};

struct credential_cache *cache = NULL;

void add_data(unsigned int key, int index1, int index2, int index3, int index4)
{
	struct credential_cache *s;
	s = malloc(sizeof(struct credential_cache));
	s->key = key;

	
	s->id1 = index1;
	s->id2 = index2;
	s->id3 = index3;
	s->id4 = index4;
	HASH_ADD_INT(cache, key, s);
}

void print_indices() {
    struct credential_cache *s;
	//printf("PRINTING ALL FROM CACHE\n");
    for(s=cache; s != NULL; s=s->hh.next) {
       // printf("key %u\n: INDICES %d\t%d\t%d\t%d\n", s->key,s->id1,s->id2,s->id3,s->id4);
    }
}

int sd;//Socket descriptor declared as global variable
static void die(struct ipq_handle *h) {

    ipq_perror("passer");
    ipq_destroy_handle(h);

}

void start_packet_engine() {

	int status;
    	unsigned char buf[BUFSIZE];
	struct ipq_handle *h;
    	//struct in_addr ipaddr;

//	printf("\nWaiting for packets\n");

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
				print_indices();
				unsigned int key;	
				
				key =  (get_src_ip(msg) + get_dst_ip(msg) + get_cred_dst_port(msg) +  get_cred_src_port(msg)+ get_cred_nexthdr(msg) % 1024);
 				//printf("the key is %u\n",key);
				//printf("Packet Received\n");
				struct credential_cache *s;	
				HASH_FIND_INT(cache, &key, s);
    				if (!s)
				{
					 printf("Five tuple not found\n");
					 if (get_setup_setupflag(msg)== 1)
                                         {
                                         	printf("Setup packet is received\n\n\n");
                                                unsigned int nonce_generated;
                                                nonce_generated = get_nonce();
						
                                                //write nonce to file
                                                write_noncesent_to_file(get_dst_ip(msg), get_src_ip(msg), get_cred_dst_port(msg), get_cred_src_port(msg), get_cred_nexthdr(msg), nonce_generated);
                                                unsigned char Bloom_Filter[16];
                                                get_BFilter(msg, Bloom_Filter);
                                                //Create and send the Challene packet with nonce
                                                Create_Send_ChallengePacket(get_dst_ip(msg), get_src_ip(msg), get_cred_dst_port(msg), get_cred_src_port(msg), nonce_generated, Bloom_Filter);
                                          }
                                          else if(get_setup_responseflag(msg)==1)
                                          {
 	                                         printf("Reponse packet is received\n\n\n");
                                                 unsigned char *data;
                                                 data = (buf + 140);// If making changes to the main cred_hdr struct , this one changes too.......
                                                 write_encrypted_data_to_file(data); //Writes the recevd encrypted data to file for decryption purpose
                                                                        //Call Perl for RSA DECRYPTION
                                                 system("openssl enc -aes-256-cbc -in /users/kamlesh/implementation_1.6/sender/encr.txt -out noncereceived:.txt -pass file:password.txt");

                                                 unsigned char nonce_recv[11];
                                                 read_nonce_decrypted_from_file(nonce_recv);//Gets the nonce decrypted from file
						
                                                //Writes all data to the file nonce_recv.txt for comparison
                                                 write_recvd_data_to_file_with_nonce(get_src_ip(msg), get_dst_ip(msg), get_cred_src_port(msg), get_cred_dst_port(msg), get_cred_nexthdr(msg), nonce_recv);
						
		
						
                                                 int str_pos1;
                                                 str_pos1 = compare_nonces();//Compares the nonces and gives the result

                                                 if (str_pos1 != -1){
	                                                 printf("Nonce received for the src IP is at position  %d\n", str_pos1);
                                                         printf("Nonce received is valid\n");
							 write_recvd_data_to_file_without_nonce(get_src_ip(msg), get_dst_ip(msg), get_cred_src_port(msg), get_cred_dst_port(msg), get_cred_nexthdr(msg));

                                                         //printf("Generating index values for bit filter array.........\n");
                                               		system("perl sha1_digest.pl");
							int numbers[4];
						        get_index(numbers);

							add_data(key,numbers[0], numbers[1], numbers[2], numbers[3]); 
							unsigned char Bloom_Filter[16];
                                                        get_BFilter(msg, Bloom_Filter);
							
	
						
						 	//Create and send the credential packet with Credential indices
                                                        Create_Send_Credential_IndexPacket(get_dst_ip(msg),get_src_ip(msg), get_cred_dst_port(msg), get_cred_src_port(msg),numbers, Bloom_Filter);
                                                }
                                                else{
                                               	printf("Nonce Invalid\n");
	                                                printf("Packet Droppped\n");
	                                                status = ipq_set_verdict(h, msg->packet_id, NF_DROP, 0, NULL);
	                                        //        printf("-------------------------------------------------------- \n");
                                                }
					}

                                        else{
                                        	printf("No flags found, not a pack type,,, dropping\n");
                                                status = ipq_set_verdict(h, msg->packet_id, NF_DROP, 0, NULL);
					}
				}
				else
				{
					printf(" key%u\n  id is %d\t %d\t %d\t %d\n", s->key, s->id1, s->id2, s->id3, s->id4);
					unsigned char BloomFilter[16];
                                        get_BFilter(msg, BloomFilter);
                                        int flag;
                                        int counter;
                                        int bitNum;            // Bit number
                                        int byteNum;           // Byte number
                                        unsigned char testBit;            // Map bit
					 int indices[4];
                                                        indices[0] = s->id1;
                                                        indices[1] = s->id2;
                                                        indices[2] = s->id3;
                                                        indices[3] = s->id4;

					flag = 1;

                                        for(counter=0;counter<4;counter++)
                                        {
	                                         //printf("Counter is %d\n", counter);
                                                 byteNum = indices[counter] / 8;
                                                 bitNum = indices[counter] % 8;
                                                 testBit = 0x80;
                                                 testBit = testBit >> bitNum;
                                                 if(!(BloomFilter[byteNum] & testBit))
                                                 {
         	                                        flag = 0;
                                                        break;
                                                 }
                                        }
					if(flag != 0)

                                        {
						//Bloom filter matches
						printf("The BFilter matches...Packet forwarded\n");
						
						 status = ipq_set_verdict(h, msg->packet_id, NF_ACCEPT, 0, NULL);
						
					}
					else
					{
					
						printf("Bloom filter doesnt match\n");
						if (get_setup_setupflag(msg)== 1)
                                         {
                                              printf("Setup packet is received\n\n\n");
                                                unsigned int nonce_generated;
                                                nonce_generated = get_nonce();
                                                //write nonce to file
                                                write_noncesent_to_file(get_dst_ip(msg), get_src_ip(msg), get_cred_dst_port(msg), get_cred_src_port(msg), get_cred_nexthdr(msg), nonce_generated);
                                                unsigned char Bloom_Filter[16];
                                                get_BFilter(msg, Bloom_Filter);
                                                //Create and send the Challene packet with nonce
                                                Create_Send_ChallengePacket(get_dst_ip(msg), get_src_ip(msg), get_cred_dst_port(msg), get_cred_src_port(msg), nonce_generated, Bloom_Filter);
                                          }
                                          else if(get_setup_responseflag(msg)==1)
                                          {
                                                 printf("Reponse packet is received\n\n\n");
                                                 unsigned char *data;
                                                 data = (buf + 140);// If making changes to the main cred_hdr struct , this one changes too.......
                                                 write_encrypted_data_to_file(data); //Writes the recevd encrypted data to file for decryption purpose
                                                                        //Call Perl for RSA DECRYPTION
                                                 system("perl rsadecr.pl");

                                                 unsigned char nonce_recv[11];
                                                 read_nonce_decrypted_from_file(nonce_recv);//Gets the nonce decrypted from file

                                                //Writes all data to the file nonce_recv.txt for comparison
                                                 write_recvd_data_to_file_with_nonce(get_src_ip(msg), get_dst_ip(msg), get_cred_src_port(msg), get_cred_dst_port(msg), get_cred_nexthdr(msg), nonce_recv);

						 int str_pos;
                                                 str_pos = compare_nonces();//Compares the nonces and gives the result
                                                 if (str_pos != -1){
                                                 //       printf("Nonce received for the src IP is at position  %s\n", str_pos);
                                                        printf("Nonce received is valid\n");
                                                      //   printf("Retriveintg Indices from the cache.........\n");
                                                         int indices[4];
                                                        indices[0] = s->id1;
                                                        indices[1] = s->id2;
                                                        indices[2] = s->id3;
                                                        indices[3] = s->id4;


                                                        unsigned char Bloom_Filter[16];
                                                        get_BFilter(msg, Bloom_Filter);

                                                        write_recvd_data_to_file_without_nonce(get_src_ip(msg), get_dst_ip(msg), get_cred_src_port(msg), get_cred_dst_port(msg), get_cred_nexthdr(msg));


                                                        //Create and send the credential packet with Credential indices
                                                        Create_Send_Credential_IndexPacket(get_dst_ip(msg),get_src_ip(msg), get_cred_dst_port(msg), get_cred_src_port(msg),indices, Bloom_Filter);
                                          //              printf("-------------------------------------------------------- \n");
                                                }

                                                
                                                else{
                                                      printf("Nonce Invalid\n");
                                                        printf("Packet Droppped\n");
                                                        status = ipq_set_verdict(h, msg->packet_id, NF_DROP, 0, NULL);
                                                //        printf("-------------------------------------------------------- \n");
						 }
                                        }

                                        else{
                                                printf("No flags found, not a pack type,,, dropping\n");
                                                status = ipq_set_verdict(h, msg->packet_id, NF_DROP, 0, NULL);
                                        }


				}	
                                		
			}

	
	
                break;
            	}

            	default: {
                fprintf(stderr, "Unknown message type!\n");
                break;
            }
        }

    }

   while (1);

//    printf("Engine Stopped...\n");

    ipq_destroy_handle(h);

}

int main() {

 
   	start_packet_engine();
    	return 0;
}

