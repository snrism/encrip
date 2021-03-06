extern unsigned int get_seq_no(ipq_packet_msg_t *msg);
extern int identify_ip_protocol (ipq_packet_msg_t *msg);
extern unsigned int get_src_ip (ipq_packet_msg_t *msg);
extern unsigned int get_dst_ip (ipq_packet_msg_t *msg);
extern int get_cred_src_port (ipq_packet_msg_t *msg);
extern int get_cred_dst_port (ipq_packet_msg_t *msg);
extern int get_cred_nexthdr (ipq_packet_msg_t *msg);
extern int get_udp_dst_port (ipq_packet_msg_t *msg);
extern int tcp_connection_request_check (ipq_packet_msg_t *msg);
extern int tcp_connection_termination_check (ipq_packet_msg_t *msg);
extern int tcp_connection_ack_check (ipq_packet_msg_t *msg);
extern int tcp_get_payload_size(ipq_packet_msg_t *msg);
extern void get_tcp_connection_id(ipq_packet_msg_t *msg, char *connectid);
extern void tcp_get_payload(ipq_packet_msg_t *msg, char *buffer);
extern unsigned int get_credentials_cred (ipq_packet_msg_t *msg);
extern unsigned int get_setup_setupflag (ipq_packet_msg_t *msg);
extern unsigned char *get_Bfilter_array(ipq_packet_msg_t *msg, unsigned char *BitArray);
extern unsigned int get_setup_responseflag (ipq_packet_msg_t *msg);
extern unsigned int get_setup_challengeflag (ipq_packet_msg_t *msg);
extern unsigned int get_setup_credentialsflag (ipq_packet_msg_t *msg);
extern int credentials_get_payload(ipq_packet_msg_t *msg);
extern  unsigned int get_nonce();
extern int FindStr(FILE *f, char *str);
extern char *return_index();
extern void write_noncesent_to_file(unsigned long srcaddr, unsigned long dstaddr, unsigned int src_port, unsigned dst_port, unsigned int nexthdr, unsigned int nonce_generated);
extern void write_encrypted_data_to_file(unsigned char *encrdata);
extern unsigned char  *read_nonce_decrypted_from_file(unsigned char *nonce_recv);
extern unsigned char *read_fivetuple_data_from_file(unsigned char *fivetuple);
extern void write_recvd_data_to_file_with_nonce(unsigned long srcaddr, unsigned long dstaddr, unsigned int src_port, unsigned int dst_port, unsigned int nexthdr, unsigned char *nonce_decrypted);
extern void write_recvd_data_to_file_without_nonce(unsigned long srcaddr, unsigned long dstaddr, unsigned int src_port, unsigned int dst_port, unsigned int nexthdr);
extern int compare_nonces();
extern unsigned int *get_index(unsigned int *numbers);
extern void PrintInHex(char *mesg, unsigned char *p, int len);
extern void PrintPacketInHex(unsigned char *packet, int len);
extern unsigned short in_cksum(unsigned short *addr, int len);
extern void identify_incomimg_interface(ipq_packet_msg_t *msg, char *interface);
extern  void Create_Send_ChallengePacket(unsigned long srcip, unsigned long dstip,  int srcport, int dstport, unsigned int nonce, unsigned char *Bloom_Filter);
extern void Create_Send_Credential_IndexPacket(unsigned long srcip, unsigned long dstip,  int srcport, int dstport,int *indices, unsigned char *Bloom_Filter);
extern unsigned char *get_BFilter(ipq_packet_msg_t *msg, unsigned char *BloomFilter);
extern void Create_Send_SetupRequestWithBitArray(unsigned long dstip, unsigned char *Bloom_Filter);

