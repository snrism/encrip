/*
 *  encryption.cpp
 *  Prefix-Preserving Probabilistic Encryption
 *
 *  Created by SRIRAM NATARAJAN on 11/09/11.
 *  Copyright 2011 __UMass_Amherst__. All rights reserved.
 *
 */
#include "top_hashing.h"
#include "anon_tree.h"
#include "randomize.h"
#include <iostream>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <bitset>
#include <linux/netfilter.h>
extern "C" {
#include <libipq.h>
}
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define BUFSIZE 2048
#define DATA_SIZE	100

using namespace std;

/* Create and Build the Data Structure */

/* Top Hahsing Implementation */
top_hashing top;

/* Mersenne Twister Randomization */
randomize rand_obj;

typedef struct PseudoHeader {

	unsigned long int source_ip;
	unsigned long int dest_ip;
	unsigned char reserved;
	unsigned char protocol;
	unsigned short int tcp_length;

} PseudoHeader;

static void die(struct ipq_handle *h) {
	ipq_perror("passer");
	ipq_destroy_handle(h);
	exit(1);
}

unsigned short ComputeChecksum(unsigned char *data, int len) {
	long sum = 0; /* assume 32 bit long, 16 bit short */
	unsigned short *temp = (unsigned short *) data;

	while (len > 1) {
		sum += *temp++;
		if (sum & 0x80000000) /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len) /* take care of left over byte */
		sum += (unsigned short) *((unsigned char *) temp);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

void CreatePseudoHeaderAndComputeTcpChecksum(struct tcphdr *tcp_header,
		struct iphdr *ip_header, unsigned char *data, int len) {
	/*The TCP Checksum is calculated over the PseudoHeader + TCP header +Data*/

	/* Find the size of the TCP Header + Data */
	int segment_len = ntohs(ip_header->tot_len) - ip_header->ihl * 4;

	/* Total length over which TCP checksum will be computed */
	int header_len = sizeof(PseudoHeader) + segment_len;

	/* Allocate the memory */

	unsigned char *hdr = (unsigned char *) malloc(header_len);

	/* Fill in the pseudo header first */

	PseudoHeader *pseudo_header = (PseudoHeader *) hdr;

	pseudo_header->source_ip = ip_header->saddr;
	pseudo_header->dest_ip = ip_header->daddr;
	pseudo_header->reserved = 0;
	pseudo_header->protocol = ip_header->protocol;
	pseudo_header->tcp_length = htons(segment_len);

	/* Now copy TCP */

	memcpy((hdr + sizeof(PseudoHeader)), (void *) tcp_header, tcp_header->doff
			* 4);

	/* Now copy the Data */

	memcpy((hdr + sizeof(PseudoHeader) + tcp_header->doff * 4), data, len);

	/* Calculate the Checksum */

	tcp_header->check = ComputeChecksum(hdr, header_len);

	/* Free the PseudoHeader */
	free(hdr);
}

// Declare total number of nodes in Level 1 of Anon Tree (for /8 to /24)
int first_level = 17;
int first_total_node = 262143;
int first_node_variant = 131070;
anon_tree first_node[262144];

// Declare total number of nodes in Level 2 of Anon Tree (for /25 to /32)
int second_level = 8;
int second_total_node = 511;
int second_node_variant = 254;
anon_tree second_node[512];

/* Build Level 1 Anonymization Data Sturcture */
void build_anon_tree_level_one() {
	int left_node = 0, right_node = 0;
	int count = 0;
	// Read Crypto Key Files
	int encrypt_nodes[first_total_node];
	char encrypt_nodes_string[4];
	FILE *efile;
	efile = fopen("encrypt_key_level_1.txt", "r");

	if (efile == NULL)
		perror("Error opening file");
	else {
		while (fgets(encrypt_nodes_string, sizeof(encrypt_nodes_string), efile)
				!= NULL) {
			encrypt_nodes[count] = atoi(encrypt_nodes_string);
			count++;
		}
	}
	fclose(efile);

	// Generating Tree nodes
	for (int i = 0; i < 262143; i++)
		first_node[i].setRootData(encrypt_nodes[i]);

	//Attaching SubTree nodes
	for (int i = first_node_variant; i >= 0; i--) {

		// Get left node
		left_node = ((2* i ) + 1);
		// Get right node
		right_node = ((2* i ) + 2);

		// Avoid Collisions
		if (first_node[left_node].getRootData() == 0)
			first_node[right_node].setRootData(1);
		else if (first_node[left_node].getRootData() == 1)
			first_node[right_node].setRootData(0);

		//Attaching left subtree
		first_node[i].attachLeftSubtree(first_node[left_node]);
		//Attaching right subtree
		first_node[i].attachRightSubtree(first_node[right_node]);
	}
}

/* Build Level 2 Anonymization Data Sturcture */
void build_anon_tree_level_two() {
	int left_node = 0, right_node = 0;
	int count = 0;
	// Read Crypto Key Files
	int encrypt_nodes[second_total_node];
	char encrypt_nodes_string[4];
	FILE *efile;
	efile = fopen("encrypt_key_level_2.txt", "r");

	if (efile == NULL)
		perror("Error opening file");
	else {
		while (fgets(encrypt_nodes_string, sizeof(encrypt_nodes_string), efile)
				!= NULL) {
			encrypt_nodes[count] = atoi(encrypt_nodes_string);
			count++;
		}
	}
	fclose(efile);

	// Generating Tree nodes
	for (int i = 0; i < 511; i++)
		second_node[i].setRootData(encrypt_nodes[i]);

	//Attaching SubTree nodes
	for (int i = second_node_variant; i >= 0; i--) {

		// Get left node
		left_node = ((2* i ) + 1);
		// Get right node
		right_node = ((2* i ) + 2);

		// Avoid Collisions
		if (second_node[left_node].getRootData() == 0)
			second_node[right_node].setRootData(1);
		else if (second_node[left_node].getRootData() == 1)
			second_node[right_node].setRootData(0);

		//Attaching left subtree
		second_node[i].attachLeftSubtree(second_node[left_node]);
		//Attaching right subtree
		second_node[i].attachRightSubtree(second_node[right_node]);
	}
}

string compute_encrypted_address(int addr[], int prefix_len)
{
	int randomization_addr; // To calculate the random addr
	int prefix_length = prefix_len;	 //Prefix length of the address
	int src_addr[4];

	// Strings to hold the encrypted bits	
	string top_hash_string;
	string anon_tree_string;
	string randomization_string;

	for (int n=0; n<4; n++)
	    src_addr[n] = addr[n];

	// Convert IP address into bitset and generate a single string of length 32
	string addr_string = ((bitset<8> (src_addr[0])).to_string<char,
			char_traits<char> , allocator<char> > ())
			+ ((bitset<8> (src_addr[1])).to_string<char, char_traits<char> ,
					allocator<char> > ())
			+ ((bitset<8> (src_addr[2])).to_string<char, char_traits<char> ,
					allocator<char> > ())
			+ ((bitset<8> (src_addr[3])).to_string<char, char_traits<char> ,
					allocator<char> > ());
	// cout << addr_string << endl;

	/* Top Hash Lookup --> Get top hash bits from string for top hashing */
	bitset<7> top_hash_input_bits(addr_string.substr(0, 7));
	top_hash_string = top.get_top_hash_bits(bitset<7> (
			top_hash_input_bits.to_ulong()).to_string<char, char_traits<char> ,
			allocator<char> > ());

	/* Get the remaining prefix bits for anonymization tree */
	switch (prefix_length - 7) {
	case 1: {
		bitset<1> anon_tree_input_bits(addr_string.substr(7, 1));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<1> enc1 = first_node[0].lookup_l1_Tree(bitset<1> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<24> randomization_input_bits(addr_string.substr(8, 24));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_32_bits(
					randomization_addr);
		}
	}
		break;

	case 2: {
		bitset<2> anon_tree_input_bits(addr_string.substr(7, 2));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<2> enc1 = first_node[0].lookup_l1_Tree(bitset<2> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<23> randomization_input_bits(addr_string.substr(9, 23));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_31_bits(
					randomization_addr);
		}
	}
		break;

	case 3: {
		bitset<3> anon_tree_input_bits(addr_string.substr(7, 3));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<3> enc1 = first_node[0].lookup_l1_Tree(bitset<3> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<22> randomization_input_bits(addr_string.substr(10, 22));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_30_bits(
					randomization_addr);
		}
	}
		break;

	case 4: {
		bitset<4> anon_tree_input_bits(addr_string.substr(7, 4));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<4> enc1 = first_node[0].lookup_l1_Tree(bitset<4> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<21> randomization_input_bits(addr_string.substr(11, 21));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_29_bits(
					randomization_addr);
		}
	}
		break;

	case 5: {
		bitset<5> anon_tree_input_bits(addr_string.substr(7, 5));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<5> enc1 = first_node[0].lookup_l1_Tree(bitset<5> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<20> randomization_input_bits(addr_string.substr(12, 20));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_28_bits(
					randomization_addr);
		}
	}
		break;

	case 6: {
		bitset<6> anon_tree_input_bits(addr_string.substr(7, 6));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<6> enc1 = first_node[0].lookup_l1_Tree(bitset<6> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<19> randomization_input_bits(addr_string.substr(13, 19));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_27_bits(
					randomization_addr);
		}
	}
		break;

	case 7: {
		bitset<7> anon_tree_input_bits(addr_string.substr(7, 7));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<7> enc1 = first_node[0].lookup_l1_Tree(bitset<7> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<18> randomization_input_bits(addr_string.substr(14, 18));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_26_bits(
					randomization_addr);
		}
	}
		break;

	case 8: {
		bitset<8> anon_tree_input_bits(addr_string.substr(7, 8));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<8> enc1 = first_node[0].lookup_l1_Tree(bitset<8> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<17> randomization_input_bits(addr_string.substr(15, 17));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_25_bits(
					randomization_addr);
		}
	}
		break;

	case 9: {
		bitset<9> anon_tree_input_bits(addr_string.substr(7, 9));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<9> enc1 = first_node[0].lookup_l1_Tree(bitset<9> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<16> randomization_input_bits(addr_string.substr(16, 16));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_24_bits(
					randomization_addr);
		}
	}
		break;

	case 10: {
		bitset<10> anon_tree_input_bits(addr_string.substr(7, 10));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<10> enc1 = first_node[0].lookup_l1_Tree(bitset<10> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<15> randomization_input_bits(addr_string.substr(17, 15));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_23_bits(
					randomization_addr);
		}
	}
		break;

	case 11: {
		bitset<11> anon_tree_input_bits(addr_string.substr(7, 11));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<11> enc1 = first_node[0].lookup_l1_Tree(bitset<11> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<14> randomization_input_bits(addr_string.substr(18, 14));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_22_bits(
					randomization_addr);
		}
	}
		break;

	case 12: {
		bitset<12> anon_tree_input_bits(addr_string.substr(7, 12));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<12> enc1 = first_node[0].lookup_l1_Tree(bitset<12> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<13> randomization_input_bits(addr_string.substr(19, 13));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_21_bits(
					randomization_addr);
		}
	}
		break;

	case 13: {
		bitset<13> anon_tree_input_bits(addr_string.substr(7, 13));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<13> enc1 = first_node[0].lookup_l1_Tree(bitset<13> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<12> randomization_input_bits(addr_string.substr(20, 12));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_20_bits(
					randomization_addr);
		}
	}
		break;

	case 14: {
		bitset<14> anon_tree_input_bits(addr_string.substr(7, 14));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<14> enc1 = first_node[0].lookup_l1_Tree(bitset<14> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<11> randomization_input_bits(addr_string.substr(21, 11));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_19_bits(
					randomization_addr);
		}
	}
		break;

	case 15: {
		bitset<15> anon_tree_input_bits(addr_string.substr(7, 15));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<15> enc1 = first_node[0].lookup_l1_Tree(bitset<15> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<10> randomization_input_bits(addr_string.substr(22, 10));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_18_bits(
					randomization_addr);
		}
	}
		break;

	case 16: {
		bitset<16> anon_tree_input_bits(addr_string.substr(7, 16));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<16> enc1 = first_node[0].lookup_l1_Tree(bitset<16> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<9> randomization_input_bits(addr_string.substr(23, 9));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_17_bits(
					randomization_addr);
		}
	}
		break;

	case 17: {
		bitset<17> anon_tree_input_bits(addr_string.substr(7, 17));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<17> enc1 = first_node[0].lookup_l1_Tree(bitset<17> (key1));
		
		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<8> randomization_input_bits(addr_string.substr(24, 8));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_16_bits(
					randomization_addr);
		}
	}
		break;

	case 18: {
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<1> anon_tree_input_bits_l2(addr_string.substr(24, 1));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<1> enc_l2 = second_node[0].lookup_l2_Tree(bitset<1> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());
		// Randomization Algorithm --> Get Random Bits
		{
			bitset<7> randomization_input_bits(addr_string.substr(25, 7));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_15_bits(
					randomization_addr);
		}
	}
		break;

	case 19: {
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<2> anon_tree_input_bits_l2(addr_string.substr(24, 2));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<2> enc_l2 = second_node[0].lookup_l2_Tree(bitset<2> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<6> randomization_input_bits(addr_string.substr(26, 6));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_14_bits(
					randomization_addr);
		}
	}
		break;

	case 20: {
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<3> anon_tree_input_bits_l2(addr_string.substr(24, 3));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<3> enc_l2 = second_node[0].lookup_l2_Tree(bitset<3> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<5> randomization_input_bits(addr_string.substr(27, 5));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_13_bits(
					randomization_addr);
		}
	}
		break;

	case 21: {
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<4> anon_tree_input_bits_l2(addr_string.substr(24, 4));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<4> enc_l2 = second_node[0].lookup_l2_Tree(bitset<4> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<4> randomization_input_bits(addr_string.substr(28, 4));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_12_bits(
					randomization_addr);
		}
	}
		break;

	case 22: {
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<5> anon_tree_input_bits_l2(addr_string.substr(24, 5));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<5> enc_l2 = second_node[0].lookup_l2_Tree(bitset<5> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<3> randomization_input_bits(addr_string.substr(29, 3));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_11_bits(
					randomization_addr);
		}
	}
		break;

	case 23: {
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<6> anon_tree_input_bits_l2(addr_string.substr(24, 6));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<6> enc_l2 = second_node[0].lookup_l2_Tree(bitset<6> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<2> randomization_input_bits(addr_string.substr(30, 2));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_10_bits(
					randomization_addr);
		}
	}
		break;

	case 24: {
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<7> anon_tree_input_bits_l2(addr_string.substr(24, 7));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<7> enc_l2 = second_node[0].lookup_l2_Tree(bitset<7> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());
		// Randomization Algorithm --> Get Random Bits
		{
			bitset<1> randomization_input_bits(addr_string.substr(31, 1));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_random_9_bits(
					randomization_addr);
		}
	}
		break;

	default: {
		// /32 address
		/* Level 1 Anon Tree Lookup */
		bitset<17> anon_tree_input_bits_l1(addr_string.substr(7, 17));
		int key_l1 = anon_tree_input_bits_l1.to_ulong();
		bitset<17> enc_l1 = first_node[0].lookup_l1_Tree(bitset<17> (key_l1));

		/* Level 2 Anon Tree Lookup */
		bitset<8> anon_tree_input_bits_l2(addr_string.substr(24, 8));
		int key_l2 = anon_tree_input_bits_l2.to_ulong();
		bitset<8> enc_l2 = second_node[0].lookup_l2_Tree(bitset<8> (key_l2));

		anon_tree_string += (enc_l1.to_string<char,
				char_traits<char> , allocator<char> > ());
		anon_tree_string += (enc_l2.to_string<char, char_traits<char> ,
				allocator<char> > ());

		// Add one of the random address bits to the original address (0-255)
		randomization_string = rand_obj.get_random_8_bits();

	}
	}

	string final_random_string;
	final_random_string += top_hash_string + anon_tree_string + randomization_string; 
	return final_random_string;
}

int main() {

	/* Top Hahsing Implementation */
	top.generate_top_hash();

	/* Anonymization Tree Data Structure */
	build_anon_tree_level_one();
	build_anon_tree_level_two();

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

	do {
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status < 0)
			die(h);

		switch (ipq_message_type(buf)) {
		case NLMSG_ERROR:
			fprintf(stderr, "Received error message %d\n", ipq_get_msgerr(buf));
			break;

		case IPQM_PACKET: {

			ipq_packet_msg_t *m = ipq_get_packet(buf);
			unsigned char *new_packet;
			int new_packet_len = m->data_len;
			struct iphdr *ip = (struct iphdr*) m->payload;
			struct tcphdr *tcp = (struct tcphdr*) (m->payload + (4 * ip->ihl));

	bitset<32>source(ntohl(ip->saddr));
	bitset<32>destination(ntohl(ip->daddr));	
	string src_string, dst_string;
	
	src_string = source.to_string<char, char_traits<char>,allocator<char> > ();
	dst_string = destination.to_string<char, char_traits<char>,allocator<char> > ();

	int src_addr[4] = {(bitset<8>(src_string.substr(0,8))).to_ulong(),(bitset<8>(src_string.substr(8,8))).to_ulong(),(bitset<8>(src_string.substr(16,8))).to_ulong(),(bitset<8>(src_string.substr(24,8))).to_ulong()};
	int src_prefix_length = 24;
	string src_final_random_string = compute_encrypted_address(src_addr,src_prefix_length);

	int dst_addr[4] = {(bitset<8>(dst_string.substr(0,8))).to_ulong(),(bitset<8>(dst_string.substr(8,8))).to_ulong(),(bitset<8>(dst_string.substr(16,8))).to_ulong(),(bitset<8>(dst_string.substr(24,8))).to_ulong()};
	int dst_prefix_length = 24;
	string dst_final_random_string = compute_encrypted_address(dst_addr,dst_prefix_length);

	string id_field;
	id_field += src_final_random_string.substr(32,8) + dst_final_random_string.substr(32,8); 

	/* Update IP Address and Forward */

			int ip_length = ntohs(ip->tot_len);

			struct iphdr *ip_header;
			ip_header = (struct iphdr *) malloc(sizeof(struct iphdr));

			ip_header = (struct iphdr*) new_packet;

			ip_header->version = ip->version;
			ip_header->ihl = ip->ihl;
			ip_header->tos = ip->tos;
			ip_header->tot_len = htons(ip_length);
			ip_header->id = htons((bitset<16>(id_field)).to_ulong());
			ip_header->frag_off = ip->frag_off;
			ip_header->ttl = ip->ttl;
			ip_header->protocol = IPPROTO_TCP;
			ip_header->check = 0; /* We will calculate the checksum later */
			ip_header->saddr = htonl((bitset<32> (src_final_random_string.substr(0,32))).to_ulong());
			ip_header->daddr = htonl((bitset<32> (dst_final_random_string.substr(0,32))).to_ulong());

			/* Calculate the IP checksum now : 
			 The IP Checksum is only over the IP header */

			ip_header->check = ComputeChecksum((unsigned char *) ip_header,
					ip_header->ihl * 4);

			struct tcphdr *tcp_header;
			tcp_header = (struct tcphdr*) malloc(sizeof(struct tcphdr));
			tcp_header = (struct tcphdr*) (new_packet + ip_header->ihl * 4);

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
			data = (unsigned char*) malloc(m->data_len + 1 - ip_header->ihl * 4
					- tcp_header->doff * 4);
			memcpy(data,
					m->payload + ip_header->ihl * 4 + tcp_header->doff * 4,
					m->data_len + 1 - ip_header->ihl * 4 - tcp_header->doff * 4);
			memcpy(new_packet + ip_header->ihl * 4 + tcp_header->doff * 4,
					data, m->data_len + 1 - ip_header->ihl * 4
							- tcp_header->doff * 4);

			/* Create PseudoHeader and compute TCP Checksum  */
			CreatePseudoHeaderAndComputeTcpChecksum(tcp_header, ip_header,
					data, m->data_len + 1 - ip_header->ihl * 4
							- tcp_header->doff * 4);

			cout << "Sending packet out..." << endl;
			status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT,
					new_packet_len, new_packet);

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

} // end main

