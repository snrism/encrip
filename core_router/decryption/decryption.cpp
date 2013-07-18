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

using namespace std;

// Declare total number of nodes in Level 1 of Anon Tree (for /8 to /24)
int first_level = 17;
int first_total_node = pow(2, first_level + 1) - 1;
int first_node_variant = pow(2, first_level) - 2;
anon_tree first_node[262144];

// Declare total number of nodes in Level 2 of Anon Tree (for /25 to /32)
int second_level = 8;
int second_total_node = pow(2, second_level + 1) - 1;
int second_node_variant = pow(2, second_level) - 2;
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
	for (int i = 0; i < pow(2, first_level + 1) - 1; i++)
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
	for (int i = 0; i < pow(2, second_level + 1) - 1; i++)
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

int main() {

	/* Create and Build the Data Structure */

	/* Top Hahsing Implementation */
	top_hashing top;
	top.generate_top_hash();

	/* Anonymization Tree Data Structure */
	build_anon_tree_level_one();
	build_anon_tree_level_two();

	/* Mersenne Twister Randomization */
	randomize rand_obj;

	int src_addr[5], randomization_addr;
	int prefix_length = 32;

	// Strings to hold the encrypted bits	
	string top_hash_string;
	string anon_tree_string;
	string randomization_string;

	// Original Address 192.168.1.1/24
	src_addr[0] = 248;
	src_addr[1] = 197;
	src_addr[2] = 130;
	src_addr[3] = 181;
	src_addr[4] = 216;

	/* Convert IP address into bitset and generate a single string of length 32 */
	string addr_string = ((bitset<8> (src_addr[0])).to_string<char,
			char_traits<char> , allocator<char> > ())
			+ ((bitset<8> (src_addr[1])).to_string<char, char_traits<char> ,
					allocator<char> > ())
			+ ((bitset<8> (src_addr[2])).to_string<char, char_traits<char> ,
					allocator<char> > ())
			+ ((bitset<8> (src_addr[3])).to_string<char, char_traits<char> ,
					allocator<char> > ())
			+ ((bitset<8> (src_addr[4])).to_string<char, char_traits<char> ,
					allocator<char> > ()); 
//	cout << addr_string << endl; 

//	string addr_string = "1111100011000101000000000000101000111111";

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
			bitset<32> randomization_input_bits(addr_string.substr(8, 32));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_24_bits((long unsigned)
					randomization_addr);
		}
	}
		break;

	case 2: {bitset<2> anon_tree_input_bits(addr_string.substr(7, 2));
		int key1 = anon_tree_input_bits.to_ulong();
		bitset<2> enc1 = first_node[0].lookup_l1_Tree(bitset<2> (key1));

		anon_tree_string = enc1.to_string<char, char_traits<char> ,
				allocator<char> > ();

		// Randomization Algorithm --> Get Random Bits
		{
			bitset<31> randomization_input_bits(addr_string.substr(9, 31));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_23_bits(
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
			bitset<30> randomization_input_bits(addr_string.substr(10, 30));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_22_bits(
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
			bitset<29> randomization_input_bits(addr_string.substr(11, 29));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_21_bits(
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
			bitset<28> randomization_input_bits(addr_string.substr(12, 28));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_20_bits(
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
			bitset<27> randomization_input_bits(addr_string.substr(13, 27));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_19_bits(
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
			bitset<26> randomization_input_bits(addr_string.substr(14, 26));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_18_bits(
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
			bitset<25> randomization_input_bits(addr_string.substr(15, 25));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_17_bits(
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
			bitset<24> randomization_input_bits(addr_string.substr(16, 24));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_16_bits(
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
			bitset<23> randomization_input_bits(addr_string.substr(17, 23));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_15_bits(
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
			bitset<22> randomization_input_bits(addr_string.substr(18, 22));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_14_bits(
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
			bitset<21> randomization_input_bits(addr_string.substr(19, 21));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_13_bits(
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
			bitset<20> randomization_input_bits(addr_string.substr(20, 20));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_12_bits(
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
			bitset<19> randomization_input_bits(addr_string.substr(21, 19));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_11_bits(
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
			bitset<18> randomization_input_bits(addr_string.substr(22, 18));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_10_bits(
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
			bitset<17> randomization_input_bits(addr_string.substr(23, 17));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_9_bits(
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
			bitset<16> randomization_input_bits(addr_string.substr(24, 16));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_8_bits(
					randomization_addr);		}
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
			bitset<15> randomization_input_bits(addr_string.substr(25, 15));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_7_bits(
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
			bitset<14> randomization_input_bits(addr_string.substr(26, 14));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_6_bits(
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
			bitset<13> randomization_input_bits(addr_string.substr(27, 13));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_5_bits(
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
			bitset<12> randomization_input_bits(addr_string.substr(28, 12));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_4_bits(
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
			bitset<11> randomization_input_bits(addr_string.substr(29, 11));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_3_bits(
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
			bitset<10> randomization_input_bits(addr_string.substr(30, 10));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_2_bits(
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
			bitset<9> randomization_input_bits(addr_string.substr(31, 9));
			randomization_addr = randomization_input_bits.to_ulong();
			/* Randomization Address Bits */
			randomization_string = rand_obj.get_original_1_bit(
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
		randomization_string = "";

	}
	}
//	cout << "Top Hash Decrypted Bits: " << top_hash_string <<endl;
//	cout << "Anon Tree Decrypted Bits: " << anon_tree_string <<endl;
	
//	cout << "Randomized Address: " << top_hash_string << anon_tree_string << randomization_string<< endl;
	string final_random_string;
	final_random_string+= top_hash_string + anon_tree_string + randomization_string;

	cout << "Decrypted Original Address: "<<(bitset<8> (final_random_string.substr(0,8))).to_ulong() << "\t"<<(bitset<8> (final_random_string.substr(8,8))).to_ulong() << "\t" <<(bitset<8> (final_random_string.substr(16,8))).to_ulong()<< "\t" <<(bitset<8> (final_random_string.substr(24,8))).to_ulong()<<endl;


	return 0;
} // end main

