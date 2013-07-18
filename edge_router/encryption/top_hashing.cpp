/*
 *  top_hashing.cpp
 *  anon_tree
 *
 *  Created by SRIRAM NATARAJAN on 11/13/11.
 *  Copyright 2011 __UMass_Amherst__. All rights reserved.
 *
 */

#include "top_hashing.h"
#include <iostream>
#include <bitset>
#include <map>
#include <time.h>
#include <vector>
#include <algorithm>
#include <string>
#include <stdio.h>

using namespace std;

top_hashing::top_hashing()
{
	// default constructor
}

top_hashing::~top_hashing()
{
	// default destructor
}

map<string,string> top_hash_map;
const int TOP_HASH_SIZE = 128;
//map<string,string>::iterator it;


void top_hashing::generate_top_hash()
{
	vector<int> random_arr (TOP_HASH_SIZE); // Vector to store the encrypted values
	int temp=0;// Identify the array index to swap
	int total_node = 128; // Read Top Hash File
	char encrypt_nodes_string[4];

	// Read Top Hash Keys from file	
	FILE *top_file;
	top_file = fopen("top_hash.txt", "r");
	
	if (top_file == NULL) perror ("Error opening file");
	else {
		while (fscanf(top_file, "%d", &random_arr[temp++]) == 1);		
	     }
	fclose(top_file);

	// Update the bit values of key and encrpted values in the hash map
	for (int j=0; j<TOP_HASH_SIZE; j++)
		top_hash_map[bitset<7>(j).to_string<char,char_traits<char>,allocator<char> >()] = bitset<7>(random_arr[j]).to_string<char,char_traits<char>,allocator<char> >();

	/* Print the hash map values 
	for ( it=top_hash_map.begin() ; it != top_hash_map.end(); it++ )
		cout << (*it).first << " => " << (*it).second << endl;*/
	
}

string top_hashing::get_top_hash_bits(string key)
{
	//cout << "Key: "<< top_hash_map.find(key)->first << " value: "<< top_hash_map.find(key)->second<<endl;
	return top_hash_map.find(key)->second;
}

