/*
 *  top_hashing.h
 *  encrypted_forwarding
 *
 *  Created by SRIRAM NATARAJAN on 11/9/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#include <iostream>
#include <bitset>
#include <map>

using namespace std;

class top_hashing
{
private:
	bitset<7> key;
	bitset<7> value;
public:
	top_hashing(); // default constructor
	virtual ~top_hashing(); //default destructor
	void generate_top_hash();
	string get_top_hash_bits(string key);
};


