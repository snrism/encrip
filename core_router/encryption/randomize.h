/*
 *  randomize.h
 *  encrypted_forwarding
 *
 *  Created by SRIRAM NATARAJAN on 11/9/11.
 *  Copyright 2011 __UMass_Amherst__. All rights reserved.
 *
 */

#include <time.h>                      // define time()
#include "randomc.h"                   // define classes for random number generators
#include <iostream>
#include <bitset>
#include <string>

using namespace std;

class randomize
{
public:
	randomize(); // default constructor
	virtual ~randomize(); //default destructor
	void generate_rank_vectors();
	string get_random_8_bits();		    	// Generate Random Address Bits for /32 Address
	string get_random_9_bits(int input_address);	// Generate Random Address Bits for /31 Address
	string get_random_10_bits(int input_address);	// Generate Random Address Bits for /30 Address
	string get_random_11_bits(int input_address);	// Generate Random Address Bits for /29 Address
	string get_random_12_bits(int input_address);	// Generate Random Address Bits for /28 Address
	string get_random_13_bits(int input_address); 	// Generate Random Address Bits for /27 Address
	string get_random_14_bits(int input_address); 	// Generate Random Address Bits for /26 Address
	string get_random_15_bits(int input_address);	// Generate Random Address Bits for /25 Address
	string get_random_16_bits(int input_address);	// Generate Random Address Bits for /24 Address
	string get_random_17_bits(int input_address);	// Generate Random Address Bits for /23 Address
	string get_random_18_bits(int input_address);	// Generate Random Address Bits for /22 Address
	string get_random_19_bits(int input_address);	// Generate Random Address Bits for /21 Address
	string get_random_20_bits(int input_address);	// Generate Random Address Bits for /20 Address
	string get_random_21_bits(int input_address);	// Generate Random Address Bits for /19 Address
	string get_random_22_bits(int input_address);	// Generate Random Address Bits for /18 Address
	string get_random_23_bits(int input_address);	// Generate Random Address Bits for /17 Address
	string get_random_24_bits(int input_address);	// Generate Random Address Bits for /16 Address
	string get_random_25_bits(int input_address);	// Generate Random Address Bits for /15 Address
	string get_random_26_bits(int input_address);	// Generate Random Address Bits for /14 Address	
	string get_random_27_bits(int input_address);	// Generate Random Address Bits for /13 Address	
	string get_random_28_bits(int input_address);	// Generate Random Address Bits for /12 Address
	string get_random_29_bits(int input_address);	// Generate Random Address Bits for /11 Address	
	string get_random_30_bits(int input_address);	// Generate Random Address Bits for /10 Address
	string get_random_31_bits(int input_address);	// Generate Random Address Bits for /9 Address
	string get_random_32_bits(int input_address);	// Generate Random Address Bits for /8 Address
};
