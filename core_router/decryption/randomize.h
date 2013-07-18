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

	string get_original_1_bit(int input_address);	// Generate Original Bits for /31 Address
	string get_original_2_bits(int input_address);	// Generate Original Bits for /30 Address
	string get_original_3_bits(int input_address);	// Generate Original Bits for /29 Address
	string get_original_4_bits(int input_address);	// Generate Original Bits for /28 Address
	string get_original_5_bits(int input_address); // Generate Original Bits for /27 Address
	string get_original_6_bits(int input_address); // Generate Original Bits for /26 Address
	string get_original_7_bits(int input_address);	// Generate Original Bits for /25 Address
	string get_original_8_bits(int input_address);	// Generate Original Bits for /24 Address
	string get_original_9_bits(int input_address);	// Generate Original Bits for /23 Address
	string get_original_10_bits(int input_address);	// Generate Original Bits for /22 Address
	string get_original_11_bits(int input_address);	// Generate Original Bits for /21 Address
	string get_original_12_bits(int input_address);	// Generate Original Bits for /20 Address
	string get_original_13_bits(int input_address);	// Generate Original Bits for /19 Address
	string get_original_14_bits(int input_address);	// Generate Original Bits for /18 Address
	string get_original_15_bits(int input_address);	// Generate Original Bits for /17 Address
	string get_original_16_bits(int input_address);	// Generate Original Bits for /16 Address
	string get_original_17_bits(int input_address);	// Generate Original Bits for /15 Address
	string get_original_18_bits(int input_address);	// Generate Original Bits for /14 Address	
	string get_original_19_bits(int input_address);	// Generate Original Bits for /13 Address	
	string get_original_20_bits(int input_address);	// Generate Original Bits for /12 Address
	string get_original_21_bits(int input_address);	// Generate Original Bits for /11 Address	
	string get_original_22_bits(int input_address);	// Generate Original Bits for /10 Address
	string get_original_23_bits(int input_address);	// Generate Original Bits for /9 Address
	string get_original_24_bits(long unsigned input_address);	// Generate Original Bits for /8 Address
};
