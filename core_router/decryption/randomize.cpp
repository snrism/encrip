/*
 *  randomize.cpp
 *  anon_tree
 *
 *  Created by SRIRAM NATARAJAN on 11/13/11.
 *  Copyright 2011 __UMass_Amherst__. All rights reserved.
 *
 */

#include <time.h>                      // define time()
#include "randomize.h"
#include <iostream>
#include <bitset>
#include <string>
#include <math.h>
#include <vector>

using namespace std;

randomize::randomize()
{
	// default constructor
	
}

randomize::~randomize()
{
	// default destructor
}

vector<int> rank_vector[25];

// Generate Original Address Bits for /31 Address
string randomize::get_original_1_bit(int input_address)
{
int original_address = (input_address/256);
return bitset<1>(original_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Original Address Bits for /30 Address
string randomize::get_original_2_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<2>(original_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Original Address Bits for /29 Address
string randomize::get_original_3_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<3>(original_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Original Address Bits for /28 Address
string randomize::get_original_4_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<4>(original_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Original Address Bits for /27 Address
string randomize::get_original_5_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<5>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /26 Address
string randomize::get_original_6_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<6>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /25 Address
string randomize::get_original_7_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<7>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /24 Address
string randomize::get_original_8_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<8>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /23 Address
string randomize::get_original_9_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<9>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /22 Address
string randomize::get_original_10_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<10>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /21 Address
string randomize::get_original_11_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<11>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /20 Address
string randomize::get_original_12_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<12>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /19 Address
string randomize::get_original_13_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<13>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /18 Address
string randomize::get_original_14_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<14>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /17 Address
string randomize::get_original_15_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<15>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /16 Address
string randomize::get_original_16_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<16>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /15 Address
string randomize::get_original_17_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<17>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /14 Address
string randomize::get_original_18_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<18>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /13 Address
string randomize::get_original_19_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<19>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /12 Address
string randomize::get_original_20_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<20>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /11 Address
string randomize::get_original_21_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<21>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /10 Address
string randomize::get_original_22_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<22>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /9 Address
string randomize::get_original_23_bits(int input_address)
{
int original_address = (input_address/256);
return bitset<23>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

// Generate Original Address Bits for /8 Address
string randomize::get_original_24_bits(long unsigned input_address)
{
long unsigned original_address = (input_address/256);
cout << "Input: "<< input_address << " Original: "<< original_address << " bitset: " << bitset<24>(original_address) << endl;
return bitset<24>(original_address).to_string<char,char_traits<char>,allocator<char> >();
}

