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
int seed = (int)time(0);            // random seed	
CRandomMersenne RanGen(seed);       // make instance of random number generator

//Generate Rank Vectors
void randomize::generate_rank_vectors()
{
	for(int v=0;v<18;v++)
		{
			for(int i=0;i<pow((float)2,v+8);i++)
			rank_vector[v].push_back(i);
		}
}

// Generate Random Address Bits for /32 Address
string randomize::get_random_8_bits()
{
long unsigned random_address;       // random integer number

random_address = RanGen.IRandom(0,255);

return bitset<8>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /31 Address
string randomize::get_random_9_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<9> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<9>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /30 Address
string randomize::get_random_10_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<10> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<10>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /29 Address
string randomize::get_random_11_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<11> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<11>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /28 Address
string randomize::get_random_12_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<12> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<12>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /27 Address
string randomize::get_random_13_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<13> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<13>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /26 Address
string randomize::get_random_14_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<14> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<14>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /25 Address
string randomize::get_random_15_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<15> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<15>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /24 Address
string randomize::get_random_16_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<16> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<16>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /23 Address
string randomize::get_random_17_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<17> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<17>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /22 Address
string randomize::get_random_18_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<18> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<18>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /21 Address
string randomize::get_random_19_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<19> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<19>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /20 Address
string randomize::get_random_20_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<20> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<20>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /19 Address
string randomize::get_random_21_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<21> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<21>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /18 Address
string randomize::get_random_22_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<22> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<22>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /17 Address
string randomize::get_random_23_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<23> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<23>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /16 Address
string randomize::get_random_24_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<24> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<24>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /15 Address
string randomize::get_random_25_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<25> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<25>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /14 Address
string randomize::get_random_26_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<26> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<26>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /13 Address
string randomize::get_random_27_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<27> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<27>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /12 Address
string randomize::get_random_28_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<28> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<28>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /11 Address
string randomize::get_random_29_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<29> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<29>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /10 Address
string randomize::get_random_30_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<30> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<30>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /9 Address
string randomize::get_random_31_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<31> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();
random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<31>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

// Generate Random Address Bits for /8 Address
string randomize::get_random_32_bits(int input_address)
{
long unsigned address_int;	    // convert bitset to unsigned long int
long unsigned random_address;       // random integer number

bitset<32> address_bits (input_address); // Convert string to bitset

// Get the Integer equivalent of bitset value
address_int = address_bits.to_ulong();

random_address = RanGen.IRandom(address_int*256,((address_int+1)*256)-1);

return bitset<32>(random_address).to_string<char,char_traits<char>,allocator<char> >();	
}

