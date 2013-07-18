#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <bitset>
#include <stdio.h>
#include <math.h>
#include <vector>
#include "randomc.h"                   // define classes for random number generators

using namespace std;

const int TREE_SIZE = pow(2,9);
const int TOP_HASH_SIZE = 128;
int main() {
int seed = (int)time(0);            // random seed	
CRandomMersenne RanGen(seed);       // make instance of random number generator

/* Anonymization Tree Node Value Generation */
  FILE *efile,*dfile;

  efile = fopen("encrypt_key_level_2.txt","w");
  dfile = fopen("decrypt_key_level_2.txt","w");

    int value=0;
    srand(time(NULL));

    for(int i=0;i<TREE_SIZE;i++)
	{
		value = RanGen.IRandom(0,1);

			if(value==1)
			  {
			    fprintf(efile,"%d \n",value);
			    fprintf(dfile,"%d \n",value-1);
			  }
			else
			  {
			    fprintf(efile,"%d \n",value);
			    fprintf(dfile,"%d \n",value+1);
			  }
	}
	fclose(efile);
	fclose(dfile); 

/* Top Hashing Value Generation */

srand(time(NULL));
FILE *top_file;

  top_file = fopen("top_hash.txt","w");
  vector<int> value_arr (TOP_HASH_SIZE); // Vector to generate key 
  vector<int> random_arr (TOP_HASH_SIZE); // Vector to store the encrypted values
  int temp;// Identify the array index to swap
	
	// Fisher Yates Random Permutation 
	
	// Generate numbers for 2^8
	for (int i=0;i<TOP_HASH_SIZE;i++)
		value_arr.at(i)=i;
	
	//Swap Elements 
	for (int i=TOP_HASH_SIZE; i>0; i--) {
		temp = rand()%i;
		random_arr[TOP_HASH_SIZE-i] = value_arr[temp];
		value_arr.erase(value_arr.begin() + temp);
	}

	// Save to file
	for(int i=0;i<TOP_HASH_SIZE;i++)
		fprintf(top_file,"%d \n",random_arr[i]);
	fclose(top_file);
	cout << "Keys Generated" <<endl;
return 0;
}
