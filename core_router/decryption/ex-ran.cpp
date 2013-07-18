#include <time.h>                      // define time()
#include "randomc.h"                   // define classes for random number generators
#include <iostream>
#include <bitset>
#ifndef MULTIFILE_PROJECT
// If compiled as a single file then include these cpp files, 
// If compiled as a project then compile and link in these cpp files.
   // Include code for the chosen random number generator:
   #include "mersenne.cpp"
   // define system specific user interface:
   #include "userintf.cpp"
#endif

using namespace std;
int main() {
   int seed = (int)time(0);            // random seed

   // choose one of the random number generators:
   CRandomMersenne RanGen(seed);       // make instance of random number generator

   int i;                              // loop counter
   int ir;                             // random integer number
   double fr;                          // random floating point number


   // make random integers in interval from 0 to 99, inclusive:
//   printf("\n\nRandom integers in interval from 0 to 99:\n");
int x=0;
  // for (i = 0; i < 256; i++) {
      ir = RanGen.IRandom(x*256,((x+1)*256)-1);
      //printf ("%6i  ", ir);
	cout << bitset<8>(ir) <<endl;
  // }


   EndOfProgram();                     // system-specific exit code
   return 0;
}

