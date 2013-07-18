//======================================================== file = bloom2.c =====
//=  Program to implement a general Bloom filter (settable k and m)            =
//==============================================================================
//=  Notes:                                                                    =
//=    1) Program implements a Bloom filter or length m and with k bit set     =
//=       per mapping.  The program flow is:                                   =
//=        - Reads in a first string list to "program" the Bloom filter        =
//=        - Reads in a second string list to do tests in Bloom filter         =
//=        - Outputs the strings from the second list that matched             =
//=    2) For CRC32 uses the standard "Charles Michael Heard" code from        =
//=       http://cell-relay.indiana.edu/cell-relay/publications/software       =
//=       /CRC which was adapted from the algorithm described by Avarm         =
//=       Perez, "Byte-wise CRC Calculations," IEEE Micro 3, 40 (1983).        =
//=    3) Must set #define M and #define K.                                    =
//=    4) Note that M must be divisible 8 (to get an integral number of bytes) =
//=----------------------------------------------------------------------------=
//= Example input (in1.txt and in2.txt used in below example execution):       =
//=                                                                            =
//=    in1.txt:                                                                =
//=      apple pie                                                             =
//=      big box                                                               =
//=      cats and dogs                                                         =
//=      ditto                                                                 =
//=      easy does it                                                          =
//=      fun and games                                                         =
//=      good enough                                                           =
//=                                                                            =
//=    in2.txt:                                                                =
//=      apple pie                                                             =
//=      bigger box                                                            =
//=      cats and dogs and mice                                                =
//=      ditto                                                                 =
//=      easy does it for now                                                  =
//=      fun and games and what else                                           =
//=      good enough                                                           =
//=----------------------------------------------------------------------------=
//= Example execution:                                                         =
//=                                                                            =
//=   ----------------------------------------- bloom2.c -----                 =
//=   -  Program to implement a general Bloom filter         -                 =
//=   --------------------------------------------------------                 =
//=   File name of input list to add to filter ===========> in1.txt            =
//=   File name of input list to check for match =========> in2.txt            =
//=   --------------------------------------------------------                 =
//=   Bloom filter is (M = 32 bits and K = 4 mappings)...                      =
//=    0 1 2 3                                                                 =
//=   B5057DEF                                                                 =
//=   --------------------------------------------------------                 =
//=   Matching strings are...                                                  =
//=   apple pie                                                                =
//=   ditto                                                                    =
//=   good enough                                                              =
//=   --------------------------------------------------------                 =
//=----------------------------------------------------------------------------=
//=  Build: bcc32 bloom2.c                                                     =
//=----------------------------------------------------------------------------=
//=  Execute: bloom2                                                           =
//=----------------------------------------------------------------------------=
//=  Author: Ken Christensen                                                   =
//=          University of South Florida                                       =
//=          WWW: http://www.csee.usf.edu/~christen                            =
//=          Email: christen@cse.usf.edu                                       =
//=----------------------------------------------------------------------------=
//=  History: KJC (05/12/06) - Genesis (from bloom1.c)                         =
//=           KJC (02/28/08) - Created faster bitwise mapping and test         =
//==============================================================================
//----- Include files ----------------------------------------------------------
#include <stdio.h>                 // Needed for printf() and feof()
#include <stdlib.h>                // Needed for exit()
#include <string.h>                // Needed for strlen()

//----- Type defines -----------------------------------------------------------
typedef unsigned char      byte;   // Byte is a char
typedef unsigned short int word16; // 16-bit word is a short int
typedef unsigned int       word32; // 32-bit word is an int

//----- Constant defines -------------------------------------------------------
#define      FALSE             0   // Boolean false
#define       TRUE             1   // Boolean true
#define POLYNOMIAL    0x04C11DB7L  // Standard CRC-32 polynomial
#define          M            128   // Number of bits in the Bloom filter
#define          K             4   // Number of bits set per mapping in filter

//----- Global variables -------------------------------------------------------
static word32 CrcTable[256];       // Table of 8-bit CRC32 
byte          BFilter[M / 8];      // Bloom filter array of M/8 bytes
word32        NumBytes;            // Number of bytes in Bloom filter

//----- Function prototypes ----------------------------------------------------
void   gen_crc_table(void);
word32 update_crc(word32 crc_accum, byte *data_blk_ptr, word32 data_blk_size);
void   mapBloom(word32 hash);
int    testBloom(word32 hash);

//==============================================================================
//=  Main program                                                              =
//==============================================================================
int main(void)
{
  FILE   *fp1;                     // File pointer to input file #1
  FILE   *fp2;                     // File pointer to input file #2
  char   inFile1[256];             // File name for input file #1
  char   inFile2[256];             // File name for input file #2
  char   inString[1024];           // Input string
  word32 crc32;                    // CRC32 value
  int    retCode;                  // Return code (TRUE or FALSE)
  word32 i;                        // Loop counter

  // Output banner
  printf("----------------------------------------- bloom2.c ----- \n");
  printf("-  Program to implement a general Bloom filter         - \n");
  printf("-------------------------------------------------------- \n");

  // Determine number of bytes in Bloom Filter
  NumBytes = M / 8;
  if ((M % 8) != 0)
  {
    printf("*** ERROR - M value must be divisible by 8 \n");
    exit(1);
  }

  // Clear the Bloom filter
  for (i=0; i<NumBytes; i++)
    BFilter[i] = 0x00;

  // Initialize the CRC32 table
  gen_crc_table();

  // Prompt for (and open) filename of list of strings to enter into filter
  printf("File name of input list to add to filter ===========> ");
  scanf("%s", inFile1);
  fp1 = fopen(inFile1, "r");
  if (fp1 == NULL)
  {
    printf("*** ERROR in opening input file #1 (%s) *** \n", inFile1);
    exit(1);
  }

  // Prompt for (and open) filename of list of strings to check for filter match
  printf("File name of input list to check for match =========> ");
  scanf("%s", inFile2);
  fp2 = fopen(inFile2, "r");
  if (fp2 == NULL)
  {
    printf("*** ERROR in opening input file #2 (%s) *** \n", inFile2);
    exit(1);
  }

  // Read input file #1 and map each string to Bloom filter
  while(TRUE)
  {
    fgets(inString, 1024, fp1);
    if (feof(fp1)) break;
    for (i=0; i<K; i++)
    {
      crc32 = update_crc(i, inString, strlen(inString));

      mapBloom(crc32);
    }
  
   }
  fclose(fp1);

  // Output the Bloom filter
  printf("-------------------------------------------------------- \n");
  printf("Bloom filter is (M = %d bits and K = %d mappings)... \n", M, K);
  for (i=0; i<NumBytes; i++)
    printf("%2d", i);
  printf("\n");
  for (i=0; i<NumBytes; i++)
    printf("%02X", BFilter[i]);
  printf("\n");

  // Output results header
  printf("-------------------------------------------------------- \n");
  printf("Matching strings are... \n");

  // Read input file #2 and test (and output) if match to Bloom filter
  while(TRUE)
  {
    fgets(inString, 1024, fp2);
    if (feof(fp2)) break;
    for (i=0; i<K; i++)
    {
      crc32 = update_crc(i, inString, strlen(inString));
      retCode = testBloom(crc32);
      if (retCode == FALSE) break;
    }
    if (retCode == TRUE) printf("%s", inString);
  }
  fclose(fp2);

  // Output closing trailer
  printf("-------------------------------------------------------- \n");
}

//------------------------------------------------------------------------------
//-  Function to initialize CRC32 table                                        -
//------------------------------------------------------------------------------
void gen_crc_table(void)
{
  register word32 crc_accum;       // CRC32 accumulator
  register word16 i, j;            // Loop counters

  // Initialize the CRC32 8-bit look-up table
  for (i=0; i<256; i++)
  {
    crc_accum = ((word32) i << 24);
    for (j=0; j<8; j++)
    {
      if (crc_accum & 0x80000000L)
        crc_accum = (crc_accum << 1) ^ POLYNOMIAL;
      else
        crc_accum = (crc_accum << 1);
    }
    CrcTable[i] = crc_accum;
  }
}

//------------------------------------------------------------------------------
//-  Function to generate CRC32                                                -
//------------------------------------------------------------------------------
word32 update_crc(word32 crc_accum, byte *data_blk_ptr, word32 data_blk_size)
{
  register word32 i, j;            // Loop counters and index values

  // Compute CRC32 for data block
  for (j=0; j<data_blk_size; j++)
  {
    i = ((int) (crc_accum >> 24) ^ *data_blk_ptr++) & 0xFF;
    crc_accum = (crc_accum << 8) ^ CrcTable[i];
  }
  crc_accum = ~crc_accum;

  return crc_accum;
}

//------------------------------------------------------------------------------
//-  Function to map hash into Bloom filter                                    -
//------------------------------------------------------------------------------
void mapBloom(word32 hash)
{
  int           tempInt;           // Temporary integer
  int           bitNum;            // Bit number
  int           byteNum;           // Byte number
  unsigned char mapBit;            // Map bit

  // Get the byte and bit numbers
//printf("the hash is %02X\n",hash);
  tempInt = hash % M;
//printf("the tempint is %d\n",tempInt);
  byteNum = tempInt / 8;
//printf("the bytenum is %d\n",byteNum);
  bitNum = tempInt % 8;

  // Set the map bit
  mapBit = 0x80;
  mapBit = mapBit >> bitNum;
printf("the mapbit is %d\n",mapBit);
  
// Map the bit into the Bloom filter
  BFilter[byteNum] = BFilter[byteNum] | mapBit;
}

//------------------------------------------------------------------------------
//-  Function to test for a Bloom filter match                                 -
//------------------------------------------------------------------------------
int testBloom(word32 hash)
{
  int           tempInt;           // Temporary integer
  int           bitNum;            // Bit number
  int           byteNum;           // Byte number
  unsigned char testBit;           // Test bit
  int           retCode;           // Return code

  // Get the byte and bit numbers
  tempInt = hash % M;
  byteNum = tempInt / 8;
  bitNum = tempInt % 8;

  // Set the test bit
  testBit = 0x80;
  testBit = testBit >> bitNum;

  // Test the bit
  if (BFilter[byteNum] & testBit)
    retCode = TRUE;
  else
    retCode = FALSE;

  // Return the return code
  return retCode;
}

