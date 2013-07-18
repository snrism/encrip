#include <sys/cdefs.h>
#include <sys/types.h>

struct setup_credhdr {
  u_int16_t src;
 u_int16_t dest;
u_int8_t nexthdr;
u_int8_t   request:1;
  u_int8_t   challenge:1;
u_int8_t response:1;
u_int8_t credentials:1;  
//u_int16_t bloom;
// u_int32_t fid;
u_int32_t nonce;
//u_int16_t auth;
u_int8_t Cindex[4];
unsigned char Bfilter[16];
};

