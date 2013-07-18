#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include"sha1.h"

int
hex2bin(char *hex, char *bin, int hex_len)
{
        register int i = 0, j = 0;

        if(hex_len == 0 || !hex)
                return -1;

        if(hex_len > 2 && hex[0] == '0' && hex[1] == 'x')
                i = 2;

        for( ; i < hex_len; i++, j += 4) {
                switch(tolower(hex[i])) {
                case '0': memmove(&bin[j], "0000", 4); break;
                        case '1': memmove(&bin[j], "0001", 4); break;
                        case '2': memmove(&bin[j], "0010", 4); break;
                        case '3': memmove(&bin[j], "0011", 4); break;
                        case '4': memmove(&bin[j], "0100", 4); break;
                        case '5': memmove(&bin[j], "0101", 4); break;
                        case '6': memmove(&bin[j], "0110", 4); break;
                        case '7': memmove(&bin[j], "0111", 4); break;
                        case '8': memmove(&bin[j], "1000", 4); break;
                        case '9': memmove(&bin[j], "1001", 4); break;
                        case 'a': memmove(&bin[j], "1010", 4); break;
                        case 'b': memmove(&bin[j], "1011", 4); break;
                        case 'c': memmove(&bin[j], "1100", 4); break;
                        case 'd': memmove(&bin[j], "1101", 4); break;
                        case 'e': memmove(&bin[j], "1110", 4); break;
                        case 'f': memmove(&bin[j], "1111", 4); break;
                        default:
                                return -1;        // invalid hex digit
                }
        }
        return 0;
}



int  main()
{
//unsigned int nbr1;
unsigned char recv[40];
 FILE *f;
                       int n;

                        f = fopen("nonce_recv.txt","rb");
                        if (f == NULL) {
                                printf("couldn't open nonce_recv.txt file for reading.\n");
                                exit(0);
                        }


                      n=   fread(recv,1,39,f);
                        recv[n] ='\0';
                        printf("Nonce recv is %s\n", recv);
                        fclose(f);  


	 SHA1Context sha;
  //  	int i;
	 char *hash = "";
   // static char bin[64];
    
    SHA1Reset(&sha);
    SHA1Input(&sha, recv, strlen(recv));

    if (!SHA1Result(&sha))
    {
        fprintf(stderr, "ERROR-- could not compute message digest\n");
    }
    else
    {
        printf("\t");
      	hash = sha.Message_Digest[0];
            printf("%X ", sha.Message_Digest[0]);
//	hex2bin(hash,bin,strlen(hash));

//	printf("Bin is %s\n", bin);
        //}
        printf("\n");
	printf("Hash is %X\n", hash);
	
      }
return 0;
}
