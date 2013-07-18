#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
        FILE *fp=fopen("nonce_sent.txt","r");
        char  tmp[256]={0x0};
	FILE *fp1 = fopen("nonce_recv.txt","r");
	char tmp1[256] = {0x0};
	fgets(tmp1, sizeof(tmp1), fp1);\
	printf("String to be searcghed is %s\n", tmp1);
        while(fp!=NULL && fgets(tmp, sizeof(tmp),fp)!=NULL)
        {
        if (strstr(tmp, tmp1)){
        printf("Match found%s", tmp);
	}
	else {
	printf("Nope\n");
        }
	}
        if(fp!=NULL) fclose(fp);
        return 0;
}
