#include<stdio.h>
int main() {
int lSize;
 FILE *fp=fopen("index.txt","r");
                                if (fp == NULL) {
                                        printf("couldn't open index.txt file for writing.\n");
                                        exit(0);
                                }
				fseek (fp, 0, SEEK_END);
		lSize = ftell(fp);
		if(lSize == 0)
		{
		fclose(fp);
                printf("\nInput file is empty, exting the program\n");
		}
		else{
			printf("Not empty");
			fclose(fp);
		}
		


}
