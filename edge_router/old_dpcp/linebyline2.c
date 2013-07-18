#include <stdio.h>
#include <string.h>

int main( void ) {
    char string[3];
    char arra[3];
    FILE *fileptr = fopen("Cindex.txt","r");
    
    while( feof(fileptr) != EOF ) {
        if( fgets(string, 3, fileptr) == NULL ) {
            return 0;
        }
	
	
        printf("%s", string);
    }
    
    return 0;
}
