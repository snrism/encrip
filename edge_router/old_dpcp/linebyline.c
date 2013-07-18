

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>

int main ( void )
{
static const char filename[] = "Cindex.txt";
FILE *file = fopen ( filename, "r" );
int i, j;
char arra[4][4];
char line[4]; /* or other suitable maximum line size */


for(i=0; i<4; i++)
for(j=0; j<4; j++)
arra[i][j] = '\0';

for(i=0; i<4; i++)
line[i] = '\0';

if ( file != NULL )
{

i=0;

while ( fgets ( line, sizeof line, file ) != NULL ) /* read a line */
{

strcpy(arra[i], line);
printf("array ----> %s ", &arra[i]);
i++;

}
printf("mine is %s\n",&arra[1]);
fclose ( file );
}
else
{
perror ( filename ); /* why didn't the file open? */
}


return 0;
}  
