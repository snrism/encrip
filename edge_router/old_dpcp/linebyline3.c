#include <stdio.h>

int main() {
  FILE *file;
  int numbers[4]; 
  /* make sure it is large enough to hold all the data! */
  int i,j;

  file = fopen("Cindex.txt", "r");

  if(file==NULL) {
    printf("Error: can't open file.\n");
    return 1;
  }
  else {
    printf("File opened successfully.\n");

    i = 0 ;    

    while(!feof(file)) { 
      /* loop through and store the numbers into the array */
      fscanf(file, "%d", &numbers[i]);
      i++;
    }

    printf("Number of numbers read: %d\n\n", i);
    printf("The numbers are:\n");

    for(j=0 ; j<4 ; j++) { /* now print them out 1 by 1 */
      printf("%d\n", numbers[j]);
    }

    fclose(file);
    return 0;
  }
}
