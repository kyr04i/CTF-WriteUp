#include <stdio.h>
#include <stdlib.h>

int main(void) {
  FILE *fp = fopen("some_random_file", "w,ccs=NC_NC00-10");
  fclose(fp);
}