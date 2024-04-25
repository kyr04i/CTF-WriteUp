#include <stdio.h>
#include <stdlib.h>

char* hi = "hello";

int main(){
 	void * a = malloc(0x20) + 0x28;
	void* b = hi + 0x1ffc;
	
	printf("diff: %p", a - b);
}