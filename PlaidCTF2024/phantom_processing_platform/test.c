#include <stdio.h>

int main() {
    float a = 1e20;
    float b = -1e20;
    float c = 3.14;
    float d = (a + b) + c;
    printf("%f", d);
    return 0;
}