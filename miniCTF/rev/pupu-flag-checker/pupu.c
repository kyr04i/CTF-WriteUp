#include <stdio.h>
#include <string.h>

char* bytetoa(unsigned char* byteArray, int length);
void xorStrings(char* string1, char* string2, char* result);
void check(char* inputString);

void xorStrings(char* string1, char* string2, char* result) {
    int i;
    int len = strlen(string1) < strlen(string2) ? strlen(string1) : strlen(string2);
    for (i = 0; i < len; i++) {
        result[i] = string1[i] ^ string2[i];
    }
    result[i] = '\0';
}

void check(char* inputString) {
    unsigned char xorValues[] = {
      
    };

    if (strlen(inputString) != 44) {
        printf("Incorrect length!\n");
        return;
    }

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < strlen(inputString); j++) {
            inputString[j] = xorValues[inputString[j]];
        }
    }

    char* base64EncodedResult = bytetoa(inputString, strlen(inputString));

    if (strcmp(base64EncodedResult, "/52NXNAD7Lui+5G7idT7Dbue0L7vkV/bDey779tzuwf7c5G7c5HbDZHswUs=") != 0) {
        printf("Incorrect flag!\n");
        return;
    }

    printf("Good job, you're welcome!!\n");
}

int main() {
    char inputString[] = "??????????????????????????????????????????"; 
    check(inputString);
    return 0;
}
