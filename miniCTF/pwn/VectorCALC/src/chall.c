#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_FAVES 4
#define MAX_VECTORS 3
struct Vector{
	__uint64_t x;
    __uint64_t y;
    void (*printFunc)(struct Vector*);
};

struct Vector v_list[MAX_VECTORS];
__uint64_t* sum;
void* faves[MAX_FAVES];

void printData(struct Vector* v);

void enterData(){
    struct Vector* v;
    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx > MAX_VECTORS){
        puts("Invaild index!");
        exit(-1);
    }

    v = &v_list[idx];

    v->printFunc = printData;
    printf("Enter x: ");
    scanf("%lu",&v->x);
    printf("Enter y: ");
    scanf("%lu",&v->y);
}


void printData(struct Vector* v){
    puts("Data: ");
    printf("v = [%lu %lu]\n",v->x,v->y);
}

void sumVector(){
    __uint64_t idx;
    printf("Save the sum to index: ");
    scanf("%lu",&idx);
    
    if(idx > MAX_VECTORS){
        puts("Invaild index!");
        exit(-1);
    }

    sum = &v_list[idx];
    for(__uint64_t i = 0 ; i < MAX_VECTORS ;++i){
        if( i != idx){
            ((struct Vector *)sum)->x += v_list[idx].x;
            ((struct Vector *)sum)->y += v_list[idx].y;
        }
    }
}

void loadFavorite(){
    if(sum == NULL){
        puts("You must set the sum before!");
        return;
    }
    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES){
        puts("Invaild index!");
        exit(-1);
    }

    faves[idx] = malloc(sizeof(struct Vector));

    ((struct Vector *)faves[idx])->printFunc = printData;

    memcpy(faves[idx],&sum[idx], sizeof(struct Vector));
}

void printFavorite(){
    if(sum == NULL){
        puts("You must set the sum before!");
        return;
    }

    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES || faves[idx] == NULL){
        puts("Invaild index!");
        exit(-1);
    }
    if( ((__uint64_t *)faves[idx])[2] )
        ((struct Vector *)faves[idx])->printFunc(faves[idx]);
    else 
        ((struct Vector *)sum)->printFunc(faves[idx]);
}

void addFavorute(){

    __uint64_t idx;

    printf("Index: ");
    scanf("%lu",&idx);
    
    if(idx >= MAX_FAVES || faves[idx] == NULL){
        puts("Invaild index!");
        exit(-1);
    }

    ((struct Vector *)sum)->x += ((struct Vector *)faves[idx])->x;
    ((struct Vector *)sum)->y += ((struct Vector *)faves[idx])->y;
}

void init(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    for(__uint64_t i = 0 ; i < MAX_VECTORS ;++i){
        v_list[i].printFunc = printData;
    }
}

void printMenu(){
    printf(
        "\r\n"
        "1. Enter data.\n"
        "2. Sum vector.\n"
        "3. Print sum vector\n"
        "4. Save sum to favorite\n"
        "5. Print favorite\n"
        "6. Add favorite to the sum\n"
        "> "
    );
}

int main(int argc, char** argv, char** envp){
    init();
    __uint32_t choice ;
    while(1){
        printMenu();
        scanf("%u", &choice);
        switch (choice)
        {
        case 1:
            enterData();
            break;
        
        case 2:
            sumVector();
            break;
        
        case 3:
            ((struct Vector *)sum)->printFunc(sum);
            break;

        case 4:
            loadFavorite();
            break;
        
        case 5:
            printFavorite();
            break;
        
        case 6:
            addFavorute();
            break;

        default:
            puts("Invaild option!");
            exit(-1);
        }
    }
}

void w1n(); // try to view the code in a disassembler :)
