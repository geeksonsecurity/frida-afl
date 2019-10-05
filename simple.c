#include <stdio.h>

int main(int argc, char *argv[]){
    int res = 0;
    if(argc > 1){
        res = argc;
    } else {
        res = 1;
    }
    printf("[simple]\n");
    return res;
}