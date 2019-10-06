#include <stdio.h>

int main(int argc, char *argv[]){
    int res = 0;
    if(argc > 1){
        res = argc;
        if(argc == 2){
            res += 1;
        } else {
            res += argc;
        }
    } else {
        res = 1;
    }
    printf("[simple] %d\n", res);
    return res;
}