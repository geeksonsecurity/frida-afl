#include <fcntl.h>
#include <stdio.h>

#define FORKSRV_FD 198

int main(void){
    FILE *f = fopen("/tmp/checkfd.log", "a+");
    //FILE *f = stdout;
    if (fcntl(FORKSRV_FD, F_GETFL) == -1 || fcntl(FORKSRV_FD + 1, F_GETFL) == -1)
        fprintf(f, "-- [!] AFL fork server file descriptors %d, %d are not open\n", FORKSRV_FD, FORKSRV_FD + 1);
    else
        fprintf(f, "-- [+] AFL fork server file descriptors ready!\n");
    return 0;
}