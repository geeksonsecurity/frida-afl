#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

int main(int argc, char *argv[])
{
    int shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0)
    {
        printf("Failed to get memory %d: %s\n", shm_id, strerror(errno));
        return -1;
    }
    char shm_str[1024];
    sprintf(shm_str, "%d", shm_id);
    setenv("SHM_ENV_VAR", shm_str, 1);
    unsigned char *trace_bits = shmat(shm_id, NULL, 0);
    printf("Set shm %s mapped to %p\n", shm_str, trace_bits);

    char *cmd = "simple";
    printf("Executing %s\n", cmd);

    int res = system("./frida-afl.py ./simple");
    //int res = system("frida --no-pause -l afl.js -- /usr/local/bin/plistutil -i ../..//Repos/recipe/ios/Runner/Info.plist");
    printf("Execution result: %d\n", res);

    FILE* f = fopen("map.txt", "w");
    for (int i = 0; i < MAP_SIZE; i++) {

      if (!trace_bits[i]) continue;
      fprintf(f, "%06u:%u\n", i, trace_bits[i]);
    }
    fclose(f);

    shmdt(trace_bits);
    shmctl(shm_id, IPC_RMID, NULL);
    printf("Shared memory cleaned up!\n");
    return res;
}