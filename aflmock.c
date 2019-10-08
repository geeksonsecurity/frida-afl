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
#define FORKSRV_FD 198

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    printf("Usage: %s <target binary> <args>\n", argv[0]);
    return -1;
  }
  int shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0)
  {
    printf("Failed to get memory %d: %s\n", shm_id, strerror(errno));
    return -1;
  }
  char shm_str[1024];
  sprintf(shm_str, "%d", shm_id);
  setenv("__AFL_SHM_ID", shm_str, 1);
  unsigned char *trace_bits = shmat(shm_id, NULL, 0);
  printf("Set shm %s mapped to %p\n", shm_str, trace_bits);

  if (dup2(1, FORKSRV_FD) < 0) perror("dup2() failed");
  if (dup2(1, FORKSRV_FD + 1) < 0) perror("dup2() failed");

  char *myargv[argc];
  for (int i = 1; i < argc; i++)
  {
    myargv[i - 1] = argv[i];
  }
  myargv[argc-1]=NULL;

  printf("Running %s...\n", argv[1]);
  int res = execv(argv[1], myargv);
  //char *myargv[]={"fridamock", "./checkfd"};
  //int res = execv("./fridamock", myargv);
  //int res = system("frida --no-pause -l afl.js -- /usr/local/bin/plistutil -i ../..//Repos/recipe/ios/Runner/Info.plist");
  printf("Execution result: %d\n", res);

  if (res != -1)
  {
    FILE *f = fopen("map.txt", "w");
    for (int i = 0; i < MAP_SIZE; i++)
    {

      if (!trace_bits[i])
        continue;
      fprintf(f, "%06u:%u\n", i, trace_bits[i]);
    }
    fclose(f);
  }
  else
  {
    printf("Failed to execute target binary!\n");
  }
  shmdt(trace_bits);
  shmctl(shm_id, IPC_RMID, NULL);
  printf("Shared memory cleaned up!\n");
  return res;
}