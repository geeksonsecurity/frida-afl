#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <sys/wait.h>

#define FORKSRV_FD 198

#ifndef _POSIX_SPAWN_DISABLE_ASLR
# define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

extern char **environ;

int main(int argc, char* argv[])
{
    if(argc < 2){
        printf("Usage: ./%s <target_binary> <args>\n", argv[0]);
        return -1;
    }
    char *myargv[argc-1];
    for(int i = 1; i< argc; i++){
        myargv[i-1] = argv[i];
        printf("- myargv[%1d]: %s\n", i-1, myargv[i-1]);
    }

    FILE *f = stdout;
    if (fcntl(FORKSRV_FD, F_GETFL) == -1 || fcntl(FORKSRV_FD + 1, F_GETFL) == -1)
        fprintf(f, "- [!] AFL fork server file descriptors %d, %d are not open\n", FORKSRV_FD, FORKSRV_FD + 1);
    else
        fprintf(f, "- [+] AFL fork server file descriptors ready!\n");
    
    pid_t pid;
    posix_spawn_file_actions_t file_actions;
    posix_spawnattr_t attributes;
    sigset_t signal_mask_set;

    posix_spawn_file_actions_init (&file_actions);
    posix_spawnattr_init (&attributes);
    sigemptyset (&signal_mask_set);
    posix_spawnattr_setsigmask (&attributes, &signal_mask_set);
    short flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_START_SUSPENDED;
    posix_spawn_file_actions_adddup2 (&file_actions, 0, 0);
    posix_spawn_file_actions_adddup2 (&file_actions, 1, 1);
    posix_spawn_file_actions_adddup2 (&file_actions, 2, 2);
    flags |= _POSIX_SPAWN_DISABLE_ASLR;
    posix_spawnattr_setflags (&attributes, flags);

    printf("- posix_spawn --\n");
    int status = posix_spawn(&pid, argv[1], &file_actions, &attributes, myargv, environ);
    if (status == 0) {
        printf("- Child pid: %i\n", pid);
        kill (pid, SIGCONT);
        printf("- Child resumed!\n");
        if (waitpid(pid, &status, 0) != -1) {
            printf("- Child exited with status %i\n", status);
        } else {
            perror("waitpid");
        }
    } else {
        printf("- posix_spawn: %s\n", strerror(status));
    }
    
    return 0;
}