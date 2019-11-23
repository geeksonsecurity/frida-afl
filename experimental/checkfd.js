const forkserver_module = new CModule(`
#include <stdio.h>

#define FORKSRV_FD          198
#define	F_GETFL		3		/* get file status flags */

extern int fcntl(int fildes, int cmd, ...);
extern int errno;

void
start (void)
{
    if (fcntl(FORKSRV_FD, F_GETFL) == -1 || fcntl(FORKSRV_FD + 1, F_GETFL) == -1){
        printf("[!] AFL fork server file descriptors are not open, errno %d\\n", errno);
        return;
    }
    printf("AFL descriptors ready!\\n");
}
`);

var fcntl_export = Module.getExportByName(null, 'fcntl');
if (fcntl_export) {
    const fcntl = new NativeFunction(fcntl_export, 'int', ['int', 'int', '...']);
    var res = fcntl(198, 3);
    if(res > -1){
        console.log('FD 198 is readable');
    } else {
        console.log('FD 198 is NOT readable');
    }
} else {
    console.log("Unable to resolve fcntl!");
}

var forkserver_start = new NativeFunction(forkserver_module.start, 'void', []);
forkserver_start();