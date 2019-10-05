# Frida-AFL

Use Frida DBI to instrument binary and perform basic-block code coverage that is feed back to AFL.

`afl.c` simulate AFL by setting up the shared memory (code-coverage map), by running the target binary (`./simple`) via frida instrumentation and by creating a readable memory map file.

```
> ./afl
Set shm 1769472 mapped to 0x107f18000
Spawning `./simple`...                                                  
Processing basic blocks from simple only!
Found export for getenv!
Allocated env name SHM_ENV_VAR 0x10dcd7e60 , native function 0x7fff733d77ce
Shared memory ID: 1769472
trace_bits mapped at 0x10de57000
Done stalking threads.
Spawned `./simple`. Resuming main thread!                               
[simple]
[Local::simple]-> 0x10c82df30 -> 0x10c82df57 ( simple : 0x10c82d000 - 0x10c82e000 )
map_offset: 28568 id: 104951704 prev_id: 52475852 , target: 0x10de5df98 , current: 0
0x10c82df62 -> 0x10c82df77 ( simple : 0x10c82d000 - 0x10c82e000 )
map_offset: 55421 id: 104951729 prev_id: 52475864 , target: 0x10de6487d , current: 0
0x10c82df86 -> 0x10c82df8c ( simple : 0x10c82d000 - 0x10c82e000 )
map_offset: 55323 id: 104951747 prev_id: 52475873 , target: 0x10de6481b , current: 0
0x10c82df9c -> 0x10c82dfa6 ( simple : 0x10c82d000 - 0x10c82e000 )
map_offset: 55343 id: 104951758 prev_id: 52475879 , target: 0x10de6482f , current: 0                                                                                                                                                         
0x10c82df8c -> 0x10c82df9b ( simple : 0x10c82d000 - 0x10c82e000 )
map_offset: 55329 id: 104951750 prev_id: 52475875 , target: 0x10de64821 , current: 0
0x10c82df77 -> 0x10c82df85 ( simple : 0x10c82d000 - 0x10c82e000 )
map_offset: 55384 id: 104951739 prev_id: 52475869 , target: 0x10de64858 , current: 0
Process terminated                                                                                                                                                                                                                   
Execution result: 256
Shared memory cleaned up!
wizche@mac ~/D/R/frida-afl> cat map.txt 
028568:1
055323:1
055329:1
055343:1
055384:1
055421:1
wizche@mac ~/D/R/frida-afl> 
```