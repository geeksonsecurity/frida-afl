# Frida-AFL

Use Frida DBI to instrument binary and perform basic-block code coverage that is feed back to AFL.

`afl.c` simulate AFL by setting up the shared memory (code-coverage map), by running the target binary (`./simple`) via frida instrumentation and by creating a readable memory map file.

The `frida-afl.py` scripts spawn the target process with ASLR disabled, inject and execute the `bb.js` script and wait for the execution to finish. Unfortunately we cant spawn the process without ASLR with the common `frida` CLI tool.

The env-variable `WHITELIST` should be given to the frida client in order to instrument also dynamic libraries used by the target. If none is given only the main module (target binary) will be instrumented. 
For example:
```
WHITELIST="libplist.3.dylib" frida --no-pause -l bb.js -- /usr/local/bin/plistutil -i ../..//Repos/recipe/ios/Runner/Info.plist
```
Will only track `libplist` basic blocks.

## ToDo's

* ✓ whitelist modules by name
* ✓ spawned process should have ASLR disabled 
* create afl-fuzz wrapper
* Implement forkserver in frida
* Write compile block callback in C (`CModule`) to improve perf


## Example Run
```
$ WHITELIST="simple" ./afl
Set shm 4194304 mapped to 0x105b74000
Executing simple
Spawning ./simple 
Found export for getenv!
Prepared native function @ 0x7fff733d77ce
Shared memory ID: 4194304
Whitelist:  simple
trace_bits mapped at 0x100530000
Done stalking threads.
[simple] 1
0x100000f10 -> 0x100000f37 ( simple : 0x100000000 - 0x100001000 )
map_offset: 0 id: 1928 prev_id: 964 , target: 0x100530000 , current: 0
0x100000f63 -> 0x100000f7b ( simple : 0x100000000 - 0x100001000 )
map_offset: 964 id: 1969 prev_id: 984 , target: 0x1005303c4 , current: 0
0x100000f8a -> 0x100000f90 ( simple : 0x100000000 - 0x100001000 )
map_offset: 984 id: 1989 prev_id: 994 , target: 0x1005303d8 , current: 0
0x100000fa0 -> 0x100000faa ( simple : 0x100000000 - 0x100001000 )
map_offset: 994 id: 2000 prev_id: 1000 , target: 0x1005303e2 , current: 0
0x100000f90 -> 0x100000f9f ( simple : 0x100000000 - 0x100001000 )
map_offset: 1000 id: 1992 prev_id: 996 , target: 0x1005303e8 , current: 0
0x100000f7b -> 0x100000f89 ( simple : 0x100000000 - 0x100001000 )
map_offset: 996 id: 1981 prev_id: 990 , target: 0x1005303e4 , current: 0
Monitored 6  blocks!
Shared memory unmapped!
Exiting!
Execution result: 0
Shared memory cleaned up!
bash-3.2$ cat map.txt 
000000:1
000964:1
000984:1
000994:1
000996:1
001000:1
```