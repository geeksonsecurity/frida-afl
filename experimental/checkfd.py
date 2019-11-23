#!/usr/bin/env python3
import fcntl

FORKSRV_FD = 198

with open('/tmp/fork.txt', 'a+') as fp:
    try:
        flags = fcntl.fcntl(FORKSRV_FD, fcntl.F_GETFL)
        fp.write('Flags: ' + str(flags) + '\n')
    except Exception as e:
        fp.write('Exception: ' + str(e) + '\n')