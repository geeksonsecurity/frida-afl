
const logfile = new File("afl.log", "a+");

function debug(msg) {
    var args = Array.prototype.slice.call(arguments);
    console.log.apply(console, args);
    logfile.write(args.join(" "));
    logfile.write("\n");
    logfile.flush();
}

var threads = {};

var EV_TYPE_BLOCK = 8;
var EV_TYPE_COMPILE = 16;

var intSize = Process.pointerSize;
var EV_STRUCT_SIZE = 2 * Process.pointerSize + 2 * intSize;

function parseEvents(blob, callback) {
    var len = getLen(blob);
    for (var i = 0; i !== len; i++) {
        var type = getType(blob, i);
        switch (type) {
            case EV_TYPE_BLOCK:
                callback(parseBlockEvent(blob, i));
                break;
            case EV_TYPE_COMPILE:
                callback(parseCompileEvent(blob, i));
                break;
            default:
                debug('Unsupported type ' + type);
                break;
        }
    }
}

function getType(blob, idx) {
    return parseInteger(blob, idx, 0);
}

function getLen(blob) {
    return blob.byteLength / EV_STRUCT_SIZE;
}

function parseBlockEvent(blob, idx) {
    var begin = parsePointer(blob, idx, intSize);
    var end = parsePointer(blob, idx, intSize + Process.pointerSize);
    var i = begin.add(0);
    var code = [];
    while (i.compare(end) < 0) {
        var instr = Instruction.parse(i);
        code.push(i.toString() + '    ' + instr.toString());
        i = instr.next;
    }
    return {
        type: 'block',
        begin: begin,
        end: end,
        code: code.join('\n')
    };
}

function parseCompileEvent(blob, idx) {
    var parsed = parseBlockEvent(blob, idx);
    parsed.type = 'compile';
    return parsed;
}

function parseInteger(blob, idx, offset) {
    return new Int32Array(blob, idx * EV_STRUCT_SIZE + offset, 1)[0];
}

function parsePointer(blob, idx, offset) {
    var view = new Uint8Array(blob, idx * EV_STRUCT_SIZE + offset, Process.pointerSize);
    var stringed = [];
    for (var i = 0; i < Process.pointerSize; i++) {
        var x = view[i];
        var conv = x.toString(16);
        if (conv.length === 1) {
            conv = '0' + conv;
        }
        stringed.push(conv);
    }
    return ptr('0x' + stringed.reverse().join(''));
}

function reverse(arr) {
    var result = [];
    for (var i = arr.length - 1; i >= 0; i--) {
        result.push(arr[i]);
    }
    return result;
}

// Assignments
Stalker.trustThreshold = 0;
// WATCH-OUT: seems like the first module is always the binary main module
var instrument_all = false;
var trace_bits = ptr(0);
var shmat = ptr(0);
var shmdt = ptr(0);
var getpid = ptr(0);
// keep track of previous block id
var prev_id = ptr(0);
var block_monitored = 0;
var entrypoint = ptr(0);
// forkserver 
var have_forkserver = 0;

rpc.exports = {
    init: function (entrypoint_address) {
        entrypoint = ptr(entrypoint_address);
        debug("[*] Entrypoint address set to", entrypoint);
        debug("[+] Instrumentation initialized from python launcher!");
        return;
    }
};

const forkstarted = Memory.alloc(4);
const forkserver_module = new CModule(`
#include <stdio.h>

#define FORKSRV_FD          198
#define	F_GETFL		3		/* get file status flags */


extern int fork(void);
extern int read(int fildes, void *buf, unsigned int nbyte);
extern int write(int fildes, const void *buf, unsigned int nbyte);
extern int waitpid(int pid, int *stat_loc, int options);
extern int close(int fildes);
extern int fcntl(int fildes, int cmd, ...);
int getpid(void);
// logging
FILE *fopen(const char * restrict path, const char * restrict mode);
int fclose(FILE *stream);
int fflush(FILE *stream);
extern int errno;
extern volatile int forkstarted;

void
start (void)
{  
    FILE *log = fopen("fork.log", "a+");
    unsigned char tmp[4] = {};
    int child_pid = 0;
    fprintf(log, "[+] Init forkserver PID %d!\\n", getpid());

    if (fcntl(FORKSRV_FD, F_GETFL) == -1 || fcntl(FORKSRV_FD + 1, F_GETFL) == -1){
        fprintf(log, "[!] AFL fork server file descriptors are not open, errno %d\\n", errno);
        goto getout;
    } else {
        fprintf(log, "[*] FDs ready!\\n");
    }

    if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
        fprintf(log, "[!] Error writing fork server to FD %d, errno %d\\n", FORKSRV_FD + 1, errno);
        goto getout;
    } else {
        fprintf(log, "[*] write (1)!\\n");
    }

    while (1) {
        unsigned int was_killed;
        int status;
        fprintf(log, "[+] Waiting for mother!\\n");
        if (read(FORKSRV_FD, &was_killed, 4) != 4) {
            fprintf(log, "[!] Error reading fork server\\n");
            goto getout;
        } else {
            fprintf(log, "[*] Read!\\n");
        } 

        child_pid = fork();
        if (child_pid < 0) {
            fprintf(log, "[!] Error fork\\n");
            goto getout;
        } else {
            fprintf(log, "[*] Forked PID %d!\\n", child_pid);
        }

        if (child_pid == 0) {       // child
            fprintf(log, "[+] forkserver(): this is the child\\n");
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            forkstarted = 1;
            goto getout;
        } 

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
            fprintf(log, "[!] Error writing child pid to fork server (2)\\n");
            goto getout;
        } else {
            fprintf(log, "[*] Wrote child pid %d!\\n", child_pid);
        }

        fprintf(log, "[+] this is the forkserver(main) waiting for child %d\\n", child_pid);
        if (waitpid(child_pid, &status, 0) < 0) {
            fprintf(log, "[!] Error waiting for child\\n");
            goto getout;
        } else {
            fprintf(log, "[*] Waitpid!\\n");
        }

        if (write(FORKSRV_FD + 1, &status, 4) != 4) {
            fprintf(log, "[!] Fork server is gone before status submission, terminating\\n");
            goto getout;
        } else {
            fprintf(log, "[*] wrote status %d!\\n", status);
        }
        fprintf(log, "[+] forkserver(): child is done\\n");
        fflush(log);
    }
    getout:
        fflush(log);
        return;
}`, { forkstarted });

/*
// Check if one AFL FD is accessible
var fcntl_export = Module.getExportByName(null, 'fcntl');
if (fcntl_export) {
    const fcntl = new NativeFunction(fcntl_export, 'int', ['int', 'int', '...']);
    var res = fcntl(198, 3);
    if (res > -1) {
        debug('FD 198 is readable');
    } else {
        debug('FD 198 is NOT readable');
    }
} else {
    debug("Unable to resolve fcntl!");
}
*/


var getenv_export = Module.getExportByName(null, 'getenv');
if (getenv_export) {
    debug("[*] Found export for getenv!");
    const get_env = new NativeFunction(getenv_export, 'pointer', ['pointer']);
    debug("[*] Prepared native function @", get_env);
    var shm_id = parseInt(Memory.readCString(get_env(Memory.allocUtf8String("__AFL_SHM_ID"))));
    debug("[*] Shared memory ID:", shm_id);

    var forkserver_enabled = parseInt(Memory.readCString(get_env(Memory.allocUtf8String("AFL_NO_FORKSRV")))) != 1;
    debug("[*] Forkserver enabled:", forkserver_enabled);

    var whitelist_raw = Memory.readCString(get_env(Memory.allocUtf8String("WHITELIST")));
    if (whitelist_raw) {
        var whitelist = whitelist_raw.split(",").map(function (item) {
            return item.trim();
        });
        debug("[*] Whitelist: ", whitelist);
        if (whitelist.indexOf("all") > -1) {
            debug("[*] Covering all modules!");
            instrument_all = true
        }
    } else {
        var whitelist = [Process.enumerateModules()[0].name];
        debug("[!] WHITELIST env not available! tracking only main module", whitelist[0]);
    }

    
    var getpid_export = Module.getExportByName(null, 'getpid');
    if (getpid_export) {
        getpid = new NativeFunction(getpid_export, 'int', []);
        debug("[*] getpid() found");
    }

    var shmat_export = Module.getExportByName(null, 'shmat');
    var shmdt_export = Module.getExportByName(null, 'shmdt');
    if (shmat_export && shmdt_export) {
        shmat = new NativeFunction(shmat_export, 'pointer', ['int', 'pointer', 'int']);
        shmdt = new NativeFunction(shmdt_export, 'int', ['pointer']);
        if (shm_id > 0) {
            trace_bits = shmat(shm_id, ptr(0), 0);
        }
        debug("[*] trace_bits mapped at", trace_bits);
    } else {
        debug("[!] Unable to resolve shared memory exports!\n");
    }

} else {
    debug("[!] Unable to find export for getenv!");
}

Process.enumerateThreads({
    onMatch: function (thread) {
        Stalker.follow(thread.id, {
            events: {
                compile: true, // block compiled
                block: false //block executed
            },
            onReceive: function (events) {
                parseEvents(events, function (event) {
                    if (event.type === 'compile' || event.type === 'block') {
                        var block = event;
                        var module = Process.findModuleByAddress(block.begin);

                        if (forkserver_enabled && forkstarted.readInt() == 0) {
                            if (block.begin.equals(entrypoint) && have_forkserver == 0) {
                                debug("[+] Entrypoint reached!");
                                var forkserver_start = new NativeFunction(forkserver_module.start, 'void', []);
                                debug("[+] Forkserver about to start... PID", getpid(), ", flag is ", forkstarted.readInt());
                                have_forkserver = 1;
                                forkserver_start();
                                debug("[+] Forkserver started! PID", getpid(), ", flag is ", forkstarted.readInt());
                            }
                        } else {
                            if (module && (instrument_all || whitelist.indexOf(module.name) > -1)) {
                                //debug(event.type + ":" + module.name, block.begin);
                                var base = ptr(module.base);
                                //debug(block.begin + ' -> ' + block.end, "(", module.name, ":", module.base, "-", base.add(module.size), ")");
                                block_monitored += 1;
                                if (!trace_bits.isNull()) {
                                    var id = block.begin >> 1;
                                    var offset = (prev_id ^ id) & 0xFFFF;
                                    var target = trace_bits.add(offset)
                                    const current_value = target.readU16()
                                    target.writeU16(current_value + 1);
                                    prev_id = id >> 1;
                                    //debug("[*] map_offset:", offset, "id:", id, "prev_id:", prev_id, ", target:", target, ", current:", current_value);
                                }
                            }
                        }
                    }
                });
            }
        });
    },
    onComplete: function () {
        debug("[*] Done stalking threads");
    }
});

Interceptor.attach(Module.getExportByName(null, 'exit'), {
    onEnter: function (args) {
        debug("[*] Monitored", block_monitored, "blocks!");
        shmdt(trace_bits);
        debug("[*] Shared memory unmapped!");
    }
});