
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
                console.log('Unsupported type ' + type);
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
// keep track of previous block id
var prev_id = ptr(0);
var block_monitored = 0;
var entrypoint = ptr(0);
// forkserver 
var have_forkserver = 0;

const forkserver_module = new CModule(`
#include <stdio.h>

#define FORKSRV_FD          198

static int now_start = 0, loadedlibs = 0, have_forkserver = 0;

extern int fork(void);
extern int read(int fildes, void *buf, unsigned int nbyte);
extern int write(int fildes, const void *buf, unsigned int nbyte);
extern int waitpid(int pid, int *stat_loc, int options);
extern int close(int fildes);

void
start (void)
{
    unsigned char tmp[4];
    int child_pid = 0;
    printf ("[+] Init forkserver!\\n");
    if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
        printf ("[!] Error writing fork server to FD %d\\n", FORKSRV_FD);
        return;
    }

    while (1) {
        unsigned int was_killed;
        int status;
        printf ("[+] Waiting for mother!\\n");
        if (read(FORKSRV_FD, &was_killed, 4) != 4) {
            printf("[!] Error reading fork server\\n");
            return;
        }
        child_pid = fork();
        if (child_pid < 0) {
            printf("[!] Error fork\\n");
            return;
        }

        if (child_pid == 0) {       // child
            printf("[!]forkserver(): this is the child\\n");
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            now_start = 1;
            return;
        }

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
            printf("[!] Error writing fork server (2)\\n");
            return;
        }
        printf("[+] forkserver(): this is the forkserver(main)\\n");
        if (waitpid(child_pid, &status, 0) < 0) {
            printf("[!] Error waiting for child\\n");
            return;
        }

        if (write(FORKSRV_FD + 1, &status, 4) != 4) {
            printf("[!] Fork server is gone, terminating\n");
            return;
        }
        printf("[+] forkserver(): child is done\\n");
    }
}
`);

rpc.exports = {
    init: function (entrypoint_address) {
        entrypoint = ptr(entrypoint_address);
        console.log("[*] Entrypoint address set to", entrypoint);
        console.log("[+] Instrumentation initialized from python launcher!");
        return;
    }
};

var getenv_export = Module.getExportByName(null, 'getenv');
if (getenv_export) {
    console.log("[*] Found export for getenv!");
    const get_env = new NativeFunction(getenv_export, 'pointer', ['pointer']);
    console.log("[*] Prepared native function @", get_env);
    var shm_id = parseInt(Memory.readCString(get_env(Memory.allocUtf8String("__AFL_SHM_ID"))));
    console.log("[*] Shared memory ID:", parseInt(shm_id));

    var whitelist_raw = Memory.readCString(get_env(Memory.allocUtf8String("WHITELIST")));
    if (whitelist_raw) {
        var whitelist = whitelist_raw.split(",").map(function (item) {
            return item.trim();
        });
        console.log("[*] Whitelist: ", whitelist);
        if (whitelist.indexOf("all") > -1) {
            console.log("[*] Covering all modules!");
            instrument_all = true
        }
    } else {
        var whitelist = [Process.enumerateModules()[0].name];
        console.log("[!] WHITELIST env not available! tracking only main module", whitelist[0]);
    }

    var shmat_export = Module.getExportByName(null, 'shmat');
    var shmdt_export = Module.getExportByName(null, 'shmdt');
    if (shmat_export && shmdt_export) {
        shmat = new NativeFunction(shmat_export, 'pointer', ['int', 'pointer', 'int']);
        shmdt = new NativeFunction(shmdt_export, 'int', ['pointer']);
        if (shm_id > 0) {
            trace_bits = shmat(shm_id, ptr(0), 0);
        }
        console.log("[*] trace_bits mapped at", trace_bits);
    } else {
        console.log("[!] Unable to resolve shared memory exports!\n");
    }

} else {
    console.log("[!] Unable to find export for getenv!");
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

                        if (block.begin.equals(entrypoint) && have_forkserver == 0) {
                            console.log("[+] Entrypoint reached!");
                            var forkserver_start = new NativeFunction(forkserver_module.start, 'void', []);
                            have_forkserver = 1;
                            forkserver_start();
                            console.log("[+] Forkserver started!");
                        }

                        if (module && (instrument_all || whitelist.indexOf(module.name) > -1)) {
                            //console.log(event.type + ":" + module.name, block.begin);
                            var base = ptr(module.base);
                            //console.log(block.begin + ' -> ' + block.end, "(", module.name, ":", module.base, "-", base.add(module.size), ")");
                            block_monitored += 1;
                            if (!trace_bits.isNull()) {
                                var id = block.begin >> 1;
                                var offset = (prev_id ^ id) & 0xFFFF;
                                var target = trace_bits.add(offset)
                                const current_value = target.readU16()
                                target.writeU16(current_value + 1);
                                prev_id = id >> 1;
                                //console.log("[*] map_offset:", offset, "id:", id, "prev_id:", prev_id, ", target:", target, ", current:", current_value);
                            }
                        }
                    }
                });
            }
        });
    },
    onComplete: function () {
        console.log("[*] Done stalking threads");
    }
});

Interceptor.attach(Module.getExportByName(null, 'exit'), {
    onEnter: function (args) {
        console.log("[*] Monitored", block_monitored, "blocks!");
        shmdt(trace_bits);
        console.log("[*] Shared memory unmapped!");
    }
});