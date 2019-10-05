
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

var main_binary = "simple";
Stalker.trustThreshold = 0;
console.log("Processing basic blocks from", main_binary, "only!");
var getenv_export = Module.getExportByName(null, 'getenv');
if(getenv_export){
    console.log("Found export for getenv!");
    var shm_env_name = Memory.allocUtf8String("SHM_ENV_VAR");
    const get_env = new NativeFunction(getenv_export, 'pointer', ['pointer']);
    console.log("Allocated env name SHM_ENV_VAR", shm_env_name, ", native function", get_env);
    var shm_id = Memory.readCString(get_env(shm_env_name));
    console.log("Shared memory ID:", parseInt(shm_id));

    var shmat_export = Module.getExportByName(null, 'shmat');
    var shmdt_export = Module.getExportByName(null, 'shmdt');
    if(shmat_export && shmdt_export){
        const shmat = new NativeFunction(shmat_export, 'pointer', ['int', 'pointer', 'int']);
        const shmdt = new NativeFunction(shmdt_export, 'int', ['pointer']);

        const trace_bits = shmat(parseInt(shm_id), ptr(0), 0);
        console.log("trace_bits mapped at", trace_bits);
    } else {
        console.log("Unable to resolve shared memory exports!\n");
    }

} else {
    console.log("Unable to find export for getenv!");
}


// void *trace_bits = shmat(shm_id, NULL, 0);

var prev_id = ptr(0);

Process.enumerateThreads({
    onMatch: function (thread) {
        Stalker.follow(thread.id, {
            events: {
                compile: true, // block compiled
                block: false //block executed
            },
            onReceive: function (events) {
                //console.log(Stalker.parse(event));
                parseEvents(events, function (event) {
                    if (event.type === 'compile' || event.type === 'block') {
                        var block = event;
                        var module = Process.findModuleByAddress(block.begin);
                        if(module && module.name == main_binary){
                            var base = ptr(module.base);
                            console.log(block.begin + ' -> ' + block.end, "(", module.name, ":", module.base, "-", base.add(module.size), ")");
                            const id = block.begin >> 1;
                            var offset = (prev_id ^ id) & 0xFFFF;
                            var target = trace_bits.add(offset)
                            const current_value = target.readU16()
                            target.writeU16(current_value + 1);
                            prev_id = id >> 1;
                            console.log("map_offset:", offset, "id:", id, "prev_id:", prev_id, ", target:", target, ", current:", current_value);
                        }
                      //console.log(event.code + '\n');
                    }
                });
            }
        });
    },
    onComplete: function () { 
        console.log('Done stalking threads.'); 
        //shmdt(trace_bits);
        //console.log("Shared memory unmapped!");
    }
});