#!/usr/bin/env python3

import frida
import sys
import time
import threading
import os

from optparse import OptionParser

finished = threading.Event()


def on_message(message, data):
    print("[{}] => {}".format(message, data))


def exiting():
    finished.set()
    print("Exiting!")


def main(target_binary, entrypoint):
    shm_var = os.getenv("__AFL_SHM_ID")
    print("__AFL_SHM_ID is {}".format(shm_var))
    print("Spawning {} ".format(" ".join(target_binary)))
    pid = frida.spawn(target_binary, aslr="disable")
    session = frida.attach(pid)
    session.on('detached', exiting)
    with open('afl.js', 'r') as file:
        data = file.read()
        script = session.create_script(data, runtime='v8')
    script.on("message", on_message)
    script.load()
    script.exports.init(entrypoint)
    frida.resume(pid)
    finished.wait()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage {} target".format(sys.argv[0]))
        sys.exit(-1)
    else:
        parser = OptionParser(usage="usage: %prog [options] target_binary args")
        parser.add_option("-e", "--entrypoint", dest="entrypoint",
                          help="Specify entrypoint")
        (options, args) = parser.parse_args()
        if not options.entrypoint: 
            parser.error("Entrypoint not given")

        main(args, options.entrypoint)
