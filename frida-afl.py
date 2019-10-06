#!/usr/bin/env python3

import frida
import sys
import time
import threading

finished = threading.Event()

def on_message(message, data):
    print("[{}] => {}".format(message, data))

def exiting():
    finished.set()
    print("Exiting!")

def main(target_binary):
    print("Spawning {} ".format(" ".join(target_binary)))
    pid = frida.spawn(target_binary, aslr="disable")
    session = frida.attach(pid)
    session.on('detached', exiting)
    with open('bb.js', 'r') as file:
        data = file.read()
        script = session.create_script(data)
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    finished.wait()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage {} target".format(sys.argv[0]))
        sys.exit(-1)
    else:
        main(sys.argv[1:])