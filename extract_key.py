#!/usr/bin/env python3

import subprocess
import sys
import frida


def on_message(message, data):
    print("[%s] => %s" % (message, data))


def main(pid):
    session = frida.attach(pid)

    script = session.create_script("""

    var baseAddr = Process.enumerateModulesSync()[0].base;
    console.log(Process.enumerateModulesSync()[0].name + ' baseAddr: ' + baseAddr);

    var decryptor = resolveAddress('0x4852E0'); // Symbol address
    console.log("Intercepting function at address " + decryptor);

    Interceptor.attach(decryptor, {
        onEnter: function (args) {
            var offset = ptr('0x360');
            var arg = ptr(this.context["eax"]).add(offset);

            console.log("key = b'" + String.fromCharCode(92));

            // Ugly code to write a Python bytearray
            var x;
            for (x = 0; x < 256; ) {
                var y = 0;
                var line = "";
                for (y = 0; y < 16; y++) {
                    var value = arg.add(ptr(x)).readU8();
                    line += String.fromCharCode(92) + 'x';
                    if (value < 16)
                        line += '0';
                    line += value.toString(16);
                    x++;
                }

                if (x < 256)
                    console.log(line + String.fromCharCode(92));
                else
                    console.log(line + "'");
            }

            // Uncomment to dump bytearray
            //console.log(hexdump(arg, { offset: 0, length: 256, header: true, ansi: true}));
        },
    });

    function resolveAddress(addr) {
        var idaBase = ptr('0x400000'); // IDA base address
        var offset = ptr(addr).sub(idaBase);
        var result = baseAddr.add(offset);
        return (result);
    }
    """)

    script.on("message", on_message)
    script.load()
    input("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.")
    print("[+] Quitting")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <binary.exe>" % __file__)
        sys.exit(1)

    # Process spawning on Windows
    # From https://stackoverflow.com/questions/11585168/launch-an-independent-process-with-python
    DETACHED_PROCESS = 0x00000008
    results = subprocess.Popen([sys.argv[1]], close_fds=True, creationflags=DETACHED_PROCESS)

    print("[+] Process spawned with PID " + str(results.pid))

    main(results.pid)