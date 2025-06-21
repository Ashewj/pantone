import pymem.process as process
import pymem

import ctypes.wintypes as wintypes
import ctypes
import frida
import sys

import contextlib
#from cyminhook import *
#from minhook import *
import win32api
import win32con

signature_proto= ctypes.WINFUNCTYPE(
    ctypes.c_int,          # void return type
    ctypes.c_void_p,       # TForm1_Self (in RCX)
    ctypes.c_void_p        # TObject_Sender (in RDX)
)

report_previewmodal_pattern = b"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x00\x48\x8B\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\x83\x05"

pm = pymem.Pymem('Project1.exe')
report_previewmodal_address = pymem.pattern.pattern_scan_all(pm.process_handle, report_previewmodal_pattern.translate(bytes.maketrans(b'\x00', b'.')), return_multiple=False)

def on_message(message, data):
    print("[%s] => %s" % (message, data))

session = frida.attach('Project1.exe')

print(hex(report_previewmodal_address))

script = session.create_script("""
                               
    Interceptor.attach(ptr(%d), {
        onEnter: function (args) {
            console.log("Self ptr: " + args[0]);
        }
    });
    """ % report_previewmodal_address
)

script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()