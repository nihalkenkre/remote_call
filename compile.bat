@echo off
nasm -f bin shellcode.asm -o shellcode.bin
python c:\users\someone\documents\maldev_tools\transform\transform_file.py -i c:\users\someone\documents\maldev\sektor7\MDA\RemoteCall\shellcode.bin -o c:\users\someone\documents\maldev\sektor7\MDA\RemoteCall\shellcode.x64.bin.asm -vn shellcode_x64
nasm -f bin remote_call.asm -o remote_call.bin
python c:\users\someone\documents\maldev_tools\transform\transform_file.py -i c:\users\someone\documents\maldev\sektor7\MDA\RemoteCall\remote_call.bin -o c:\users\someone\documents\maldev\sektor7\MDA\RemoteCall\remote_call.x64.bin.h -vn remote_call_x64
cl /nologo /W3 /MT /O2 /GS- main.c /link kernel32.lib vcruntime.lib

del *.obj