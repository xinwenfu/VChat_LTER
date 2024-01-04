#! /bin/python3

# Specify Instruction, Long   E9 43F2FFFF      JMP 0109F21E
long_buff= b'\xe9\x43\xf2\xff\xff'
# Specify Instruction, Short   \xeb\x80 (Longest Short Jump 127 bytes)
short_buff= b'\xeb\x80'
# E11 Buff
e11_buff = b'\xe9\x9b\xf2\x2C\x00'

# Open Files for writing
fd_l= open('jmp_l.bin', 'wb')
fd_s = open('jmp_s.bin', 'wb')
fd_e = open('jmp_e10.bin', 'wb')

# Write to files
fd_l.write(long_buff)
fd_s.write(short_buff)
fd_e.write(e11_buff)
