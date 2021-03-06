---
layout: post
title: SLAE Assignment  3 - Egg Hunter (Linux/x86)
---

The third assigment is to study about Egg Hunters and implement a working demo of egg hunters with configurable payloads. So, what is an **Egg Hunter**?!.
> An egghunter is a short piece of code which is safely able to search the Virtual Address Space for
an “egg” – a short string signifying the beginning of a larger payload. The egghunter code will
usually include an error handling mechanism for dealing with access to non allocated memory
ranges.

<!-- more -->

Often during exploit research, we may have control over a small amount of space, say 50 bytes. But in most cases, this much space is not  enough to accomodate a reverse shell or or bind shell. We may observe that a larger space is available somewhere else enough to accomodate a larger payload. But its location in memory is not known. Here is where egg hunters come in to play. A unique mark (EGG) is prepended before the shellcode and the egghunter will safely search the virtual address space for this egg. Once the egg is found the egghunter will jump to the larger payload followed by the egg.

There is wonderful paper regarding egg hunter implementations on both Linux and Windows platforms - [Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf). I found this very comprehensive and easy to follow. For Linux, the author - Matt Miller (skape) - explains in detail 3 implementaions of egghunter, each with their Pros and Cons. I will be using the second implementation of egg hunter in the aforementioned paper.

As described in the paper, the three requirements of an egg hunter are:

1. **It must be robust** - This requirement is used to express the fact that the egg hunter must be capable of searching through memory regions that are invalid and would otherwise crash the application if they were to be dereferenced improperly. It must also be capable of searching for the egg anywhere in memory.

2. **It must be small** - Given the scope of this paper, size is a principal requirement for the egg hunters as they must be able to go where no other payload would be able to fit when used in conjunction with an exploit. The smaller the better.

3. **It should be fast** - In order to avoid sitting idly for minutes while the egg hunter does its task, the methods used to search VAS should be as quick as possible, without violating the first requirement or second requirements without proper justification.

So, without further ado, lets look at one of the egg hunter implementations.

### Matt Miller's "access(2) - revisited" Egg hunter

The reason why I chose this implementaion is that it does not require the egg itself to be executable assembly, opening up a wider range of possible eggs to be used when searching, thus making it much more robust. In this implementation an **eight byte egg** is used when doing the searching. The reason for this stems from the fact that the implementations for the egg hunting algorithms tend to have a four byte version of the key stored once in the searching code itself, thus it might be possible if one were to use a four byte version of the key to accidentaly run into the egg hunter itself vice running into the expected buffer.

So, in the following implementation of egg hunter we are searching for two consecutive occurrances EGG (0x50905090).
```
EGG
EGG
<Larger Shellcode>
```

The egg hunter must be capable of searching through memory regions. This is where the ```access(2)``` system call is helpful. The real purpose of ```access(2)``` system call is to check and see if the current process has the specific access rights to a given file on disk. The man page entry for ```access(2)``` is as follows:
```
int access(const char *pathname, int mode);
```
The ```pathname``` pointer is the argument that will be used to do the address validation. The system call number for ```access(2)``` is defined in ```/usr/include/i386-linux-gnu/asm/unistd_32.h``` as follows:
```
#define __NR_access 33
```
When a system call encounters an invalid memory address, most will return the EFAULT (-14)error code to indicate that a pointer provided to the system call was not valid. This logic is applied in this egg hunter.

```nasm
;
; Description	: Matt Miller's access(2) - revisited Egg Hunter 
; File 		: egghunter.nasm
;


global _start

section .text
	_start:
		
		
		xor edx,edx			; EDX holds the pointer that is to be validated by the access system call
	
		next_page:
			or dx,0xfff		; page alignment logic
						; allows the hunting code to move up in PAGE SIZE
                           			; increments vice doing in single byte increments.
		
			next_address:
				inc edx
	
				; validating eight bytes of contiguous memory in a single swoop
				; The reason that it works in all cases is because the implementation
				; will increment by PAGE SIZE when it encounters invalid addresses, thus it’s
				; impossible that edx plus four could be valid and edx itself not be valid.
			
				lea ebx,[edx+0x4]

				push byte +0x21
				pop eax			; EAX = 33 = access()
				int 0x80

				; if memory pointed by ebx is not accessible, 
        	    		; then access() syscall returns value 0xfffffff2 (-14) EFAULT to EAX
				; compare the lower bytes of EAX with 0xf2

				cmp al,0xf2
				jz next_page	; pointer not valid

		; pointer is valid, search for egg
		
		mov eax,0x50905090	; EGG = 0x50905090
		mov edi,edx			; EDX has the valid pointer, copy it to edi
		scasd				; check for first appearance of EGG
        					; compare EAX with contents of memory pointed by EDI,
    						; EDI is incremented automatically by 4 bytes after SCASD (Even if scasd comparison are not equal)
		jnz next_address	; EGG not found, got to next address in page
		scasd			; Check for consecutive second appearance of EGG
		jnz next_address	; EGG not found, got to next address in page
		jmp edi			; we found egg consecutively two times, now EDI  = EDX + 8 = start of shellcode, jump to it
```

Assemble, Link the egghunter assembly file and Dump shellcode from the executable using ```objdump```. Later we will put this in a c file to test the egg hunter.
```
// egg hunter shellcode
// EGG : 0x50905090
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"
```
The following assembly code prints the string "EGG IS FOUND" onto stdout.

```nasm
;
; Author 	: RIZAL MUHAMMED (UB3RSiCK)
; Description 	: Print EGG IS FOUND
;

global _start
section .text
	_start:
		xor eax, eax
		mov al, 0x4			; write syscall
		
		xor ebx, ebx
		mov bl, 0x1			; write to stdout
		
		xor ecx, ecx
		jmp short get_me_buffer_address
			here_is_your_buffer:
				pop ecx		; now ecx will have address of message

		xor edx, edx
		mov dl, 0xd			; param3 how many bytes to write
		int 0x80

		; exit the program

		xor eax, eax			; exit system call - #define __NR_exit 1
		mov al, 0x1
		int 0x80

		get_me_buffer_address:
			call here_is_your_buffer				; when call is executed, address of message is
			message db "EGG IS FOUND", 0xA			; pushed on to the stack

```
Assemble, Link the above assembly code and Dump the shellcode from executable.
```
"\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x31\xc9\xeb\x0d\x59\x31\xd2\xb2\x0d\xcd\x80\x31\xc0\xb0\x01\xcd\x80\xe8\xee\xff\xff\xff\x45\x47\x47\x20\x49\x53\x20\x46\x4f\x55\x4e\x44\x0a";
```

Insert the egg hunter shellcode and the shellcode to print "EGG IS FOUND" to the following c file. Different shellcode payloads of different sizes can be used. The place where to put in shellcode is marked in the template file.
```c
#include<stdio.h>
#include<string.h>

unsigned char egghunter[] = \
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";


unsigned char shellcode[] = \
"\x90\x50\x90\x50" //egg mark 1
"\x90\x50\x90\x50" //egg mark 2

// Place second stage larger payload here
// Print EGG IS FOUND shellcode
"\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x31\xc9\xeb\x0d\x59\x31\xd2\xb2\x0d\xcd\x80\x31\xc0"
"\xb0\x01\xcd\x80\xe8\xee\xff\xff\xff\x45\x47\x47\x20\x49\x53\x20\x46\x4f\x55\x4e\x44\x0a";

main()
{
        printf("Egghunter Shellcode Length:  %d\n", strlen(egghunter));
        int (*ret)() = (int(*)())egghunter;
        ret();

}
```
Compile the c file and execute.
![Running Egg Hunter](/assets/asn-3-egg-found.PNG)

We can now use larger shellcodes, just insert shellcode in the above c file and compile. And we are done. Nice. 

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: **SLAE-933**
