---
layout: post
title: Playsecure CTF 2021 - Reverse Engineering - 0x03
---
### Challenge Description

Reverse engineer the attached file to get the flag.

_Difficulty_: **Medium**

_Category_: **Reverse**

<!-- more -->

### Recon

```bash
# file prog 
prog: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f53c6d7f3c9435791ec158b90deab3b2435e81f5, for GNU/Linux 3.2.0, not stripped

# ./prog
[-] Wrong usage
# ./prog 1234
[-] Failure
# 
```

1. The file is a 64 bit ELF executable.
2. Needs a command line argument to be passed to run.

### Debugging the binary in GDB

**Listing functions and setting break points:**

![re03_1](/assets/playsecure2021/re03_1.png)

We see two functions which are of interest to us:
1. check
2. main

We set breakpoint at both.

**Dis-assembling main and check functions:**

```nasm
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000001198 <+0>:	push   rbp
   0x0000000000001199 <+1>:	mov    rbp,rsp
   0x000000000000119c <+4>:	sub    rsp,0x10
   0x00000000000011a0 <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000000011a3 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000000011a7 <+15>:	cmp    DWORD PTR [rbp-0x4],0x2
   0x00000000000011ab <+19>:	je     0x11c0 <main+40>
   0x00000000000011ad <+21>:	lea    rdi,[rip+0xe50]        # 0x2004
   0x00000000000011b4 <+28>:	call   0x1030 <puts@plt>
   0x00000000000011b9 <+33>:	mov    eax,0x1
   0x00000000000011be <+38>:	jmp    0x11f6 <main+94>
   0x00000000000011c0 <+40>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011c4 <+44>:	add    rax,0x8
   0x00000000000011c8 <+48>:	mov    rax,QWORD PTR [rax]
   0x00000000000011cb <+51>:	mov    rdi,rax
   0x00000000000011ce <+54>:	call   0x1135 <check>
   0x00000000000011d3 <+59>:	test   eax,eax
   0x00000000000011d5 <+61>:	je     0x11e5 <main+77>
   0x00000000000011d7 <+63>:	lea    rdi,[rip+0xe36]        # 0x2014
   0x00000000000011de <+70>:	call   0x1030 <puts@plt>
   0x00000000000011e3 <+75>:	jmp    0x11f1 <main+89>
   0x00000000000011e5 <+77>:	lea    rdi,[rip+0xe34]        # 0x2020
   0x00000000000011ec <+84>:	call   0x1030 <puts@plt>
   0x00000000000011f1 <+89>:	mov    eax,0x0
   0x00000000000011f6 <+94>:	leave  
   0x00000000000011f7 <+95>:	ret    
End of assembler dump.
gdb-peda$ disas check
Dump of assembler code for function check:
   0x0000000000001135 <+0>:	push   0x7d
   0x0000000000001137 <+2>:	push   0x1
   0x0000000000001139 <+4>:	movabs rax,0x65646f635f656e68
   0x0000000000001143 <+14>:	pop    rsi
   0x0000000000001144 <+15>:	xor    rsi,rax
   0x0000000000001147 <+18>:	push   rsi
   0x0000000000001148 <+19>:	movabs rax,0x6863616d5f6f745f
   0x0000000000001152 <+29>:	push   rax
   0x0000000000001153 <+30>:	push   0x2a
   0x0000000000001155 <+32>:	pop    rax
   0x0000000000001156 <+33>:	movabs rcx,0x6863616d5f6f745f
   0x0000000000001160 <+43>:	xchg   rcx,rax
   0x0000000000001162 <+45>:	push   rax
   0x0000000000001163 <+46>:	movabs rax,0x65736f6c635f7369
   0x000000000000116d <+56>:	push   0x13371337
   0x0000000000001172 <+61>:	pop    rdx
   0x0000000000001173 <+62>:	push   rax
   0x0000000000001174 <+63>:	push   0x13333337
   0x0000000000001179 <+68>:	pop    rsi
   0x000000000000117a <+69>:	movabs rax,0x5f637b4541465443
   0x0000000000001184 <+79>:	push   rax
   0x0000000000001185 <+80>:	xor    rax,rax
   0x0000000000001188 <+83>:	mov    rsi,rsp
   0x000000000000118b <+86>:	repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
   0x000000000000118d <+88>:	sete   al
   0x0000000000001190 <+91>:	add    rsp,0x30
   0x0000000000001194 <+95>:	ret    
   0x0000000000001195 <+96>:	nop
   0x0000000000001196 <+97>:	ud2    
End of assembler dump.
gdb-peda$ 
```

**Running the executable within GDB:**

GDB command: `r AAAAAAAA`

![re03_2](/assets/playsecure2021/re03_2.png)

We hit the first break point which is the main function. 

![re03_3](/assets/playsecure2021/re03_3.png)

Continue execution till we hit the second break point.

![re03_4](/assets/playsecure2021/re03_4.png)

We hit the second break point which is the check function. Now stepping through execution and observing the stack to see if any interesting strings are being pushed on to it.

![re03_5](/assets/playsecure2021/re03_5.png)

When execution reaches `check+83`, we see the flag on top of the stack and the stack pointer is pointing to it.

![re03_6](/assets/playsecure2021/re03_6.png)

When execution reaches `check+86`, the assembly instruction compares the bytes pointed by RSI and RDI. RSI points to the FLAG and RDI to the user input we supplied.

**Testing the flag against the binary:**

`./prog CTFAE{c_is_close_to_mach_to_machine_code}`

![re03_7](/assets/playsecure2021/re03_7.png)

We get success.

*FLAG: CTFAE{c_is_close_to_mach_to_machine_code}*
