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
