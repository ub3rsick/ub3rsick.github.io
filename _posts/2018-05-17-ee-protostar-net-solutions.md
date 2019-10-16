---
layout: post
title: "Exploit Exercises Protostar - Net 0-3 Solution"
---

[Protostar](https://exploit-exercises.com/protostar/) introduces the following in a friendly way:

-    Network programming
-    Byte order
-    Handling sockets
-    Stack overflows
-    Format strings
-    Heap overflows


### Net0
This level takes a look at converting strings to little endian integers. This level is at **/opt/protostar/bin/net0**

#### Source Code
```c
#include "../common/common.c"
#define NAME "net0"
#define UID 999
#define GID 999
#define PORT 2999
void run()
{
	unsigned int i;
	unsigned int wanted;
	wanted = random();
	printf("Please send '%d' as a little endian 32bit int\n", wanted);
	if(fread(&i, sizeof(i), 1, stdin) == NULL) {
		errx(1, ":(\n");
	}
	if(i == wanted) {
		printf("Thank you sir/madam\n");
	} else {
		printf("I'm sorry, you sent %d instead\n", i);
	}
}
int main(int argc, char **argv, char **envp)
{
	int fd;
	char *username;
	
    /* Run the process as a daemon */
	background_process(NAME, UID, GID);
	
    /* Wait for socket activity and return */
	fd = serve_forever(PORT);
	
    /* Set the client socket to STDIN, STDOUT, and STDERR */
	set_io(fd);
 	
    /* Don't do this :> */
	srandom(time(NULL));
    
	run();
}
```
The net0 process listens on port 2999. Let us interact with it using netcat.

```bash
user@protostar:/opt/protostar/bin$ clear
user@protostar:/opt/protostar/bin$ nc localhost 2999
Please send '827889081' as a little endian 32bit int
^C
user@protostar:/opt/protostar/bin$ nc localhost 2999
Please send '1477868572' as a little endian 32bit int
827889081
I'm sorry, you sent 943141432 instead
user@protostar:/opt/protostar/bin$
```
On connecting to port 2999, the net0 process sends a text containing a number. We are expected to send back the number in little endian 32 bit.
#### Solution
Below is what needs to be done in order to solve this challenge.
1. Connect to target process on port 2999.
2. Read the text sent by net0.
3. Identify the number to be sent back.
4. Convert the number to little endian 32 bit.
5. Send back the result.
6. Read the response.

Below is the net0 solution written in python.

```python
# Author        : RIZAL MUHAMMED [UB3RSiCK]
# Desc          : Exploit Exercises Protostar - Net0 Solution

from socket import create_connection as cc
import struct
import sys
import re

try:
        con = cc(('localhost', 2999))
except:
        print '[-] Connection Failed'
        sys.exit(0)

print '[*] Connected'
dat = con.recv(1024)

# Get the wanted number from the received string - enclosed within single quotes
wanted_num = re.findall(r"'(.*?)'", dat, re.DOTALL)[0]

print '[*] Received data \n\t', dat
print '[*] Number to send back in little endian 32 bit', wanted_num

# convert int to little endian
res = struct.pack("<I", int(wanted_num))

print '[*] Sending back result', repr(res)
con.send(res)
print '[*] Reading response from server'
print '\t', con.recv(1024)
```

Terminal Output

```bash
user@protostar:/opt/protostar/bin$ python /tmp/net0.py 
[*] Connected
[*] Received data 
	Please send '312988072' as a little endian 32bit int

[*] Number to send back in little endian 32 bit 312988072
[*] Sending back result '\xa8\xd1\xa7\x12'
[*] Reading response from server
	Thank you sir/madam

```

### Net1

This level tests the ability to convert binary integers into ascii representation. This level is at **/opt/protostar/bin/net1**

#### Source Code
```c
#include "../common/common.c"
#define NAME "net1"
#define UID 998
#define GID 998
#define PORT 2998

void run()
{
	char buf[12];
	char fub[12];
	char *q;
	unsigned int wanted;
	
    wanted = random();
	sprintf(fub, "%d", wanted);

	if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {
		errx(1, ":(\n");
	}
	if(fgets(buf, sizeof(buf)-1, stdin) == NULL) {
		errx(1, ":(\n");
	}

	q = strchr(buf, '\r'); if(q) *q = 0;
	q = strchr(buf, '\n'); if(q) *q = 0;

	if(strcmp(fub, buf) == 0) {
		printf("you correctly sent the data\n");
	} else {
		printf("you didn't send the data properly\n");
	}
}
int main(int argc, char **argv, char **envp)
{
	int fd;
	char *username;

	/* Run the process as a daemon */
	background_process(NAME, UID, GID);

	/* Wait for socket activity and return */
	fd = serve_forever(PORT);

	/* Set the client socket to STDIN, STDOUT, and STDERR */
	set_io(fd);

	/* Don't do this :> */
	srandom(time(NULL));

	run();
}
```

#### Solution
Below is what needs to be done in order to solve this challenge.
1. Connect to target process on port 2998.
2. Read in data sent by net0.
3. Unpack the data and convert to unsigned int.
4. Send back the result in string format.
5. Read the response.

Below is the net1 solution written in python.

```python
# Author        : RIZAL MUHAMMED [UB3RSiCK]
# Desc          : Exploit Exercises Protostar - Net1 Solution

from socket import create_connection as cc
import struct
import sys

try:
        con = cc(('localhost', 2998))
except:
        print '[-] Connection Failed'
        sys.exit(0)

print '[*] Connected to localhost on port 2998'
dat = con.recv(1024)

# int to unsigned int
unpacked_dat = struct.unpack("<I", dat)[0]
print '[*] Received data \n\t', repr(dat)
print '[*] Unpacked unsigned data', unpacked_dat

# Convert the unpacked data to string
res = str(unpacked_dat)

print '[*] Sending back result',  res
con.send(res)

print '[*] Reading response from server'
print '\t', con.recv(1024)
```

Terminal Output
```bash
user@protostar:/opt/protostar/bin$ python /tmp/net1.py 
[*] Connected to localhost on port 2998
[*] Received data 
	'$y*o'
[*] Unpacked unsigned data 1865054500
[*] Sending back result 1865054500
[*] Reading response from server
	you correctly sent the data
user@protostar:/opt/protostar/bin$ 
```

### Net2
This code tests the ability to add up 4 unsigned 32-bit integers. 
> Hint: Keep in mind that it wraps.

This level is at **/opt/protostar/bin/net2**

#### Source Code
```c
#include "../common/common.c"
#define NAME "net2"
#define UID 997
#define GID 997
#define PORT 2997
void run()
{
	unsigned int quad[4];
	int i;
	unsigned int result, wanted;
	result = 0;
	
    for(i = 0; i < 4; i++) {
		quad[i] = random();
		result += quad[i];

		if(write(0, &(quad[i]), sizeof(result)) != sizeof(result)) {
			errx(1, ":(\n");
		}
	}

	if(read(0, &wanted, sizeof(result)) != sizeof(result)) {
		errx(1, ":<\n");
	}
	
    if(result == wanted) {
		printf("you added them correctly\n");
	} else {
		printf("sorry, try again. invalid\n");
	}
}
int main(int argc, char **argv, char **envp)
{
	int fd;
	char *username;

    /* Run the process as a daemon */
	background_process(NAME, UID, GID);

	/* Wait for socket activity and return */
	fd = serve_forever(PORT);

	/* Set the client socket to STDIN, STDOUT, and STDERR */
	set_io(fd);

	/* Don't do this :> */
	srandom(time(NULL));

	run();
}
```
#### Solution
The net0 process sends back four 32 bit numbers in little endian. We are expecteed to send back their sum. Below is what needs to be done in order to solve this challenge.

1. Connect to target process on port 2997.
2. Read in the 4 numbers (they are in little endian).
3. Unpack the 4 numbers to unsigned integer.
4. Add the four numbers (handle wrapping as well).
5. Send back the result.
6. Read the response.

Below is the solution for net2.

```python
# Author	: RIZAL MUHAMMED [UB3RSiCK]
# Desc		: Exploit Exercises Protostar - Net2 Solution

from socket import create_connection as cc
import struct
import sys

# Handle wrapping when adding
M32 = 0xffffffffL
def m32(n):
    return n & M32

def madd(a, b):
    return m32(a+b)

try:
	con = cc(('localhost', 2997))
except:
	print '[-] Connection Failed'
	sys.exit(0)

print '[*] Connected to localhost on port 2997'

dat_list = []

# Read the four numbers
for i in range(4):
	dat = con.recv(1024)
	dat_list.append(dat)

print '[*] Received Data ', dat_list

# unpack the data from int to unsigned int
unpacked_dat_list = [struct.unpack("<I", item)[0] for item in dat_list]

sum = 0
print '[*] Unpacked unsigned integer data ', unpacked_dat_list

for item in unpacked_dat_list:
	sum = madd(sum, item)

print '[*] Final added sum : ', sum

res = str(struct.pack("<I", sum))
print '[*] Sending sum [string, little endian] to server : ', repr(res)
con.send(res)

print '[*] Response from server : \033[92m', con.recv(1024), '\033[0m'
```

Terminal Output
```bash
user@protostar:/opt/protostar/bin$ python /tmp/net2.py 
[*] Connected to localhost on port 2997
[*] Received Data  ['\xd6\xe4e\x1a', '\xd3\x94k\x17', '\xf0mN\x05', '\xc2\x1b\xaa9']
[*] Unpacked unsigned integer data  [442885334, 392926419, 89026032, 967449538]
[*] Final added sum :  1892287323
[*] Sending sum [string, little endian] to server :  '[\x03\xcap'
[*] Response from server :  you added them correctly
user@protostar:/opt/protostar/bin$
```

### Net3
This level tests the ability to understand code, and implement a simple network protocol. This level is at **/opt/protostar/bin/net3**

#### Source Code
```c
#include "../common/common.c"

#define NAME "net3"
#define UID 996
#define GID 996
#define PORT 2996

/*
 * Extract a null terminated string from the buffer 
 */

int get_string(char **result, unsigned char *buffer, u_int16_t len)
{
  unsigned char byte;

  byte = *buffer;

  if(byte > len) errx(1, "badly formed packet");
  *result = malloc(byte);
  strcpy(*result, buffer + 1);

  return byte + 1;
}

/*
 * Check to see if we can log into the host
 */

int login(unsigned char *buffer, u_int16_t len)
{
  char *resource, *username, *password;
  int deduct;
  int success;

  if(len < 3) errx(1, "invalid login packet length");

  resource = username = password = NULL;

  deduct = get_string(&resource, buffer, len);
  deduct += get_string(&username, buffer+deduct, len-deduct);
  deduct += get_string(&password, buffer+deduct, len-deduct);

  success = 0;
  success |= strcmp(resource, "net3");
  success |= strcmp(username, "awesomesauce");
  success |= strcmp(password, "password");

  free(resource);
  free(username);
  free(password);

  return ! success;
}

void send_string(int fd, unsigned char byte, char *string)
{
  struct iovec v[3];
  u_int16_t len;
  int expected;

  len = ntohs(1 + strlen(string));

  v[0].iov_base = &len;
  v[0].iov_len = sizeof(len);
  
  v[1].iov_base = &byte;
  v[1].iov_len = 1;

  v[2].iov_base = string;
  v[2].iov_len = strlen(string);

  expected = sizeof(len) + 1 + strlen(string);

  if(writev(fd, v, 3) != expected) errx(1, "failed to write correct amount of bytes");
  
}

void run(int fd)
{
  u_int16_t len;
  unsigned char *buffer;
  int loggedin;

  while(1) {
      nread(fd, &len, sizeof(len));
      len = ntohs(len);
      buffer = malloc(len);

      if(! buffer) errx(1, "malloc failure for %d bytes", len);

      nread(fd, buffer, len);

      switch(buffer[0]) {
          case 23:
              loggedin = login(buffer + 1, len - 1);
              send_string(fd, 33, loggedin ? "successful" : "failed");
              break;
          
          default:
              send_string(fd, 58, "what you talkin about willis?");
              break;
      }
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run(fd);
}
```

#### Solution

The net3 process reads from socket a value and converts the unsigned short integer netshort from network byte order to host byte order - the **ntohs()** function. This value is saved in a variable named **len**.

```c
      nread(fd, &len, sizeof(len));
      len = ntohs(len);
      buffer = malloc(len);
```

Then, **len** amount of memory is allocated for **buffer** in heap using **malloc()**. After this, the process again reads from socket **len** amount of data and stores in **buffer**.

The process then checks if the first element, ie buffer[0] is **23 or 0x17**. If the value is 0x17, then the login() function is invoked with parameters **buffer[1:]**  and **(len-1)**.

> buffer[1:] - buffer starting from first element. The zeroth value, ie the 0x17 is avoided.
> len-1 is the lenth of the buffer now.

The login function checks the received buffer for the presence of three null terminated strings. Each should be prepended with their respective lengths, taking into consideration the null byte at the end.

> \x05net3\x00
> \x0dawesomesauce\x00
> \x09password\x00

Below is the net3 solution.

```python
# Author	: RIZAL MUHAMMED [UB3RSiCK]
# Desc.		: Exploit Exercises Protostar - Net3 Solution

from socket import create_connection as cc
import sys
import struct

try:
	con = cc(('localhost', 2996))
except:
	print '[-] Connection Failed'
	sys.exit(0)

print '[*] Connected to localhost on port 2996'

login_string = '\x17'
login_string += '\x05net3\x00'
login_string += '\x0dawesomesauce\x00'
login_string += '\x09password\x00'

login_len = len(login_string)

print '[*] Login string : ', repr(login_string)
print '[*] Login string length : ', login_len

print '[*] Sending Login string length'

# ! -	network (= big-endian) /
# > -	big-endian
# H -	unsigned short

# Either !H or >H would work
con.send(struct.pack('!H', login_len))

print '[*] Sending Login string'
con.send(login_string)

print '[*] Response from net3 : ', con.recv(1024)
```

Terminal Output
```bash
user@protostar:/opt/protostar/bin$ python /tmp/net3.py 
[*] Connected to localhost on port 2996
[*] Login string :  '\x17\x05net3\x00\rawesomesauce\x00\tpassword\x00'
[*] Login string length :  31
[*] Sending Login string length
[*] Sending Login string
[*] Response from net3 :  
                          !successful
user@protostar:/opt/protostar/bin$ 
```