---
layout: post
title: OverTheWire: Bandit
---

The Bandit wargame is aimed at absolute beginners. It will teach the basics needed to be able to play other wargames.

<!--more-->

## Level 0
he goal of this level is for you to log into the game using SSH. The host to which you need to connect is **bandit.labs.overthewire.org**, on port **2220**. The username is **bandit0** and the password is **bandit0**.

## Level 0 - Level 1
The password for the next level is stored in a file called **readme** located in the home directory. Use this password to log into bandit1 using SSH.
```
bandit0@bandit:/home$ find . -type f -name readme 2>/dev/null
./bandit18/readme
./bandit0/readme
bandit0@bandit:/home$ cat ./bandit0/readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```
## Level 1 - Level 2
The password for the next level is stored in a file called **-** located in the home directory.
```
bandit1@bandit:~$ pwd
/home/bandit1
bandit1@bandit:~$ ls -l
total 4
-rw-r----- 1 bandit2 bandit1 33 Dec 28 14:34 -
bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```
## Level 2 - Level 3
The password for the next level is stored in a file called **spaces in this filename** located in the home directory.
```
bandit2@bandit:~$ ls -l
total 4
-rw-r----- 1 bandit3 bandit2 33 Dec 28 14:34 spaces in this filename
bandit2@bandit:~$ cat spaces\ in\ this\ filename
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```
## Level 3 - Level 4
The password for the next level is stored in a hidden file in the **inhere** directory.
```
bandit3@bandit:~/inhere$ ls -la
total 12
drwxr-xr-x 2 root    root    4096 Dec 28 14:34 .
drwxr-xr-x 3 root    root    4096 Dec 28 14:34 ..
-rw-r----- 1 bandit4 bandit3   33 Dec 28 14:34 .hidden
bandit3@bandit:~/inhere$ cat ./.hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```
## Level 4 - Level 5
The password for the next level is stored in the **only human-readable** file in the inhere directory.
```
bandit4@bandit:~/inhere$ ls -l
total 40
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file00
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file01
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file02
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file03
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file04
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file05
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file06
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file07
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file08
-rw-r----- 1 bandit5 bandit4 33 Dec 28 14:34 -file09
bandit4@bandit:~/inhere$ strings ./*
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
~!\
=?G0
```
## Level 5 - Level 6
The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:
> 
    human-readable
    1033 bytes in size
    not executable

```
bandit5@bandit:~/inhere$ find . -type f -size 1033c ! -executable
./maybehere07/.file2
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```
## Level 6 - Level 7
The password for the next level is stored somewhere on the server and has all of the following properties:

>    owned by user bandit7
    owned by group bandit6
    33 bytes in size

```
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```
## Level 7 - Level 8
The password for the next level is stored in the file data.txt next to the word **millionth**.
```
bandit7@bandit:~$ ls -l
total 4088
-rw-r----- 1 bandit8 bandit7 4184396 Dec 28 14:34 data.txt
bandit7@bandit:~$ grep millionth data.txt
millionth	cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```
## Level 8 - Level 9
The password for the next level is stored in the file **data.txt** and is the only line of text that occurs only once.
```
bandit8@bandit:~$ cat data.txt | sort | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```
## Level 9 - Level 10
The password for the next level is stored in the file **data.txt** in one of the few human-readable strings, beginning with several '=' characters.
```
bandit9@bandit:~$ strings data.txt | grep "^==*"
=-VW+
========== theP`
========== password
========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```
## Level 10 - Level 11
The password for the next level is stored in the file **data.txt**, which contains **base64 encoded** data.
```
bandit10@bandit:~$ cat data.txt | base64 -d
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```
## Level 11 - Level 12
The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions.
[ROT13 Decode](https://exploitshit.wordpress.com/2015/04/25/decode-rot13-on-linux-command-line/)
```
bandit11@bandit:~$ cat data.txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```
## Level 12 - Level 13
The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed.
```
bandit12@bandit:/tmp/ub3r$ cat data.txt 
00000000: 1f8b 0808 ecf2 445a 0203 6461 7461 322e  ......DZ..data2.
00000010: 6269 6e00 0149 02b6 fd42 5a68 3931 4159  bin..I...BZh91AY
00000020: 2653 5930 3e1b 4000 0014 ffff dde3 2b6d  &SY0>.@.......+m
00000030: afff dd1e dfd7 ffbf bdfb 3f67 bfff ffff  ..........?g....
00000040: bde5 bfff aff7 bfdb e5ff ffef b001 39b0  ..............9.
00000050: 480d 3400 0068 0068 1a00 0000 01a3 4000  H.4..h.h......@.
....snipped
```

```
bandit12@bandit:/tmp/ub3r$ cat data.txt | xxd -r > data1.bin
bandit12@bandit:/tmp/ub3r$ file data1.bin
data1.bin: gzip compressed data, was "data2.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
bandit12@bandit:/tmp/ub3r$ cp data1.bin data1.gz
bandit12@bandit:/tmp/ub3r$ zcat data1.gz > data2.bin
```

```
bandit12@bandit:/tmp/ub3r$ file data2.bin
data2.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/ub3r$ cp data2.bin data2.bz2
bandit12@bandit:/tmp/ub3r$ bzip2 -dk data2.bz2
```

```
bandit12@bandit:/tmp/ub3r$ file data2
data2: gzip compressed data, was "data4.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
bandit12@bandit:/tmp/ub3r$ cp data2 data3.gz
bandit12@bandit:/tmp/ub3r$ zcat data3.gz > data4.bin
bandit12@bandit:/tmp/ub3r$ file data4.bin
```

```
bandit12@bandit:/tmp/ub3r$ file data4.bin
data4.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/ub3r$ cp data4.bin data4.tar
bandit12@bandit:/tmp/ub3r$ tar -xvf data4.tar
data5.bin
bandit12@bandit:/tmp/ub3r$ file data5.bin
data5.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/ub3r$ cp data5.bin data5.tar
bandit12@bandit:/tmp/ub3r$ tar -xvf data5.tar
data6.bin
bandit12@bandit:/tmp/ub3r$ file data6.bin
data6.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/ub3r$ cp data6.bin data6.bz2
bandit12@bandit:/tmp/ub3r$ bzip2 -dk data6.bz2
bandit12@bandit:/tmp/ub3r$ ls -l data6
-rw-r--r-- 1 bandit12 bandit12 10240 Apr 16 09:06 data6
```

```
bandit12@bandit:/tmp/ub3r$ file data6
data6: POSIX tar archive (GNU)
bandit12@bandit:/tmp/ub3r$ cp data6 data6.tar
bandit12@bandit:/tmp/ub3r$ tar -xvf data6.tar
data8.bin
bandit12@bandit:/tmp/ub3r$ file data8.bin
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
bandit12@bandit:/tmp/ub3r$ cp data8.bin data8.gz
bandit12@bandit:/tmp/ub3r$ zcat data8.gz > data9.bin
bandit12@bandit:/tmp/ub3r$ file data9.bin
data9.bin: ASCII text
```
Finally we get the password.
```
bandit12@bandit:/tmp/ub3r$ cat data9.bin 
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```
## Level 13 - Level 14
The password for the next level is stored in **/etc/bandit_pass/bandit14** and **can only be read by user bandit14**. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level.
```
bandit13@bandit:~$ ls -l
total 4
-rw-r----- 1 bandit14 bandit13 1679 Dec 28 14:34 sshkey.private
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
....
bandit14@bandit:~$
```
## Level 14 - Level 15
The password for the next level can be retrieved by submitting the password of the current level to port **30000** on localhost.
```
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
bandit14@bandit:~$ which nc
/bin/nc
bandit14@bandit:~$ nc localhost 30000
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```
## Level 15 - Level 16
The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption.
```
bandit15@bandit:~$ echo BfMYroe26WYalil77FoDi9qh59eK5xNr | openssl s_client -connect localhost:30001 -quiet
depth=0 CN = bandit
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = bandit
verify return:1
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd
```
## Level 16 - Level 17
The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.
```
bandit16@bandit:~$ for port in {31000..32000};do echo ''; echo Connected to $port;openssl s_client -connect localhost:$port -quiet;done
```
```
....
Connected to 31517
connect: Connection refused
connect:errno=111

Connected to 31518
depth=0 CN = bandit
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = bandit
verify return:1
test
test
```

```
bandit16@bandit:~$ for port in {31519..32000};do echo ''; echo Connected to $port;openssl s_client -connect localhost:$port -quiet;done
.....
Connected to 31789
connect: Connection refused
connect:errno=111

Connected to 31790
depth=0 CN = bandit
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = bandit
verify return:1
cluFn7wTiGryunymYOu4RcffSxQluehd
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```
## Level 17 - Level 18
There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new
```
root@kali:~/Desktop/WarGames/OverTheWire/bandit# chmod 700 ./bandit17.pvt
root@kali:~/Desktop/WarGames/OverTheWire/bandit# ls -l
total 4
-rwx------ 1 root root 1675 Apr 16 03:57 bandit17.pvt
root@kali:~/Desktop/WarGames/OverTheWire/bandit# ssh -i bandit17.pvt bandit17@bandit.labs.overthewire.org -p 2220
```
```
bandit17@bandit:~$ diff passwords.new passwords.old 
42c42
< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> 6vcSC74ROI95NqkKaeEC2ABVMDX9TyUr
```

## Level 18 - Level 19
The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.
```
bandit17@bandit:~$ ssh bandit18@localhost "cat readme"
bandit18@localhost's password: <bandit18 password - kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd>
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```
## Level 19 - Level 20
To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.
```
bandit19@bandit:~$ ls -l
total 8
-rwsr-x--- 1 bandit20 bandit19 7408 Dec 28 14:34 bandit20-do
bandit19@bandit:~$ ./bandit20-do 
Run a command as another user.
  Example: ./bandit20-do id
bandit19@bandit:~$ ./bandit20-do whoami
bandit20
bandit19@bandit:~$ ./bandit20-do uname -a
Linux bandit 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```
## Level 20 - Level 21
There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).
```
Terminal 1:
bandit20@bandit:~$ nc -lp 4455
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr

Terminal 2:
bandit20@bandit:~$ ./suconnect 4455
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
```
## Level 21 - Level 22
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.
```
bandit21@bandit:~$ cd /etc/cron.d/
bandit21@bandit:/etc/cron.d$ ls -l
total 16
-rw-r--r-- 1 root root 120 Dec 28 14:34 cronjob_bandit22
-rw-r--r-- 1 root root 122 Dec 28 14:34 cronjob_bandit23
-rw-r--r-- 1 root root 120 Dec 28 14:34 cronjob_bandit24
-rw-r--r-- 1 root root 190 Oct 31 13:21 popularity-contest
bandit21@bandit:/etc/cron.d$ cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
bandit21@bandit:/etc/cron.d$ ls -l /usr/bin/cronjob_bandit22.sh
-rwxr-x--- 1 bandit22 bandit21 130 Dec 28 14:34 /usr/bin/cronjob_bandit22.sh
bandit21@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```
## Level 22 - Level 23
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.
```
bandit22@bandit:~$ cd /etc/cron.d
bandit22@bandit:/etc/cron.d$ ls -l
total 16
-rw-r--r-- 1 root root 120 Dec 28 14:34 cronjob_bandit22
-rw-r--r-- 1 root root 122 Dec 28 14:34 cronjob_bandit23
-rw-r--r-- 1 root root 120 Dec 28 14:34 cronjob_bandit24
-rw-r--r-- 1 root root 190 Oct 31 13:21 popularity-contest
bandit22@bandit:/etc/cron.d$ cat cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit22@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
bandit22@bandit:/etc/cron.d$ whoami
bandit22
bandit22@bandit:/etc/cron.d$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:/etc/cron.d$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```
## Level 23 - Level 24
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!

NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…
```
bandit23@bandit:~$ cd /etc/cron.d
bandit23@bandit:/etc/cron.d$ ls -l
total 16
-rw-r--r-- 1 root root 120 Dec 28 14:34 cronjob_bandit22
-rw-r--r-- 1 root root 122 Dec 28 14:34 cronjob_bandit23
-rw-r--r-- 1 root root 120 Dec 28 14:34 cronjob_bandit24
-rw-r--r-- 1 root root 190 Oct 31 13:21 popularity-contest
bandit23@bandit:/etc/cron.d$ cat cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
bandit23@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
	echo "Handling $i"
	timeout -s 9 60 ./$i
	rm -f ./$i
    fi
done


bandit23@bandit:/etc/cron.d$ cd /var/spool/bandit24/
bandit23@bandit:/var/spool/bandit24$ echo '/bin/cat /etc/bandit_pass/bandit24 > /tmp/b24' > b24pass
bandit23@bandit:/var/spool/bandit24$ chmod +x b24pass
bandit23@bandit:/var/spool/bandit24$ ls -l b24pass
-rwxrwxr-x 1 bandit23 bandit23 46 Apr 16 10:57 b24pass
bandit23@bandit:/var/spool/bandit24$ cat b24pass
/bin/cat /etc/bandit_pass/bandit24 > /tmp/b24
```
Wait for few seconds.
```
bandit23@bandit:/var/spool/bandit24$ cat /tmp/b24
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```
## Level 24 - Level 25
A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

```
bandit24@bandit:~$ nc localhost 30002
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 1234
Wrong! Please enter the correct pincode. Try again.
^C
```
```
for pin in {0..9}{0..9}{0..9}{0..9};do echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $pin | nc localhost 30002;done
```
The above method will definetely find the correct pin eventually, but it takes a lot of time.

```
bandit24@bandit:~$ for pin in {0..9}{0..9}{0..9}{0..9};do echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $pin;done > /tmp/blah
bandit24@bandit:~$
bandit24@bandit:~$ cat /tmp/blah | nc localhost 30002 > /tmp/result
bandit24@bandit:~$ grep -v Wrong /tmp/result
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

Exiting.
bandit24@bandit:~$
```
## Level 25 - Level 26
Logging in to bandit26 from bandit25 should be fairly easy. The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.
```
bandit25@bandit:~$ ls -l               
total 4
-r-------- 1 bandit25 bandit25 1679 Dec 28 14:34 bandit26.sshkey
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost 
Could not create directory '/home/bandit25/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit25/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames
               
      ,----..            ,----,          .---. 
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' ' 
  |   :  | ; | ' ;    |.';  ; ;   \  \;      : 
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ; 
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"  
     \   \ .'        ;   |.'       \   \ ;     
  www. `---` ver     '---' he       '---" ire.org     
               
              
Welcome to OverTheWire!
...................
...................snipped

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us through IRC on
  irc.overthewire.org #wargames.

  Enjoy your stay!

  _                     _ _ _   ___   __  
 | |                   | (_) | |__ \ / /  
 | |__   __ _ _ __   __| |_| |_   ) / /_  
 | '_ \ / _` | '_ \ / _` | | __| / / '_ \ 
 | |_) | (_| | | | | (_| | | |_ / /| (_) |
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/ 
Connection to localhost closed.
bandit25@bandit:~$
```
The connection closes as soon as the banner is printed out. Let us examine further.
```
bandit25@bandit:~$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit25@bandit:~$     
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
bandit25@bandit:~$
```
So, the connection is closed as soon as `more ~/text.txt` is run. **more** is a filter for paging through text **one screenful** at a time. so if we were to login from a terminal much smaller - two or three lines height - terminal, the more command would pause in between displaying the banner giving us a chance to escape this tight scenario.
```
enter vi by pressing v.
press escape key and type ":e /etc/bandit_pass/bandit26" (without quotes)
5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
```
