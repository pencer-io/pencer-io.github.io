---
title: "Walk-through of Pickle Rick from TryHackMe"
header:
  teaser: /assets/images/2021-01-24-21-53-17.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - sudoers
  - ssh
  - Linux
---

## Machine Information

![pickle-rick](/assets/images/2021-01-24-21-53-17.png)

Pickle Rick is a nice and simple easy level Rick and Morty themed room. We exploit a web application to find three ingredients to help Rick make his potion to transform himself back in to a human from a pickle! Skills required are basic enumeration techniques of ports, services and Linux file systems.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Pickle Rick](https://tryhackme.com/room/picklerick) |
| Machine Release Date | 10th March 2019 |
| Date I Completed It | 24th January 2021 |
| Distribution Used | THM AttackBox – [Info](https://help.tryhackme.com/106142-my-machine/tryhackme-attack-machine) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@ip-10-10-19-48:~# nmap -sC -sV -Pn 10.10.24.11

Starting Nmap 7.60 ( https://nmap.org ) at 2021-01-24 17:34 GMT
Nmap scan report for ip-10-10-24-11.eu-west-1.compute.internal (10.10.24.11)
Host is up (0.0013s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1c:d4:64:ba:20:29:90:d3:6c:29:7f:e7:55:47:64:8e (RSA)
|   256 8b:95:2d:c8:b1:6d:de:e3:96:9e:a9:38:f7:97:40:a8 (ECDSA)
|_  256 e1:f3:1b:a8:02:49:d7:ec:63:cf:47:0b:06:2a:fe:3c (EdDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
MAC Address: 02:7B:7E:82:36:C3 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Just two open ports, lets start with the easy one by trying a web browser on port 80:

![pickle-hone](/assets/images/2021-01-24-17-38-40.png)

We get a static page with nothing obvious. Let's look at the source code by pressing CTRL+U:

![pickle-home-source](/assets/images/2021-01-24-17-39-34.png)

We have a username, that was easy!

With nothing else obvious here let's use Nikto to scan for web pages:

```text
root@ip-10-10-19-48:~# nikto -h 10.10.24.11
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.24.11
+ Target Hostname:    ip-10-10-24-11.eu-west-1.compute.internal
+ Target Port:        80
+ Start Time:         2021-01-24 17:44:07 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x426 0x5818ccf125686 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" retrieved but it does not contain any 'disallow' entries (which is odd).
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 6544 items checked: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-01-24 17:44:16 (GMT0) (9 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Nikto has found two files:

```text
+ "robots.txt" retrieved but it does not contain any 'disallow' entries (which is odd).
```

## Gaining Access

This sounds interesting, let's have a look here first:

![pickle-robots](/assets/images/2021-01-24-17-42-33.png)

Just one word, maybe that's a password to go with the username we found before.

The second page Nikto found was this one:

```text
+ /login.php: Admin login page/section found.
```

Seems like an obvious place to try the credentials we've found:

![pickle-login](/assets/images/2021-01-24-17-45-36.png)

## First Ingredient

The creds are correct and after login we end up here:

![pickle-commands](/assets/images/2021-01-24-17-47-49.png)

Trying any other section along the top gives this:

![pickle-rick](/assets/images/2021-01-24-17-47-22.png)

Back on the commands page let's see what we can do:

![pickle-ls](/assets/images/2021-01-24-17-48-36.png)

We can use ls to see what in the current directory, let's look at this first text file:

![pickle-supersecret](/assets/images/2021-01-24-17-49-36.png)

We find more is not allowed, let's try less instead:

![pickle-less](/assets/images/2021-01-24-17-50-02.png)

## Second Ingredient

We have the answer to our first question. Let's enter that and start looking for the next ingredient.

Let's have a look at that other interesting text file:

![pickle-clue](/assets/images/2021-01-24-17-51-45.png)

Ok, not very helpful!

There's a few areas you always start at when enumerating Linux boxes. I like to start with /home to see what users exist:

![pickle-userhome](/assets/images/2021-01-24-17-52-32.png)

Let's look in the rick folder:

![pickle-rickhome](/assets/images/2021-01-24-17-53-01.png)

A file called "second ingredients, with the contents we need for the second question:

![pickle-second](/assets/images/2021-01-24-17-53-38.png)

## Third Ingredient

Time to look for the last ingredient. With no more users to search, I should see what we can do to further enumerate.

First let's see what we can do with the account we've logged in with. Always try sudo -l to see your user can run:

![pickle-sudo](/assets/images/2021-01-24-17-56-34.png)

Well that was nice and easy! We can run any command as root using sudo. Let's first look in the root directory to see if there is anything interesting:

![pickle-roothome](/assets/images/2021-01-24-17-57-58.png)

Hmm, 3rd.txt looks to be what we wanted:

![pickle-third](/assets/images/2021-01-24-17-58-38.png)

Now we have our last ingredient.

As you can see this box was easily completed just using the browser and an insecure web application.

## Alternate Method To Root

If you wanted to get a reverse shell, you could do it this way with the help of ![Pentest Monkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

Check for php:

![pickle-php](/assets/images/2021-01-24-18-04-11.png)

Try the php reverse shell pentest monkey:

![pickle-phprev](/assets/images/2021-01-24-18-05-23.png)

We get a connection on our waiting netcat session, but it immediately disconnects:

```text
root@ip-10-10-19-48:~# nc -nlvp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 10.10.24.11 57488 received!
root@ip-10-10-19-48:~# 
```

Let's try another one:

![pickle-perl](/assets/images/2021-01-24-18-06-28.png)

Perl installed, set a nc listening, then try:
![pickle-perlrevshell](/assets/images/2021-01-24-18-07-55.png)

Back on attack box we have a connection to our waiting netcat session:

```text
root@ip-10-10-19-48:~# nc -nlvp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 10.10.24.11 57492 received!
/bin/sh: 0: can't access tty; job control turned off
```

Check who we are and then escalate:

```text
$ whoami
www-data
$ sudo /bin/sh
whoami
root
```

Now we have a reverse shell and have escalated to root so can complete the questions as before.

All done. See you next time.
