---
title: "Walk-through of Retro from TryHackMe"
header:
  teaser: /assets/images/2021-05-08-17-35-50.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Windows
  - WordPress
---

## Machine Information

![retro](/assets/images/2021-05-08-17-35-50.png)

Retro is a hard difficulty room on TryHackMe. An initial scan reveals just two ports, a WordPress site on port 80, and RDP open on 3389. We find credentials hidden in the WordPress site which lets us logon on to a remote desktop. From there we discover an exploit in the recycle bin that we use to escalate to administrator.

<!--more-->

Skills required are basic enumeration and file manipulation. Skills learned are researching and using exploits.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Hard - Retro](https://tryhackme.com/room/retro) |
| Machine Release Date | 2nd January 2022 |
| Date I Completed It | 5th May 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with nmap. However, note that on this box you cannot use ping which means the standard nmap command won't work. Instead you need to use the -Pn switch to disable host discovery:

```text
┌──(root💀kali)-[~/thm/retro]
└─# ports=$(nmap -p- -Pn --min-rate=1000 -T4 10.10.197.9 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

┌──(root💀kali)-[~/thm/retro]
└─# nmap -p$ports -Pn -sC -sV -oA retro 10.10.197.9
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-04 21:08 BST
Nmap scan report for retro.thm (10.10.197.9)
Host is up (0.043s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2021-05-04T20:08:41+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2021-05-03T20:04:25
|_Not valid after:  2021-11-02T20:04:25
|_ssl-date: 2021-05-04T20:08:42+00:00; 0s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.23 seconds
```

From the scan we can see we're dealing with a Window 2016 server with IIS 10.0 installed. There looks to be just a website on port 80 and RDP on port 3389.

First add the machine IP to our hosts file:

```text
┌──(root💀kali)-[~/thm/retro]
└─# echo 10.10.197.9 retroweb.thm >> /etc/hosts
```

Let's look at the website:

![retro-web](/assets/images/2021-05-04-21-16-11.png)

A standard IIS landing page, which means no default website. Fire up gobuster and see if we can find anything hidden:

```text
┌──(root💀kali)-[~/thm/retro]
└─# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://retroweb.thm
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://retroweb.thm
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/05/04 21:07:54 Starting gobuster in directory enumeration mode
===============================================================
http://retroweb.thm/retro      (Status: 301) [Size: 148] [--> http://retroweb.thm/retro/]
http://retroweb.thm/Retro      (Status: 301) [Size: 148] [--> http://retroweb.thm/Retro/]
===============================================================
2021/05/04 21:09:15 Finished
===============================================================
```

## WordPress Site

We've found a subfolder called retro, let's have a look:

![retro-fanatics](/assets/images/2021-05-04-21-23-27.png)

Here we find a WordPress site hosting a selection of interesting articles about retro games.

How do I know it's WordPress? I have Wappalyzer installed in Kali:

![retro-wappalyzer](/assets/images/2021-05-04-21-31-50.png)

And also there's a login link that gives it away:

![retro-login](/assets/images/2021-05-04-21-34-02.png)

I notice all posts are by someone called Wade, clicking on him shows us a list of all his entries, and one recent comment:

![retro-wade-posts](/assets/images/2021-05-04-21-28-51.png)

Looking at the post he commented on we see something suspicious:

![retro-comment](/assets/images/2021-05-04-21-36-54.png)

The obvious thing to try next is logging in as Wade with this password:

![retro-wade-login](/assets/images/2021-05-04-21-38-25.png)

This works and we get to the standard admin dashboard:

![retro-admin](/assets/images/2021-05-04-21-39-53.png)

In the spirit of following the intended path for this room I'm going to stop at this point. With access to the admin panel we could go down the route of replacing one of the files within WordPress with a reverse shell. I've covered this before in another TryHackMe room called [Internal](https://pencer.io/ctf/ctf-thm-internal/). We could also use Meterpreter to get a shell, which I've covered previously on a HackTheBox server called [Spectra](https://pencer.io/ctf/ctf-htb-spectra).

## Remote Desktop

Instead let's go back to our list of open ports we found earlier, and review what we have. The credentials found could also be useful on port 3389 to log on to a remote desktop. Kali has an RDP client built in so let's try it:

```text
┌──(root💀kali)-[~/thm/retro]
└─# xfreerdp /v:retroweb.thm /u:wade /p:'<HIDDEN>' +clipboard /dynamic-resolution

[22:00:31:849] [1333:1334] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[22:00:31:849] [1333:1334] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[22:00:31:850] [1333:1334] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[22:00:31:850] [1333:1334] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[22:00:31:850] [1333:1334] [INFO][com.freerdp.client.common.cmdline] - loading channelEx drdynvc
[22:00:31:174] [1333:1334] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
[22:00:31:211] [1333:1334] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting error state
[22:00:31:211] [1333:1334] [INFO][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state
<SNIP>
[22:00:32:431] [1333:1334] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[22:00:32:431] [1333:1334] [WARN][com.freerdp.crypto] - CN = RetroWeb
[22:00:34:678] [1333:1334] [INFO][com.winpr.sspi.NTLM] - VERSION ={
[22:00:34:678] [1333:1334] [INFO][com.winpr.sspi.NTLM] -        ProductMajorVersion: 6
[22:00:34:678] [1333:1334] [INFO][com.winpr.sspi.NTLM] -        ProductMinorVersion: 1
[22:00:34:678] [1333:1334] [INFO][com.winpr.sspi.NTLM] -        ProductBuild: 7601
[22:00:34:678] [1333:1334] [INFO][com.winpr.sspi.NTLM] -        Reserved: 0x000000
[22:00:34:678] [1333:1334] [INFO][com.winpr.sspi.NTLM] -        NTLMRevisionCurrent: 0x0F
```

We find that the credentials are indeed valid allowing us to log on to the desktop:

![retro-desktop](/assets/images/2021-05-06-22-37-18.png)

Before we move on lets grab that user flag:

![retro-user](/assets/images/2021-05-06-22-38-58.png)

## CVE-2019-1388 Exploit

After an initial look around I find two interesting things. Firstly there is a file in the recycle bin:

![retro-hhupd](/assets/images/2021-05-06-22-44-07.png)

Secondly looking at the browsing history in Chrome shows Dark searched for and visited sites related to CVE-2019-1388 and how to patch against it:

![retro-chrome](/assets/images/2021-05-08-16-42-29.png)

He also saved a bookmark to one, so seems like he was interested in it for some reason.

I found [this](https://www.zerodayinitiative.com/blog/2019/11/19/thanksgiving-treat-easy-as-pie-windows-7-secure-desktop-escalation-of-privilege) post that explains how you can exploit that vulnerability:

```text
The bug is found in the UAC (User Account Control) mechanism. By default, Windows shows all UAC prompts on a separate desktop known as the Secure Desktop.
The prompts themselves are produced by an executable named consent.exe, running as NT AUTHORITY\SYSTEM and having an integrity level of System.
```

A quick search found [this video](https://www.youtube.com/watch?v=3BQKpPNlTSo) on YouTube. It shows how to use the hhupd file we found in the recycle bin to get us an administrator command prompt.

This looks to be the intended path, so let's give it a go. First run hhupd as administrator:

![retro-hhupd](/assets/images/2021-05-08-16-22-38.png)

On the dialog that opens click on the "Show information about the publishers certificate" link:

![retro-show-info](/assets/images/2021-05-08-16-21-47.png)

On the certificate dialog click on the Verisign link in the Issued by area:

![retro-cert](/assets/images/2021-05-08-16-21-33.png)

You may get this box appear, if you do I couldn't find a way around it:

![retro-default-app](/assets/images/2021-05-08-16-21-14.png)

If you don't then Internet Explorer will open with the verisign URL visible:

![retro-verisign-url](/assets/images/2021-05-08-16-26-50.png)

If the Set up Internet Explorer 11 box appears just close it.

There's no internet connection from this server so IE will fail to get to the site. Now you can press CTRL+S to open the Save Webpage dialog:

![retro-no-internet](/assets/images/2021-05-08-16-27-21.png)

Press Ok to get rid of the error message. Then in the file name box put the path like so:

![retro-path-to-cmd](/assets/images/2021-05-08-16-27-58.png)

This let's you see all files in the System32 folder. Find cmd, right click it, then chose Open:

![retro-cmd](/assets/images/2021-05-08-16-29-07.png)

We now have a command prompt as system:

![retro-cmd-prompt](/assets/images/2021-05-08-16-29-27.png)

Time to get the root flag:

![retro-root-flag](/assets/images/2021-05-08-16-30-10.png)

That was the intended way to complete this room, however there is another way.

## CVE-2017-0213 Exploit

There is another exploit that works on this version of Windows Server 2016. In fact this one is much easier to use. Rapid7 has an article [here](https://www.rapid7.com/db/vulnerabilities/msft-cve-2017-0213/) that explains it:

```text
An elevation of privilege exists in Windows COM Aggregate Marshaler. An attacker who successfully exploited the vulnerability could run arbitrary code with elevated privileges
```

If you search you'll find a few proof of concepts available for this. Let's get one:

```text
┌──(root💀kali)-[~/thm/retro]
└─# wget https://github.com/WindowsExploits/Exploits/raw/master/CVE-2017-0213/Binaries/CVE-2017-0213_x64.zip                                              
--2021-05-08 17:02:03--  https://github.com/WindowsExploits/Exploits/raw/master/CVE-2017-0213/Binaries/CVE-2017-0213_x64.zip
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/WindowsExploits/Exploits/master/CVE-2017-0213/Binaries/CVE-2017-0213_x64.zip [following]
--2021-05-08 17:02:03--  https://raw.githubusercontent.com/WindowsExploits/Exploits/master/CVE-2017-0213/Binaries/CVE-2017-0213_x64.zip
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 83287 (81K) [application/zip]
Saving to: ‘CVE-2017-0213_x64.zip’

CVE-2017-0213_x64.zip    100%     [==================>]  81.33K  --.-KB/s    in 0.02s   

2021-05-08 17:02:04 (3.45 MB/s) - ‘CVE-2017-0213_x64.zip’ saved [83287/83287]
```

Make sure you get a x64 version. Now unzip it and start a webserver so we can get to it:

```text
┌──(root💀kali)-[~/thm/retro]
└─# unzip CVE-2017-0213_x64.zip
Archive:  CVE-2017-0213_x64.zip
  inflating: CVE-2017-0213_x64.exe   

┌──(root💀kali)-[~/thm/retro]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Switch back to the desktop on the server and use certutil to pull the file over:

![retro-certutil](/assets/images/2021-05-08-17-07-48.png)

Now run the exploit:

![retro-run-exploit](/assets/images/2021-05-08-17-06-56.png)

A separate command prompt opens and we are system:

![retro-system-again](/assets/images/2021-05-08-17-09-08.png)

Now wasn't that much easier!

I hope you enjoyed this room as much as I did. For now we are all done. See you next time.
