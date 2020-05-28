---
title: "Walk-through of Anthem from TryHackMe"
header:
  teaser: /assets/images/2020-05-28-22-18-43.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - RDP
  - Windows
---

## Machine Information

![anthem](/assets/images/2020-05-28-22-18-43.png)

Anthem is a beginner level room which requires you to answer eight questions, and find six flags. Skills required are basic knowledge of Windows and enumerating ports and services. Skills learned are the importance of examining source code, and manipulating NTFS permissions.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Mr Anthem](https://tryhackme.com/room/anthem) |
| Machine Release Date | 15th May 2020 |
| Date I Completed It | 28th May 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Task 1 - Website Analysis

First start with a port scan:

```text
root@kali:~# ports=$(nmap -p- --min-rate=1000 -T4 10.10.83.110 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~# nmap -p$ports -v -sC -sV -oA anthem 10.10.83.110

Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-26 22:27 BST
Initiating Ping Scan at 22:27
Scanning 10.10.83.110 [4 ports]
Completed Ping Scan at 22:27, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:27
Completed Parallel DNS resolution of 1 host. at 22:27, 0.04s elapsed
Initiating SYN Stealth Scan at 22:27
Scanning 10.10.83.110 [15 ports]
Discovered open port 139/tcp on 10.10.83.110
Discovered open port 80/tcp on 10.10.83.110
Discovered open port 445/tcp on 10.10.83.110
Discovered open port 47001/tcp on 10.10.83.110
Discovered open port 3389/tcp on 10.10.83.110
Discovered open port 135/tcp on 10.10.83.110
Discovered open port 49668/tcp on 10.10.83.110
Discovered open port 49670/tcp on 10.10.83.110
Discovered open port 49664/tcp on 10.10.83.110
Discovered open port 49671/tcp on 10.10.83.110
Discovered open port 49666/tcp on 10.10.83.110
Discovered open port 49672/tcp on 10.10.83.110
Discovered open port 49665/tcp on 10.10.83.110
Discovered open port 49667/tcp on 10.10.83.110
Discovered open port 5985/tcp on 10.10.83.110
Completed SYN Stealth Scan at 22:27, 0.10s elapsed (15 total ports)
Initiating Service scan at 22:27
Scanning 15 services on 10.10.83.110
Completed Service scan at 22:28, 57.14s elapsed (15 services on 1 host)
Nmap scan report for 10.10.83.110
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2020-05-26T21:28:19+00:00
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Issuer: commonName=WIN-LU09299160F
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-04T22:56:38
| Not valid after:  2020-10-04T22:56:38
| MD5:   2814 61de 95b7 e9b5 4789 3027 7f1f 60d2
|_SHA-1: d47d 2a8f 6143 b820 936e 4120 cdd1 9ddc 5385 d285
|_ssl-date: 2020-05-26T21:29:15+00:00; -3s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  unknown
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  unknown
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  unknown
49672/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: -2s, deviation: 0s, median: -3s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2020-05-26T21:28:19
|_  start_date: N/A
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.27 seconds
           Raw packets sent: 19 (812B) | Rcvd: 16 (688B)
```

Lots of open ports. This Nmap scan will provide the answer to Task 1, questions 2 and 3.

Reading [this](https://support.google.com/webmasters/answer/6062608?hl=en) article will help with the answers to Task 1, questions 4 and 5.

![robots](/assets/images/2020-05-28-22-04-21.png)

The front page of the website gives you the domain for Task 1 question 6.

For Task 1 question 7 we are asked for the name of the administrator. Looking around we find this article:

![article](/assets/images/2020-05-28-22-05-08.png)

Searching the Internet for words from the song gets you to a Wikipedia page that reveals the name we are looking for.

For Task 1 question 8 we are asked for the administrators email address. Reading the other article gives us the naming convention used for a different user:

![another_article](/assets/images/2020-05-28-22-05-46.png)

We can easily work out what it will be based on the answer to question 7.

## Task 2 - Spot The Flags

Now we look for flags. The clue to their format is in the page where we enter them:

![tryhackme](/assets/images/2020-05-28-22-06-10.png)

Answer format shows three characters then opening brace. We can use this to help search the source code.

First download the whole site:

```text
root@kali:~/thm/anthem# wget --recursive http://10.10.83.110
root@kali:~/thm/anthem# cd 10.10.83.110/
```

Now we can grep through all the files for our search string:

```text
root@kali:~/thm/anthem/10.10.83.110# grep -R 'THM' .
./authors/jane-doe/index.html:        <input type="text" name="term" placeholder="Search...<<HIDDEN>> />
./authors/jane-doe/index.html:                <p>Website: <a href="<<HIDDEN>>}</a>
./tags:        <input type="text" name="term" placeholder="Search...<<HIDDEN />
./categories:        <input type="text" name="term" placeholder="Search...<<HIDDEN>> />
```

All four flags for this task are easily distinguishable in the output.

## Task 3 - Final Stage

Time to connect to the machine to get the user and root flags.

Kali has rdesktop built in so can use that, some info on it [here](https://www.tecmint.com/rdesktop-connect-windows-desktop-from-linux/).

```text
root@kali:~/thm/anthem/10.10.83.110# rdesktop -u SG 10.10.83.110
Autoselecting keyboard map 'en-us' from locale
ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);
 1. Certificate issuer is not trusted by this system.
     Issuer: CN=WIN-LU09299160F
Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection attempt will be aborted:
    Subject: CN=WIN-LU09299160F
     Issuer: CN=WIN-LU09299160F
 Valid From: Sat Apr  4 23:56:38 2020
         To: Sun Oct  4 23:56:38 2020
  Certificate fingerprints:
       sha1: d47d2a8f6143b820936e4120cdd19ddc5385d285
     sha256: 3902c5857bc89cd9546216953642364aa2fe8c9f4a35a7ca6ff035c4091adbe6
Do you trust this certificate (yes/no)? yes
```

Use password obtained earlier in r********s.txt file:

![win_login](/assets/images/2020-05-28-22-06-35.png)

First flag is on the desktop:

![desktop](/assets/images/2020-05-28-22-06-58.png)

Browse to C:, then change view settings to show hidden files/folders, reveals the backup folder:

![explorer](/assets/images/2020-05-28-22-07-27.png)

Inside is the file restore.txt, SG hasn't got the rights to view it, but has got rights to change security:

![file_perms](/assets/images/2020-05-28-22-07-49.png)

Add SG with read permissions, you can then open the file to reveal the password.

Now we have the administrator password, so we can open a new PowerShell window as administrator and enter the password we have just found. We can now navigate to the administrators desktop to find the root flag:

![powershell](/assets/images/2020-05-28-22-08-10.png)

All done. See you next time.
