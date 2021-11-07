---
title: "CTF All The Things"
header:
  teaser: /assets/images/2021-10-13-21-39-10.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - 
  - 
  - 
---

![ctf](/assets/images/2021-10-13-21-39-10.png)

# Recon

## Gobuster

Install:

```text
apt-get install gobuster
```

Mode:

```text
gobuster dns -d <target domain> -w <wordlist>
gobuster dir -u <target url> -w <wordlist>
gobuster vhost -u <target url> -w <wordlist>
```

File type:

```text
gobuster dir -u <target url> -w <wordlist> -x .php
```

Ignore certificate errors:

```text
gobuster dir -u <target url> -w <wordlist> -k
```

Specify cookie:

```text
gobuster dir -u <target url> -w <wordlist> -c 'session=123456'
```

# Shell

## Upgrade

First job is to upgrade our terminal to something more useable:

Check if Python is available:

```text
www-data@writer:/$ which python
which python
www-data@writer:/$ which python3
which python3
/usr/bin/python3
```

Spawn proper session:

```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Ctrl+Z to background then set stty:

```sh
tomcat@seal:/var/lib/tomcat9$ ^Z
zsh: suspended  nc -nlvp 1337
┌──(root💀kali)-[~/htb/seal]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 1337
```

Sort terminal, check local first:

```sh
┌──(root💀kali)-[~/htb/writer]
└─# stty size          
52 237

┌──(root💀kali)-[~/htb/writer]
└─# echo $TERM                                                            
xterm-256color
```

Then set on box:

```sh
tomcat@seal:/var/lib/tomcat9$ export TERM=xterm
tomcat@seal:/var/lib/tomcat9$ stty rows 52 cols 237
```

## Bash wget

```sh
function __wget() {
    read proto server path <<<$(echo ${1//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
 
    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
    (while read line; do
        [[ "$line" == $'\r' ]] && break
    done && cat) <&3
    exec 3>&-
}
```