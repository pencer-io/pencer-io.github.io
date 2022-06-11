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

## Bash Port Enumeration

We can scan all ports like this:

```sh
i=1
max=65535
while [ $i -lt $max ]
do
    echo "Port: $i"
    nc -w 1 -v 172.17.0.1 $i </dev/null; echo $?
    true $(( i++ ))
done
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

## Bash mkdir & cd

```sh
mkcdir ()
{
    mkdir -p -- "$1" &&
      cd -P -- "$1"
}
```

## Look for active services

```sh
jennifer@admirertoo:~$ systemctl list-units --type=service
UNIT                               LOAD   ACTIVE SUB     DESCRIPTION                                                       
apache2.service                    loaded active running The Apache HTTP Server                                            
apache2@opencats.service           loaded active running The Apache HTTP Server                                            
apparmor.service                   loaded active exited  Load AppArmor profiles                                            
console-setup.service              loaded active exited  Set console font and keymap                                       
cron.service                       loaded active running Regular background program processing daemon                      
dbus.service                       loaded active running D-Bus System Message Bus                                          
fail2ban.service                   loaded active running Fail2Ban Service                                                  
getty@tty1.service                 loaded active running Getty on tty1                                                     
hbase.service                      loaded active running HBase                                                             
ifup@eth0.service                  loaded active exited  ifup for eth0
```

## Evil-WinRM

Standard connection with user and password, also use SSL:
```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# evil-winrm -i 10.10.11.152 -u user123 -p 'password123' -S
```

Connect using certificate and private key, no user or password needed, use SSL:

```sh
┌──(root💀kali)-[~/htb/timelapse]
└─# evil-winrm -i 10.10.11.152 -c ./pfx.crt -k ./priv.key -p -u -S 
```
