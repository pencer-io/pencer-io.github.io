---
title: "Securing connectivity with a VPN on Kali"
header:
  teaser: /assets/images/2021-01-24-21-53-17.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Guides
tags:
  - Linux
  - Kali
  - FastVPN
  - OpenVPN
---

## Overview

![fastvpn](/assets/images/2021-11-10-15-44-59.png)

As hackers we frequently want to hide our activities and identity. Why use a VPN to help with this?

1. Hide your IP address to make sure no one sees your real location.
2. Encrypt the traffic between you and your ISP to prevent them snooping on your activity.
3. Secure your connectivity when using public Wi-Fi.
4. Unblock geo-fenced content and websites like Netflix etc.
5. Never access Tor or Darknet sites without a VPN or other method to protect your identity.

There's load of choices. You can host your own on Digital Ocean or similar platform. Or go with a trusted company. I've been with Namecheap for years without issues, and at only £0.74 per month it's cheap enough to not think about it.

See [here](https://www.namecheap.com/vpn/) for info from their site.

## FastVPN Configuration

After buying a plan login [here](https://vpn.ncapi.io/info) with your Namecheap account to find your FastVPN network credentials. Make a note then switch to Kali and download the server ovpn file bundle:

```sh
──(root💀kali)-[~]
└─# wget https://vpn.ncapi.io/groupedServerList.zip
--2021-11-10 15:14:55--  https://vpn.ncapi.io/groupedServerList.zip
Resolving vpn.ncapi.io (vpn.ncapi.io)... 34.213.250.17
Connecting to vpn.ncapi.io (vpn.ncapi.io)|34.213.250.17|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 222109 (217K) [application/zip]
Saving to: ‘groupedServerList.zip’

groupedServerList.zip    100%[==================>] 216.90K   402KB/s  in 0.5s    

2021-11-10 15:14:57 (402 KB/s) - ‘groupedServerList.zip’ saved [222109/222109]
```

The bundle contains all of the different servers around the world that you can connect to. Let's unzip them:

```sh
┌──(root💀kali)-[~]
└─# unzip groupedServerList.zip 
Archive:  groupedServerList.zip
   creating: tcp/
  inflating: tcp/NCVPN-AE-Dubai-TCP.ovpn  
  inflating: tcp/NCVPN-AL-Tirana-TCP.ovpn  
<SNIP> 
  inflating: tcp/NCVPN-US-Seattle-TCP.ovpn  
  inflating: tcp/NCVPN-ZA-Johannesburg-TCP.ovpn  
   creating: udp/
  inflating: udp/NCVPN-AE-Dubai-UDP.ovpn  
  inflating: udp/NCVPN-AL-Tirana-UDP.ovpn  
<SNIP>
  inflating: udp/NCVPN-US-Seattle-UDP.ovpn  
  inflating: udp/NCVPN-ZA-Johannesburg-UDP.ovpn  
```

Once unzipped you'll find 80 different servers you can connect to over TCP and the same 80 you can connect to over UDP.

Why have the choice between TCP and UDP? Here's a table from [this](https://nordvpn.com/blog/tcp-or-udp-which-is-better/) useful article from NordVPN:

![tcp vs udp](/assets/images/2021-11-10-16-49-36.png)

A summary is go with UDP, if you have problems try switching to TCP.

Let's make a folder and move our files to safety:

```sh
┌──(root💀kali)-[~]
└─# mkdir -p /etc/openvpn && mv tcp /etc/openvpn && mv udp /etc/openvpn && rm -f groupedServerList.zip
```

Now we can connect to a server. I wrote this quick Bash script to randomly pick a VPN server to connect to instead of the same one each time:

```sh
┌──(root💀kali)-[~]
└─# cat vpn.sh
#!/bin/bash
user="CHANGE-ME"
filepath="/etc/openvpn/udp/"
echo -n "Enter password to connect to VPN: "; read password
echo "$user\n$password" > vpn.txt
ls $filepath | sort -R | tail -n1 | while read file; do
    echo -n "Connecting to: "; echo $file    
    openvpn --config $filepath$file --auth-user-pass vpn.txt --daemon > /dev/null
    rm vpn.txt; sleep 3
    echo -n "VPN connected. External IP now: "; curl -s https://ipinfo.io/ip
done
```

Just change the user to your own, and filepath if you didn't use the above command to move the ovpn files to /etc/openvpn. Now run it:

```sh
┌──(root💀kali)-[~]
└─# ./vpn.sh    
Enter password to connect to VPN: <HIDDEN>
Connecting to: NCVPN-NO-Oslo-UDP.ovpn
Connected IP: 84.247.50.249
```

We can also see the process running to confirm the VPN is connected:

```sh
┌──(root💀kali)-[~]
└─# ps aux | grep openvpn
root        6812  0.0  0.3  11208  6900 ?        Ss   22:09   0:00 openvpn --config /etc/openvpn/udp/NCVPN-NO-Oslo-UDP.ovpn --auth-user-pass vpn.txt --daemon
root        6924  0.0  0.1   6184  2244 pts/1    S+   22:09   0:00 grep --color=auto openvpn
```

If you want to stop the VPN then you can kill the process:

```sh
┌──(root💀kali)-[~]
└─# killall openvpn
```

Now we can run our script whenever we want to connect to a random VPN server any where in the world.
