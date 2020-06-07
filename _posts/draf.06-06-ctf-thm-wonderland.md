---
title: "Walk-through of Wonderland from TryHackMe"
header:
  teaser: /assets/images/2020-06-07-14-11-13.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - 
  - 
  - Linux
---

## Machine Information

![wonderland](/assets/images/2020-06-07-14-11-13.png)

Wonderland is a mid level room themed around Alice In Wonderland. Skills required are basic enumeration techniques of websites and Linux file systems. Skills learned are exploiting unquoted paths, and reverse engineering binaries to understand how they function.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Wonderland](https://tryhackme.com/room/wonderland) |
| Machine Release Date | 5th June 2020 |
| Date I Completed It | 6th June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:~/thm/wonderland# ports=$(nmap -p- --min-rate=1000 -T4 10.10.159.58 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/thm/wonderland# nmap -p$ports -v -sC -sV -oA wonderland 10.10.159.58
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-05 21:43 BST
Scanning 10.10.159.58 [4 ports]
Completed Ping Scan at 21:43, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:43
Completed Parallel DNS resolution of 1 host. at 21:43, 0.02s elapsed
Initiating SYN Stealth Scan at 21:43
Scanning 10.10.159.58 [2 ports]
Discovered open port 80/tcp on 10.10.159.58
Discovered open port 22/tcp on 10.10.159.58
Completed SYN Stealth Scan at 21:43, 0.06s elapsed (2 total ports)
Initiating Service scan at 21:43
Scanning 2 services on 10.10.159.58
Completed Service scan at 21:44, 11.36s elapsed (2 services on 1 host)
Nmap scan report for 10.10.159.58
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Follow the white rabbit.

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.99 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

Just two ports open, let's have a look at the website first:

![follow_the_rabbit](/assets/images/2020-06-07-14-14-59.png)

