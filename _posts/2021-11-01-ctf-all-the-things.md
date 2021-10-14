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
