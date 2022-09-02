---
title: "Walk-through of Support from HackTheBox"
header:
  teaser: /assets/images/2022-08-06-16-10-57.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Windows
  - smbmap
  - dotPeek
  - Kerbrute
  - Ldapdomindump
  - Evil-WinRM
  - BloodHound
  - RBCD
  - Impacket
---

[Support](https://www.hackthebox.com/home/machines/profile/484) is an easy level machine by [0xdf](https://www.hackthebox.com/home/users/profile/4935) on [HackTheBox](https://www.hackthebox.com/home). This Windows box explores the risks of insecure permissions in an Active Directory environment.

<!--more-->

## Machine Information

![support](/assets/images/2022-08-06-16-10-57.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Support](https://www.hackthebox.com/home/machines/profile/484) |
| Machine Release Date | 30th July 2022 |
| Date I Completed It | August 2022 |
| Distribution Used | Kali 2022.2 – [Release Info](https://www.kali.org/blog/kali-linux-2022-2-release/) |

## Protected Content

At the time of publication this box is live so the walkthrough is password protected [here](/assets/pdfs/2022-08-10-ctf-htb-support.pdf).

The password for this is the administrator password hash which looks like this:

```text
Administrator:500:aad3  <<HIDDEN>>  26:::
```
