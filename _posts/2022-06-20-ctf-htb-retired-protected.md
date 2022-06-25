---
title: "Walk-through of Retired from HackTheBox"
header:
  teaser: /assets/images/2022-06-15-22-51-20.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - LFI
  - BOF
  - NX Enabled
  - RELRO
  - GDB
  - Peda
  - ROP
  - msfvenom
  - binfmt_rootkit
---

[Retired](https://www.hackthebox.com/home/machines/profile/456) is a medium level machine by [uco2KFh](https://www.hackthebox.com/home/users/profile/590762) on [HackTheBox](https://www.hackthebox.com/home). It focuses on binary exploitation and taking advantage of poorly designed scripts and services.

<!--more-->

## Machine Information

![retired](/assets/images/2022-06-15-22-51-20.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Retired](https://www.hackthebox.com/home/machines/profile/456) |
| Machine Release Date | 2nd April 2022 |
| Date I Completed It | 25th June 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Protected Content

At time of publication the box is live so walkthrough is password protected [here](/assets/pdfs/2022-06-20-ctf-htb-retired.pdf).

The password for this is the root users entry in the /etc/shadow file on the box which looks like this:

```text
root:$y$j   <<HIDDEN>>   7:::
```
