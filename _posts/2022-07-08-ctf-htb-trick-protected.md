---
title: "Walk-through of Trick from HackTheBox"
header:
  teaser: /assets/images/2022-07-04-22-43-40.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Dig
  - SQLMap
  - Fail2ban
---

[Trick](https://www.hackthebox.com/home/machines/profile/477) is an easy level machine by [Geiseric](https://www.hackthebox.com/home/users/profile/184611) on [HackTheBox](https://www.hackthebox.com/home). This Linux box focuses on web app and OS enumeration, and using SQLMap to dump data.

<!--more-->

## Machine Information

![trick](/assets/images/2022-07-04-22-43-40.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - Trick](https://www.hackthebox.com/home/machines/profile/477) |
| Machine Release Date | 18th June 2022 |
| Date I Completed It | 6th July 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Protected Content

At the time of publication this box is live so the walkthrough is password protected [here](/assets/pdfs/2022-07-08-ctf-htb-trick.pdf).

The password for this is the root password hash which looks like this:

```text
root:$6$l   <<HIDDEN>>   7:::
```
