---
title: "Walk-through of StreamIO from HackTheBox"
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
  - Windows
  - SQLMap
  - Feroxbuster
---

[StreamIO](https://www.hackthebox.com/home/machines/profile/474) is a medium level machine by [JDgodd](https://www.hackthebox.com/home/users/profile/481778) and [nikk37](https://www.hackthebox.com/home/users/profile/247264) on [HackTheBox](https://www.hackthebox.com/home). It's A Windows box that focuses on recon and enumeration, with an interesting mix of tools and techniques used to complete it.

<!--more-->

## Machine Information

![streamio](/assets/images/2022-06-26-21-42-13.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - StreamIO](https://www.hackthebox.com/home/machines/profile/474) |
| Machine Release Date | 4th June 2022 |
| Date I Completed It | 3rd July 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Protected Content

At the time of publication this box is live so the walkthrough is password protected [here](/assets/pdfs/2022-06-30-ctf-htb-streamio.pdf).

The password for this is the Administrator password hash which looks like this:

```text
Administrator:500:aad   <HIDDEN>  767:::
```
