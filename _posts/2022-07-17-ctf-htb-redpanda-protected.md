---
title: "Walk-through of RedPanda from HackTheBox"
header:
  teaser: /assets/images/2022-07-14-23-06-20.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - SSTI
  - XXE
  - pspy64
---

[RedPanda](https://www.hackthebox.com/home/machines/profile/481) is an easy level machine by [Woodenk](https://www.hackthebox.com/home/users/profile/25507) on [HackTheBox](https://www.hackthebox.com/home). This Linux box focuses on a Java web application and a couple of OWASP favourite methods of exploiting it.

<!--more-->

## Machine Information

![redpanda](/assets/images/2022-07-14-23-06-20.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - RedPanda](https://www.hackthebox.com/home/machines/profile/481) |
| Machine Release Date | 9th July 2022 |
| Date I Completed It | 17th July 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Protected Content

At the time of publication this box is live so the walkthrough is password protected [here](/assets/pdfs/2022-07-17-ctf-htb-redpanda.pdf).

The password for this is the root password hash which looks like this:

```text
root:$6$H  <<HIDDEN>>  :7:::
```
