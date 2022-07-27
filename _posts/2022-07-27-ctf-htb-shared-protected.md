---
title: "Walk-through of Shared from HackTheBox"
header:
  teaser: /assets/images/2022-07-25-16-46-47.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - SQLi
  - JohnTheRipper
  - Pspy64
  - IPython
  - CVE-2022-21699
  - Redis
  - CVE-2022-0543
---

[Shared](https://www.hackthebox.com/home/machines/profile/483) is a medium level machine by [Nauten](https://www.hackthebox.com/home/users/profile/27582) on [HackTheBox](https://www.hackthebox.com/home). This Linux box explores using recent publicly disclosed vulnerabilities against a couple of well known applications.

<!--more-->

## Machine Information

![shared](/assets/images/2022-07-25-16-46-47.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Shared](https://www.hackthebox.com/home/machines/profile/483) |
| Machine Release Date | 23rd July 2022 |
| Date I Completed It | 27th July 2022 |
| Distribution Used | Kali 2022.2 – [Release Info](https://www.kali.org/blog/kali-linux-2022-2-release/) |

## Protected Content

At the time of publication this box is live so the walkthrough is password protected [here](/assets/pdfs/2022-07-27-ctf-htb-shared.pdf).

The password for this is the root password hash which looks like this:

```text
root:$y$j  <<HIDDEN>>  :7:::
```
