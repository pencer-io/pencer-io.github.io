---
title: "Walk-through of OpenSource from HackTheBox"
header:
  teaser: /assets/images/2022-05-27-16-29-49.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Flask
---

[OpenSource](https://www.hackthebox.com/home/machines/profile/471) is an easy level machine by [irogir](https://www.hackthebox.com/home/users/profile/476556) on [HackTheBox](https://www.hackthebox.com/home). It focuses on applications, containers and working with git.

<!--more-->

## Machine Information

![opensource](/assets/images/2022-05-27-16-29-49.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - OpenSource](https://www.hackthebox.com/home/machines/profile/471) |
| Machine Release Date | 21st May 2022 |
| Date I Completed It | 11th June 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Now Retired

This box has now been retired. The PDF is still available [here](/assets/pdfs/2022-05-30-ctf-htb-opensource.pdf).

The password for this is the root users entry in the /etc/shadow file on the box which looks like this:

```text
root:$6$5sA85UVX$HupltM.bMqXkLc269pHDk1lryc4y5LV0FPMtT3x.yUdbe3mGziC8aUXWRQ2K3jX8mq5zItFAkAfDgPzH8EQ1C/:19072:0:99999:7:::
```

The full walk-through is now available [here](https://pencer.io/ctf/ctf-htb-opensource/) without a password.
