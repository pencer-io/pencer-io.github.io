---
title: "Walk-through of Noter from HackTheBox"
header:
  teaser: /assets/images/2022-05-21-17-03-56.png
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
  - diff
---

Noter is a medium level machine by [kavigihan](https://www.hackthebox.com/home/users/profile/389926) on [HackTheBox](https://www.hackthebox.com/home).

<!--more-->

## Machine Information

![noter](/assets/images/2022-05-21-17-03-56.png)

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Noter](https://www.hackthebox.com/home/machines/profile/467) |
| Machine Release Date | 7th May 2022 |
| Date I Completed It | 22nd May 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Now Retired

This box has now been retired. The PDF is still available [here](/assets/pdfs/2022-05-24-ctf-htb-noter.pdf).

The password for this is the root users entry in the /etc/shadow file on the box which looks like this:

```text
root:$6$09RSjU3jIh/2JW1u$8jlcYzW5Oyzgh/TrlTPX5Wq2HMTA6zUooij/9j0.NIttTYp4x0h6wmq8chrcdtvNpZzHlHzwsI8GesOKI3NYn.:18991:0:99999:7:::
```

The full walk-through is now available [here](https://pencer.io/ctf/ctf-htb-noter) without a password.
