---
title: "Walk-through of Introduction To Django from TryHackMe"
header:
  teaser: /assets/images/2020-06-07-22-39-46.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - CTF
tags:
  - THM
  - CTF

  - Linux
---

## Machine Information

![django](/assets/images/2020-06-07-22-39-46.png)

Introduction Django is a beginner level room, aimed at giving you a good understanding of why it's an important area to gain knowledge in. Skills required are a basic level of Linux knowledge and an ability to enumerate it's file system. Skills learned are installing Django and creating simple applications with it.
<!--more-->

| Details |  |
| --- | --- |
| Hosting Site | [TryHackMe](https://tryhackme.com/) |
| Link To Machine | [THM - Medium - Introduction To Django](https://tryhackme.com/room/django) |
| Machine Release Date | 27th May 2020 |
| Date I Completed It | 8th June 2020 |
| Distribution used | Kali 2020.1 – [Release Info](https://www.kali.org/releases/kali-linux-2020-1-release/) |

## Task 1

This is an introduction to Django and the room. You don't need to answer and questions here.

## Task 2 - Getting Started

First need to install Django if it isn't already there:

```text
root@kali:~# pip3 install Django==2.2.12
Collecting Django==2.2.12
  Downloading Django-2.2.12-py3-none-any.whl (7.5 MB)
     |████████████████████████████████| 7.5 MB 2.5 MB/s
Requirement already satisfied: sqlparse in /usr/lib/python3/dist-packages (from Django==2.2.12) (0.2.4)
Requirement already satisfied: pytz in /usr/lib/python3/dist-packages (from Django==2.2.12) (2019.3)
Installing collected packages: Django
  Attempting uninstall: Django
    Found existing installation: Django 1.11.23
    Not uninstalling django at /usr/lib/python3/dist-packages, outside environment /usr
    Can't uninstall 'Django'. No files were found to uninstall.
Successfully installed Django-2.2.12
```

Starting a new project creates a few files and a folder with some configuration files inside:

```text
root@kali:~/thm/django# django-admin startproject pencer_project
root@kali:~/thm/django# cd pencer_project
root@kali:~/thm/django/pencer_project# ls
manage.py  pencer_project
```

Migrations are Django’s way of propagating changes you make to your application into your database schema:

```text
root@kali:~/thm/django/pencer_project# python3 manage.py migrate
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, sessions
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying admin.0003_logentry_add_action_flag_choices... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying auth.0009_alter_user_last_name_max_length... OK
  Applying auth.0010_alter_group_name_max_length... OK
  Applying auth.0011_update_proxy_permissions... OK
  Applying sessions.0001_initial... OK
```

If we check the project folder we see a new file called db.sqlite3 has appeared, which is where your changes have been written to by the migrate command:

```text
root@kali:~/thm/django/pencer_project# ls
db.sqlite3  manage.py  pencer_project
```

In the project folder we see the manage.py script, here's what the docs say about it:

```text
Manage.py is automatically created in each Django project. It does the same thing as django-admin but also sets the DJANGO_SETTINGS_MODULE environment variable so that it points to your project’s settings.py file.
```

So we've created our project, now we need to start it. To do that we use manage.py from with the project folder. Here's what the docs say about using the runserver command:

```text
Starts a lightweight development Web server on the local machine. By default, the server runs on port 8000 on the IP address 127.0.0.1. You can pass in an IP address and port number explicitly.
```

We do this now to get our web application running:

```text
root@kali:~/thm/django/pencer_project# python3 manage.py runserver
Watching for file changes with StatReloader
Performing system checks...
System check identified no issues (0 silenced).
June 02, 2020 - 13:18:27
Django version 2.2.12, using settings 'pencer_project.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.
```

### Question 2.2

If you browse to your loopback address you can see the default site:

![django_success](/assets/images/2020-06-07-22-48-32.png)

If you want this dev server to be visible on the local network you can use your actual IP address, or 0.0.0.0. If we try that now we get this:

![django_disallowed](/assets/images/2020-06-07-22-49-07.png)

If you do want to use 0.0.0.0 then you need to edit the settings file:

```text
root@kali:~/thm/django/pencer_project/pencer_project# nano settings.py
```

Change it to look like this:

![settings.py](/assets/images/2020-06-07-22-49-42.png)

Now start the server again:

```text
root@kali:~/thm/django/pencer_project# python3 manage.py runserver 0.0.0.0:8000
Watching for file changes with StatReloader
Performing system checks...
System check identified no issues (0 silenced).
June 02, 2020 - 13:22:06
Django version 2.2.12, using settings 'pencer_project.settings'
Starting development server at http://0.0.0.0:8000/
Quit the server with CONTROL-C.
```

Now browse to the site on 0.0.0.0 again:

![django_success](/assets/images/2020-06-07-22-50-38.png)

This should give you enough information to answer Task 2 Question 2.

### Question 2.1

Next we can create an admin user:

```text
root@kali:~/thm/django/pencer_project# python3 manage.py createsuperuser
Username (leave blank to use 'root'):
Email address:
Password:
Password (again):
The password is too similar to the username.
This password is too short. It must contain at least 8 characters.
Bypass password validation and create user anyway? [y/N]: y
Superuser created successfully.
```

Now that's created we can browse to the admin site, which is the IP and port you're using, with /admin on the end:

![django_admin](/assets/images/2020-06-07-22-51-44.png)

Once authenticated you'll see the admin section:

![django_admin_login](/assets/images/2020-06-07-22-52-44.png)

Now we have our project set up, an admin user ready to manage it, so we can create our first application. There's a good tutorial here if you want to learn more [here.](https://docs.djangoproject.com/en/3.0/intro/tutorial01/)

For now we just need to use manage.py again to create our application:

```text
root@kali:~/thm/django/pencer_project# python3 manage.py startapp pencer_app
```

A folder is created with a few configuration files:

```text
root@kali:~/thm/django/pencer_project# cd pencer_app
root@kali:~/thm/django/pencer_project/pencer_app# ls
admin.py  apps.py  __init__.py  migrations  models.py  tests.py  views.py
```

This should give you enough information to answer Task 2 Question 1.

## Task 3 - Creating A Website

Now we need to edit our settings file to add the new app in:

```text
root@kali:~/thm/django/pencer_project/pencer_app# cd ..
root@kali:~/thm/django/pencer_project# cd pencer_project
root@kali:~/thm/django/pencer_project/pencer_project# nano settings.py
```

And now we need to edit our url file:

```text
root@kali:~/thm/django/pencer_project/pencer_project# nano urls.py
```

Finally we need to edit the views file:

```text
root@kali:~/thm/django/pencer_project/pencer_app# nano views.py
```

Now we can start our server again:

```text
root@kali:~/thm/django/spen/pencer_app# cd ..
db.sqlite3  Forms  manage.py  pencer_app

root@kali:~/thm/django/spen# python3 manage.py runserver
Watching for file changes with StatReloader
Performing system checks...
System check identified no issues (0 silenced).
June 02, 2020 - 13:47:25
Django version 2.2.12, using settings 'pencer_project.settings'
Starting development server at http://0.0.0.0:8000/
Quit the server with CONTROL-C.
```

Now if we browse to our new app we can see it working:

![django_pencer_app](/assets/images/2020-06-07-22-53-51.png)

## Task 4 - Concluding

Now you've worked through the previous tasks you can visit [here.](https://github.com/Swafox/Django-example) This gives example files based on what you've done, and will help you answer Task 4 :

![django_github_example](/assets/images/2020-06-07-22-54-32.png)

## Task 5 - CTF

We know from the lessons that we should look on port 8000, but viewing the website we get this:

![django_disallowed](/assets/images/2020-06-07-22-55-10.png)

We are given these creds to ssh on to box:

Username: django-admin

Password: roottoor1212

Let's get on there and add our IP to the config file:

```text
root@kali:~# ssh django-admin@10.10.44.132
The authenticity of host '10.10.44.132 (10.10.44.132)' can't be established.
ECDSA key fingerprint is SHA256:6e2cPhl+76hmwqPelHGq0T5KXqFu4cuyptr8miKD2cA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.44.132' (ECDSA) to the list of known hosts.
django-admin@10.10.44.132's password:
Permission denied, please try again.
django-admin@10.10.44.132's password:
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
django-admin@py:~$
```

Find the settings file and edit it:

```text
jango-admin@py:~$ ls
messagebox
django-admin@py:~$ cd messagebox/
django-admin@py:~/messagebox$ ls
db.sqlite3  lmessages  manage.py  messagebox
django-admin@py:~/messagebox$ cd messagebox/
django-admin@py:~/messagebox/messagebox$ ls
home.html  __init__.py  __pycache__  settings.py  urls.py  views.py  wsgi.py
django-admin@py:~/messagebox/messagebox$ nano settings.py
```

Add our IP:

![settings.py](/assets/images/2020-06-07-22-56-19.png)

Now if we visit the site we see this:

![message_box](/assets/images/2020-06-07-22-56-49.png)

Clicking on Messages gets us here:

![message_1](/assets/images/2020-06-07-22-57-34.png)

Reading through there is nothing obvious of interest, at the bottom we see a button but clicking it just gives an error:

![button_error](/assets/images/2020-06-07-22-58-21.png)

Looking at the source we can see it's fake:

![source_fake](/assets/images/2020-06-07-22-58-59.png)

So nothing obvious on the site, we also know about the admin section, let's try that:

![django_login_fail](/assets/images/2020-06-07-22-59-38.png)

The creds we have don't work, but we are on the box and know how to add a superuser, so let's do that:

```text
django-admin@py:~/messagebox/messagebox$ cd ..
django-admin@py:~/messagebox$ ls
db.sqlite3  lmessages  manage.py  messagebox
django-admin@py:~/messagebox$ python3 manage.py createsuperuser
Username (leave blank to use 'django-admin'): pencer
Email address:
Password:
Password (again):
The password is too similar to the username.
This password is too short. It must contain at least 8 characters.
Bypass password validation and create user anyway? [y/N]: y
Superuser created successfully.
```

Now we can get in with our new account:

![django_login_success](/assets/images/2020-06-07-23-00-34.png)

Looking at users we get our first flag:
***EDIT PIC***
![django_users](/assets/images/2020-06-07-23-01-04.png)

There is also an interesting user called StrangeFox, with a link to a pastebin site. Let's see what we find there:

![pastebin](/assets/images/2020-06-07-23-01-46.png)

Use hash-identifier to see what we have:

```text
root@kali:~# hash-identifier C06029563B2765020613F5BF79FC528344FFA039EF1483D0C390786D8010C630
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
Possible Hashs:
[+] SHA-256
[+] Haval-256
Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
```

Possible SHA-256 hash, lots of online crackers, this was first hit when searching on Google:

![hash_cracker](/assets/images/2020-06-07-23-02-20.png)

Now we have a user and password let's try to switch to them:

```text
django-admin@py:~/messagebox$ su StrangeFox
Password:
StrangeFox@py:/home/django-admin/messagebox$ id
uid=1001(StrangeFox) gid=1001(StrangeFox) groups=1001(StrangeFox)
```

That worked, let's have a look around:

```text
StrangeFox@py:/home/django-admin/messagebox$ ls
db.sqlite3  lmessages  manage.py  messagebox

StrangeFox@py:/home/django-admin/messagebox$ ls /home
django-admin  StrangeFox

StrangeFox@py:/home/django-admin/messagebox$ ls /home/StrangeFox/
user.txt

StrangeFox@py:/home/django-admin/messagebox$ cat /home/StrangeFox/user.txt
THM{<<HIDDEN>>}
```

There's a hidden flag somewhere, let's have a further look around:

```text
StrangeFox@py:/$ ls
bin  boot  cdrom  dev  etc  home  initrd.img  initrd.img.old  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  swapfile  sys  tmp  usr  var  vmlinuz
StrangeFox@py:/$ cd home

StrangeFox@py:/home$ ls
django-admin  StrangeFox

StrangeFox@py:/home$ cd django-admin/

StrangeFox@py:/home/django-admin$ ls
messagebox

StrangeFox@py:/home/django-admin$ cd messagebox/

StrangeFox@py:/home/django-admin/messagebox$ ls
db.sqlite3  lmessages  manage.py  messagebox

StrangeFox@py:/home/django-admin/messagebox$ cd messagebox/
home.html  __init__.py  __pycache__  settings.py  urls.py  views.py  wsgi.py

StrangeFox@py:/home/django-admin/messagebox/messagebox$ ls -lsa
total 40
4 drwxr-xr-x 3 django-admin django-admin 4096 Jun  3 16:57 .
4 drwxr-xr-x 4 django-admin django-admin 4096 Jun  3 17:37 ..
8 -rw-r--r-- 1 django-admin django-admin 6148 Apr 10 13:23 .DS_Store
4 -rw-r--r-- 1 django-admin django-admin  412 Apr 10 14:10 home.html
0 -rw-r--r-- 1 django-admin django-admin    0 Apr 10 12:59 __init__.py
4 drwxr-xr-x 2 django-admin django-admin 4096 Jun  3 16:56 __pycache__
4 -rw-r--r-- 1 django-admin django-admin 3155 Jun  3 16:56 settings.py
4 -rw-r--r-- 1 django-admin django-admin  866 Apr 10 13:31 urls.py
4 -rw-r--r-- 1 django-admin django-admin   94 Apr 10 13:32 views.py
4 -rw-r--r-- 1 django-admin django-admin  397 Apr 10 13:14 wsgi.py

StrangeFox@py:/home/django-admin/messagebox/messagebox$ cat home.html
        <center><p>Hi! Welcome back to your inbox. Seems like you got a new message!</p></center>
        <center><p>Check it out here:</p></center>
        <center><p><a href="/messages">Messages</a></p></center>
        <!-- Flag 3: THM{<<HIDDENN>>} -->
```

Found it! We could also have just searched like this:

```text
trangeFox@py:/$ grep -r 'THM' 2>/dev/null
home/django-admin/messagebox/messagebox/home.html:      <!-- Flag 3: THM{<<HIDDEN>>} -->
Binary file home/django-admin/messagebox/db.sqlite3 matches
home/StrangeFox/user.txt:THM{<<HIDDEN>>}
Binary file boot/initrd.img-4.15.0-20-generic matches
boot/config-4.15.0-20-generic:CONFIG_RWSEM_XCHGADD_ALGORITHM=y
boot/config-4.15.0-20-generic:CONFIG_SENSORS_THMC50=m
Binary file lib/udev/hwdb.bin matches
lib/udev/hwdb.d/20-OUI.hwdb: ID_OUI_FROM_DATABASE=ALGORITHMS SOFTWARE PVT. LTD.
lib/udev/hwdb.d/20-OUI.hwdb: ID_OUI_FROM_DATABASE=ALGORITHMICS LTD.
```

All done. See you next time.
