---
title: "Things to do with Kali after first boot"
header:
  teaser: /assets/images/2020-07-26-17-20-20.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Cyber
tags:
  - Kali
  - Offensive Security
---

![kali-custom-desktop](/assets/images/2020-07-26-17-20-20.png)

## Kali Information

In **this previous guide** I went through the steps of importing the VirtualBox specific pre-built image of Kali 2020.2a. Now we will walk through a first boot of that virtual machine, and the things you will probably want to do before using it in earnest.

First thing to know is the old root:toor user and password have been replaced. We now have a non root user called kali, with a password of kali. Let's log in and get to our desktop:

![kali-login](/assets/images/2020-07-26-16-59-31.png)

Now we see our new xfce based desktop:

![kali-desktop](/assets/images/2020-07-26-17-21-37.png)

## Customising the desktop

The default theme is Kali-Dark, if you want to change it use the Appearance app from the menu:

![kali-appearance](/assets/images/2020-07-26-17-07-36.png)

There's a good article [here](https://www.offensive-security.com/kali-linux/kali-linux-customization) on customizing the new xcfe based Kali. There's also a good article [here](https://drasite.com/blog/Kali%202020.2%20desktop%20and%20theme%20updates) on the many new interface related changes in this version of Kali, including some info on additional desktop wallpapers.

## Adding sources to Kali

Before you start updating, you can optionally add the deb-src repository to your sources file. This lets you install programs from source and compile yourself later if you want to get a version different to the one packaged up in the normal kali-rolling repository. Let's open a terminal and edit the sources.list file:

```text
kali@kali:~$ sudo nano /etc/apt/sources.list
```

Looking at the file we see the deb-src one is commented out:
![kali-sources](/assets/images/2020-07-26-17-31-31.png)

Remove that comment and exit nano. There is more information [here](https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/) about the sources in Kali.

## Updating the system

Now let's get everything updated:

```text
kali@kali:~$ sudo apt-get update
Get:1 http://kali.download/kali kali-rolling InRelease [30.5 kB]
Get:2 http://kali.download/kali kali-rolling/contrib Sources [61.4 kB]
Get:3 http://kali.download/kali kali-rolling/main Sources [13.1 MB]
Get:4 http://kali.download/kali kali-rolling/non-free Sources [125 kB]
Get:5 http://kali.download/kali kali-rolling/main amd64 Packages [16.7 MB]
Get:6 http://kali.download/kali kali-rolling/non-free amd64 Packages [196 kB]
Get:7 http://kali.download/kali kali-rolling/contrib amd64 Packages [96.9 kB]
Fetched 30.3 MB in 3s (10.4 MB/s)
Reading package lists... Done
```

## Upgrading all packages

Now let's upgrade any software that has been updated since the Kali image was created. This takes a fair amount of time. When you're ready let's go:

```text
kali@kali:~$ sudo apt-get -y upgrade
Reading package lists... Done
Building dependency tree
Reading state information... Done
Calculating upgrade... Done
<<SNIP>>
The following packages will be upgraded:
  acl adwaita-icon-theme amass amass-common apparmor autopsy avahi-daemon axel base-files bind9-dnsutils bind9-host bind9-libs binutils
  binutils-common binutils-x86-64-linux-gnu bundler burpsuite busybox bzip2 ca-certificates clang-9 commix console-setup console-setup-linux
  <<SNIP>>
  vim-tiny virtualbox-guest-dkms
  virtualbox-guest-utils virtualbox-guest-x11 whatweb wifite wireless-regdb wpasupplicant wpscan xfce4-notifyd xfce4-taskmanager xfconf
  xserver-xorg-video-intel xterm xtightvncviewer xxd zsh zsh-common
587 upgraded, 0 newly installed, 0 to remove and 153 not upgraded.
Need to get 1,155 MB of archives.
After this operation, 136 MB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 base-files amd64 1:2020.3.1 [72.3 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 perl-modules-5.30 all 5.30.3-4 [2,806 kB]
<<SNIP>>
Setting up kali-linux-default (2020.3.10) ...
Processing triggers for libc-bin (2.30-8) ...
Processing triggers for systemd (245.4-3) ...
Processing triggers for mime-support (3.64) ...
Processing triggers for initramfs-tools (0.137) ...
update-initramfs: Generating /boot/initrd.img-5.5.0-kali2-amd64
Processing triggers for hicolor-icon-theme (0.17-2) ...
Processing triggers for ca-certificates (20200601) ...
Updating certificates in /etc/ssl/certs...
0 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
done.
Processing triggers for libgdk-pixbuf2.0-0:amd64 (2.40.0+dfsg-5) ...
```

## Upgrade the distribution

Now we can upgrade the distribution:

```text
kali@kali:~$ sudo apt-get dist-upgrade -Vy
[sudo] password for kali:
Reading package lists... Done
Building dependency tree
Reading state information... Done
Calculating upgrade... Done
The following packages were automatically installed and are no longer required:
   fonts-glyphicons-halflings (1.009~3.4.1+dfsg-1)
   <<SNIP>>
   ruby-did-you-mean (1.2.1-1)
Use 'sudo apt autoremove' to remove them.
The following packages will be REMOVED:
   lib32gcc1 (1:10-20200418-1)
   libapache2-mod-php7.3 (7.3.15-3)
   <<SNIP>>
   php7.3 (7.3.15-3)
   php7.3-cli (7.3.15-3)
   php7.3-common (7.3.15-3)
The following NEW packages will be installed:
   bsdextrautils (2.35.2-6)
   cabextract (1.9-3)
   <<SNIP>>
Processing triggers for man-db (2.9.3-2) ...
Processing triggers for dbus (1.12.20-1) ...
Processing triggers for shared-mime-info (1.15-1) ...
Processing triggers for postgresql-common (215) ...
supported-versions: WARNING! Unknown distribution: kali
debian found in ID_LIKE, treating as Debian
supported-versions: WARNING: Unknown Debian release: 2020.3
Building PostgreSQL dictionaries from installed myspell/hunspell packages...
  en_us
Removing obsolete dictionary files:
Processing triggers for fontconfig (2.13.1-4.2) ...
Processing triggers for kali-menu (2020.3.2) ...
Processing triggers for desktop-file-utils (0.26-1) ...
Processing triggers for mime-support (3.64) ...
Processing triggers for hicolor-icon-theme (0.17-2) ...
Processing triggers for libglib2.0-0:amd64 (2.64.3-2) ...
Processing triggers for php7.4-cli (7.4.5-1+b1) ...
Processing triggers for libapache2-mod-php7.4 (7.4.5-1+b1) ...
```

## Tidy up packages

Finally let's tidy up anything no longer needed:

```text
kali@kali:~$ sudo apt-get autoremove -y
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages will be REMOVED:
  fonts-glyphicons-halflings gir1.2-appindicator3-0.1 libappindicator3-1 libboost-iostreams1.67.0 libboost-system1.67.0 libboost-thread1.67.0
  libgdal26 libicu63 libpython3.7-minimal libpython3.7-stdlib libqhull7 libre2-6 libx265-179 python3-deprecation python3-flask-session
  python3-pcapfile python3-winrm python3.7 python3.7-minimal ruby-did-you-mean
0 upgraded, 0 newly installed, 20 to remove and 0 not upgraded.
After this operation, 101 MB disk space will be freed.
(Reading database ... 323658 files and directories currently installed.)
Removing fonts-glyphicons-halflings (1.009~3.4.1+dfsg-1) ...
dpkg: warning: while removing fonts-glyphicons-halflings, directory '/usr/share/fonts/truetype/glyphicons' not empty so not removed
Removing gir1.2-appindicator3-0.1:amd64 (0.4.92-8) ...
Removing libappindicator3-1:amd64 (0.4.92-8) ...
Removing libboost-iostreams1.67.0:amd64 (1.67.0-17+b1) ...
Removing libboost-thread1.67.0:amd64 (1.67.0-17+b1) ...
Removing libboost-system1.67.0:amd64 (1.67.0-17+b1) ...
Removing libgdal26 (3.0.4+dfsg-1+b4) ...
Removing libicu63:amd64 (63.2-3) ...
Removing python3.7 (3.7.7-1+b1) ...
Removing libpython3.7-stdlib:amd64 (3.7.7-1+b1) ...
Removing python3.7-minimal (3.7.7-1+b1) ...
Unlinking and removing bytecode for runtime python3.7
Removing libpython3.7-minimal:amd64 (3.7.7-1+b1) ...
Removing libqhull7:amd64 (2015.2-4) ...
Removing libre2-6:amd64 (20200401+dfsg-1) ...
Removing libx265-179:amd64 (3.2.1-1) ...
Removing python3-deprecation (2.1.0-1) ...
Removing python3-flask-session (0.3.1-0kali2) ...
Removing python3-pcapfile (0.12.0+git20181010-0kali2) ...
Removing python3-winrm (0.4.1-0kali1) ...
Removing ruby-did-you-mean (1.2.1-1) ...
Processing triggers for kali-menu (2020.3.2) ...
Processing triggers for desktop-file-utils (0.26-1) ...
Processing triggers for mime-support (3.64) ...
Processing triggers for libc-bin (2.30-8) ...
Processing triggers for man-db (2.9.3-2) ...
Processing triggers for fontconfig (2.13.1-4.2) ...
```

## Useful tweaks

Now a few tweaks to sort a couple of annoying defaults. First I have a GB keyboard, the default layout is US, so let's change it:

### Keyboard layout

```text
kali@kali:~$ setxkbmap -layout gb
```

Next I change the timezone, first check what is set:

### Timezone

```text
kali@kali:~$ timedatectl status
               Local time: Sun 2020-07-26 17:18:52 EDT
           Universal time: Sun 2020-07-26 21:18:52 UTC
                 RTC time: Sun 2020-07-26 21:18:52
                Time zone: America/New_York (EDT, -0400)
System clock synchronized: no
              NTP service: n/a
          RTC in local TZ: no
```

For me I want it set to London, you can check the list of available timezones like this:

```text
kali@kali:~$ timedatectl list-timezones
Africa/Abidjan
Africa/Accra
Africa/Algiers
Africa/Bissau
Africa/Cairo
Africa/Casablanca
Africa/Ceuta
<<SNIP>>
```

Once you've found yours you can change it like this:

```text
kali@kali:~$ sudo timedatectl set-timezone Europe/London
```

Now check it again to see it's changed:

```text
kali@kali:~$ timedatectl status
               Local time: Sun 2020-07-26 22:20:18 BST
           Universal time: Sun 2020-07-26 21:20:18 UTC
                 RTC time: Sun 2020-07-26 21:20:18
                Time zone: Europe/London (BST, +0100)
System clock synchronized: no
              NTP service: n/a
          RTC in local TZ: no

kali@kali:~$ date
Sun 26 Jul 2020 10:20:21 PM BST
```

### Aliases

There's a few commands you repeat often, to save time create an alias. Here's a few examples for ls:

```text
alias ll='ls -l'
alias la='ls -A'
alias l='ls -CF'
```

### Bash history

The default size of the Bash history file is not big enough for me, so I also change these. If you look at your .bashrc file you'll find these lines:

```text
# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000
```

I change them to be ten times bigger with this:

```text
kali@kali:~$ sed -i 's/HISTSIZE=1000/HISTSIZE=10000/g' .bashrc
kali@kali:~$ sed -i 's/HISTSIZESIZE=2000/HISTSIZE=20000/g' .bashrc
```

### Silence Firefox

I use the preinstalled version of Firefox, but there's a lot of features enabled that make it noisy. I use the custom user.js file from [here](https://gist.github.com/puzzlepeaches/afb8d748ce3530def9ccfb55846d6d4b) to silence it. First open Firefox and go to the profile page:

![firefox-profile](/assets/images/2020-07-26-22-59-54.png)

Make a note of the path for the root directory, close Firefox, now in a terminal cd to the path:

```text
kali@kali:~$ cd .mozilla/firefox/up56m7v8.default-esr/
kali@kali:~/.mozilla/firefox/up56m7v8.default-esr$
```

Now we can get the user.js file from GitHub, make sure you get the RAW version:

```text
kali@kali:~/.mozilla/firefox/up56m7v8.default-esr$ wget https://gist.githubusercontent.com/puzzlepeaches/afb8d748ce3530def9ccfb55846d6d4b/raw/07c9d21aa2d76733179da05235e440fbf636b718/user.js -O user.js
```

Now open FireFox, and check the settings have changed by going to the config page:

![firefox-settins](/assets/images/2020-07-26-23-03-59.png)

Anything in bold has been changed by the user.js file.

### VirtualBox Additions upgrade

Finally we need to update the VirtualBox guest additions. We have VirtualBox 6.1.12 installed, but version 6.1.6 of guest additions came pre-installed. You may find bi-directional copy and paste isn't working. Also dynamic resizing of your Kali guest window might not work. It's easy to update to the version of VirtualBox we have installed. First from the Devices menu choose Insert Guest Additions CD Image:

![kali-insert-guest-additions](/assets/images/2020-07-26-22-02-58.png)

In file manager you can see the CD is inserted and the contents accessible:

![kali-guest-cd](/assets/images/2020-07-26-22-03-59.png)

Now open a terminal and run the script to do the update:

```text
kali@kali:~$ cd /media/cdrom0/
kali@kali:/media/cdrom0$ sudo bash autorun.sh
```

A seperate window will open, and you can see the progress as it uninstalls the old version and installs the new one:

![kali-guest-update](/assets/images/2020-07-26-21-58-15.png)

Press enter to close the window and then reboot your Kali virtual machine for the last time.

Hopefully you've reached this point without any problems, and now have a fully updated version of Kali ready for you to enjoy using.

In my next guide I will look at some of the useful software I add to Kali. All of them are generally used during penetration testing and capture the flag activites.
