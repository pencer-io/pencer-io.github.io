---
title: "Installing VirtualBox 6.1.12 and Extensions"
header:
  teaser: /assets/images/2020-07-20-17-30-33.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Cyber
tags:
  - virtualbox
  - extensions
  - Windows 10
---

![virtualbox](/assets/images/2020-07-20-17-30-33.png)

## VirtualBox Information

For all my Cyber Security work I use Kali as a VM within VirtualBox. There is a special VirtualBox image available from Offensive Security with some settings already pre-configured for you. See **this guide** on how to set up Kali 2020.2 with VirtualBox.

You can get the latest version of VirtualBox and it's Extension pack [here.](https://www.virtualbox.org/wiki/Downloads)

The following guide follows the steps to install VirtualBox on Windows 10 64bit. For anything other than that YMMV.

## Installing VirtualBox

If you have VirtualBox installed, then skip this section, or use it as a reference to get yourself updated to the latest version. Once you've downloaded VirtualBox, run it and follow the wizard, then click Next:

![virtualbox-welcome](/assets/images/2020-07-20-15-47-48.png)

On the custom setup page leave the defaults, unless you know what you're doing to change them. Click Next:

![virtualbox-custom-setup](/assets/images/2020-07-20-15-48-54.png)

Leave the default options selected, unless you have a reason to change them. Click Next:

![virtualbox-custom-2](/assets/images/2020-07-20-15-51-08.png)

Whilst it installs the virtual networking you'll be disconnected from the network briefly. Click Yes:

![virtualbox-networking](/assets/images/2020-07-20-15-52-41.png)

That's all there is to it for the basic setup. Click Install and wait for it to complete:

![virtualbox-ready](/assets/images/2020-07-20-15-53-59.png)

It takes a while, be patient:

![virtualbox-installing](/assets/images/2020-07-20-15-55-30.png)

Eventually you will get here:

![virtualbox-complete](/assets/images/2020-07-20-15-58-30.png)

Click Finish to close the installer, and start VirtualBox. First thing to do is install the extensions pack. You can find information on what they are, and why you need them [here.](https://www.virtualbox.org/manual/ch01.html#intro-installing).

From the main VirtualBox window click on File menu, choose Preferences (or press CTRL+G), then click on Extensions:

![virtualbox-gui-extensions](/assets/images/2020-07-20-16-19-07.png)

Click on the green + on the right, and find the extensions file you downloaded earlier. There's a brief explanation of what the pack gives you. Click Install:

![virtualbox-install-extension](/assets/images/2020-07-20-16-23-05.png)

Read the license agreement. Click I Agree:

![virtualbox-extension-agree-license](/assets/images/2020-07-20-16-31-59.png)

The Extension pack should now be installed:

![virtualbox-extension-completed](/assets/images/2020-07-20-16-33-32.png)

You may get an error like this:

![virtualbox-extension-failure](/assets/images/2020-07-20-16-37-19.png)

If you do it's because VirtualBox was started with an account that isn't local administrator on your device. Close the installer, close VirtualBox, and start it again running as administrator. Repeat the steps above to install the extension pack.

## Upgrading Existing VirtualBox Extensions

If you are upgrading from a previous version of VirtualBox you'll see this when you first open it:

![virtualbox-extension-update](/assets/images/2020-07-20-16-00-47.png)

If you click Download it will check for the latest version and offer to download it for you:

![virtualbox-extension-download](/assets/images/2020-07-20-16-01-58.png)

Once downloaded you'll get prompted to install now, or you can cancel and do it later. Click Install:

![virtualbox-extension-install](/assets/images/2020-07-20-16-03-10.png)

A final check, and then you are ready to upgrade the extensions. Click Upgrade:

![virtualbox-extension-upgrade-older](/assets/images/2020-07-20-16-04-25.png)

Read the license agreement. Click I Agree:

![virtualbox-extension-agree-license](/assets/images/2020-07-20-16-31-59.png)

As above, you may get this error:

![virtualbox-extension-fail](/assets/images/2020-07-20-16-07-47.png)

If you do t's because VirtualBox was started with an account that isn't local administrator on your device. Close the updater, close VirtualBox, and start it again running as administrator:

![virtualbox-running-as-admin](/assets/images/2020-07-20-16-11-11.png)

You should be back to same place as before, being asked to update the extensions. Follow the same steps:

![virtualbox-extensions-done](/assets/images/2020-07-20-16-12-40.png)

Once completed, you get the opportunity to tidy up:

![virtualbox-tidyup](/assets/images/2020-07-20-16-13-38.png)

That's all there is to installing VirtualBox on Windows 10.

You can now follow **this guide** to install Kali 2020.2 as a VM within it.