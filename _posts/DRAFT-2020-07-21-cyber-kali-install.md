---
title: "Installing VirtualBox 6.1.12 and Extensions"
header:
  teaser: /assets/images/2020-07-20-15-33-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Cyber
tags:
  - kali
  - Offensive Security
---

![kali-2020.2](/assets/images/2020-07-20-15-33-12.png)

## VirtualBox And Kali Information

For all my Cyber Security work I use Kali as a VM within VirtualBox. There is a special VirtualBox image available from Offensive Security with some settings already pre-configured for you.

See **this guide** on how to set up VirtualBox if you haven't already got it installed.

You can find information about the 2020.2 release of Kali [here.](https://www.kali.org/news/kali-linux-2020-2-release/). 

You can download the VirtualBox specific image of Kali 2020.2 [here.](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/#1572305786534-030ce714-cc3b)

## Importing Kali 2020.2

After you've downloaded the VirtualBox specific Kali pre-built image, open VirtualBox and click on Import:

![virtualbox-import](/assets/images/2020-07-20-17-12-15.png)

Browse to your downloaded file, select it:

![virtualbox-import-kali](/assets/images/2020-07-20-17-08-03.png)

After clicking Next you'll see the default appliance settings already configured:

![virtualbox-kali-settings](/assets/images/2020-07-20-17-13-57.png)

The only things I change at this point is CPU and RAM:

![virtualbox-kali-cpuram](/assets/images/2020-07-20-17-16-37.png)

After clicking Import you'll now have to agree to the software license:

![virtualbox-kali-license](/assets/images/2020-07-20-17-17-26.png)

After clicking Agree you should see the appliance importing:

![virtualbox-kali-importing](/assets/images/2020-07-20-17-17-48.png)

Eventually you should be back to the main window with Kali imported:

![virtualbox-kali-done](/assets/images/2020-07-20-17-21-44.png)

