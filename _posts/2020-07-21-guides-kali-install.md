---
title: "Importing Kali 2020.2a in to VirtualBox"
header:
  teaser: /assets/images/2020-07-20-15-33-12.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Cyber
tags:
  - Kali
  - Offensive Security
---

![kali-2020.2](/assets/images/2020-07-20-15-33-12.png)

## VirtualBox And Kali Information

Kali is one of the most popular pre-built cyber security environments. It's well maintained and kept updated regularly, with a dedicated team at [Offensive Sercurity](https://www.offensive-security.com/) working on it. It's also referenced and used in many blogs, articles and guides. So to keep things simple I like to use it whenever I can.

You can find information about the 2020.2a release of Kali [here.](https://www.kali.org/news/kali-linux-2020-2-release/).

You can download the VirtualBox specific image of Kali 2020.2a [here.](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/#1572305786534-030ce714-cc3b)

See [this guide](https://pencer.io/cyber/cyber-virtualbox-install/) on how to set up VirtualBox if you haven't already got it installed.

## Importing Kali 2020.2a

After you've downloaded the VirtualBox specific Kali pre-built image, open VirtualBox and click on Import:

![virtualbox-import](/assets/images/2020-07-20-17-12-15.png)

Browse to your downloaded file, select it:

![virtualbox-import-kali](/assets/images/2020-07-20-17-08-03.png)

After clicking Next you'll see the default appliance settings already configured:

![virtualbox-kali-settings](/assets/images/2020-07-20-17-13-57.png)

The only things I change at this point is CPU and RAM. Make sure your host machine has enough of it's own resources before changing these:

![virtualbox-kali-cpuram](/assets/images/2020-07-20-17-16-37.png)

After clicking Import you'll now have to agree to the software license:

![virtualbox-kali-license](/assets/images/2020-07-20-17-17-26.png)

After clicking Agree you should see the appliance importing:

![virtualbox-kali-importing](/assets/images/2020-07-20-17-17-48.png)

Eventually you should be back to the main window with Kali imported:

![virtualbox-kali-done](/assets/images/2020-07-20-17-21-44.png)

There's a few tweaks you can do to try and squeeze the maximum performance out of your virtual Kali machine. [This TechRepublic article](https://www.techrepublic.com/article/how-to-improve-virtualbox-guest-performance-in-five-steps/) is worth having a quick read if you need a few ideas.

Now we're ready to fire up our Kali machine and get it ready for use. Follow my [next guide](https://pencer.io/cyber/cyber-kali-first-boot/) on the things you'll want to do with Kali after it's first boot.
