---
title: "Getting started with VSCode"
header:
  teaser: /assets/images/2020-06-01-21-54-29.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Web
tags:
  - VSCode
  - Github
---

## Overview

![header](/assets/images/2020-06-01-21-54-29.png)

This is the second post in a series, aimed at showing you step by step guides to creating your own static website hosted on GitHub for free. This post focuses on setting up VSCode. I'll show you how to install it, configure it to connect to your GitHub repository, and install a few useful plugins that help you write articles efficiently.
<!--more-->

The starting point for this series of guides is [here](https://pencer.io/web/web-creating-free-blog/). The first article explaining how to set up a GitHub account is [here.](https://pencer.io/web/web-getting-started-github/)

## Install VSCode on Windows 10

First of all lets grab the latest version of VSCode. For Windows you have two choices, either download from the Microsoft site [here](https://code.visualstudio.com/download) or use PowerShell.

Let's download via the browser first. Go to the URL above and then click on the relevant blue box for your setup:

![vscode-download](/assets/images/2020-08-05-16-46-30.png)

For me it's Windows 10, I clicked on the box on the left, and Edge downloads the setup exe:

![vscode-setup](/assets/images/2020-08-05-16-48-39.png)

Once downloaded click run, depending on which account your logged on as you might get this warning:

![vscode-nonadmin](/assets/images/2020-08-05-16-51-15.png)

If you want to install as Administrator click ok, otherwise cancel and log on with the user you want to use. At the license agreement choose I accept the agreement and click Next:

![vscode-license](/assets/images/2020-08-05-16-52-38.png)



Or do this: 
Install-Script Install-VSCode -Scope CurrentUser; Install-VSCode.ps1
https://github.com/PowerShell/vscode-powershell

## Summary

So in this first post we've learnt a little about GitHub, Markdown, Jekyll and its remote themes. We've also cloned our first repository and enabled a basic website for the world to see.
