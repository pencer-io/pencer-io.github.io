---
title: "Getting started with VSCode and Git"
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
  - Git
---

## Overview

![header](/assets/images/2020-06-01-21-54-29.png)

This is the second post in a series of articles, that are aimed at showing you simple step by step guides for creating your own static website hosted on GitHub for free. This post focuses on setting up VSCode and Git. I'll show you how to install and configure them, then we'll connect to our GitHub repository.
<!--more-->
As mentioned we're going to use Git and GitHub for version control. If you're not sure what Git is and why it makes sense to use it, then [this](https://www.nobledesktop.com/blog/what-is-git-and-why-should-you-use-it) is a good article that explains the basics.

The starting point for this series of guides is [here](https://pencer.io/web/web-creating-free-blog/). The first article explaining how to set up a GitHub account is [here.](https://pencer.io/web/web-getting-started-github/) in case you need to do that.

## Install VSCode on Windows 10

First of all lets grab the latest version of VSCode. For Windows you have two choices, either download from the Microsoft site [here](https://code.visualstudio.com/download) or use PowerShell.

Let's keep it simple and download via the browser. Go to the URL above and then click on the relevant blue box for your setup:

![vscode-download](/assets/images/2020-08-05-16-46-30.png)

For me it's Windows 10, I clicked on the box on the left, and Edge downloads the setup exe:

![vscode-setup](/assets/images/2020-08-05-16-48-39.png)

Once downloaded click run, depending on which account your logged on as you might get this warning:

![vscode-nonadmin](/assets/images/2020-08-05-16-51-15.png)

If you want to install as Administrator click ok, otherwise cancel and log on with the user you want to use. At the license agreement choose I accept the agreement and click Next:

![vscode-license](/assets/images/2020-08-05-16-52-38.png)

Choose where you want to install VSCode, then click Next:

![vscode-location](/assets/images/2020-08-06-22-09-08.png)

Choose if you want a Start Menu shortcut and where, then click Next:

![vscode-startmenu](/assets/images/2020-08-06-22-10-11.png)

Choose any additional settings, and then click Next:

![vscode-tasks](/assets/images/2020-08-06-22-14-09.png)

Review your choices, and then click Install:

![vscode-choices](/assets/images/2020-08-06-22-15-25.png)]

Wait while VSCode is installed:

![vscode-install](/assets/images/2020-08-06-22-16-42.png)

After installation click Finish to start VSCode:

![vscode-launch](/assets/images/2020-08-06-22-17-12.png)

You now have VSCode installed, and ready to configured:

![vscode-startup](/assets/images/2020-08-06-22-18-20.png)

You'll need to have already set up your GitHub account and repository before proceeding with the following install and configuration of Git. Follow my previous guide [here.](https://pencer.io/web/web-getting-started-github/) if you still need to do that, then come back and follow on with the below.

## Installing Git

On Windows 10 you will need to install Git, so you can connect your VSCode workspace to your GitHub repository. Download Git for Windows from [here](https://git-scm.com/download/win) and run it. Read the license and then click Next:

![git-setup](/assets/images/2020-08-06-22-36-32.png)

Choose where you want it installed, then click Next:

![git-location](/assets/images/2020-08-06-22-37-32.png)

Select which components you want to install, I leave the defaults, then click Next:

![git-components](/assets/images/2020-08-06-22-44-30.png)

Choose if you want a Start Menu folder creating, and where, then click Next:

![git-startmenu](/assets/images/2020-08-06-22-46-05.png)

On the Choosing default editor screen change it to Use Visual Studio Code, and click Next:

![git-vscode](/assets/images/2020-08-06-22-47-29.png)

On the adjusting path screen leave the default recommended option, and click Next:

![git-path](/assets/images/2020-08-06-22-49-32.png)

On the HTTPS selection screen leave the default OpenSSL option, and click Next:

![git-https](/assets/images/2020-08-06-22-53-30.png)

On the configure line ending conversion screen leave the default, and click Next:

![git-lineendings](/assets/images/2020-08-06-22-55-25.png)

If installing Git on Windows 10 the you can change the terminal to use the default console window, then click Next:

![git-terminal](/assets/images/2020-08-06-22-57-59.png)

On the git pull behavior screen leave the default selection, and click Next:

![git-pull](/assets/images/2020-08-06-22-59-33.png)

On the Git credential helper screen leave the default middle option, or you can use the bottom option to install the new Core version. Either works with Windows 10, after selecting click Next:

![git-creds](/assets/images/2020-08-06-23-02-22.png)

On the configuring extras screen leave caching enabled, and then click Next:

![git-extras](/assets/images/2020-08-06-23-04-54.png)

On the experimental options screen leave pseudo console disabled, and then click Install:

![git-experiment](/assets/images/2020-08-06-23-05-59.png)

Wait while Git is installed:

![git-install](/assets/images/2020-08-06-23-07-23.png)

Select Launch Git Bash, and click Next:

![git-launch](/assets/images/2020-08-06-23-08-22.png)

You'll now see your Git Bash window:

![git-bash](/assets/images/2020-08-06-23-09-40.png)

The files we create and edit in VSCode will be kept in our local Git repository. We can connect this to GitHub and store our credentials. VSCode will then use these to synchronize your local files with your remote GitHub repository, without you needing to log in each time.

## Configure Git

First make a new folder to use as your local workspace:

![workspace](/assets/images/2020-08-09-21-47-10.png)

In the Git Bash window we need to set the username we'll use to connect to GitHub:

![git-username](/assets/images/2020-08-09-21-55-24.png)

This is the same username we used to set up our GitHub account in the [last guide](https://pencer.io/web/web-getting-started-github/). Next we set the email address we used:

![git-username](/assets/images/2020-08-09-21-57-32.png)

Now we change directory in to our workspace folder:

![git-workspace](/assets/images/2020-08-09-21-58-46.png)

Finally we can clone our remote repository down to our local workspace:

![git-clone](/assets/images/2020-08-09-21-59-57.png)

If we CD in to that cloned repository, we see the files match what we have on the GitHub site:

![git-local-files](/assets/images/2020-08-09-22-01-26.png)

Here's how our repo looked on GitHub when created it in the previous guide:

![github-repo](/assets/images/2020-08-09-22-03-48.png)

## Configure Workspace

Now we have our remote GitHub repository cloned to our local Git instance. Let's go back to VSCode and click on **Add workspace folder**:

![vscode-add-workspace](/assets/images/2020-08-09-22-16-17.png)

Browse to the folder where we cloned our GitHub repository, and click Add:

![vscode-add-folder](/assets/images/2020-08-09-22-27-26.png)

Clicking on the Explorer tab on the left shows our files in the workspace folder:

![vscode-new-workspace](/assets/images/2020-08-09-22-19-26.png)

Let's save the workspace, so later we can change some of its settings:

![vscode-save-workspace](/assets/images/2020-08-09-22-21-44.png)

Choose a name for the workspace configuration file and where you want to save it:

![vscode-name-workspace](/assets/images/2020-08-09-22-32-48.png)

Run a sync to ensure all local files are up to date:

![vscode-git-sync](/assets/images/2020-08-09-22-36-09.png)

Click OK to run the sync:

![vscode-confirm-sync](/assets/images/2020-08-09-22-36-33.png)

Doing this also gets VSCode to ask you to enable periodic fetches:

![vscode-periodic-git-fetch](/assets/images/2020-08-09-22-37-15.png)

## Create and publish test file

Now let's create a test file:

![vscode-test-file](/assets/images/2020-08-09-22-39-22.png)

Add anything as content:

![vscode-test-text](/assets/images/2020-08-09-22-42-29.png)

Run another sync:

![vscode-command-palate](/assets/images/2020-08-09-22-40-59.png)

Choose to save and commit the file:

![vscode-test-commit](/assets/images/2020-08-09-22-44-44.png)

Choose Yes to automatically stage all change:

![vscode-test-stage](/assets/images/2020-08-09-22-45-18.png)

Enter a meaningful message to the commit:

![vscode-test-commit-message](/assets/images/2020-08-09-22-54-35.png)

Now push your changes to GtiHub:

![vscode-test-push](/assets/images/2020-08-09-22-47-26.png)

If this is the first time you've pushed to GitHub you'll need to enter your credentials:

![github-login-credentials](/assets/images/2020-08-09-22-50-31.png)

If you look at the repository on GitHub you should see the newly committed test.md file:

![github-test-check](/assets/images/2020-08-09-22-55-42.png)

That's it for our installation and configuration of VSCode and Git.

## Summary

So in this post we've looked at grabbing the latest version of VSCode, and Git. We've installed and configured them, and connected to our remote GitHib repository. Next time we'll look at some of the useful extensions that you can install in VSCode, which turn it in to a comfortable writing environment.
