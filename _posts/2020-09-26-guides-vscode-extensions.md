---
title: "Extensions for VSCode to help you write posts easier"
header:
  teaser: /assets/images/2020-09-26-18-01-05.png)
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Guides
tags:
  - VSCode
  - Github
  - Git
  - Extensions
---

## Overview

![header](/assets/images/2020-09-26-18-01-05.png)

This is the third post in a series of articles, that are aimed at showing you simple step by step guides to creating your own static website hosted on GitHub for free. This post focuses on a few useful extensions I use with VSCode. These give me a comfortable working environment, and some of the shortcuts really speed things up.

<!--more-->

The starting point for this series of guides is [here](https://pencer.io/guides/web-creating-free-blog/). The first article explaining how to set up a GitHub account is [here.](https://pencer.io/guides/web-getting-started-github/) in case you need to do that. The second article which goes through installing VSCode and Git is [here.](https://pencer.io/guides/web-vscode-git/)

## VSCode Extensions overview

One of the reasons why VSCode has become so popular is it's versatility. With the addition of a few selected extensions, you can change your environment from a Python playground to a writing suite. It's quick and simple to install extensions, and looking over the [VSCode Marketplace](https://marketplace.visualstudio.com/VSCode) you'll see there are hundreds to choose from.

Microsoft has a good guide to the Extension Marketplace [here.](https://code.visualstudio.com/docs/editor/extension-gallery)

Below I show you the extensions I've used to give me a comfortable writing environment. I now do all of my writing in VSCode. So hopefully you'll find it a nice place to work as well.

## Activity Bar

The area on the left of the interface is called the Activity Bar. You can get to the Extensions view by clicking on the fifth button down that looks like four small squares:

![activity-bar](/assets/images/2020-09-27-11-46-50.png)

You can also get there by clicking Ctrl+Shift+X.

Microsoft has a good guide to the user interface of VSCode [here](https://code.visualstudio.com/docs/getstarted/userinterface), which explains all of the different views, shortcuts and so on.

## Finding Extensions

You can search the Marketplace for extensions from within VSCode by simply typing what your looking for in the search area at the top of the Extension view:

![search-marketplace](/assets/images/2020-09-28-20-57-49.png)

When you've found the one you want just click install:

![install-extension](/assets/images/2020-09-28-21-01-49.png)

You can also find and install extensions from the Marketplace in your web browser:

![install-via-browser](/assets/images/2020-09-28-21-09-39.png)

## Extensions I Use

Hopefully the above has given you an idea of how to find and install extensions in VSCode. Now I will show you the ones I use in my writing Workspace, which is what I use to write blogs, articles and so on.

### Code Spell Checker

![code-spell-checker](/assets/images/2020-09-28-21-15-00.png)

The first one is simple enough. When enabled you'll see extra information in the status bar at the bottom of the screen:

![status-bar](/assets/images/2020-09-28-21-22-23.png)

On the right it shows the name of the currently focussed document. On the left it shows you the language it's detected, in this example it's a Markdown file. You can click on this to get to the settings for the spell checker:

![code-spell-checker-settings](/assets/images/2020-09-28-21-25-55.png)

Here you can make sure the correct language is set.

### Word Count

![word-count](/assets/images/2020-09-28-21-56-07.png)

The next one is even simpler. Word Count just shows you the number of words in the currently active document:

![status-bar-word-count](/assets/images/2020-09-28-21-58-48.png)

Useful to know at any time, especially if you're writing an article and need to hit a particular number of words.

### Markdown All In One

![markdown-all-in-one](/assets/images/2020-09-28-21-28-07.png)

As we've already seen, the blog we're creating is based on Jekyll which uses Markdown for all files. This next extension gives us a few useful shortcuts to speed things up. There's so many useful features in this extension, that you really need to have a look through the list to see what you can do. Things like auto completions, keyboard shortcuts and list editing save you a lot of time once you get the hang of them.

### Markdown Lint

![markdownlint](/assets/images/2020-09-28-22-02-54.png)

This extension is here to help us be consistent with our Markdown. A description of a linter from Wikipedia ([here](https://en.wikipedia.org/wiki/Lint_(software))) is:

```text
A lint, or a linter, is a static code analysis tool used to flag programming errors, bugs, stylistic errors, and suspicious constructs.
```

This extension adds a counter to the status bar at the bottom, where you can see errors and warnings:

![errors-warnings](/assets/images/2020-09-28-22-29-13.png)

If you click on that counter a window describing each problem pops up:

![error-details](/assets/images/2020-09-28-22-31-25.png)

You can now click on each error to see information on what's wrong, and how you can fix it to smarten up your Markdown.

### Paste Image

![paste-image](/assets/images/2020-09-29-21-11-11.png)

I find this extension is incredibly useful. If you're doing technical writing, then you will probably be inserting a lot of screenshots like me. With this extension set up and enabled you can simply press Ctrl+Alt+V to paste the contents of the clipboard straight in to your document.

To get this to work correctly for our Jekyll based website we've been creating you need to change a couple of settings. First under the Workspace section change the Base Path to ${projectRoot}/ like this:

![paste-image-settings](/assets/images/2020-09-29-21-26-09.png)

Secondly we need to change the Path to ${projectRoot}/assets/images and Prefix to /, like this:

![paste-image-more-settings](/assets/images/2020-09-29-21-26-37.png)

The image will be saved in the folder based on the Path above. The relative path to that file will be pasted in to the file you're editing, like this:

```text
![](/assets/images/2020-09-29-21-26-37.png)
```

For accessibility reasons we should always add an alternate text to the image, like this:

```text
![example-image](/assets/images/2020-09-29-21-26-37.png)
```

This extension really does save me a lot of time.

### vscode-icons

![vscode-icons](/assets/images/2020-09-29-21-43-28.png)

This extension just makes the VSCode interface look a little prettier, with custom colourful icons for the different types of files:

![vscode-icons-example](/assets/images/2020-09-29-21-44-42.png)

### Dracula Official

![dracula-theme](/assets/images/2020-09-29-21-48-59.png)

This is another extension aimed at making the VSCode environment a little easier on the eyes. The [Dracula theme](https://github.com/dracula/dracula-theme) has been around for many years, and there are hundreds of versions built to work with every editor, console and app you can think of that supports themes.

## Summary

So in this third post we've looked at how to find and install extensions for VSCode. I've also shown you the extensions I use for my writing Workspace. Next time we'll look closer at Jekyll, and how you can customise a remote theme to your own liking.
