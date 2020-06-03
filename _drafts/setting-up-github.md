---
title: "Getting started with Github"
header:
  teaser: /assets/images/2020-06-01-21-54-29.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Web
tags:
  - Github
  - Jekyll
  - remote_them
  - markdown
  - blog
---

## Overview

![header](/assets/images/2020-06-01-21-54-29.png)

This is the first post in a series, aimed at showing you step by step guides to creating your own static website hosted on GitHub for free. This post focuses on setting up a new GitHub account, choosing your Jekyll theme, and the cloning it to your first repository.

<!--more-->

Other posts in this series:

1. vscode
2. blah blah

If you already have a GitHub account, or you're familiar with the process, then you can skip this post, and move on to the next one.

First we need to sign up for a free account with GitHub. You need a valid email address for this stage, so you can verify your account. GitHub will also email you periodically, so probably best not to use a burner address. A Gmail account created just to use with this can work well, especially if you want to look at integrating other Google services introduced in later posts such as Google Search and Google Analytics.

So head over to [GitHub](https://github.com), and let's get going by filling in the sign up form:

![github_signup](/assets/images/2020-06-01-21-10-28.png)

The username you pick here will be visible to everyone on GitHub, so pick something appropriate to you. After you hit the sign up button you'll need to solve a puzzle to verify you're not a robot:

![github_verify](/assets/images/2020-06-01-21-16-35.png)

Once you've solved that, click on Join a free plan. Now you can fill in a few questions about what you want to use this account for (or skip it):

![github_welcome](/assets/images/2020-06-01-21-19-29.png)

If you'll be using this account just to host your blog then None is ok for this, but really it doesn't matter too much what you pick:

![github_experience](/assets/images/2020-06-01-21-20-22.png)

Here choose **Create a website with GitHub Pages**:

![github_whatfor](/assets/images/2020-06-01-21-21-15.png)

Here you can enter interests, or leave blank, then click on **Complete setup**:

![github_interests](/assets/images/2020-06-01-21-22-35.png)

Head over to your emails and look for the verify email from GitHub:

![github_verify](/assets/images/2020-06-01-21-23-15.png)

Once you've clicked on the link in the verify email you'll end up here. If you're new to GitHub then it might be worth choosing **Start Learning** first. This will take you through cloning your first repository and doing some guided learning on GitHub basics. You can do this later, so don't worry if you don't want to do that now. If you're ready then choose **Skip this for now**:

![github_whatfirst](/assets/images/2020-06-01-21-24-11.png)

If you skipped the guided learning, and now wish you'd had a look, then you can get to the help guides [here](https://guides.github.com/?email_source=welcome).

When you're ready to get started on creating your new Jekyll based blog, you'll want to have a look at the many pre-built themes that are available, many of which are free. Whilst you're still working out if this is the right platform for you, I would encourage you to have a look around and see what's out there.

Here are few sites to get you started:

1. [JamStackThemes](https://jamstackthemes.dev/ssg/jekyll/)
2. [JekyllThemes.io](https://jekyllthemes.io/)
3. [JekyllThemes.org](http://jekyllthemes.org/)
4. [Jekyll-Themes.com](https://jekyll-themes.com/)

I played with a few different ones, before settling on [this one](https://jekyllthemes.io/theme/minimal-mistakes):

![jekyll_mm](/assets/images/2020-06-01-21-45-33.png)

I'll be basing the rest of this guide, assuming you're following along with me using the Minimal Mistakes theme here. Other posts in this series of guides also use the same theme as a reference for the instructions. So if this is all new to you, then for simplicity I would suggest you go with Minimal Mistakes for now.

THe good thing to know about Jekyll themes, especially remote themes which is what we will look at here, is that they are simple to swap in and out for different ones.

It's worth noting you can have a play with the theme by trying the live demo [here](https://mmistakes.github.io/minimal-mistakes).

When you're ready, let's move on and get the Minimal Mistakes theme cloned to our own repository so we can start customising it:

![get_mm](/assets/images/2020-06-01-21-46-14.png)



![mm_repo](/assets/images/2020-06-01-21-47-39.png)

![mm_remotetheme](/assets/images/2020-06-01-21-50-24.png)

![mm_deployfromtemplate](/assets/images/2020-06-01-21-53-10.png)

![github_repogenerate](/assets/images/2020-06-01-21-53-53.png)

![mm_remotetheme](/assets/images/2020-06-01-21-54-38.png)


