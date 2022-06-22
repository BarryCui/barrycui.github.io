---
layout: post
title: Windows Fundamentals 1
categories: [TryHackMe]
tags: [Writeup]
---

# TryHackMe: Windows Fundamentals 1
> In part 1 of the Windows Fundamentals module, we'll start our journey learning about the Windows desktop, the NTFS file system, UAC, the Control Panel, and more..

### Task 2

**What encryption can you enable on Pro that you can't enable in Home?**

> BitLocker

### Task 3

**Which selection will hide/disable the Search box?**

> Hidden

**Which selection will hide/disable the Task View button?**

> show task view button

**Besides Clock and Network, what other icon is visible in the Notification Area?**

On the bottom right-handed corner, right-click the icon and you can see "Open Action Center".
![](/img/posts/winfun_1.png)
> action center

### Task 4

**What is the meaning of NTFS?**

> New Technology File System

### Task 5

**What is the system variable for the Windows folder?**

> %windir%

### Task 6

**What is the name of the other user account?**

Type 'lusrmgr.msc' to see local users:
![](/img/posts/winfun_2.png)
> tryhackmebilly

**What groups is this user a member of?**

Check its properties:
![](/img/posts/winfun_3.png)
> Remote Desktop Users,Users

**What built-in account is for guest access to the computer?**

![](/img/posts/winfun_4.png)
> Guest

**What is the account status?**

Check its properties and you can tell the account is disabled:
![](/img/posts/winfun_5.png)
> account is disabled

### Task 7

**What does UAC mean?**

> User Account Control

### Task 8

**In the Control Panel, change the view to Small icons. What is the last setting in the Control Panel view?**

![](/img/posts/winfun_6.png)
![](/img/posts/winfun_7.png)
> windows defender firewall

### Task 9

**What is the keyboard shortcut to open Task Manager?**

> Ctrl+Shift+Esc






