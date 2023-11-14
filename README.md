# HackTheBox Writeups

## Description

This repository contains detailed writeups for various Hack The Box machines and challenges that I've tackled, following the suggested machines by TJ_Null. These writeups serve as a comprehensive guide for each penetration testing scenario, documenting the enumeration, exploitation, privilege escalation, and key takeaways.

## Purpose

I am actively using this repository as part of my preparation for the Offensive Security Certified Professional (OSCP) certification. The writeups here are structured to provide clear insights into the penetration testing process, sharing the steps taken and lessons learned.


## Table of Contents
- [Information](#information)
- [Enumeration](#enumeration)
- [Initial Access](#initial-access)
  - [Port [X] - [Service Name]](#port-x---service-name)
- [User Access](#user-access)
- [Privilege Escalation](#privilege-escalation)
- [Conclusion](#conclusion)
- [Additional Notes](#additional-notes)
- [Resources](#resources)
- [Acknowledgments](#acknowledgments)

## Information

| Property     | Value                       |
|--------------|-----------------------------|
| **Name**     | [Machine/Challenge Name]    |
| **IP Address**| [Machine IP Address]        |
| **OS**       | [Operating System]          |
| **Difficulty**| [Easy/Medium/Hard/Insane]   |

## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap_scan.txt [Machine IP]
```

*Include any additional enumeration steps or tools used.*

## Initial Access
### Port [X] - [Service Name]
*Describe the service and any initial observations.*

#### Vulnerability Exploited
*Explain the vulnerability and the exploitation process.*

#### Exploitation Steps
1. *Step 1*
2. *Step 2*
3. *Step 3*

### User Access
*Detail the steps taken to escalate privileges and gain user access.*

#### User Flag
*Provide the content of the user flag.*

## Privilege Escalation
*Explain the steps to escalate privileges from the initial user to root.*

#### Root Flag
*Provide the content of the root flag.*

## Conclusion
*Summarize the key steps taken and lessons learned during the penetration test.*

## Additional Notes
*Include any additional information, tips, or tricks that might be helpful for others attempting the challenge or machine.*

## Resources
*List any external resources, tools, or references used during the process.*

## Acknowledgments
*If you consulted any walkthroughs, writeups, or other resources, give credit and provide links.*

```
Feel free to customize this template based on your specific needs or preferences.
```