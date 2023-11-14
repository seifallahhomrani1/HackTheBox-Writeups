---
cover: .gitbook/assets/bg (1).png
coverY: 0
---

# HackTheBox Writeups


## Description

This repository contains detailed writeups for various Hack The Box machines and challenges that I've tackled, following the suggested machines by TJ\_Null. These writeups serve as a comprehensive guide for each penetration testing scenario, documenting the enumeration, exploitation, privilege escalation, and key takeaways.

## Purpose

I am actively using this repository as part of my preparation for the Offensive Security Certified Professional (OSCP) certification. The writeups here are structured to provide clear insights into the penetration testing process, sharing the steps taken and lessons learned.

## Table of Contents

* [Information](./#information)
* [Enumeration](./#enumeration)
* [Initial Access](./#initial-access)
  * [Port \[X\] - \[Service Name\]](./#port-x---service-name)
* [User Access](./#user-access)
* [Privilege Escalation](./#privilege-escalation)
* [Conclusion](./#conclusion)
* [Additional Notes](./#additional-notes)
* [Resources](./#resources)
* [Acknowledgments](./#acknowledgments)

## Information

| Property       | Value                      |
| -------------- | -------------------------- |
| **Name**       | \[Machine/Challenge Name]  |
| **IP Address** | \[Machine IP Address]      |
| **OS**         | \[Operating System]        |
| **Difficulty** | \[Easy/Medium/Hard/Insane] |

## Enumeration

### Nmap Scan

```bash
nmap -sC -sV -oN nmap_scan.txt [Machine IP]
```

_Include any additional enumeration steps or tools used._

## Initial Access

### Port \[X] - \[Service Name]

_Describe the service and any initial observations._

#### Vulnerability Exploited

_Explain the vulnerability and the exploitation process._

#### Exploitation Steps

1. _Step 1_
2. _Step 2_
3. _Step 3_

### User Access

_Detail the steps taken to escalate privileges and gain user access._

#### User Flag

_Provide the content of the user flag._

## Privilege Escalation

_Explain the steps to escalate privileges from the initial user to root._

#### Root Flag

_Provide the content of the root flag._

## Conclusion

_Summarize the key steps taken and lessons learned during the penetration test._

## Additional Notes

_Include any additional information, tips, or tricks that might be helpful for others attempting the challenge or machine._

## Resources

_List any external resources, tools, or references used during the process._

## Acknowledgments

_If you consulted any walkthroughs, writeups, or other resources, give credit and provide links._

```
Feel free to customize this template based on your specific needs or preferences.
```
