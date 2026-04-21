# Active Directory / Infrastructure

Active Directory pentest cheatsheets. Authorized testing only.

## Index

| File | MITRE ATT&CK |
| --- | --- |
| [enumeration.md](./enumeration.md) | [TA0007 Discovery](https://attack.mitre.org/tactics/TA0007/), [T1087.002 Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/) |
| [kerberos.md](./kerberos.md) | [T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/), [T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/), [T1558.004 AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) |
| [lateral-movement.md](./lateral-movement.md) | [TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008/), [T1550.002 Pass-the-Hash](https://attack.mitre.org/techniques/T1550/002/), [T1550.003 Pass-the-Ticket](https://attack.mitre.org/techniques/T1550/003/) |

## Sources
- BloodHound CE: https://github.com/SpecterOps/BloodHound
- harmj0y blog: https://harmj0y.medium.com/
- ired.team — AD attacks: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
- HackTricks Active Directory: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
- Microsoft — AD security best practices: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
- Microsoft — Privileged Access strategy: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-strategy
- MITRE ATT&CK: https://attack.mitre.org/
