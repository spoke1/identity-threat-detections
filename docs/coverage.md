# ATT&CK coverage

Generated from the detection files by `scripts/Build-SentinelRules.ps1`. Do not edit by hand.

## By technique

| Technique | Detections | Preventive controls |
|---|---|---|
| [T1003.006](https://attack.mitre.org/techniques/T1003/006/) OS Credential Dumping: DCSync | ITD-A001 Directory replication (DCSync) by an account that is not a domain controller | hybrid-workplace-automation · Get-ADTier0Exposure.ps1 finding ReplicationRights (no replication rights outside domain controllers) |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs | ITD-A006 Security event log cleared | Forward security events to the SIEM in near real time, so clearing the local log does not remove the evidence. |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) Valid Accounts: Domain Accounts | ITD-A007 Tier-0 account signed in to a host outside Tier 0 | hybrid-workplace-automation · Get-ADTier0Exposure.ps1 findings PrivilegedAccountDelegable and ComputerInPrivilegedGroup (Protected Users, sensitive accounts)<br>Authentication policies and silos, or user rights assignments that deny Tier-0 logons outside Tier 0 |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts | ITD-E008 Sign-in attempt with a break-glass account<br>ITD-E010 Successful sign-in with legacy authentication | id-hub Level 1 · at least two cloud-only break-glass accounts with passkeys or certificates, excluded only through one group<br>id-hub Level 2 · alerting on break-glass use<br>id-hub Level 3 · break-glass governance with regular tests<br>id-hub Level 1 · CA101 block legacy authentication |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Account Manipulation: Additional Cloud Credentials | ITD-E002 New credential added to an application or service principal | id-hub Level 2 · application credentials (named owners, certificates or federated credentials instead of secrets)<br>id-hub Level 3 · CA306 workload identities only from trusted locations |
| [T1098.003](https://attack.mitre.org/techniques/T1098/003/) Account Manipulation: Additional Cloud Roles | ITD-E004 Directory role assigned outside Privileged Identity Management | id-hub Level 2 · PIM for all privileged roles<br>id-hub Level 3 · zero standing privilege, PIM activation with authentication context |
| [T1098.005](https://attack.mitre.org/techniques/T1098/005/) Account Manipulation: Device Registration | ITD-E006 Authentication method registered after a risky sign-in | id-hub Level 2 · CA206 security info registration only with MFA or from trusted locations<br>id-hub Level 1 · Temporary Access Pass for onboarding and recovery |
| [T1098.007](https://attack.mitre.org/techniques/T1098/007/) Account Manipulation: Additional Local or Domain Groups | ITD-A003 Member added to a Tier-0 group | hybrid-workplace-automation · Get-ADTier0Exposure.ps1 (review of PrivilegedAccounts.csv) |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying | ITD-A005 Password spray against Active Directory<br>ITD-E007 Password spray against Microsoft Entra ID | hybrid-workplace-automation · Get-ADTier0Exposure.ps1 findings PasswordNeverExpires and PasswordOld for privileged accounts<br>id-hub Level 1 · CA101 block legacy authentication<br>id-hub Level 2 · CA201 MFA for all users and apps |
| [T1484.002](https://attack.mitre.org/techniques/T1484/002/) Domain or Tenant Policy Modification: Trust Modification | ITD-A002 Domain trust created, removed or modified<br>ITD-E009 Domain federation or authentication settings changed | hybrid-workplace-automation · Get-ADTier0Exposure.ps1 (Tier-0 membership limited to the accounts that need it)<br>id-hub Level 3 · zero standing privilege for Global and Hybrid Identity Administrator |
| [T1528](https://attack.mitre.org/techniques/T1528/) Steal Application Access Token | ITD-E003 Consent to an application with high-risk permissions<br>ITD-E005 Successful sign-in with the device code flow | id-hub Level 1 · application consent (user consent limited, admin consent workflow)<br>id-hub Level 2 · CA209 block device code flow |
| [T1556.009](https://attack.mitre.org/techniques/T1556/009/) Modify Authentication Process: Conditional Access Policies | ITD-E001 Conditional Access policy created, changed or deleted | id-hub Level 3 · zero standing privilege for the Conditional Access Administrator role (PIM with authentication context)<br>id-hub Level 3 · CA301 phishing-resistant MFA for admins |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting | ITD-A004 Kerberoasting: RC4 service tickets for many service accounts | hybrid-workplace-automation · Get-ADTier0Exposure.ps1 finding Kerberoastable (no SPNs on privileged accounts, gMSAs for services) |

## By detection

| Detection | Severity | Data | Tactics | Techniques |
|---|---|---|---|---|
| ITD-A001 Directory replication (DCSync) by an account that is not a domain controller | High | SecurityEvent | CredentialAccess | T1003.006 |
| ITD-A002 Domain trust created, removed or modified | High | SecurityEvent | DefenseEvasion, PrivilegeEscalation | T1484.002 |
| ITD-A003 Member added to a Tier-0 group | High | SecurityEvent | Persistence, PrivilegeEscalation | T1098.007 |
| ITD-A004 Kerberoasting: RC4 service tickets for many service accounts | Medium | SecurityEvent | CredentialAccess | T1558.003 |
| ITD-A005 Password spray against Active Directory | Medium | SecurityEvent | CredentialAccess | T1110.003 |
| ITD-A006 Security event log cleared | Medium | SecurityEvent | DefenseEvasion | T1070.001 |
| ITD-A007 Tier-0 account signed in to a host outside Tier 0 | High | SecurityEvent | DefenseEvasion, Persistence, PrivilegeEscalation, InitialAccess | T1078.002 |
| ITD-E001 Conditional Access policy created, changed or deleted | Medium | AuditLogs | DefenseEvasion, Persistence, CredentialAccess | T1556.009 |
| ITD-E002 New credential added to an application or service principal | Medium | AuditLogs | Persistence, PrivilegeEscalation | T1098.001 |
| ITD-E003 Consent to an application with high-risk permissions | Medium | AuditLogs | CredentialAccess | T1528 |
| ITD-E004 Directory role assigned outside Privileged Identity Management | Medium | AuditLogs | Persistence, PrivilegeEscalation | T1098.003 |
| ITD-E005 Successful sign-in with the device code flow | Medium | SigninLogs | CredentialAccess | T1528 |
| ITD-E006 Authentication method registered after a risky sign-in | High | AuditLogs, SigninLogs | Persistence, PrivilegeEscalation | T1098.005 |
| ITD-E007 Password spray against Microsoft Entra ID | Medium | SigninLogs | CredentialAccess | T1110.003 |
| ITD-E008 Sign-in attempt with a break-glass account | High | SigninLogs | InitialAccess, Persistence, PrivilegeEscalation, DefenseEvasion | T1078.004 |
| ITD-E009 Domain federation or authentication settings changed | High | AuditLogs | DefenseEvasion, PrivilegeEscalation | T1484.002 |
| ITD-E010 Successful sign-in with legacy authentication | Medium | SigninLogs | InitialAccess, DefenseEvasion | T1078.004 |
