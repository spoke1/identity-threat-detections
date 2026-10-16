# Identity Threat Detections

Microsoft Sentinel analytics rules for the attacks that actually happen against Microsoft Entra ID and Active Directory: Conditional Access tampering, consent phishing, device code phishing, MFA method takeover, password spraying, DCSync, Kerberoasting and Tier-0 credential exposure.

Every rule says what it detects and why it matters, which false positives to expect, how to triage it and which preventive control would have stopped the attack in the first place.

[![CI](https://github.com/spoke1/identity-threat-detections/actions/workflows/ci.yml/badge.svg)](https://github.com/spoke1/identity-threat-detections/actions/workflows/ci.yml)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-analytics%20rules-0078D4)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-13%20techniques-C8102E)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Why

Preventive controls fail quietly. A Conditional Access exclusion added at 2 a.m., a client secret on an app with `Mail.ReadWrite`, a Domain Admin logging on to a workstation: none of these breaks anything, so nobody notices. The rules in this repository watch for exactly these moves, and each one points back to the control that should have prevented it. Detection and prevention are two halves of one design.

## Detections

### Microsoft Entra ID

| ID | Detection | Severity | ATT&CK |
|---|---|---|---|
| [ITD-E001](detections/entra-id/ITD-E001-ConditionalAccessPolicyChanged.yaml) | Conditional Access policy created, changed or deleted | Medium | T1556.009 |
| [ITD-E002](detections/entra-id/ITD-E002-CredentialAddedToApplication.yaml) | New credential added to an application or service principal | Medium | T1098.001 |
| [ITD-E003](detections/entra-id/ITD-E003-ConsentToHighRiskPermissions.yaml) | Consent to an application with high-risk permissions | Medium | T1528 |
| [ITD-E004](detections/entra-id/ITD-E004-RoleAssignedOutsidePIM.yaml) | Directory role assigned outside Privileged Identity Management | Medium | T1098.003 |
| [ITD-E005](detections/entra-id/ITD-E005-DeviceCodeFlowSignIn.yaml) | Successful sign-in with the device code flow | Medium | T1528 |
| [ITD-E006](detections/entra-id/ITD-E006-AuthMethodRegisteredAfterRiskySignIn.yaml) | Authentication method registered after a risky sign-in | High | T1098.005 |
| [ITD-E007](detections/entra-id/ITD-E007-PasswordSprayEntraId.yaml) | Password spray against Microsoft Entra ID | Medium | T1110.003 |
| [ITD-E008](detections/entra-id/ITD-E008-BreakGlassAccountSignIn.yaml) | Sign-in attempt with a break-glass account | High | T1078.004 |
| [ITD-E009](detections/entra-id/ITD-E009-DomainFederationChanged.yaml) | Domain federation or authentication settings changed | High | T1484.002 |
| [ITD-E010](detections/entra-id/ITD-E010-LegacyAuthenticationSuccess.yaml) | Successful sign-in with legacy authentication | Medium | T1078.004 |

### Active Directory

| ID | Detection | Severity | ATT&CK |
|---|---|---|---|
| [ITD-A001](detections/active-directory/ITD-A001-DCSyncFromNonDomainController.yaml) | Directory replication (DCSync) by an account that is not a domain controller | High | T1003.006 |
| [ITD-A002](detections/active-directory/ITD-A002-DomainTrustChanged.yaml) | Domain trust created, removed or modified | High | T1484.002 |
| [ITD-A003](detections/active-directory/ITD-A003-MemberAddedToTier0Group.yaml) | Member added to a Tier-0 group | High | T1098.007 |
| [ITD-A004](detections/active-directory/ITD-A004-KerberoastingRc4Tickets.yaml) | Kerberoasting: RC4 service tickets for many service accounts | Medium | T1558.003 |
| [ITD-A005](detections/active-directory/ITD-A005-PasswordSprayActiveDirectory.yaml) | Password spray against Active Directory | Medium | T1110.003 |
| [ITD-A006](detections/active-directory/ITD-A006-SecurityLogCleared.yaml) | Security event log cleared | Medium | T1070.001 |
| [ITD-A007](detections/active-directory/ITD-A007-Tier0LogonOnNonTier0Host.yaml) | Tier-0 account signed in to a host outside Tier 0 | High | T1078.002 |

The [ATT&CK coverage page](docs/coverage.md) maps every technique to its detections and to the preventive controls in [id-hub](https://github.com/spoke1/id-hub) and [hybrid-workplace-automation](https://github.com/spoke1/hybrid-workplace-automation).

## Anatomy of a detection

Each YAML file follows the Microsoft Sentinel analytics rule format and adds four fields that turn an alert into a decision:

| Field | Purpose |
|---|---|
| `falsePositives` | The legitimate activity that will trigger the rule, so tuning starts on day one |
| `triage` | The questions an analyst answers first, in order |
| `preventiveControls` | The control that would have stopped the attack, with a reference to the baseline |
| `references` | The ATT&CK technique and the Microsoft documentation of the events used |

The build appends these fields to the rule description, so they show up in every incident.

## Quick start

Prerequisites: a Log Analytics workspace with Microsoft Sentinel, the Microsoft Entra ID data connector (`SigninLogs`, `AuditLogs`) and, for the Active Directory rules, security events from the domain controllers. Details, audit policy and watchlists: [docs/deployment.md](docs/deployment.md).

```bash
git clone https://github.com/spoke1/identity-threat-detections.git
cd identity-threat-detections

az deployment group create \
  --resource-group <sentinel-resource-group> \
  --template-file deploy/sentinel-rules.bicep \
  --parameters workspaceName=<workspace-name> enableRules=false
```

`enableRules=false` creates the rules disabled, so you can review and tune them before they raise incidents.

## Quality gates

Every push runs:

- **Semantic KQL validation** of every query with [Kusto.Language](https://github.com/microsoft/Kusto-Query-Language), Microsoft's open-source KQL parser and analyser, against the column schemas of `SigninLogs`, `AuditLogs` and `SecurityEvent` from the Azure Monitor table reference. Unknown columns, tables and functions and syntax errors fail the build.
- **Rule checks** with Pester: required metadata, GUIDs, Sentinel tactic names and schedule limits, ATT&CK ID format and reference links, entity mappings that point to columns of the query output, declared data types that match the tables the query reads, no tenant-specific identifiers.
- **Build check**: `dist/sentinel-rules.json` and `docs/coverage.md` must match the YAML files.
- **Bicep lint and build** of `deploy/sentinel-rules.bicep` against the resource type schema.
- **gitleaks** secret scan of the full history.

The validation is static. It proves that a query is well-formed against the schema, not that it finds an attack; see the roadmap.

## Development

```powershell
Install-Module Pester, PSScriptAnalyzer, powershell-yaml -Scope CurrentUser

# Validate all queries (downloads the pinned Kusto.Language package on first run)
.\scripts\Test-DetectionQuery.ps1

# Regenerate the Sentinel rules and the coverage page after changing a YAML file
.\scripts\Build-SentinelRules.ps1

Invoke-Pester ./tests
```

## Repository structure

```text
detections/
  entra-id/                 ITD-E*** rules (SigninLogs, AuditLogs)
  active-directory/         ITD-A*** rules (SecurityEvent)
schemas/
  log-analytics.json        Column schemas used for query validation
  attack-techniques.json    ATT&CK technique names
scripts/
  Test-DetectionQuery.ps1   Semantic KQL validation
  Build-SentinelRules.ps1   YAML to Sentinel rule properties and coverage page
  Get-KustoLanguage.ps1     Pinned, checksum-verified download of Kusto.Language
dist/sentinel-rules.json    Generated rule properties (do not edit)
deploy/sentinel-rules.bicep Deployment of all rules to a workspace
docs/                       Deployment guide, ATT&CK coverage
tests/                      Pester tests
```

## Roadmap

- [x] Entra ID and Active Directory rules with triage and preventive controls
- [x] Semantic KQL validation in CI
- [ ] Execution tests: run every query against synthetic attack and benign logs in the Azure Data Explorer emulator
- [ ] Microsoft Defender XDR variants (`IdentityLogonEvents`, `IdentityDirectoryEvents`) for tenants with Defender for Identity
- [ ] Rules for workload and agent identities: service principal sign-ins from new locations, unused high-privilege permissions

## Related repositories

- [id-hub](https://github.com/spoke1/id-hub): staged Conditional Access, identity security and governance baselines for Microsoft Entra ID, with a threat coverage map that links back to these rules
- [hybrid-workplace-automation](https://github.com/spoke1/hybrid-workplace-automation): read-only PowerShell tooling for AD, Entra ID and Intune, including the AD Tier-0 exposure check
- [zero-trust-iac](https://github.com/spoke1/zero-trust-iac): Bicep foundation for the security workspace, Microsoft Sentinel and Defender for Cloud

## Maintainer

Built and maintained by **Ramón Lotz**, IAM & Security Architect (Cloud Security).

[ramonlotz.de](https://ramonlotz.de) · Blog: [Access Insights](https://ramonlotz.de/blog) · [LinkedIn](https://www.linkedin.com/in/ramonlotz)

## Disclaimer

The rules are a starting point. Deploy them disabled, check the results against your own environment for a few days and tune thresholds and exclusions before you rely on them.

## License

[MIT](LICENSE)
