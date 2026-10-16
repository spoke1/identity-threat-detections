# Deployment

## 1. Data sources

| Rules | Table | Source |
|---|---|---|
| ITD-E001 to ITD-E010 | `SigninLogs`, `AuditLogs` | Microsoft Entra ID data connector, or a diagnostic setting in Entra ID that sends *SignInLogs* and *AuditLogs* to the workspace. Requires Entra ID P1 or P2. |
| ITD-A001 to ITD-A007 | `SecurityEvent` | Windows Security Events via the Azure Monitor Agent, collected from all domain controllers. ITD-A006 and ITD-A007 also benefit from member servers. |

For `SecurityEvent`, either collect *All Security Events* or use a data collection rule with a custom XPath query that contains at least these events:

```text
Security!*[System[(EventID=1102 or EventID=4624 or EventID=4625 or EventID=4662 or EventID=4706 or EventID=4707 or EventID=4716 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4769 or EventID=4771)]]
```

Event 4624 is high volume. If cost matters, collect it from domain controllers and Tier-0 servers first.

## 2. Audit policy on the domain controllers

The events above are only written when the matching audit subcategories are enabled, for example in the *Default Domain Controllers Policy* under *Advanced Audit Policy Configuration*:

| Subcategory | Setting | Events | Rules |
|---|---|---|---|
| Account Logon: Audit Kerberos Authentication Service | Failure | 4771 | ITD-A005 |
| Account Logon: Audit Kerberos Service Ticket Operations | Success | 4769 | ITD-A004 |
| Logon/Logoff: Audit Logon | Success, Failure | 4624, 4625 | ITD-A005, ITD-A007 |
| Account Management: Audit Security Group Management | Success | 4728, 4732, 4756 | ITD-A003 |
| Policy Change: Audit Authentication Policy Change | Success | 4706, 4707, 4716 | ITD-A002 |
| DS Access: Audit Directory Service Access | Success | 4662 | ITD-A001 |

Event 1102 (log cleared) is always written.

**DCSync (ITD-A001)** additionally needs an auditing entry (SACL) on the domain root object: *Everyone*, *Success*, for the extended rights *Replicating Directory Changes*, *Replicating Directory Changes All* and *Replicating Directory Changes In Filtered Set*. Without it, event 4662 is not written for replication requests.

## 3. Watchlists

Three rules read their scope from Microsoft Sentinel watchlists. Create them under **Sentinel → Configuration → Watchlist** with exactly these aliases. The rules return nothing until the watchlists exist.

| Alias | SearchKey column | Content | Used by |
|---|---|---|---|
| `BreakGlassAccounts` | `UserPrincipalName` | The user principal names of the emergency access accounts | ITD-E008 |
| `Tier0Accounts` | `SamAccountName` | sAMAccountNames of all Tier-0 admin accounts (for example the members of Domain Admins from `PrivilegedAccounts.csv` of `Get-ADTier0Exposure.ps1`) | ITD-A007 |
| `Tier0Hosts` | `HostName` | Host names without domain of domain controllers, privileged access workstations, Entra Connect, AD FS, PKI and other Tier-0 servers | ITD-A007 |

Example `Tier0Hosts.csv`:

```csv
HostName,Role
dc01,Domain controller
dc02,Domain controller
paw-adm01,Privileged access workstation
aadc01,Entra Connect
```

## 4. Deploy the rules

The deploying identity needs **Microsoft Sentinel Contributor** on the resource group of the workspace.

```bash
# Review the changes
az deployment group what-if \
  --resource-group <sentinel-resource-group> \
  --template-file deploy/sentinel-rules.bicep \
  --parameters workspaceName=<workspace-name> enableRules=false

# Deploy, rules disabled for review
az deployment group create \
  --resource-group <sentinel-resource-group> \
  --template-file deploy/sentinel-rules.bicep \
  --parameters workspaceName=<workspace-name> enableRules=false
```

Each rule uses the GUID from its YAML file as resource name. Redeploying updates the rules in place; changes made in the portal are overwritten.

The workspace and Sentinel itself can be deployed with [zero-trust-iac](https://github.com/spoke1/zero-trust-iac) (`enableSentinel = true`).

## 5. Tune before you enable

1. Run each query in **Logs** for the last 14 days.
2. Add known exceptions to the query (accounts, hosts, IP ranges), not to the watchlists that define scope.
3. Adjust the thresholds of ITD-A004, ITD-A005 and ITD-E007 to your environment.
4. Enable the rules one by one and watch the incident volume for a week.

Keep your changes in the YAML files and rebuild with `scripts/Build-SentinelRules.ps1`, so the repository stays the source of truth.

## Removing the rules

Delete the analytics rules whose display name starts with `ITD-` under **Sentinel → Analytics**, or delete the resources `Microsoft.SecurityInsights/alertRules/<guid>` with the GUIDs from `dist/sentinel-rules.json`.
