# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-16

### Added

- Ten Microsoft Entra ID detections (ITD-E001 to ITD-E010): Conditional Access changes, application credentials, consent to high-risk permissions, role assignments outside PIM, device code flow, authentication method registration after a risky sign-in, password spraying, break-glass sign-ins, federation changes and legacy authentication.
- Seven Active Directory detections (ITD-A001 to ITD-A007): DCSync, trust changes, Tier-0 group changes, Kerberoasting, password spraying, cleared security logs and Tier-0 logons outside Tier 0.
- False positives, triage steps, preventive controls and references for every detection.
- `scripts/Test-DetectionQuery.ps1`: semantic KQL validation with Kusto.Language against the table schemas.
- `scripts/Build-SentinelRules.ps1`: generates the Sentinel rule properties and the ATT&CK coverage page.
- `deploy/sentinel-rules.bicep`: deploys all rules to a Sentinel workspace.
- CI with Pester, PSScriptAnalyzer, Bicep lint and build, build check and gitleaks.
