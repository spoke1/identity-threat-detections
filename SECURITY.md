# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting instead: **Security → Report a vulnerability** in this repository. You will get a response within a few working days.

## Scope

In scope are the detections, scripts and workflows in this repository, for example:

- a detection that misses the attack it claims to detect, or that can be bypassed trivially
- a query that exposes more data in incidents than it needs
- a script or workflow that downloads or runs code without verifying it
- secrets or tenant-specific identifiers committed to the repository

## Handling of secrets

This repository contains no secrets, tenant IDs, object IDs or SIDs of any environment, and it must stay that way:

- Queries contain only schema GUIDs of AD extended rights. A CI test rejects any other GUID and any domain SID.
- Scope that differs per environment (break-glass accounts, Tier-0 accounts and hosts) lives in Microsoft Sentinel watchlists, not in the queries.
- Third-party tooling (Kusto.Language, gitleaks) is pinned to a version and verified with a SHA-256 checksum before use.
- Every push and pull request is scanned with [gitleaks](https://github.com/gitleaks/gitleaks).
