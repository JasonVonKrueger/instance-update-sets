# Instance Update Sets

Deployment pipeline repository for **ServiceNow update sets**.

## Overview

This repository stores and promotes ServiceNow update sets through a deployment pipeline process.  
It is intended to provide:

- Repeatable deployments across environments
- Better change traceability
- Version-controlled update set artifacts
- Safer promotion workflows (Dev → Test → Prod)

## Purpose

ServiceNow update sets are often moved manually between instances, which can lead to drift and inconsistent deployments.  
This repo helps standardize that process by treating update sets as deployable artifacts and tracking them in Git.

## Repository Structure

Suggested structure (customize as needed):

- `update-sets/` – exported update set XML files
- `manifests/` – metadata for release grouping and deployment order
- `scripts/` – automation scripts for validation, packaging, and promotion
- `.github/workflows/` – CI/CD workflows for pipeline execution
- `docs/` – process documentation and runbooks

## Pipeline Flow

Typical deployment flow:

1. **Export** update set(s) from source instance
2. **Commit** artifacts and metadata to this repository
3. **Validate** naming, dependencies, and file integrity
4. **Promote** through target environments (e.g., Test/UAT/Prod)
5. **Record** deployment results and references

## Branching and Promotion Model

A common model:

- `main` → production-ready state
- feature/topic branches → in-progress or environment-specific changes
- pull requests required for promotion and review

## Naming Conventions (Recommended)

For consistency, use predictable names such as:

- Update set file: `<app>_<feature>_<yyyymmdd>.xml`
- Release manifest: `release-<yyyy-mm-dd>.json`

## Change Management

Each deployment should include:

- Related ticket/change request ID
- Source and target instance details
- Dependency notes
- Validation status
- Reviewer/approver evidence (via PR history)

## Getting Started

1. Clone the repository
2. Add exported update set XML files to `update-sets/`
3. Add or update manifest metadata
4. Open a pull request for review
5. Merge after validation and approval
6. Execute deployment pipeline to target instance(s)

## Security and Compliance

- Do **not** commit credentials or secrets
- Use GitHub Secrets / OIDC / secure secret manager for auth material
- Restrict production promotion permissions
- Keep audit-friendly PR and deployment logs

## Contributing

1. Create a branch
2. Commit update set artifacts and related metadata
3. Open a PR with deployment context and validation notes
4. Request review from platform owners

## License

Add a project license if required by your organization.
