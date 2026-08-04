# ServiceNow Update Set Review Instructions

## Repository Model

This repository contains ServiceNow artifacts exported as XML records.

Do **not** review the XML structure itself.

Instead, treat each XML file as though it represents the actual ServiceNow artifact stored in the platform. The goal is to review artifacts exactly as if they were already imported into a ServiceNow instance.

Ignore XML serialization details including:

- sys_id
- sys_created_by
- sys_created_on
- sys_updated_by
- sys_updated_on
- sys_mod_count
- update_name
- payload formatting
- XML element ordering
- CDATA wrappers

Focus only on the artifact represented by the XML.

---

## Artifact Extraction

When reviewing a record, mentally reconstruct the artifact before performing analysis.

For example:

### sys_script.xml

Treat the following fields as one Business Rule:

- script
- condition
- when
- order
- active
- filter_condition
- collection
- action_* fields

Review these fields together as a complete Business Rule.

---

### sys_script_include.xml

Treat these fields as a JavaScript class:

- script
- api_name
- name
- client_callable
- accessible_from
- extends

Ignore surrounding XML.

---

### sys_ui_action.xml

Treat as a complete UI Action using:

- script
- condition
- onclick
- form_action
- list_action
- client
- active

---

### sys_ui_policy.xml

Combine:

- conditions
- actions
- scripts

into a single UI Policy.

---

### sys_client_script.xml

Treat the script independently of XML.

Review according to Client Script best practices.

---

### sys_properties.xml

Review the property itself rather than XML formatting.

Determine whether:

- naming is appropriate
- default value is safe
- property should be documented
- security implications exist

---

### sys_dictionary.xml

Treat this as a Dictionary Entry.

Review:

- field type
- attributes
- indexing
- default values
- reference qualifiers
- choice handling
- auditing
- encryption

---

### ACL Records

Review the ACL logic using:

- operation
- condition
- script
- roles
- requires_role

Do not review XML.

---

### Scripted REST APIs

Reconstruct the API from:

- resources
- scripts
- paths
- HTTP methods

Review as an API implementation.

---

## Related XML Files

Assume XML files are part of one application.

Cross-reference artifacts when appropriate.

For example:

- Business Rules calling Script Includes
- UI Actions invoking Script Includes
- Client Scripts using GlideAjax
- Script Includes extending other Script Includes
- Flow Actions invoking Script Includes

Mention possible cross-artifact issues when evidence exists.

---

## JavaScript Extraction

Most executable code exists inside CDATA blocks.

Treat CDATA contents exactly as JavaScript source files.

Ignore XML indentation.

Ignore escaped entities.

Review only the executable code.

---

## ServiceNow XML schema

- sys_script = Business Rule
- sys_script_include = Script Include
- sys_ui_action = UI Action
- sys_ui_policy = UI Policy
- sys_ui_policy_action = UI Policy Action
- sys_client_script = Client Script
- sys_security_acl = ACL
- sys_dictionary = Dictionary Entry
- sys_db_object = Table
- sys_choice = Choice
- sys_properties = System Property
- sys_transform_map = Transform Map
- sys_transform_entry = Transform Field Map
- sys_ws_operation = Scripted REST Resource
- sys_hub_action_type_definition = Flow Action
- sys_hub_flow = Flow Designer Flow

---

## Ignore XML Noise

Never report:

- whitespace
- indentation
- XML formatting
- element ordering
- update metadata
- export formatting

These are serialization artifacts.

---

## Review Goal

Always review the logical ServiceNow artifact, **not** the XML document.

Pretend every XML file has already been imported into a ServiceNow instance and you are reviewing the resulting record directly from the platform.

---

# ServiceNow Platform Review Standards

Review every artifact as if it will be deployed to a large enterprise ServiceNow instance.

Prioritize:

1. Platform stability
2. Security
3. Performance
4. Upgrade safety
5. Maintainability
6. Code quality

Do not recommend changes based only on JavaScript style.
Favor ServiceNow platform patterns.

---

# Business Rule Review

When reviewing sys_script records, evaluate:

## Execution

Check:

- before vs after vs async appropriateness
- order of execution
- condition usage
- unnecessary execution
- recursive updates
- transaction impact

Flag:

- current.update() inside Business Rules
- GlideRecord updates against the same table
- missing conditions causing unnecessary execution
- synchronous integrations
- expensive processing in before/after rules

---

# GlideRecord Review

Analyze all GlideRecord usage.

Flag:

- queries without filters
- queries inside loops
- nested GlideRecord queries
- unnecessary database calls
- missing query limits
- querying large tables inefficiently
- retrieving unused fields
- the use of gr as a GlideRecord variable

Verify:

- get() return values are checked
- records are validated before update/delete
- updates are intentional

---

# Script Include Review

Review Script Includes as reusable application APIs.

Check:

- single responsibility
- method naming
- parameter validation
- error handling
- scope accessibility
- inheritance patterns

Flag:

- duplicated logic
- global pollution
- unnecessary client callable exposure
- business logic that belongs elsewhere

---

# Client-Side Review

For:

- sys_client_script
- sys_ui_policy
- sys_ui_action with client scripts

Check:

- GlideRecord usage on client
- excessive GlideAjax calls
- synchronous calls
- DOM manipulation
- unnecessary form refreshes
- poor user experience

---

# Security Review

Identify:

- missing ACL protections
- insecure GlideRecord access
- privilege escalation risks
- exposed Script Includes
- client-callable security issues
- sensitive information exposure
- hardcoded credentials
- unsafe input handling

---

# Integration Review

For REST, SOAP, MID Server, and integration artifacts:

Review:

- authentication handling
- timeout configuration
- retry logic
- error handling
- response validation
- logging practices
- sensitive data handling

Flag:

- credentials in scripts
- missing error handling
- synchronous calls from user transactions
- excessive logging

---

# Data Model Review

For:

- sys_dictionary
- sys_db_object
- sys_choice

Review:

- field naming
- data types
- indexing
- reference qualifiers
- choice management
- auditing
- encryption
- mandatory fields

Flag:

- unnecessary custom fields
- poor naming conventions
- missing indexes on heavily queried fields
- unsafe dictionary changes

---

# Flow Designer Review

For:

- sys_hub_flow
- sys_hub_action_type_definition

Review:

- unnecessary scripting
- error handling
- reusable actions
- input/output definitions
- transaction impact

Prefer Flow Designer capabilities over custom scripting when practical.

---

# Upgrade Safety Review

Identify customizations that may create upgrade conflicts.

Flag:

- modifying out-of-box functionality unnecessarily
- overriding platform behavior
- hardcoded sys_ids
- direct table manipulation
- unsupported APIs
- customizations that duplicate platform capabilities

---

# Application Architecture Review

Evaluate relationships between artifacts.

Identify:

- duplicate logic
- circular dependencies
- poor separation of concerns
- missing Script Includes
- excessive Business Rules
- integration logic embedded in UI components

Recommend architectural improvements when appropriate.

---

# Code Review Output

For each finding provide:

## Severity

Use:

- Critical
- High
- Medium
- Low
- Informational

## Category

Use:

- Security
- Performance
- Maintainability
- Upgrade Risk
- Architecture
- Reliability

## Finding

Describe the issue clearly.

## Evidence

Reference the artifact and relevant field/script section.

## Recommendation

Provide a specific improvement.

---

# Review Behavior

Do not report:

- XML formatting issues
- sys metadata differences
- export differences
- harmless naming preferences

Only report issues that would impact:

- production stability
- maintainability
- security
- performance
- upgradeability

When no issues are found, identify positive implementation patterns.

## Custom app vs global distinction

When reviewing scoped applications:
- Prefer scoped APIs
- Validate cross-scope access
- Avoid global dependencies

When reviewing global applications:
- Be more cautious with modifications to shared tables
- Consider enterprise impact

## Instance scan-like 

Identify patterns likely to trigger ServiceNow Instance Scan findings, including:
- GlideRecord queries without filters
- Client-side GlideRecord
- Hardcoded credentials
- Synchronous waits
- Missing ACL protections
- Deprecated APIs
