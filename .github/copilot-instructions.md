# ServiceNow Update Set Review Instructions

## Repository Model

This repository contains ServiceNow artifacts exported as XML records.

Do **not** review the XML structure itself.

Instead, treat each XML file as though it represents the actual ServiceNow artifact stored in the platform.

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
