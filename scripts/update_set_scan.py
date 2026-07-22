#!/usr/bin/env python3
"""
ServiceNow Update Set XML Reviewer

Scans update set XML files for common issues and anti-patterns.
Exits with code 1 if any critical issues are found.

Assumes the standard ServiceNow "Retrieve Update Set" / GitLabCommitter export
shape: ONE <?xml?> document, ONE <unload> root, with <sys_update_xml> records
nested as children (not multiple concatenated documents).
"""

import re
import sys
import glob
import argparse
from lxml import etree
from dataclasses import dataclass, field
from typing import List, Optional, Set

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Patterns that suggest hardcoded environment-specific values.
# Scoped to config-shaped fields only (see check_hardcoded_values) to avoid
# false-positiving on XML namespace URIs, SOAP schemas, etc.
HARDCODED_PATTERNS = [
    (r'\bWINLAPMID\b',                    'Hardcoded MID server name'),
    (r'\blocalhost\b',                    'Hardcoded localhost reference'),
    (r'127\.0\.0\.1',                     'Hardcoded loopback IP address'),
    (r'admin:admin',                      'Hardcoded admin credentials'),
    (r'password\s*=\s*["\'][^"\']+["\']', 'Possible hardcoded password'),
]

# Fields where a bare http:// URL is actually suspicious (endpoints, aliases).
# We deliberately do NOT scan the whole payload for this -- XML namespace
# declarations (xmlns="http://www.w3.org/..."), SOAP schemas, etc. are
# extremely common and are not hardcoded endpoints.
ENDPOINT_FIELD_NAMES = {'endpoint', 'url', 'rest_endpoint', 'soap_endpoint', 'value'}
NON_HTTPS_ENDPOINT_PATTERN = re.compile(r'^http://(?!localhost)', re.IGNORECASE)

# Secret-shaped strings, independent of field name.
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                       'Possible AWS access key ID'),
    (r'-----BEGIN [A-Z ]*PRIVATE KEY-----',     'Embedded private key'),
    (r'\bgh[pousr]_[A-Za-z0-9]{20,}\b',         'Possible GitHub token'),
    (r'\bglpat-[A-Za-z0-9\-_]{20,}\b',          'Possible GitLab personal access token'),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'Possible JWT token'),
]

# sys_id pattern (32-char hex), reserved for future use (e.g. cross-referencing).
SYS_ID_PATTERN = re.compile(r'(?<![a-zA-Z_"])([0-9a-f]{32})(?![0-9a-f])')

# Tables that should always have an ACL present somewhere in the update set.
TABLES_REQUIRING_ACLS = {'sp_widget', 'sys_script_include', 'sys_ui_page', 'sys_ws_operation'}

# Known dangerous JS patterns in client scripts.
DANGEROUS_JS_PATTERNS = [
    (r'contentWindow\.document',    'Cross-origin iframe DOM access (security risk)'),
    (r'eval\s*\(',                  'Use of eval() (security risk)'),
    (r'innerHTML\s*=',              'Direct innerHTML assignment (XSS risk)'),
    (r'document\.write\s*\(',       'Use of document.write() (security risk)'),
    (r'replaceAll\([\'"][\'"\s]*,', 'replaceAll() with empty string placeholder (likely broken URL template)'),
]

# Server-side anti-patterns. GlideRecordSecure nudge is OPT-IN (--strict) since
# plain GlideRecord is the normal, intentional choice in most script includes
# and flagging it by default drowns real issues in noise.
SERVER_ANTIPATTERNS = [
    (r'\.setLimit\(\)',  'setLimit() called with no argument', False),
    (r'gs\.log\b',       'gs.log() is deprecated, use gs.info/debug/warn/error', False),
    (r'new GlideRecord\b(?!Secure)', 'GlideRecord used instead of GlideRecordSecure', True),  # strict-only
]

REST_PATH_ISSUES = [
    (r'//', 'Double slash in REST relative path'),
    (r'\{[^}]*\s[^}]*\}', 'Path parameter contains whitespace (likely a typo)'),
]

MAX_REASONABLE_RECORD_COUNT = 300  # heuristic threshold for "wrong update set was active"

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Issue:
    severity: str          # CRITICAL, WARNING, INFO
    rule:     str
    message:  str
    file:     str
    record:   Optional[str] = None
    detail:   Optional[str] = None


@dataclass
class ReviewResult:
    file:     str
    issues:   List[Issue] = field(default_factory=list)

    @property
    def critical_count(self):
        return sum(1 for i in self.issues if i.severity == 'CRITICAL')

    @property
    def warning_count(self):
        return sum(1 for i in self.issues if i.severity == 'WARNING')

    @property
    def info_count(self):
        return sum(1 for i in self.issues if i.severity == 'INFO')


# ---------------------------------------------------------------------------
# Secure XML parsing (XXE-hardened)
# ---------------------------------------------------------------------------

def make_secure_parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        load_dtd=False,
        dtd_validation=False,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_text(element, tag, default=''):
    """Safely get text content of a direct child element."""
    child = element.find(tag)
    return (child.text or default) if child is not None else default


def extract_cdata(payload_text: str) -> str:
    """Extract content from CDATA sections within a payload string."""
    matches = re.findall(r'<!\[CDATA\[(.*?)\]\]>', payload_text, re.DOTALL)
    return '\n'.join(matches)


def parse_inner_xml(payload_element, parser: etree.XMLParser) -> Optional[etree._Element]:
    """Parse the inner XML payload (a CDATA-wrapped record snapshot)."""
    if payload_element is None or payload_element.text is None:
        return None
    raw = payload_element.text
    try:
        return etree.fromstring(raw.encode('utf-8'), parser=parser)
    except etree.XMLSyntaxError:
        return None


def get_field_text(inner_xml, field_name: str) -> str:
    """Get a field value from the inner record XML (direct child of the table root)."""
    if inner_xml is None:
        return ''
    el = inner_xml.find(field_name)
    return (el.text or '') if el is not None else ''


def inner_table_name(inner_xml) -> str:
    """
    The inner payload's root tag IS the table name in the normal case
    (e.g. <sys_script_include>...</sys_script_include>). The
    <record_update table="..."> wrapper is only used by some custom
    exporters as a fallback when payload XML couldn't be parsed --
    handle both shapes.
    """
    if inner_xml is None:
        return ''
    if inner_xml.tag == 'record_update':
        return inner_xml.get('table', '')
    return inner_xml.tag


# ---------------------------------------------------------------------------
# Check functions (each takes what it needs, returns a list of Issues)
# ---------------------------------------------------------------------------

def check_delete_actions(update_xml, file: str, record_name: str) -> List[Issue]:
    issues = []
    action = get_text(update_xml, 'action')
    record_type = get_text(update_xml, 'type')
    if action == 'DELETE':
        issues.append(Issue(
            'WARNING', 'DELETE_ACTION',
            f'DELETE action found for {record_type}: "{record_name}"',
            file, record_name,
            'Verify this deletion is intentional. DELETEs in the same update set as '
            'INSERTs can leave the instance in a broken state if the install fails midway.'
        ))
    return issues


def check_replace_on_upgrade(update_xml, file: str, record_name: str) -> List[Issue]:
    issues = []
    if get_text(update_xml, 'replace_on_upgrade').lower() == 'true':
        issues.append(Issue(
            'WARNING', 'REPLACE_ON_UPGRADE',
            f'"{record_name}" has replace_on_upgrade=true',
            file, record_name,
            'This record will be overwritten on every ServiceNow upgrade, losing any customizations.'
        ))
    return issues


def check_scope(update_xml, file: str, record_name: str) -> List[Issue]:
    issues = []
    app_el = update_xml.find('application')
    if app_el is not None and (app_el.text or '').lower() == 'global':
        record_type = get_text(update_xml, 'type')
        sensitive_types = {'Widget', 'Script Include', 'Business Rule', 'UI Action', 'Scripted REST Resource'}
        if record_type in sensitive_types:
            issues.append(Issue(
                'INFO', 'GLOBAL_SCOPE',
                f'{record_type} "{record_name}" is in the Global scope',
                file, record_name,
                'Global scope records have no isolation. Consider using a scoped application.'
            ))
    return issues


def check_cross_scope_contamination(update_xml, file: str, record_name: str,
                                     expected_scope: Optional[str]) -> List[Issue]:
    """Flag records whose application scope doesn't match the update set's dominant scope."""
    issues = []
    if not expected_scope:
        return issues
    app_el = update_xml.find('application')
    record_scope = (app_el.text or '') if app_el is not None else ''
    if record_scope and record_scope != expected_scope:
        issues.append(Issue(
            'WARNING', 'CROSS_SCOPE_CONTAMINATION',
            f'"{record_name}" belongs to scope "{record_scope}", but this update set is '
            f'predominantly scope "{expected_scope}"',
            file, record_name,
            'This often means the wrong application was active when the change was made. '
            'Verify it belongs in this update set.'
        ))
    return issues


def check_require_confirmation(inner_xml, file: str, record_name: str) -> List[Issue]:
    issues = []
    if inner_xml is None:
        return issues
    rc = inner_xml.find('require_confirmation')
    if rc is not None and (rc.text or '').lower() == 'true':
        issues.append(Issue(
            'INFO', 'REQUIRE_CONFIRMATION',
            f'"{record_name}" has require_confirmation=true',
            file, record_name,
            'Users will see a confirmation dialog before navigating. Verify this UX is intentional.'
        ))
    return issues


def check_public_widget(inner_xml, file: str, record_name: str) -> List[Issue]:
    issues = []
    if inner_xml is None:
        return issues
    public_el = inner_xml.find('public')
    if public_el is not None and (public_el.text or '').lower() == 'true':
        issues.append(Issue(
            'WARNING', 'PUBLIC_WIDGET',
            f'Widget "{record_name}" is marked public=true',
            file, record_name,
            'Public widgets are accessible without authentication. Verify this is intentional.'
        ))
    return issues


def check_hardcoded_values(text: str, file: str, record_name: str) -> List[Issue]:
    issues = []
    for pattern, description in HARDCODED_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append(Issue(
                'CRITICAL', 'HARDCODED_VALUE',
                f'{description} in "{record_name}"',
                file, record_name, f'Pattern matched: {pattern}'
            ))
    return issues


def check_secrets(text: str, file: str, record_name: str) -> List[Issue]:
    issues = []
    for pattern, description in SECRET_PATTERNS:
        if re.search(pattern, text):
            issues.append(Issue(
                'CRITICAL', 'POSSIBLE_SECRET',
                f'{description} in "{record_name}"',
                file, record_name,
                'Rotate this credential immediately if it is real, and remove it from source control history.'
            ))
    return issues


def check_endpoint_fields(inner_xml, file: str, record_name: str) -> List[Issue]:
    """Only flags non-HTTPS URLs in fields that are actually meant to hold endpoints."""
    issues = []
    if inner_xml is None:
        return issues
    for field_name in ENDPOINT_FIELD_NAMES:
        el = inner_xml.find(field_name)
        if el is not None and el.text and NON_HTTPS_ENDPOINT_PATTERN.match(el.text.strip()):
            issues.append(Issue(
                'WARNING', 'NON_HTTPS_ENDPOINT',
                f'Non-HTTPS endpoint in field "{field_name}" of "{record_name}": {el.text.strip()}',
                file, record_name
            ))
    return issues


def check_dangerous_js(script: str, file: str, record_name: str) -> List[Issue]:
    issues = []
    for pattern, description in DANGEROUS_JS_PATTERNS:
        if re.search(pattern, script, re.DOTALL):
            issues.append(Issue(
                'CRITICAL', 'DANGEROUS_JS',
                f'{description} in "{record_name}"',
                file, record_name, f'Pattern matched: {pattern}'
            ))
    return issues


def check_server_antipatterns(script: str, file: str, record_name: str, strict: bool) -> List[Issue]:
    issues = []
    for pattern, description, strict_only in SERVER_ANTIPATTERNS:
        if strict_only and not strict:
            continue
        if re.search(pattern, script):
            issues.append(Issue(
                'WARNING', 'SERVER_ANTIPATTERN',
                f'{description} in "{record_name}"',
                file, record_name, f'Pattern matched: {pattern}'
            ))
    return issues


def check_acl_missing(table: str, file: str, record_name: str, acl_tables_seen: Set[str]) -> List[Issue]:
    issues = []
    if table in TABLES_REQUIRING_ACLS and table not in acl_tables_seen:
        issues.append(Issue(
            'INFO', 'MISSING_ACL',
            f'No ACL found for table "{table}" containing "{record_name}"',
            file, record_name,
            'Ensure an ACL exists for this table either in this update set or already on the target instance.'
        ))
    return issues


def check_permissive_acl(inner_xml, file: str, record_name: str) -> List[Issue]:
    issues = []
    if inner_xml is None:
        return issues
    admin_overrides = inner_xml.find('admin_overrides')
    operation = inner_xml.find('operation')
    active = inner_xml.find('active')
    if (admin_overrides is not None and (admin_overrides.text or '').lower() == 'true'
            and active is not None and (active.text or '').lower() == 'true'):
        op_text = operation.text if operation is not None else 'unknown'
        if op_text in ('write', 'delete', 'create'):
            issues.append(Issue(
                'WARNING', 'PERMISSIVE_ACL',
                f'ACL "{record_name}" allows admin_overrides=true on a "{op_text}" operation',
                file, record_name,
                'Confirm this level of access is intentional -- admin_overrides bypasses the ACL for admins, '
                'which is normal, but worth a second look on destructive operations.'
            ))
    return issues


def check_empty_payload(update_xml, payload_text: str, file: str, record_name: str) -> List[Issue]:
    issues = []
    if not payload_text or len(payload_text.strip()) < 20:
        issues.append(Issue(
            'WARNING', 'EMPTY_OR_SUSPICIOUS_PAYLOAD',
            f'"{record_name}" has an empty or suspiciously short payload',
            file, record_name,
            'This can indicate a corrupted capture or a record that failed to export correctly.'
        ))
    return issues


def check_rest_paths(inner_xml, file: str, record_name: str) -> List[Issue]:
    issues = []
    if inner_xml is None:
        return issues
    path_el = inner_xml.find('relative_path')
    if path_el is not None and path_el.text:
        for pattern, description in REST_PATH_ISSUES:
            if re.search(pattern, path_el.text):
                issues.append(Issue(
                    'WARNING', 'REST_PATH_ISSUE',
                    f'{description} in "{record_name}": {path_el.text}',
                    file, record_name
                ))
    return issues


def check_business_rule_collisions(business_rules: List[dict], file: str) -> List[Issue]:
    """business_rules: list of {name, table, when, order, active}. Flags same table/when/order collisions."""
    issues = []
    seen = {}
    for br in business_rules:
        if br['active'].lower() != 'true':
            continue
        key = (br['table'], br['when'], br['order'])
        if key in seen:
            issues.append(Issue(
                'WARNING', 'BUSINESS_RULE_ORDER_COLLISION',
                f'Business Rules "{seen[key]}" and "{br["name"]}" both run on table "{br["table"]}" '
                f'at "{br["when"]}" with order {br["order"]}',
                file, br['name'],
                'Execution order between colliding rules is not guaranteed. Assign distinct order values.'
            ))
        else:
            seen[key] = br['name']
    return issues


def check_duplicate_sys_ids(all_records: List[dict], file: str) -> List[Issue]:
    """all_records: list of {sys_id, name}. Flags the same sys_id appearing more than once."""
    issues = []
    seen = {}
    for rec in all_records:
        sid = rec['sys_id']
        if not sid:
            continue
        if sid in seen:
            issues.append(Issue(
                'WARNING', 'DUPLICATE_SYS_ID',
                f'sys_id {sid} appears more than once ("{seen[sid]}" and "{rec["name"]}")',
                file, rec['name'],
                'Can happen when update sets are merged or a record was re-captured. '
                'May cause unpredictable install order.'
            ))
        else:
            seen[sid] = rec['name']
    return issues


def check_record_count(record_count: int, file: str) -> List[Issue]:
    issues = []
    if record_count > MAX_REASONABLE_RECORD_COUNT:
        issues.append(Issue(
            'INFO', 'LARGE_UPDATE_SET',
            f'Update set contains {record_count} records',
            file, None,
            'Large update sets often mean the wrong update set was active during unrelated work. '
            'Consider splitting into smaller, purpose-scoped update sets.'
        ))
    return issues


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def review_file(xml_file: str, strict: bool = False) -> ReviewResult:
    result = ReviewResult(file=xml_file)
    parser = make_secure_parser()

    try:
        with open(xml_file, 'rb') as f:
            content = f.read()
    except Exception as e:
        result.issues.append(Issue('CRITICAL', 'FILE_READ_ERROR', f'Could not read file: {e}', xml_file))
        return result

    try:
        root = etree.fromstring(content, parser=parser)
    except etree.XMLSyntaxError as e:
        result.issues.append(Issue('CRITICAL', 'XML_PARSE_ERROR', f'Failed to parse XML: {e}', xml_file))
        return result

    update_xml_records = root.findall('.//sys_update_xml')

    # --- First pass: gather context needed by later per-record checks ---
    acl_tables_seen: Set[str] = set()
    scope_counts: dict = {}
    business_rules: List[dict] = []
    all_records: List[dict] = []

    parsed_cache = []  # (update_xml, inner_xml, payload_text, record_name, record_type, table)

    for update_xml in update_xml_records:
        record_name = get_text(update_xml, 'target_name') or get_text(update_xml, 'name')
        record_type = get_text(update_xml, 'type')
        payload_el = update_xml.find('payload')
        payload_text = payload_el.text if payload_el is not None and payload_el.text else ''
        inner_xml = parse_inner_xml(payload_el, parser)
        table = inner_table_name(inner_xml)

        if table == 'sys_security_acl':
            acl_table_el = inner_xml.find('name') if inner_xml is not None else None
            if acl_table_el is not None and acl_table_el.text:
                acl_tables_seen.add(acl_table_el.text.split('.')[0])

        app_el = update_xml.find('application')
        app_scope = app_el.text if app_el is not None and app_el.text else ''
        if app_scope:
            scope_counts[app_scope] = scope_counts.get(app_scope, 0) + 1

        if table == 'sys_script' and inner_xml is not None:
            business_rules.append({
                'name': record_name,
                'table': get_field_text(inner_xml, 'collection'),
                'when': get_field_text(inner_xml, 'when'),
                'order': get_field_text(inner_xml, 'order'),
                'active': get_field_text(inner_xml, 'active') or 'false',
            })

        sys_id_el = update_xml.find('name')  # sys_update_xml.name is typically "<table>_<sys_id>"
        target_sys_id_match = re.search(r'([0-9a-f]{32})$', sys_id_el.text) if sys_id_el is not None and sys_id_el.text else None
        all_records.append({
            'sys_id': target_sys_id_match.group(1) if target_sys_id_match else '',
            'name': record_name,
        })

        parsed_cache.append((update_xml, inner_xml, payload_text, record_name, record_type, table))

    dominant_scope = max(scope_counts, key=scope_counts.get) if scope_counts else None

    # --- Update-set-level checks ---
    result.issues.extend(check_record_count(len(update_xml_records), xml_file))
    result.issues.extend(check_business_rule_collisions(business_rules, xml_file))
    result.issues.extend(check_duplicate_sys_ids(all_records, xml_file))

    # --- Second pass: per-record checks ---
    for update_xml, inner_xml, payload_text, record_name, record_type, table in parsed_cache:
        result.issues.extend(check_delete_actions(update_xml, xml_file, record_name))
        result.issues.extend(check_replace_on_upgrade(update_xml, xml_file, record_name))
        result.issues.extend(check_scope(update_xml, xml_file, record_name))
        result.issues.extend(check_cross_scope_contamination(update_xml, xml_file, record_name, dominant_scope))
        result.issues.extend(check_require_confirmation(inner_xml, xml_file, record_name))
        result.issues.extend(check_empty_payload(update_xml, payload_text, xml_file, record_name))

        if record_type == 'Widget':
            result.issues.extend(check_public_widget(inner_xml, xml_file, record_name))

        result.issues.extend(check_hardcoded_values(payload_text, xml_file, record_name))
        result.issues.extend(check_secrets(payload_text, xml_file, record_name))
        result.issues.extend(check_endpoint_fields(inner_xml, xml_file, record_name))
        result.issues.extend(check_rest_paths(inner_xml, xml_file, record_name))

        if table == 'sys_security_acl':
            result.issues.extend(check_permissive_acl(inner_xml, xml_file, record_name))

        if inner_xml is not None:
            client_script = get_field_text(inner_xml, 'client_script')
            server_script = get_field_text(inner_xml, 'script')
            operation_script = get_field_text(inner_xml, 'operation_script')

            if client_script:
                result.issues.extend(check_dangerous_js(client_script, xml_file, record_name))

            for script_content in (server_script, operation_script):
                if script_content:
                    result.issues.extend(check_server_antipatterns(script_content, xml_file, record_name, strict))
                    result.issues.extend(check_hardcoded_values(script_content, xml_file, record_name))
                    result.issues.extend(check_secrets(script_content, xml_file, record_name))

        if table:
            result.issues.extend(check_acl_missing(table, xml_file, record_name, acl_tables_seen))

    # De-duplicate: the same secret/hardcoded-value pattern can legitimately match
    # both the full payload scan and a specific extracted script field scan.
    seen_dedupe_keys = set()
    deduped_issues = []
    for issue in result.issues:
        dedupe_key = (issue.rule, issue.record, issue.message)
        if dedupe_key not in seen_dedupe_keys:
            seen_dedupe_keys.add(dedupe_key)
            deduped_issues.append(issue)
    result.issues = deduped_issues

    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_ICON = {'CRITICAL': '\U0001F534', 'WARNING': '\U0001F7E1', 'INFO': '\U0001F7E2'}


def print_report(results: List[ReviewResult], fail_on_warning: bool = False):
    total_critical = total_warning = total_info = 0

    for result in results:
        if not result.issues:
            print(f'\n\u2705  {result.file} \u2014 No issues found')
            continue

        divider = '=' * 70
        print(f'\n{divider}')
        print(f'\U0001F4C4  {result.file}')
        print(f'    Critical: {result.critical_count}  |  '
              f'Warnings: {result.warning_count}  |  '
              f'Info: {result.info_count}')
        print(divider)

        for issue in result.issues:
            icon = SEVERITY_ICON.get(issue.severity, '\u2753')
            print(f'\n  {icon} [{issue.severity}] {issue.rule}')
            print(f'     Record : {issue.record or "N/A"}')
            print(f'     Message: {issue.message}')
            if issue.detail:
                print(f'     Detail : {issue.detail}')

        total_critical += result.critical_count
        total_warning += result.warning_count
        total_info += result.info_count

    sep = '-' * 70
    print(f'\n{sep}')
    print(f'SUMMARY  |  Files: {len(results)}  |  '
          f'Critical: {total_critical}  |  '
          f'Warnings: {total_warning}  |  '
          f'Info: {total_info}')
    print(f'{sep}\n')

    if total_critical > 0:
        print('\u274C  Review FAILED \u2014 critical issues must be resolved.')
        sys.exit(1)
    elif fail_on_warning and total_warning > 0:
        print('\u274C  Review FAILED \u2014 warnings found (--fail-on-warning is set).')
        sys.exit(1)
    else:
        print('\u2705  Review PASSED')
        sys.exit(0)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Review ServiceNow update set XML files for issues.')
    parser.add_argument(
        'files', nargs='*', default=glob.glob('update_sets/*.xml'),
        help='XML files to review (defaults to update_sets/*.xml)'
    )
    parser.add_argument(
        '--fail-on-warning', action='store_true',
        help='Exit with code 1 if any warnings are found (in addition to criticals)'
    )
    parser.add_argument(
        '--strict', action='store_true',
        help='Enable stricter, noisier checks (e.g. GlideRecord vs GlideRecordSecure)'
    )
    args = parser.parse_args()

    if not args.files:
        print('No XML files found to review.')
        sys.exit(0)

    print(f'\n\U0001F50D  Reviewing {len(args.files)} file(s)...\n')
    results = [review_file(f, strict=args.strict) for f in args.files]
    print_report(results, fail_on_warning=args.fail_on_warning)


if __name__ == '__main__':
    main()
