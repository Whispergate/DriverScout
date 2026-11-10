r"""
Binary Ninja plugin - DACL / Security Descriptor analysis.

Parses SDDL strings from IoCreateDeviceSecure calls and manual security
descriptor setup. Decodes ACEs and flags overly permissive DACLs.

SDDL Reference:
  D:(A;;GA;;;WD)     = Everyone gets GENERIC_ALL
  D:(A;;GA;;;BU)     = BUILTIN\Users gets GENERIC_ALL
  D:(A;;GA;;;BA)     = BUILTIN\Administrators gets GENERIC_ALL
  D:(A;;GA;;;SY)     = LocalSystem gets GENERIC_ALL
  D:(A;;0x1;;BU)     = BUILTIN\Users gets FILE_READ_DATA

Severity:
  - Everyone or BUILTIN\Users with GENERIC_ALL/FILE_ALL_ACCESS = CRITICAL
  - BUILTIN\Users with read/write but not GENERIC_ALL = HIGH
  - Only Administrators/System = LOW (defense-in-depth still matters)

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers

# Well-known SID abbreviations
_SID_MAP = {
    'WD': 'Everyone',
    'BA': 'BUILTIN\\Administrators',
    'BU': 'BUILTIN\\Users',
    'BG': 'BUILTIN\\Guests',
    'SY': 'NT AUTHORITY\\SYSTEM',
    'LS': 'LOCAL SERVICE',
    'NS': 'NETWORK SERVICE',
    'AU': 'Authenticated Users',
    'AN': 'Anonymous',
    'IU': 'Interactive Users',
    'SU': 'Service Logon Users',
    'NU': 'Network Logon Users',
    'RC': 'Restricted Code',
    'WR': 'Write Restricted',
    'AC': 'ALL APPLICATION PACKAGES',
    'CO': 'Creator Owner',
    'CG': 'Creator Group',
    'DA': 'Domain Admins',
    'DU': 'Domain Users',
    'DD': 'Domain Domain Controllers',
    'S-1-1-0': 'Everyone',
    'S-1-5-18': 'SYSTEM',
    'S-1-5-32-544': 'BUILTIN\\Administrators',
    'S-1-5-32-545': 'BUILTIN\\Users',
    'S-1-5-11': 'Authenticated Users',
}

# Access rights abbreviations
_ACCESS_MAP = {
    'GA': ('GENERIC_ALL', 0x10000000),
    'GR': ('GENERIC_READ', 0x80000000),
    'GW': ('GENERIC_WRITE', 0x40000000),
    'GX': ('GENERIC_EXECUTE', 0x20000000),
    'FA': ('FILE_ALL_ACCESS', 0x001F01FF),
    'FR': ('FILE_GENERIC_READ', 0x00120089),
    'FW': ('FILE_GENERIC_WRITE', 0x00120116),
    'FX': ('FILE_GENERIC_EXECUTE', 0x001200A0),
    'KA': ('KEY_ALL_ACCESS', 0x000F003F),
    'KR': ('KEY_READ', 0x00020019),
    'KW': ('KEY_WRITE', 0x00020006),
    'SD': ('DELETE', 0x00010000),
    'RC': ('READ_CONTROL', 0x00020000),
    'WD': ('WRITE_DAC', 0x00040000),
    'WO': ('WRITE_OWNER', 0x00080000),
}

# SIDs that indicate non-admin access
_NON_ADMIN_SIDS = {'WD', 'BU', 'BG', 'AU', 'AN', 'IU', 'NU', 'AC', 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'}

# High-privilege access rights
_HIGH_PRIV_ACCESS = {'GA', 'FA', 'GW', 'KA'}


def _parse_sddl(sddl):
    """Parse SDDL string into structured ACE list."""
    aces = []
    # Extract DACL section
    dacl_match = re.search(r'D:\s*(.+?)(?:\s*S:|$)', sddl)
    if not dacl_match:
        dacl_match = re.search(r'D:(.+)', sddl)
    if not dacl_match:
        return aces

    dacl = dacl_match.group(1)
    # Parse individual ACEs: (type;;rights;;;sid)
    for m in re.finditer(r'\(([^)]+)\)', dacl):
        parts = m.group(1).split(';')
        if len(parts) < 6:
            continue
        ace_type = parts[0]
        ace_flags = parts[1]
        ace_rights = parts[2]
        ace_guid = parts[3]
        ace_inherit_guid = parts[4]
        ace_sid = parts[5]

        # Resolve SID
        sid_name = _SID_MAP.get(ace_sid, ace_sid)

        # Resolve rights
        rights_desc = []
        if ace_rights in _ACCESS_MAP:
            rights_desc.append(_ACCESS_MAP[ace_rights][0])
        elif ace_rights.startswith('0x'):
            try:
                rights_desc.append('0x{:08X}'.format(int(ace_rights, 16)))
            except ValueError:
                rights_desc.append(ace_rights)
        else:
            # Multiple two-char codes concatenated
            i = 0
            while i < len(ace_rights):
                code = ace_rights[i:i+2]
                if code in _ACCESS_MAP:
                    rights_desc.append(_ACCESS_MAP[code][0])
                else:
                    rights_desc.append(code)
                i += 2

        aces.append({
            'type': ace_type,
            'flags': ace_flags,
            'rights': ace_rights,
            'rights_desc': rights_desc,
            'sid': ace_sid,
            'sid_name': sid_name,
            'raw': m.group(0),
        })

    return aces


def _assess_ace_risk(ace):
    """Return severity for a single ACE."""
    is_allow = ace['type'] == 'A'
    if not is_allow:
        return 'INFO'

    is_non_admin = ace['sid'] in _NON_ADMIN_SIDS
    has_high_priv = bool(set(ace['rights'][i:i+2] for i in range(0, len(ace['rights']), 2)) & _HIGH_PRIV_ACCESS)

    # Check hex rights for GENERIC_ALL / FILE_ALL_ACCESS
    if ace['rights'].startswith('0x'):
        try:
            val = int(ace['rights'], 16)
            if val & 0x10000000 or val == 0x001F01FF:
                has_high_priv = True
        except ValueError:
            pass

    if is_non_admin and has_high_priv:
        return 'CRITICAL'
    elif is_non_admin:
        return 'HIGH'
    elif has_high_priv:
        return 'MEDIUM'
    return 'LOW'


def _find_sddl_strings(bv):
    """Find SDDL strings in binary via string scan and HLIL scan."""
    sddl_strings = []
    seen = set()

    # String table scan
    for s in bv.strings:
        try:
            val = s.value
            if 'D:' in val and '(' in val and ')' in val:
                if re.search(r'D:\s*\(', val):
                    if val not in seen:
                        seen.add(val)
                        sddl_strings.append(('string_table', val, s.start))
        except Exception:
            pass

    # HLIL scan in IoCreateDeviceSecure callers
    for api in ['IoCreateDeviceSecure', 'WdmlibIoCreateDeviceSecure',
                'RtlCreateSecurityDescriptorRelative']:
        for func, ref_addr in get_callers(bv, api):
            dt = get_hlil_text(func)
            for m in re.finditer(r'"([^"]*D:\s*\([^"]*)"', dt):
                val = m.group(1)
                if val not in seen:
                    seen.add(val)
                    sddl_strings.append(('hlil', val, ref_addr))

    return sddl_strings


def _check_null_dacl(bv):
    """Detect IoCreateDevice without any DACL setup."""
    findings = []
    has_create = any(bv.get_symbols_by_name(n) for n in ['IoCreateDevice'])
    has_secure = any(bv.get_symbols_by_name(n) for n in ['IoCreateDeviceSecure', 'WdmlibIoCreateDeviceSecure'])
    has_manual = any(bv.get_symbols_by_name(n) for n in [
        'RtlCreateSecurityDescriptor', 'ObSetSecurityDescriptorInfo',
        'SeSetSecurityDescriptorInfo', 'ZwSetSecurityObject',
    ])

    if has_create and not has_secure and not has_manual:
        has_symlink = any(bv.get_symbols_by_name(n) for n in ['IoCreateSymbolicLink'])
        sev = 'HIGH' if has_symlink else 'MEDIUM'
        findings.append((sev,
            'IoCreateDevice without IoCreateDeviceSecure or manual DACL setup',
            'Default DACL allows non-admin access; symbolic link exposes to Win32 API'))
    return findings


def _check_manual_sd(bv):
    """Detect manual security descriptor construction and analyze."""
    findings = []
    for api in ['RtlCreateSecurityDescriptor', 'SeSetSecurityDescriptorInfo']:
        for func, ref_addr in get_callers(bv, api):
            dt = get_hlil_text(func)
            if 'NULL' in dt or ', 0,' in dt:
                findings.append(('HIGH',
                    'Manual security descriptor in {} may set NULL DACL'.format(func.name),
                    'NULL DACL = unrestricted access from any user'))
    return findings


def analyze_dacl(bv: BinaryView):
    lines = [
        "=== DACL / Security Descriptor Analysis ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-dacl.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    # SDDL strings
    sddl_found = _find_sddl_strings(bv)
    if sddl_found:
        emit("[+] SDDL strings found: {}".format(len(sddl_found)))
        for source, sddl, addr in sddl_found:
            emit("\n  SDDL at 0x{:x} ({}):".format(addr, source))
            emit("    Raw: {}".format(sddl))
            aces = _parse_sddl(sddl)
            if aces:
                overall_risk = 'LOW'
                for ace in aces:
                    risk = _assess_ace_risk(ace)
                    type_desc = 'Allow' if ace['type'] == 'A' else 'Deny' if ace['type'] == 'D' else ace['type']
                    emit("    [{}] {} {} -> {}".format(
                        risk, type_desc, ace['sid_name'],
                        ", ".join(ace['rights_desc'])))
                    if risk == 'CRITICAL':
                        overall_risk = 'CRITICAL'
                    elif risk == 'HIGH' and overall_risk not in ('CRITICAL',):
                        overall_risk = 'HIGH'
                    elif risk == 'MEDIUM' and overall_risk == 'LOW':
                        overall_risk = 'MEDIUM'
                emit("    Overall DACL risk: {}".format(overall_risk))
                if overall_risk in ('CRITICAL', 'HIGH'):
                    emit("    [!!!] Non-admin users can open this device - exploitable without elevation")
            else:
                emit("    (could not parse SDDL ACEs)")
    else:
        emit("[-] No SDDL strings found in binary")

    # NULL DACL check
    emit("\n[>] Device creation ACL check...")
    for sev, desc, detail in _check_null_dacl(bv):
        emit("    [{}] {}".format(sev, desc))
        emit("         {}".format(detail))

    # Manual SD check
    for sev, desc, detail in _check_manual_sd(bv):
        emit("    [{}] {}".format(sev, desc))
        emit("         {}".format(detail))

    # Cross-reference DACL with detected primitives
    emit("\n[>] DACL vs Primitive cross-reference...")
    try:
        from .win_primitives import find_exploit_primitives
        emit("    (run Exploit Primitive Finder separately and cross-reference)")
        emit("    Non-admin DACL + CRITICAL primitive = immediate BYOVD candidate")
    except ImportError:
        pass

    emit("\n[+] DACL analysis complete.")

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write DACL report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\DACL Analysis",
    "Parse SDDL strings and assess device object access control",
    analyze_dacl,
)
