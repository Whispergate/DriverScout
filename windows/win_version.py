"""
Binary Ninja plugin - Windows version-aware analysis.

Detects target Windows version from PE metadata and version-conditional code.
Annotates findings with version-specific exploitability context:
  - Mitigations present (VBS, HVCI, KDP, KVAS, CET)
  - API availability / deprecation
  - EPROCESS/TOKEN offset differences
  - Exploit technique viability per version

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
import struct
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text

# Windows version mapping from PE OS version fields
_WIN_VERSIONS = {
    (6, 1): 'Windows 7 / Server 2008 R2',
    (6, 2): 'Windows 8 / Server 2012',
    (6, 3): 'Windows 8.1 / Server 2012 R2',
    (10, 0): 'Windows 10+ / Server 2016+',
}

# Build number ranges for Windows 10+ (from linker/debug info heuristics)
_WIN10_BUILDS = {
    10240: ('1507', 'RTM'),
    10586: ('1511', 'November Update'),
    14393: ('1607', 'Anniversary Update'),
    15063: ('1703', 'Creators Update'),
    16299: ('1709', 'Fall Creators Update'),
    17134: ('1803', 'April 2018 Update'),
    17763: ('1809', 'October 2018 Update'),
    18362: ('1903', 'May 2019 Update'),
    18363: ('1909', 'November 2019 Update'),
    19041: ('2004', 'May 2020 Update'),
    19042: ('20H2', ''),
    19043: ('21H1', ''),
    19044: ('21H2', ''),
    19045: ('22H2', ''),
    22000: ('Win11 21H2', ''),
    22621: ('Win11 22H2', ''),
    22631: ('Win11 23H2', ''),
    26100: ('Win11 24H2', ''),
}

# Mitigations by version
_MITIGATIONS = {
    (6, 1): {
        'ASLR': 'Partial (opt-in)',
        'DEP': 'Yes',
        'SMEP': 'No',
        'SMAP': 'No',
        'HVCI': 'No',
        'VBS': 'No',
        'CET': 'No',
        'KDP': 'No',
        'Pool': 'Legacy pool allocator',
        'Notes': 'Most permissive target. No kernel hardening.',
    },
    (6, 3): {
        'ASLR': 'Forced',
        'DEP': 'Yes',
        'SMEP': 'Yes (if CPU supports)',
        'SMAP': 'No',
        'HVCI': 'No',
        'VBS': 'No',
        'CET': 'No',
        'KDP': 'No',
        'Pool': 'Legacy pool allocator',
        'Notes': 'SMEP blocks user-page exec from ring-0.',
    },
    (10, 0): {
        'ASLR': 'High entropy',
        'DEP': 'Yes',
        'SMEP': 'Yes',
        'SMAP': 'Yes (1903+)',
        'HVCI': 'Optional (default on newer SKUs)',
        'VBS': 'Optional (default on newer SKUs)',
        'CET': 'Yes (Win11 24H2+, kernel-mode)',
        'KDP': 'Yes (20H1+)',
        'Pool': 'Segment Heap (2004+), Legacy (1909-)',
        'Notes': 'Mitigation level varies heavily by build and SKU.',
    },
}

# APIs deprecated/restricted by version
_DEPRECATED_APIS = {
    'ExAllocatePool': {
        'deprecated_in': '2004 (19041)',
        'replacement': 'ExAllocatePool2',
        'severity': 'INFO',
    },
    'ExAllocatePoolWithTag': {
        'deprecated_in': '2004 (19041)',
        'replacement': 'ExAllocatePool2',
        'severity': 'INFO',
    },
    'NtQuerySystemInformation (SystemModuleInformation)': {
        'restricted_in': '24H2',
        'impact': 'Kernel address leak via SystemModuleInformation restricted from medium IL',
        'severity': 'MEDIUM',
    },
}

# Pool allocator change affects exploitability
_SEGMENT_HEAP_BUILD = 19041  # Win10 2004

# Technique viability matrix
_TECHNIQUE_VIABILITY = {
    'pool_overflow_header': {
        'viable_before': 19041,
        'note': 'POOL_HEADER manipulation blocked by Segment Heap (2004+)',
    },
    'bitmap_gdi_abuse': {
        'viable_before': 16299,
        'note': 'GDI bitmap abuse mitigated in RS3 (1709)',
    },
    'pipe_attribute_spray': {
        'viable_after': 17763,
        'note': '_PIPE_ATTRIBUTE available as 0x200 pool spray object',
    },
    'lstar_hijack': {
        'blocked_by': 'HVCI',
        'note': 'LSTAR write blocked with HVCI enabled (W+X on system pages)',
    },
    'user_page_exec': {
        'blocked_by': 'SMEP',
        'note': 'User-page execution from ring-0 blocked by SMEP (Win8.1+)',
    },
    'cr4_smep_disable': {
        'blocked_by': 'HVCI',
        'note': 'CR4 modifications trapped by hypervisor with HVCI',
    },
    'token_overwrite': {
        'viable_all': True,
        'note': 'Data-only attack - works regardless of HVCI/SMEP/SMAP',
    },
    'callback_removal': {
        'viable_all': True,
        'note': 'Data-only attack - remove Ob/Ps/Cm callbacks via arbitrary write',
    },
}


def _detect_pe_version(path):
    """Extract OS version and linker info from PE headers."""
    info = {}
    try:
        with open(path, 'rb') as f:
            f.seek(0x3C)
            pe_off = struct.unpack('<I', f.read(4))[0]

            f.seek(pe_off)
            if f.read(4) != b'PE\x00\x00':
                return info

            # Machine type
            machine = struct.unpack('<H', f.read(2))[0]
            info['machine'] = {0x14C: 'x86', 0x8664: 'x64', 0xAA64: 'ARM64'}.get(machine, hex(machine))

            # Timestamp
            f.seek(pe_off + 8)
            info['timestamp'] = struct.unpack('<I', f.read(4))[0]

            # Optional header
            f.seek(pe_off + 24)
            magic = struct.unpack('<H', f.read(2))[0]
            info['pe_type'] = 'PE32+' if magic == 0x20B else 'PE32'

            # Linker version
            major_link = struct.unpack('<B', f.read(1))[0]
            minor_link = struct.unpack('<B', f.read(1))[0]
            info['linker'] = '{}.{}'.format(major_link, minor_link)

            # OS version
            if magic == 0x20B:
                f.seek(pe_off + 24 + 40)
            else:
                f.seek(pe_off + 24 + 40)
            os_major = struct.unpack('<H', f.read(2))[0]
            os_minor = struct.unpack('<H', f.read(2))[0]
            info['os_version'] = (os_major, os_minor)

            # Subsystem version
            sub_major = struct.unpack('<H', f.read(2))[0]
            sub_minor = struct.unpack('<H', f.read(2))[0]
            info['subsystem_version'] = (sub_major, sub_minor)

    except Exception:
        pass
    return info


def _detect_version_checks(bv):
    """Find version-conditional code paths."""
    checks = []
    version_apis = [
        'RtlGetVersion', 'RtlVerifyVersionInfo', 'IoIsWdmVersionAvailable',
        'PsGetVersion', 'ExIsProcessorFeaturePresent',
    ]
    version_globals = [
        'NtBuildNumber', 'IoIsWdmVersionAvailable',
    ]

    for api in version_apis:
        callers = list(get_callers(bv, api))
        if callers:
            checks.append(('api', api, len(callers)))

    for g in version_globals:
        syms = bv.get_symbols_by_name(g)
        if syms:
            checks.append(('global', g, len(syms)))

    return checks


def _detect_deprecated_apis(bv):
    """Check for deprecated/restricted API usage."""
    found = []
    for api, info in _DEPRECATED_APIS.items():
        clean_name = api.split(' (')[0]
        syms = bv.get_symbols_by_name(clean_name)
        if syms:
            found.append((api, info))
    return found


def _assess_technique_viability(os_version, build_hint=None):
    """Assess exploit technique viability for detected version."""
    results = []
    for technique, info in _TECHNIQUE_VIABILITY.items():
        if info.get('viable_all'):
            results.append(('OK', technique, info['note']))
            continue

        if 'viable_before' in info:
            threshold = info['viable_before']
            if build_hint and build_hint >= threshold:
                results.append(('BLOCKED', technique, info['note']))
            elif os_version >= (10, 0):
                results.append(('DEPENDS', technique,
                    info['note'] + ' (need build number to confirm)'))
            else:
                results.append(('OK', technique, info['note']))

        elif 'blocked_by' in info:
            blocker = info['blocked_by']
            if os_version >= (10, 0):
                results.append(('DEPENDS', technique,
                    '{} (blocked if {} enabled)'.format(info['note'], blocker)))
            else:
                results.append(('OK', technique, info['note']))

        elif 'viable_after' in info:
            threshold = info['viable_after']
            if build_hint and build_hint >= threshold:
                results.append(('OK', technique, info['note']))
            elif os_version >= (10, 0):
                results.append(('DEPENDS', technique,
                    info['note'] + ' (need build number to confirm)'))
            else:
                results.append(('N/A', technique, info['note']))

    return results


def analyze_version(bv: BinaryView):
    lines = [
        "=== Windows Version-Aware Analysis ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-version.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    # PE version detection
    pe_info = _detect_pe_version(bv.file.filename)

    if pe_info:
        emit("[+] PE Metadata:")
        emit("    Architecture: {}".format(pe_info.get('machine', 'unknown')))
        emit("    PE type: {}".format(pe_info.get('pe_type', 'unknown')))
        emit("    Linker: {}".format(pe_info.get('linker', 'unknown')))

        os_ver = pe_info.get('os_version', (0, 0))
        ver_name = _WIN_VERSIONS.get(os_ver, 'Unknown ({}.{})'.format(*os_ver))
        emit("    Target OS: {} ({}.{})".format(ver_name, *os_ver))

        sub_ver = pe_info.get('subsystem_version', (0, 0))
        emit("    Subsystem version: {}.{}".format(*sub_ver))
    else:
        emit("[-] Could not parse PE headers")
        os_ver = (10, 0)

    # Linker-based build hint
    build_hint = None
    linker = pe_info.get('linker', '')
    if linker:
        try:
            major, minor = map(int, linker.split('.'))
            if major >= 14:
                # MSVC linker 14.x maps to specific VS versions / Windows SDKs
                if minor >= 40:
                    build_hint = 26100  # VS 2022 17.10+ / Win11 24H2
                elif minor >= 36:
                    build_hint = 22621  # VS 2022 17.6+ / Win11 22H2
                elif minor >= 30:
                    build_hint = 19041  # VS 2022 / Win10 2004+
                elif minor >= 20:
                    build_hint = 17763  # VS 2019 / Win10 1809
                elif minor >= 10:
                    build_hint = 14393  # VS 2017 / Win10 1607
        except Exception:
            pass

    if build_hint:
        build_info = _WIN10_BUILDS.get(build_hint)
        if build_info:
            emit("    Build hint (from linker): {} ({})".format(build_info[0], build_hint))

    # Mitigations for target
    emit("\n[>] Mitigation Context:")
    mits = _MITIGATIONS.get(os_ver, _MITIGATIONS.get((10, 0), {}))
    for k, v in sorted(mits.items()):
        emit("    {}: {}".format(k, v))

    # Version-conditional code
    emit("\n[>] Version-Conditional Code:")
    checks = _detect_version_checks(bv)
    if checks:
        for kind, name, count in checks:
            emit("    {} {} ({} references)".format(kind, name, count))
        emit("    [INFO] Driver has version-conditional paths - behavior may differ across Windows versions")
    else:
        emit("    No version checks detected - driver likely targets a single version range")

    # Deprecated API usage
    emit("\n[>] API Deprecation Check:")
    deprecated = _detect_deprecated_apis(bv)
    if deprecated:
        for api, info in deprecated:
            if 'deprecated_in' in info:
                emit("    [{}] {} deprecated in {} -> use {}".format(
                    info['severity'], api, info['deprecated_in'], info['replacement']))
            elif 'restricted_in' in info:
                emit("    [{}] {} restricted in {}".format(
                    info['severity'], api, info['restricted_in']))
                emit("         {}".format(info['impact']))
    else:
        emit("    No deprecated APIs detected")

    # Technique viability
    emit("\n[>] Exploit Technique Viability:")
    techniques = _assess_technique_viability(os_ver, build_hint)
    for status, technique, note in techniques:
        marker = {'OK': '+', 'BLOCKED': '-', 'DEPENDS': '?', 'N/A': ' '}
        emit("    [{}] {}: {}".format(marker.get(status, '?'), technique, note))

    # EPROCESS considerations
    emit("\n[>] EPROCESS/TOKEN Offset Notes:")
    if os_ver < (10, 0):
        emit("    Pre-Win10: fixed EPROCESS layout per service pack")
        emit("    Token offset: 0x208 (Win7 x64), 0x2C8 (Win8.1 x64)")
    else:
        emit("    Win10+: EPROCESS layout changes per build")
        emit("    Use PDB-based resolution or hardcoded offset table")
        if build_hint and build_hint >= _SEGMENT_HEAP_BUILD:
            emit("    [WARN] Segment Heap active - pool overflow exploitation significantly harder")

    emit("\n[+] Version analysis complete.")

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write version report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Version-Aware Analysis",
    "Detect target Windows version and assess exploit technique viability",
    analyze_version,
)
