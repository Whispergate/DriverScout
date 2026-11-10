"""
Binary Ninja plugin - Windows kernel driver vulnerability triage.

Surfaces:
  - DriverEntry location (exact or heuristic)
  - Device names (\\Device\\, \\DosDevices\\, etc.)
  - Pool tags (ExAllocatePool* argument scanning via MLIL)
  - Dangerous opcodes: rdpmc / rdmsr / wrmsr / control reg / port IO
  - Dangerous C functions: sprintf / memcpy / memmove / RtlCopyMemory
  - Windows kernel API inventory (Mm*, Zw*, Io*, Flt*, ProbeFor*, Rtl*, Ob*)
  - IOCTL enumeration (via shared dispatch + IOCTL modules)
  - Physical memory / IO space: MmMapIoSpace, MmCopyMemory, ZwOpenSection
  - General vuln patterns:
      * Uninstrumented copies: memcpy/RtlCopyMemory near user buffer without ProbeFor
      * Integer-overflow allocations: ExAllocatePool near user input without safe arithmetic
      * Missing privilege gate: sensitive ops without SeSinglePrivilegeCheck
      * Missing METHOD_NEITHER probes

Uses shared modules: dispatch.py, ioctl_shared.py, primitive_db.py, helpers.py

Output: Binary Ninja log + report at ~/.logs/WinDriverVulns/<name>-win-vulns.txt
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers
from ..shared.dispatch import find_dispatch_routines
from ..shared.ioctl_shared import (
    ctl_decode, format_ioctl, fmt_ioctl_row, find_ioctls_in_func,
    plausible_ioctl, METHOD_MAP, extract_const, iter_case_consts,
    ioctl_branches_for_dispatcher, resolve_callee_name,
)
from ..shared.primitive_db import (
    scan_text_for_vulns, NAME_VULN_HINTS, NAME_HINT_SKIP_PREFIX,
    walk_collect_text, walk_collect_calls, branch_text, branch_callees,
    walk_callees_recursive, deep_text, MAX_CLASSIFY_DEPTH, MAX_CALLEES_PER_LEVEL,
    MAX_DEEP_CALLEES,
)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_OPCODE_SEVERITY = {
    'rdpmc': 'HIGH', 'rdmsr': 'HIGH', 'wrmsr': 'HIGH',
    'in': 'HIGH', 'out': 'HIGH', 'hlt': 'HIGH',
    'cli': 'MEDIUM', 'sti': 'MEDIUM',
    'invd': 'HIGH', 'wbinvd': 'MEDIUM',
    'lgdt': 'HIGH', 'lidt': 'HIGH',
    'swapgs': 'HIGH', 'xsetbv': 'HIGH',
}

_INTRINSIC_OPCODES = {
    '__rdmsr': 'HIGH', '__wrmsr': 'HIGH',
    '_rdpmc': 'HIGH', '__rdpmc': 'HIGH',
    '__in_': 'HIGH', '__out_': 'HIGH',
    '__halt': 'HIGH', 'trap(0xd)': 'HIGH',
    '__readcr': 'HIGH', '__writecr': 'HIGH',
    '__readdr': 'HIGH', '__writedr': 'HIGH',
    '__lgdt': 'HIGH', '__lidt': 'HIGH',
    '__sgdt': 'MEDIUM', '__sidt': 'MEDIUM',
    '__swapgs': 'HIGH', '__invd': 'HIGH', '__wbinvd': 'MEDIUM',
    '__cli': 'MEDIUM', '__sti': 'MEDIUM',
    '__cpuid': 'LOW',
}

_C_FUNCS = ['sprintf', 'swprintf', 'snprintf', 'vsprintf',
            'memcpy', 'memmove', 'RtlCopyMemory',
            'strcpy', 'strcat', 'wcscpy', 'wcscat']

_WINAPI_PREFIXES = [
    'ProbeFor', 'Rtl', 'Ob', 'Zw', 'Mm',
    'IofCallDriver', 'Io', 'Flt', 'ExAllocatePool', 'Se',
]

_DRIVER_INDICATORS = [
    'IoCreateDevice', 'IoCreateSymbolicLink', 'IoRegisterDeviceInterface',
    'FltRegisterFilter', 'FltStartFiltering', 'RtlInitUnicodeString',
]

_PHYSMEM_APIS = [
    'ZwOpenSection', 'ZwMapViewOfSection',
    'MmCopyMemory', 'MmMapIoSpace', 'MmMapIoSpaceEx',
    'MmGetPhysicalAddress', 'MmAllocateContiguousMemory',
    'MmProbeAndLockPages', 'MmMapLockedPagesSpecifyCache',
    'MmGetSystemAddressForMdlSafe',
    'HalGetBusDataByOffset', 'HalSetBusDataByOffset',
    'HalGetBusData', 'HalSetBusData',
]

_ALLOC_NAMES = [
    'ExAllocatePool', 'ExAllocatePoolWithTag',
    'ExAllocatePool2', 'ExAllocatePoolWithTagPriority',
]
_FREE_NAMES = ['ExFreePoolWithTag', 'ExFreePool']

_STRING_COPY_NAMES = ['memcpy', 'memmove', 'RtlCopyMemory', 'RtlCopyUnicodeString']

_PRIV_GUARD_APIS = [
    'SeSinglePrivilegeCheck', 'SeAccessCheck',
    'ZwQueryInformationToken', 'IoIsSystemThread',
    'PsGetCurrentProcess', 'SeTokenIsAdmin',
]

_DEVICE_INDICATORS = ["\\device\\", "\\dosdevices\\", "\\\\.\\", "\\??\\"]

# ---------------------------------------------------------------------------
# New detection: ALPC, WNF, Power IRP, WMI, NDIS, WFP, PNP dispatch
# ---------------------------------------------------------------------------

_ALPC_APIS = [
    'AlpcRegisterWaitReceivePort', 'AlpcSendWaitReceivePort',
    'AlpcCreatePortSection', 'AlpcCreateSecurityContext',
    'AlpcConnectPort', 'AlpcDisconnectPort',
]

_WNF_APIS = [
    'WnfSubscribeToStateName', 'WnfPublishStateName',
    'NtUpdateWnfStateData', 'NtQueryWnfStateData',
]

_POWER_IRP_TYPES = [
    'IRP_MJ_POWER', 'IRP_MN_SET_POWER', 'IRP_MN_QUERY_POWER',
    'IRP_MN_WAIT_WAKE', 'PoRegisterSystemState', 'PoSetSystemState',
]

_WMI_APIS = [
    'IoWMIRegistrationControl', 'WmiCompleteRequest',
    'WmiFireEvent', 'WmiQueryTraceInformation',
]

_NDIS_APIS = [
    'NdisRegisterProtocolDriver', 'NdisRegisterMiniportDriver',
    'NdisRegisterFilterDriver', 'NdisRegisterIntermediateDriver',
    'NdisAllocateMemoryWithTagPriority',
]

_WFP_APIS = [
    'FwpsCalloutRegister', 'FwpsFlowAssociateContext',
    'FwpsInjectNetworkReceiveAsync', 'FwpsInjectNetworkSendAsync',
    'FwpsAllocateNetBufferAndNetBufferList',
]

_PNP_DISPATCH_TYPES = [
    'IRP_MJ_PNP', 'IRP_MN_START_DEVICE', 'IRP_MN_REMOVE_DEVICE',
    'IRP_MN_QUERY_REMOVE_DEVICE', 'IRP_MN_DEVICE_USAGE_NOTIFICATION',
]

_CANCELLATION_APIS = [
    'IoSetCancelRoutine', 'IoCancelIrp', 'IoAcquireCancelSpinLock',
    'IoReleaseCancelSpinLock',
]

_OB_CALLBACK_APIS = [
    'ObRegisterCallbacks', 'ObUnRegisterCallbacks',
    'ObGetFilterVersion',
]

_EX_CALLBACK_APIS = [
    'ExRegisterCallback', 'CmRegisterCallback',
    'CmRegisterCallbackEx', 'SeRegisterLogonSessionTerminatedRoutine',
]


def _looks_user_driven_win(dt):
    keys = [
        'Parameters.DeviceIoControl.InputBufferLength',
        'Parameters.DeviceIoControl.OutputBufferLength',
        'Parameters.DeviceIoControl.Type3InputBuffer',
        'Irp->AssociatedIrp.SystemBuffer',
        'AssociatedIrp.SystemBuffer',
        'AssociatedIrp.MasterIrp',
        'Irp->UserBuffer',
        'UserBuffer',
        'MdlAddress',
        '+ 0x8)', '+ 0x10)', '+ 0x18)',
    ]
    return any(k in dt for k in keys)


# ---------------------------------------------------------------------------
# Pool tag collection via MLIL
# ---------------------------------------------------------------------------

def _decode_pooltag(val):
    v = val & 0xFFFFFFFF
    return ''.join(chr((v >> (8 * i)) & 0xFF) for i in range(4))


def _likely_pooltag_dword(val):
    s = _decode_pooltag(val)
    return all(32 <= ord(c) <= 126 for c in s) and sum(c.isalnum() for c in s) >= 2


def _collect_pooltags(bv: BinaryView):
    tags = {}
    for alloc_name in _ALLOC_NAMES:
        for func, ref_addr in get_callers(bv, alloc_name):
            try:
                mlil = func.mlil
                if not mlil:
                    continue
                idx = mlil.get_instruction_start(ref_addr)
                if idx is None:
                    continue
                instr = mlil[idx]
                for param in getattr(instr, 'params', []):
                    try:
                        val = param.constant & 0xFFFFFFFF
                        if _likely_pooltag_dword(val):
                            tag = ''.join(
                                c if 32 <= ord(c) <= 126 else '.'
                                for c in _decode_pooltag(val)
                            )
                            tags.setdefault(tag, set()).add(func.name)
                    except Exception:
                        pass
            except Exception:
                pass
    return tags


# ---------------------------------------------------------------------------
# Vulnerability classification
# ---------------------------------------------------------------------------

def _classify_branch_vulns(bv, instrs):
    """Given list of HLIL instructions forming a handler branch, return vuln labels.

    Walks call graph up to MAX_CLASSIFY_DEPTH deep catching
    Handler -> Trigger -> primitive wrapper chains.
    """
    text_parts = []
    direct_callees = set()
    for instr in instrs:
        walk_collect_text(instr, text_parts)
        walk_collect_calls(instr, direct_callees)
    branch_text_str = "\n".join(text_parts)
    vulns = scan_text_for_vulns(branch_text_str)

    visited = set()
    for caddr in direct_callees:
        for sub_f in walk_callees_recursive(bv, caddr, MAX_CLASSIFY_DEPTH, visited):
            try:
                ctext = get_hlil_text(sub_f)
            except Exception:
                continue
            for v in scan_text_for_vulns(ctext):
                vulns.add("{} (via {})".format(v, sub_f.name))

    name_hint_vulns = _scan_callee_names_for_vulns(bv, direct_callees, visited)
    vulns |= name_hint_vulns
    return vulns, direct_callees


def _scan_callee_names_for_vulns(bv, direct_callees, visited_extra):
    """Name-pattern fallback - HEVD names its handlers literally after the bug class."""
    hits = set()
    visited = set(visited_extra)
    for caddr in direct_callees:
        f = bv.get_function_at(caddr)
        for sub_f in walk_callees_recursive(bv, caddr, MAX_CLASSIFY_DEPTH, visited):
            if sub_f.name and not sub_f.name.startswith(NAME_HINT_SKIP_PREFIX):
                nl = sub_f.name.lower().replace('_', '').replace('-', '')
                for needle, label in NAME_VULN_HINTS.items():
                    if needle in nl:
                        hits.add("{} via {}".format(label, sub_f.name))
    return hits


# ---------------------------------------------------------------------------
# IOCTL-to-Vuln mapping
# ---------------------------------------------------------------------------

def _emit_ioctl_vuln_map(bv, emit):
    """Map each IOCTL constant in each dispatcher to vuln APIs/intrinsics."""
    dispatchers = find_dispatch_routines(bv)
    if not dispatchers:
        emit("    (no dispatcher)")
        return
    rows = []
    for df in dispatchers:
        branches = ioctl_branches_for_dispatcher(df)
        by_code = {}
        for entry in branches:
            code, instrs = entry[0], entry[1]
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in by_code.items():
            vulns, callees = _classify_branch_vulns(bv, instrs)
            callee_names = sorted({resolve_callee_name(bv, c) for c in callees})
            rows.append((code, df.name, vulns, callee_names))
    if not rows:
        emit("    (none)")
        return
    for code, dname, vulns, callees in sorted(rows, key=lambda x: x[0]):
        d = ctl_decode(code)
        method = METHOD_MAP.get(d['method'], str(d['method']))
        vlabel = ", ".join(sorted(vulns)) if vulns else "(no dangerous calls/intrinsics)"
        clabel = ", ".join(callees) if callees else "inline"
        sev = "HIGH" if vulns else "INFO"
        emit("    [{}] IOCTL 0x{:08X} ({}) in {}  ->  calls: {}  ::  {}".format(
            sev, code, method, dname, clabel, vlabel))


# ---------------------------------------------------------------------------
# Expanded vulnerability scanning helpers
# ---------------------------------------------------------------------------

def _scan_expanded_surface(bv, emit):
    """Scan for additional kernel driver attack surface beyond IOCTL dispatch."""
    emitted = set()

    for func in bv.functions:
        dt = get_hlil_text(func)
        if not dt:
            continue

        # ALPC port abuse
        for api in _ALPC_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [HIGH] ALPC port abuse: {} in {}".format(api, func.name))

        # WNF state data - newer pool spray target for Windows 11
        for api in _WNF_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [MEDIUM] WNF state manipulation: {} in {}".format(api, func.name))

        # Power IRP handlers
        for api in _POWER_IRP_TYPES:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [MEDIUM] Power IRP handler: {} in {}".format(api, func.name))

        # WMI data providers (kernel-mode WMI can leak kernel memory)
        for api in _WMI_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [MEDIUM] WMI data provider: {} in {}".format(api, func.name))

        # NDIS driver types
        for api in _NDIS_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [INFO] NDIS driver: {} in {}".format(api, func.name))

        # WFP callout drivers (can intercept/modify network traffic from kernel)
        for api in _WFP_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [HIGH] WFP callout driver: {} in {}".format(api, func.name))

        # PNP dispatch
        for api in _PNP_DISPATCH_TYPES:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [MEDIUM] PNP dispatch handler: {} in {}".format(api, func.name))

        # I/O cancellation races
        for api in _CANCELLATION_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [MEDIUM] Cancel routine: {} in {}".format(api, func.name))

        # ObRegisterCallbacks - process/thread handle callbacks
        for api in _OB_CALLBACK_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [HIGH] Object callback: {} in {}".format(api, func.name))

        # ExRegisterCallback - callback-based drivers
        for api in _EX_CALLBACK_APIS:
            if api in dt and api not in emitted:
                emitted.add(api)
                emit("    [MEDIUM] System callback: {} in {}".format(api, func.name))

        # IoCreateDeviceSecure / FILE_DEVICE_SECURE_OPEN flag check
        if 'IoCreateDevice' in dt and 'IoCreateDeviceSecure' not in dt and func.name not in emitted:
            emitted.add(func.name)
            emit("    [MEDIUM] IoCreateDevice without IoCreateDeviceSecure in {}".format(func.name))

    return emitted


# ---------------------------------------------------------------------------
# Main plugin entry
# ---------------------------------------------------------------------------

def find_driver_vulns(bv: BinaryView):
    lines = [
        "=== Windows Kernel Driver Vulnerability Report ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]

    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-win-vulns.txt')

    def emit(line):
        lines.append(line)
        log_info(line)

    # ---- DriverEntry discovery ----
    emit("[>] Locating DriverEntry...")
    driver_entry = None
    for func in bv.functions:
        nm = func.name
        if nm == 'DriverEntry' or nm.lower().endswith('driverentry'):
            driver_entry = func
            break

    if not driver_entry:
        best, best_score = None, -1
        for func in bv.functions:
            dt = get_hlil_text(func)
            score = sum(1 for ind in _DRIVER_INDICATORS if ind in dt)
            if dt.count('RtlInitUnicodeString') >= 2:
                score += 1
            if 'IoCreateDevice' in dt and 'IoCreateSymbolicLink' in dt:
                score += 2
            if 'FltRegisterFilter' in dt:
                score += 2
            if score > best_score:
                best, best_score = func, score
        if best and best_score >= 2:
            driver_entry = best

    if driver_entry:
        emit("[+] DriverEntry: {} at 0x{:x}".format(driver_entry.name, driver_entry.start))
    else:
        emit("[-] DriverEntry: NOT FOUND")

    # ---- Device names ----
    emit("[>] Device names...")
    devices = set()
    for s in bv.strings:
        try:
            val = s.value
            if any(k in val.lower() for k in _DEVICE_INDICATORS):
                devices.add(val)
        except Exception:
            pass
    for d in sorted(devices):
        emit("    {}".format(d))
    if not devices:
        emit("    (none)")

    # ---- Pool tags ----
    emit("[>] Pool tags...")
    pooltags = _collect_pooltags(bv)
    for tag in sorted(pooltags):
        emit("    {} - called by: {}".format(tag, ', '.join(sorted(pooltags[tag]))))
    if not pooltags:
        emit("    (none)")

    # ---- Opcodes (raw + HLIL intrinsic) ----
    emit("[>] Dangerous opcodes (raw mnemonic + HLIL intrinsic)...")
    opcode_hits = []
    seen_op = set()
    for func in bv.functions:
        try:
            for block in func.basic_blocks:
                for dl in block.disassembly_text:
                    if not dl.tokens:
                        continue
                    mnem = None
                    for tok in dl.tokens:
                        t = tok.text.strip().lower()
                        if t:
                            mnem = t
                            break
                    if mnem and mnem in _OPCODE_SEVERITY:
                        key = (mnem, func.start, dl.address)
                        if key not in seen_op:
                            seen_op.add(key)
                            opcode_hits.append(
                                (_OPCODE_SEVERITY[mnem], mnem, func.name, "0x{:x}".format(dl.address)))
        except Exception:
            pass
    # HLIL intrinsic scan
    for func in bv.functions:
        dt = get_hlil_text(func)
        for intr, sev in _INTRINSIC_OPCODES.items():
            if intr in dt:
                key = (intr, func.start)
                if key not in seen_op:
                    seen_op.add(key)
                    opcode_hits.append((sev, intr, func.name, "0x{:x}".format(func.start)))
    for sev, mnem, fn, addr in opcode_hits:
        emit("    [{}] {} in {} at {}".format(sev, mnem, fn, addr))
    if not opcode_hits:
        emit("    (none)")

    # ---- C functions ----
    emit("[>] Dangerous C functions...")
    cfunc_hits = []
    for func in bv.functions:
        dt = get_hlil_text(func)
        for cfn in _C_FUNCS:
            if cfn in dt:
                cfunc_hits.append((cfn, func.name))
    for cfn, fn in cfunc_hits:
        emit("    {} in {}".format(cfn, fn))
    if not cfunc_hits:
        emit("    (none)")

    # ---- Kernel API inventory ----
    emit("[>] Windows kernel API inventory...")
    api_hits = set()
    for func in bv.functions:
        dt = get_hlil_text(func)
        for prefix in _WINAPI_PREFIXES:
            for m in re.finditer(r'\b' + re.escape(prefix) + r'\w+\b', dt):
                api_hits.add(m.group(0))
    for api in sorted(api_hits):
        emit("    {}".format(api))
    if not api_hits:
        emit("    (none)")

    # ---- Physical memory / IO space ----
    emit("[>] Physical memory / IO space APIs...")
    phys_hits = []
    for func in bv.functions:
        dt = get_hlil_text(func)
        for api in _PHYSMEM_APIS:
            if api in dt:
                phys_hits.append((api, func.name))
    for api, fn in phys_hits:
        emit("    [CRITICAL] {} in {}".format(api, fn))
    if not phys_hits:
        emit("    (none)")

    # ---- Port/register IO from IOCTL context ----
    emit("[>] Port/register IO from user-reachable context...")
    port_hits = []
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not _looks_user_driven_win(dt):
            continue
        for pat in ['READ_PORT_', 'WRITE_PORT_', '__in', '__out']:
            for m in re.finditer(r'\b' + re.escape(pat) + r'\w+\b', dt):
                port_hits.append((m.group(0), func.name))
    for api, fn in port_hits:
        emit("    [CRITICAL] {} in {}".format(api, fn))
    if not port_hits:
        emit("    (none)")

    # ---- User copy without ProbeForRead/Write ----
    emit("[>] User copies without ProbeForRead/Write...")
    copy_missing = []
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not _looks_user_driven_win(dt):
            continue
        has_probe = any('ProbeForRead' in dt or 'ProbeForWrite' in dt)
        has_usercopy = any(c in dt for c in _STRING_COPY_NAMES)
        if has_usercopy and not has_probe:
            copy_missing.append(func.name)
    for fn in copy_missing:
        emit("    [HIGH] {} - user buffer copy without ProbeFor*".format(fn))
    if not copy_missing:
        emit("    (none)")

    # ---- Integer overflow in allocations ----
    emit("[>] Integer overflow in ExAllocatePool...")
    iof_hits = []
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not _looks_user_driven_win(dt):
            continue
        has_alloc = any(a in dt for a in _ALLOC_NAMES)
        has_safe = any(x in dt for x in ['RtlULongAdd', 'RtlULongMult', 'RtlULongLongAdd'])
        if has_alloc and not has_safe:
            iof_hits.append(func.name)
    for fn in iof_hits:
        emit("    [HIGH] {} - user-driven pool allocation without safe arithmetic".format(fn))
    if not iof_hits:
        emit("    (none)")

    # ---- Missing privilege gate ----
    emit("[>] Sensitive ops without SeSinglePrivilegeCheck...")
    missing_priv = []
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not _looks_user_driven_win(dt):
            continue
        has_sensitive = any(s in dt for s in [
            'MmMapIoSpace', '__wrmsr', '__out_', 'ZwTerminateProcess',
            'PsSetCreateProcessNotifyRoutine',
        ])
        has_gate = any(g in dt for g in _PRIV_GUARD_APIS)
        if has_sensitive and not has_gate:
            missing_priv.append(func.name)
    for fn in missing_priv:
        emit("    [HIGH] {} - privileged operation without SeSinglePrivilegeCheck".format(fn))
    if not missing_priv:
        emit("    (none)")

    # ---- Driver type detection ----
    emit("[>] Driver type detection...")
    is_minifilter = any('FltRegisterFilter' in get_hlil_text(f) for f in bv.functions)
    is_ndis = any(any(n in get_hlil_text(f) for n in _NDIS_APIS) for f in bv.functions)
    is_wfp = any(any(n in get_hlil_text(f) for n in _WFP_APIS) for f in bv.functions)
    is_alpc = any(any(n in get_hlil_text(f) for n in _ALPC_APIS) for f in bv.functions)
    dtype = []
    if is_minifilter:
        dtype.append("Mini-Filter")
    if is_ndis:
        dtype.append("NDIS")
    if is_wfp:
        dtype.append("WFP Callout")
    if is_alpc:
        dtype.append("ALPC")
    if not dtype:
        dtype.append("Standard WDM")
    emit("    Type: {}".format(", ".join(dtype)))

    # ---- IOCTL enumeration ----
    emit("[>] IOCTL enumeration...")
    _emit_ioctl_vuln_map(bv, emit)

    # ---- Expanded attack surface ----
    emit("[>] Expanded attack surface analysis...")
    _scan_expanded_surface(bv, emit)

    # ---- Save report ----
    try:
        with open(report_path, 'w') as f:
            f.write("\n".join(lines))
        emit("[+] Report saved to: {}".format(report_path))
    except Exception as e:
        log_warn("Could not write report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Vulnerability Finder",
    "Full vulnerability triage for Windows kernel drivers",
    find_driver_vulns,
)