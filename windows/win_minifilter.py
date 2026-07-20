"""
Binary Ninja plugin - Minifilter callback analysis.

Parses FLT_REGISTRATION and FLT_OPERATION_REGISTRATION structures to
enumerate pre/post operation callbacks. Applies vulnerability analysis
to each callback.

FLT_REGISTRATION (x64):
  +0x00  Size (USHORT)
  +0x02  Version (USHORT)
  +0x04  Flags (FLT_REGISTRATION_FLAGS)
  +0x08  ContextRegistration (PFLT_CONTEXT_REGISTRATION)
  +0x10  OperationRegistration (PFLT_OPERATION_REGISTRATION) ***
  +0x18  FilterUnloadCallback
  +0x20  InstanceSetupCallback
  +0x28  InstanceQueryTeardownCallback
  +0x30  InstanceTeardownStartCallback
  +0x38  InstanceTeardownCompleteCallback
  +0x40  GenerateFileNameCallback
  +0x48  NormalizeNameComponentCallback
  +0x50  NormalizeContextCleanupCallback
  +0x58  TransactionNotificationCallback
  +0x60  NormalizeNameComponentExCallback
  +0x68  SectionNotificationCallback

FLT_OPERATION_REGISTRATION (x64, array element):
  +0x00  MajorFunction (UCHAR)
  +0x04  Flags (FLT_OPERATION_REGISTRATION_FLAGS)
  +0x08  PreOperation (PFLT_PRE_OPERATION_CALLBACK)
  +0x10  PostOperation (PFLT_POST_OPERATION_CALLBACK)

Array terminated by IRP_MJ_OPERATION_END (0x80).

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers, nearby_has_check

# IRP major function codes relevant to minifilters
_IRP_MJ_NAMES = {
    0x00: 'IRP_MJ_CREATE',
    0x01: 'IRP_MJ_CREATE_NAMED_PIPE',
    0x02: 'IRP_MJ_CLOSE',
    0x03: 'IRP_MJ_READ',
    0x04: 'IRP_MJ_WRITE',
    0x05: 'IRP_MJ_QUERY_INFORMATION',
    0x06: 'IRP_MJ_SET_INFORMATION',
    0x07: 'IRP_MJ_QUERY_EA',
    0x08: 'IRP_MJ_SET_EA',
    0x09: 'IRP_MJ_FLUSH_BUFFERS',
    0x0A: 'IRP_MJ_QUERY_VOLUME_INFORMATION',
    0x0B: 'IRP_MJ_SET_VOLUME_INFORMATION',
    0x0C: 'IRP_MJ_DIRECTORY_CONTROL',
    0x0D: 'IRP_MJ_FILE_SYSTEM_CONTROL',
    0x0E: 'IRP_MJ_DEVICE_CONTROL',
    0x0F: 'IRP_MJ_INTERNAL_DEVICE_CONTROL',
    0x12: 'IRP_MJ_CLEANUP',
    0x13: 'IRP_MJ_CREATE_MAILSLOT',
    0x14: 'IRP_MJ_QUERY_SECURITY',
    0x15: 'IRP_MJ_SET_SECURITY',
    0x80: 'IRP_MJ_OPERATION_END',
}

# Risk assessment per IRP major code for minifilter context
_MJ_RISK = {
    0x00: 'HIGH',    # CREATE - filename validation, access check bypass
    0x03: 'HIGH',    # READ - data interception, buffer handling
    0x04: 'HIGH',    # WRITE - data modification, buffer handling
    0x05: 'MEDIUM',  # QUERY_INFORMATION - info leak
    0x06: 'HIGH',    # SET_INFORMATION - rename/delete interception
    0x0C: 'MEDIUM',  # DIRECTORY_CONTROL - directory enum interception
    0x0D: 'HIGH',    # FILE_SYSTEM_CONTROL - FSCTL dispatch
    0x0E: 'HIGH',    # DEVICE_CONTROL - IOCTL handling
    0x14: 'HIGH',    # QUERY_SECURITY - security descriptor bypass
    0x15: 'HIGH',    # SET_SECURITY - security descriptor modification
}

_PROBE_APIS = ['ProbeForRead', 'ProbeForWrite']
_SEH_PATS = ['__try', 'try {', '_SEH_TRY', 'except (']
_FLT_APIS = [
    'FltGetRequestorProcess', 'FltGetRequestorProcessId',
    'FltIsOperationSynchronous', 'FltDoCompletionProcessingWhenSafe',
    'FltCbdqInitialize',
]


def _is_minifilter(bv):
    """Check if driver is a minifilter."""
    return bool(bv.get_symbols_by_name('FltRegisterFilter'))


def _find_flt_registration(bv):
    """Find FLT_REGISTRATION structure via FltRegisterFilter callers."""
    registrations = []

    for func, ref_addr in get_callers(bv, 'FltRegisterFilter'):
        dt = get_hlil_text(func)
        # FltRegisterFilter(DriverObject, Registration, FilterHandle)
        # Second param is &FLT_REGISTRATION
        reg_pat = re.compile(
            r'FltRegisterFilter\s*\([^,]*,\s*(?:&\s*)?([A-Za-z_?@][A-Za-z0-9_?@]*)',
            re.IGNORECASE
        )
        for m in reg_pat.finditer(dt):
            registrations.append({
                'name': m.group(1),
                'setter': func.name,
                'setter_addr': func.start,
            })

    return registrations


def _find_operation_callbacks(bv):
    """Resolve pre/post operation callbacks. Strategies:
    1. Named PreOperation/PostOperation symbols
    2. FLT_OPERATION_REGISTRATION struct offset patterns
    3. Function name heuristic (Pre*/Post* matching IRP names)
    """
    callbacks = []
    seen = set()

    # Strategy 1: Symbol names containing Pre/Post + operation name
    pre_post_patterns = []
    for code, name in _IRP_MJ_NAMES.items():
        if code == 0x80:
            continue
        short = name.replace('IRP_MJ_', '')
        pre_post_patterns.append(('Pre' + short.title().replace('_', ''), code, 'pre'))
        pre_post_patterns.append(('Post' + short.title().replace('_', ''), code, 'post'))
        # Also common naming: PreCreate, PreRead, etc.
        simple = short.replace('_', '')
        pre_post_patterns.append(('Pre' + simple.title(), code, 'pre'))
        pre_post_patterns.append(('Post' + simple.title(), code, 'post'))

    for pat_name, mj_code, phase in pre_post_patterns:
        for sym in bv.get_symbols_by_name(pat_name):
            f = bv.get_function_at(sym.address)
            if f and f.start not in seen:
                seen.add(f.start)
                callbacks.append({
                    'mj_code': mj_code,
                    'mj_name': _IRP_MJ_NAMES.get(mj_code, 'IRP_MJ_{}'.format(mj_code)),
                    'phase': phase,
                    'func': f,
                    'source': 'symbol',
                })

    # Strategy 2: Function name heuristic
    for func in bv.functions:
        nm = func.name
        if func.start in seen:
            continue
        nm_lower = nm.lower()
        for code, name in _IRP_MJ_NAMES.items():
            if code == 0x80:
                continue
            short = name.replace('IRP_MJ_', '').lower().replace('_', '')
            if 'pre' + short in nm_lower:
                seen.add(func.start)
                callbacks.append({
                    'mj_code': code,
                    'mj_name': name,
                    'phase': 'pre',
                    'func': func,
                    'source': 'name_heuristic',
                })
                break
            elif 'post' + short in nm_lower:
                seen.add(func.start)
                callbacks.append({
                    'mj_code': code,
                    'mj_name': name,
                    'phase': 'post',
                    'func': func,
                    'source': 'name_heuristic',
                })
                break

    return callbacks


def _analyze_minifilter_callback(bv, func, mj_code, phase):
    """Analyze a minifilter callback for vulnerabilities."""
    dt = get_hlil_text(func)
    findings = []

    # Buffer access without validation
    if mj_code in (0x03, 0x04):  # READ/WRITE
        copy_apis = ['memcpy', 'RtlCopyMemory', 'memmove', 'FltReadFile', 'FltWriteFile']
        for api in copy_apis:
            if api in dt:
                idx = dt.find(api)
                if not nearby_has_check(dt, idx, ['Length', 'BufferLength', 'sizeof'], window=300):
                    findings.append(('HIGH',
                        '{} {} without length validation'.format(phase, api)))

    # Pre-CREATE callback issues
    if mj_code == 0x00 and phase == 'pre':
        # Check for filename access
        if 'FileName' in dt or 'FileNameInformation' in dt:
            if 'FltGetFileNameInformation' not in dt:
                findings.append(('MEDIUM',
                    'Filename accessed without FltGetFileNameInformation - may get raw unparsed name'))

        # TOCTOU on file attributes
        if 'FileAttributes' in dt or 'GetFileAttributes' in dt:
            findings.append(('MEDIUM',
                'File attribute check in PreCreate - potential TOCTOU if not serialized'))

    # Post-CREATE callback issues
    if mj_code == 0x00 and phase == 'post':
        if 'FltQueryInformationFile' in dt:
            has_status_check = 'STATUS_SUCCESS' in dt or 'NT_SUCCESS' in dt
            if not has_status_check:
                findings.append(('LOW',
                    'FltQueryInformationFile result not checked in PostCreate'))

    # FSCTL/IOCTL in minifilter
    if mj_code in (0x0D, 0x0E):
        if 'UserBuffer' in dt or 'SystemBuffer' in dt:
            has_probe = any(p in dt for p in _PROBE_APIS)
            has_seh = any(p in dt for p in _SEH_PATS)
            if not has_probe:
                findings.append(('HIGH',
                    'User buffer access in {} without ProbeForRead/Write'.format(
                        _IRP_MJ_NAMES.get(mj_code, ''))))
            if not has_seh:
                findings.append(('HIGH',
                    'User buffer access without SEH in minifilter callback'))

    # Reentrancy issues
    if 'FltPerformSynchronousIo' in dt or 'FltReadFile' in dt or 'FltWriteFile' in dt:
        findings.append(('MEDIUM',
            'Synchronous I/O from minifilter callback - reentrancy risk'))

    # IRQL issues
    if 'KeAcquireSpinLock' in dt and phase == 'post':
        findings.append(('MEDIUM',
            'SpinLock in PostOperation - verify IRQL <= DISPATCH_LEVEL'))

    # Missing FLT_PREOP_COMPLETE / FLT_POSTOP_FINISHED_PROCESSING
    if phase == 'pre':
        if 'FLT_PREOP_COMPLETE' not in dt and 'FLT_PREOP_SUCCESS' not in dt:
            if 'return' in dt:
                findings.append(('LOW',
                    'PreOperation may not return standard FLT_PREOP_* status'))
    elif phase == 'post':
        if 'FLT_POSTOP_FINISHED_PROCESSING' not in dt and 'FLT_POSTOP_MORE_PROCESSING_REQUIRED' not in dt:
            findings.append(('LOW',
                'PostOperation may not return standard FLT_POSTOP_* status'))

    # Memory allocation without error check
    if 'ExAllocatePool' in dt or 'FltAllocatePoolAlignedWithTag' in dt:
        alloc_pat = re.compile(r'(ExAllocatePool\w*|FltAllocatePoolAlignedWithTag)\s*\([^)]*\)')
        for m in alloc_pat.finditer(dt):
            tail = dt[m.end():m.end() + 200]
            if '== 0' not in tail and '!= 0' not in tail and 'NULL' not in tail and '!' not in tail[:50]:
                findings.append(('MEDIUM',
                    'Pool allocation result not NULL-checked in minifilter callback'))

    # Dangerous operations
    dangerous = {
        'MmMapIoSpace': 'Physical memory mapping from minifilter',
        'ZwOpenSection': 'Section open from minifilter',
        'ObReferenceObjectByHandle': 'Object reference from minifilter - verify access mode',
    }
    for needle, desc in dangerous.items():
        if needle in dt:
            findings.append(('HIGH', desc))

    return findings


def analyze_minifilter(bv: BinaryView):
    lines = [
        "=== Minifilter Callback Analysis ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-minifilter.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    if not _is_minifilter(bv):
        emit("[-] Not a minifilter driver (FltRegisterFilter not found)")
        return

    emit("[+] Minifilter driver detected")

    # Find registration structures
    regs = _find_flt_registration(bv)
    if regs:
        for r in regs:
            emit("    FLT_REGISTRATION '{}' registered in {}".format(r['name'], r['setter']))

    # Detect FltMgr APIs used
    flt_apis_used = []
    for api in _FLT_APIS + ['FltGetFileNameInformation', 'FltReleaseFileNameInformation',
                            'FltAllocatePoolAlignedWithTag', 'FltObjectDereference',
                            'FltGetVolumeFromInstance', 'FltGetVolumeProperties']:
        if bv.get_symbols_by_name(api):
            flt_apis_used.append(api)
    if flt_apis_used:
        emit("\n[+] FltMgr APIs used: {}".format(", ".join(flt_apis_used)))

    # Find callbacks
    callbacks = _find_operation_callbacks(bv)
    if not callbacks:
        emit("[-] No operation callbacks resolved")
        return

    emit("\n[+] Operation Callbacks ({} found):".format(len(callbacks)))
    emit("")

    # Sort by MJ code, then pre before post
    callbacks.sort(key=lambda c: (c['mj_code'], 0 if c['phase'] == 'pre' else 1))

    for cb in callbacks:
        risk = _MJ_RISK.get(cb['mj_code'], 'LOW')
        func = cb['func']
        emit("  [{}] {} {} -> {} (0x{:x}) [{}]".format(
            risk, cb['phase'].upper(), cb['mj_name'],
            func.name, func.start, cb['source']))

        findings = _analyze_minifilter_callback(bv, func, cb['mj_code'], cb['phase'])
        for sev, desc in findings:
            emit("    [{}] {}".format(sev, desc))

        if not findings:
            emit("    (no issues detected)")
        emit("")

    # AV/EDR bypass analysis
    emit("[>] AV/EDR Bypass Assessment:")
    has_create = any(c['mj_code'] == 0x00 for c in callbacks)
    has_write = any(c['mj_code'] == 0x04 for c in callbacks)
    has_set_info = any(c['mj_code'] == 0x06 for c in callbacks)
    has_set_sec = any(c['mj_code'] == 0x15 for c in callbacks)

    if has_create:
        emit("    PreCreate callback present - monitors file opens (AV scan trigger)")
    if has_write:
        emit("    Write callback present - monitors file writes (content inspection)")
    if has_set_info:
        emit("    SetInformation callback present - monitors rename/delete")
    if has_set_sec:
        emit("    SetSecurity callback present - monitors DACL changes")

    emit("\n[+] Minifilter analysis complete.")

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write minifilter report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Minifilter Callback Analysis",
    "Enumerate minifilter pre/post operation callbacks and analyze for vulnerabilities",
    analyze_minifilter,
)
