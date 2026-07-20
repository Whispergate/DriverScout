"""
Binary Ninja plugin - WDF/KMDF deep analysis.

Goes beyond basic WdfVersionBind detection to fully resolve WDF callback
tables, trace buffer access through WDF wrapper APIs, and analyze
WDF-specific vulnerability patterns.

WDF_IO_QUEUE_CONFIG callback offsets (x86_64):
  +0x28  EvtIoDefault
  +0x30  EvtIoRead
  +0x38  EvtIoWrite
  +0x40  EvtIoDeviceControl
  +0x48  EvtIoInternalDeviceControl
  +0x50  EvtIoStop
  +0x58  EvtIoCanceledOnQueue

Dispatch types (WDF_IO_QUEUE_DISPATCH_TYPE):
  0 = WdfIoQueueDispatchSequential   (one at a time; serialized)
  1 = WdfIoQueueDispatchParallel     (concurrent; race risk)
  2 = WdfIoQueueDispatchManual       (driver manages manually)
  3 = WdfIoQueueDispatchMax

WDF buffer access APIs:
  WdfRequestRetrieveInputBuffer  / WdfRequestRetrieveOutputBuffer
  WdfRequestRetrieveInputMemory  / WdfRequestRetrieveOutputMemory
  WdfRequestRetrieveInputWdmMdl  / WdfRequestRetrieveOutputWdmMdl
  WdfRequestRetrieveUnsafeUserInputBuffer / WdfRequestRetrieveUnsafeUserOutputBuffer

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers, nearby_has_check

# WDF markers
_WDF_INIT_SYMS = [
    'WdfVersionBind', 'WdfDriverCreate', 'WdfDeviceCreate',
    'WdfDeviceCreateDeviceInterface', 'WdfDeviceInitAssignName',
]

_WDF_QUEUE_CREATE = ['WdfIoQueueCreate', 'WdfDeviceConfigureRequestDispatching']

_WDF_BUFFER_APIS = [
    'WdfRequestRetrieveInputBuffer', 'WdfRequestRetrieveOutputBuffer',
    'WdfRequestRetrieveInputMemory', 'WdfRequestRetrieveOutputMemory',
    'WdfRequestRetrieveInputWdmMdl', 'WdfRequestRetrieveOutputWdmMdl',
    'WdfRequestRetrieveUnsafeUserInputBuffer', 'WdfRequestRetrieveUnsafeUserOutputBuffer',
]

_WDF_COMPLETE_APIS = [
    'WdfRequestComplete', 'WdfRequestCompleteWithInformation',
    'WdfRequestCompleteWithPriorityBoost',
]

_WDF_CALLBACK_NAMES = {
    'EvtIoDefault':               ('IRP_MJ_ANY', 'Default handler; receives everything not routed elsewhere'),
    'EvtIoRead':                  ('IRP_MJ_READ', 'Read requests'),
    'EvtIoWrite':                 ('IRP_MJ_WRITE', 'Write requests'),
    'EvtIoDeviceControl':         ('IRP_MJ_DEVICE_CONTROL', 'User-mode IOCTLs; primary attack surface'),
    'EvtIoInternalDeviceControl': ('IRP_MJ_INTERNAL_DEVICE_CONTROL', 'Kernel-mode IOCTLs'),
    'EvtIoStop':                  ('IRP_MJ_CLEANUP', 'Queue stop/drain notification'),
    'EvtIoCanceledOnQueue':       ('IRP_MJ_CLEANUP', 'Request cancelled while queued'),
    'EvtDeviceFileCreate':        ('IRP_MJ_CREATE', 'Device open'),
    'EvtFileClose':               ('IRP_MJ_CLOSE', 'Handle close'),
    'EvtFileCleanup':             ('IRP_MJ_CLEANUP', 'Last handle closed'),
}

_WDF_QUEUE_CONFIG_OFFSETS = {
    0x28: 'EvtIoDefault',
    0x30: 'EvtIoRead',
    0x38: 'EvtIoWrite',
    0x40: 'EvtIoDeviceControl',
    0x48: 'EvtIoInternalDeviceControl',
    0x50: 'EvtIoStop',
    0x58: 'EvtIoCanceledOnQueue',
}

_DISPATCH_TYPES = {
    0: 'Sequential (serialized)',
    1: 'Parallel (concurrent - race risk)',
    2: 'Manual (driver-managed)',
    3: 'Max (invalid)',
}

_PROBE_APIS = ['ProbeForRead', 'ProbeForWrite']
_SEH_PATS = ['__try', 'try {', '_SEH_TRY', 'except (']

_IOCTL_PATS = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'[u]?==\s*0x([0-9A-Fa-f]{5,})',
    r'case\s+(\d{7,})\s*:',
]


def _is_wdf_driver(bv):
    for sym_name in _WDF_INIT_SYMS:
        if bv.get_symbols_by_name(sym_name):
            return True
    return False


def _detect_dispatch_type(bv):
    """Detect queue dispatch model from WDF_IO_QUEUE_CONFIG initialization."""
    dispatch_type = None
    for sym_name in _WDF_QUEUE_CREATE:
        for func, ref_addr in get_callers(bv, sym_name):
            dt = get_hlil_text(func)
            # WDF_IO_QUEUE_CONFIG.DispatchType is at offset +0x08 in the struct
            m = re.search(r'\+\s*(?:0x)?8\)\s*=\s*(\d+)', dt)
            if m:
                dispatch_type = int(m.group(1))
                break
            # Named field form
            m = re.search(r'DispatchType\s*=\s*(\d+)', dt)
            if m:
                dispatch_type = int(m.group(1))
                break
    return dispatch_type


def _find_wdf_callbacks_deep(bv):
    """Resolve WDF callbacks via:
    1. Named symbol lookup (PDB present)
    2. WDF_IO_QUEUE_CONFIG struct offset pattern in WdfIoQueueCreate callers
    3. Function name heuristic
    """
    callbacks = []
    seen = set()

    # Strategy 1: Named EvtIo* symbols
    for cb_name, (irp, desc) in _WDF_CALLBACK_NAMES.items():
        for sym in bv.get_symbols_by_name(cb_name):
            f = bv.get_function_at(sym.address)
            if f and f.start not in seen:
                seen.add(f.start)
                callbacks.append({
                    'name': cb_name, 'func': f, 'irp': irp,
                    'desc': desc, 'source': 'symbol',
                })

    # Strategy 2: WDF_IO_QUEUE_CONFIG struct assignments in callers of WdfIoQueueCreate
    for sym_name in _WDF_QUEUE_CREATE:
        for func, ref_addr in get_callers(bv, sym_name):
            dt = get_hlil_text(func)
            # Offset-based: *(config + 0xNN) = &Handler
            offset_pat = re.compile(
                r'\*\s*\([^)]*\+\s*(0x[0-9a-fA-F]+)\s*\)\s*=\s*(?:&\s*)?([A-Za-z_?@][A-Za-z0-9_?@]*)',
                re.IGNORECASE
            )
            for m in offset_pat.finditer(dt):
                try:
                    offset = int(m.group(1), 16)
                    cb_name = _WDF_QUEUE_CONFIG_OFFSETS.get(offset)
                    if not cb_name:
                        continue
                    target_name = m.group(2)
                    target_syms = bv.get_symbols_by_name(target_name)
                    if target_syms:
                        tf = bv.get_function_at(target_syms[0].address)
                    else:
                        tf = None
                        for f2 in bv.functions:
                            if f2.name == target_name:
                                tf = f2
                                break
                    if tf and tf.start not in seen:
                        seen.add(tf.start)
                        irp, desc = _WDF_CALLBACK_NAMES.get(cb_name, ('UNKNOWN', cb_name))
                        callbacks.append({
                            'name': cb_name, 'func': tf, 'irp': irp,
                            'desc': desc, 'source': 'struct_offset',
                        })
                except Exception:
                    pass

    # Strategy 3: Function name heuristic
    for func in bv.functions:
        nm = func.name.lower().replace('_', '')
        for cb_name in _WDF_CALLBACK_NAMES:
            if cb_name.lower().replace('_', '') in nm and func.start not in seen:
                seen.add(func.start)
                irp, desc = _WDF_CALLBACK_NAMES[cb_name]
                callbacks.append({
                    'name': cb_name, 'func': func, 'irp': irp,
                    'desc': desc, 'source': 'name_heuristic',
                })

    return callbacks


def _analyze_wdf_handler(bv, func):
    """Analyze a WDF callback handler for vulnerability patterns."""
    dt = get_hlil_text(func)
    findings = []

    # Check WDF buffer API usage
    buffer_apis_used = [api for api in _WDF_BUFFER_APIS if api in dt]

    # Unsafe user buffer access (METHOD_NEITHER equivalent in WDF)
    if any('Unsafe' in api for api in buffer_apis_used):
        has_probe = any(p in dt for p in _PROBE_APIS)
        has_seh = any(p in dt for p in _SEH_PATS)
        if not has_probe:
            findings.append(('CRITICAL',
                'WdfRequestRetrieveUnsafeUser*Buffer without ProbeForRead/Write'))
        if not has_seh:
            findings.append(('CRITICAL',
                'WdfRequestRetrieveUnsafeUser*Buffer without __try/__except (BSOD on invalid user pointer)'))

    # Missing buffer length validation
    if buffer_apis_used:
        has_length_check = ('Length' in dt or 'length' in dt or
                           'BufferLength' in dt or 'sizeof' in dt or
                           '< 0x' in dt or '> 0x' in dt or '<= 0x' in dt)
        if not has_length_check:
            findings.append(('HIGH',
                'WDF buffer retrieved without apparent length validation'))

    # Check for memcpy/RtlCopyMemory with WDF buffers
    copy_apis = ['memcpy', 'RtlCopyMemory', 'memmove']
    for api in copy_apis:
        if api in dt:
            idx = dt.find(api)
            if not nearby_has_check(dt, idx, ['Length', 'BufferLength', 'sizeof', 'min('], window=300):
                findings.append(('HIGH',
                    '{} near WDF buffer without size validation'.format(api)))

    # Missing request completion
    has_complete = any(api in dt for api in _WDF_COMPLETE_APIS)
    if not has_complete:
        findings.append(('MEDIUM',
            'WDF handler may not complete the request (missing WdfRequestComplete*)'))

    # Double completion
    complete_count = sum(dt.count(api) for api in _WDF_COMPLETE_APIS)
    if complete_count >= 2:
        findings.append(('HIGH',
            'Multiple WdfRequestComplete* calls detected - possible double completion'))

    # ExAllocatePool without NULL check
    if 'ExAllocatePool' in dt:
        m = re.search(r'ExAllocatePool\w*\([^)]*\)', dt)
        if m:
            tail = dt[m.end():m.end() + 400]
            has_check = bool(re.search(r'==\s*0|!=\s*0|!\s*\w+|NULL', tail[:200]))
            if not has_check:
                findings.append(('MEDIUM', 'ExAllocatePool result not checked for NULL'))

    # Check for dangerous operations
    dangerous = {
        '__rdmsr': ('CRITICAL', 'MSR read from WDF handler'),
        '__wrmsr': ('CRITICAL', 'MSR write from WDF handler'),
        '__in_': ('CRITICAL', 'Port IO read from WDF handler'),
        '__out_': ('CRITICAL', 'Port IO write from WDF handler'),
        'MmMapIoSpace': ('HIGH', 'Physical memory mapping from WDF handler'),
        'MmCopyMemory': ('HIGH', 'Physical memory copy from WDF handler'),
        'ZwOpenSection': ('HIGH', 'Section open from WDF handler'),
    }
    for needle, (sev, desc) in dangerous.items():
        if needle in dt:
            findings.append((sev, desc))

    # Extract IOCTL codes
    ioctls = set()
    for pat in _IOCTL_PATS:
        for m in re.finditer(pat, dt, re.IGNORECASE):
            try:
                val = int(m.group(1), 16 if 'x' in m.group(0).lower() else 10)
                if val >= 0x200000:
                    ioctls.add(val & 0xFFFFFFFF)
            except Exception:
                pass

    return {
        'findings': findings,
        'buffer_apis': buffer_apis_used,
        'ioctls': sorted(ioctls),
    }


def analyze_wdf(bv: BinaryView):
    lines = [
        "=== WDF/KMDF Deep Analysis ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-wdf-analysis.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    if not _is_wdf_driver(bv):
        emit("[-] Not a WDF/KMDF driver (no WdfVersionBind/WdfDriverCreate symbols found)")
        emit("[*] This is a WDM driver - use the standard IRP handler analysis instead.")
        return

    emit("[+] WDF/KMDF driver detected")

    # Detect dispatch model
    dispatch_type = _detect_dispatch_type(bv)
    if dispatch_type is not None:
        desc = _DISPATCH_TYPES.get(dispatch_type, 'Unknown ({})'.format(dispatch_type))
        emit("[+] Queue dispatch type: {}".format(desc))
        if dispatch_type == 1:
            emit("    [WARN] Parallel dispatch - handlers may execute concurrently")
            emit("    [WARN] Double-fetch and race condition analysis is relevant")
        elif dispatch_type == 0:
            emit("    [INFO] Sequential dispatch - requests serialized; double-fetch less exploitable")
    else:
        emit("[*] Queue dispatch type: not resolved (check WDF_IO_QUEUE_CONFIG manually)")

    # Find callbacks
    callbacks = _find_wdf_callbacks_deep(bv)
    if not callbacks:
        emit("[-] No WDF callbacks resolved. Driver may use dynamic callback assignment.")
        return

    emit("\n[+] WDF Callbacks ({} found):".format(len(callbacks)))
    emit("")

    for cb in callbacks:
        func = cb['func']
        emit("  [{}/{}] {} -> {} (0x{:x}) [{}]".format(
            cb['irp'], cb['name'], cb['source'], func.name, func.start, cb['desc']))

        analysis = _analyze_wdf_handler(bv, func)

        if analysis['buffer_apis']:
            emit("    Buffer APIs: {}".format(", ".join(analysis['buffer_apis'])))

        if analysis['ioctls']:
            emit("    IOCTLs: {}".format(", ".join("0x{:08X}".format(c) for c in analysis['ioctls'])))

        for sev, desc in analysis['findings']:
            emit("    [{}] {}".format(sev, desc))

        if not analysis['findings']:
            emit("    (no issues detected)")
        emit("")

    # Summary
    all_findings = []
    for cb in callbacks:
        analysis = _analyze_wdf_handler(bv, cb['func'])
        all_findings.extend(analysis['findings'])

    crit = sum(1 for s, _ in all_findings if s == 'CRITICAL')
    high = sum(1 for s, _ in all_findings if s == 'HIGH')
    med = sum(1 for s, _ in all_findings if s == 'MEDIUM')

    emit("[>] Summary: {} callbacks, {} CRITICAL, {} HIGH, {} MEDIUM findings".format(
        len(callbacks), crit, high, med))

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write WDF report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\WDF Deep Analysis",
    "Deep WDF/KMDF callback resolution, buffer tracking, and vulnerability analysis",
    analyze_wdf,
)
