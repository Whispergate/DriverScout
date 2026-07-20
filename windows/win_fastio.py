"""
Binary Ninja plugin - FastIO dispatch table analysis.

FastIO is a parallel dispatch path to IRP handling. The kernel tries FastIO
first for eligible operations; if the handler succeeds, the IRP path is
never reached. Vulnerabilities in FastIO handlers are on the hot path.

FAST_IO_DISPATCH layout (x86_64, offsets from struct base):
  +0x00  SizeOfFastIoDispatch (ULONG)
  +0x08  FastIoCheckIfPossible
  +0x10  FastIoRead
  +0x18  FastIoWrite
  +0x20  FastIoQueryBasicInfo
  +0x28  FastIoQueryStandardInfo
  +0x30  FastIoLock
  +0x38  FastIoUnlockSingle
  +0x40  FastIoUnlockAll
  +0x48  FastIoUnlockAllByKey
  +0x50  FastIoDeviceControl          *** PRIMARY ATTACK SURFACE ***
  +0x58  AcquireFileForNtCreateSection
  +0x60  ReleaseFileForNtCreateSection
  +0x68  FastIoDetachDevice
  +0x70  FastIoQueryNetworkOpenInfo
  +0x78  AcquireForModWrite
  +0x80  MdlRead
  +0x88  MdlReadComplete
  +0x90  PrepareMdlWrite
  +0x98  MdlWriteComplete
  +0xA0  FastIoReadCompressed
  +0xA8  FastIoWriteCompressed
  +0xB0  MdlReadCompleteCompressed
  +0xB8  MdlWriteCompleteCompressed
  +0xC0  FastIoQueryOpen

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, nearby_has_check

_FASTIO_DISPATCH_OFFSET = {
    0x08: ('FastIoCheckIfPossible',          'LOW',  'Pre-check for fast path eligibility'),
    0x10: ('FastIoRead',                     'HIGH', 'Fast-path read; buffer validation critical'),
    0x18: ('FastIoWrite',                    'HIGH', 'Fast-path write; buffer validation critical'),
    0x20: ('FastIoQueryBasicInfo',           'MEDIUM', 'Basic file info; potential info leak'),
    0x28: ('FastIoQueryStandardInfo',        'MEDIUM', 'Standard file info query'),
    0x30: ('FastIoLock',                     'MEDIUM', 'File byte-range lock'),
    0x38: ('FastIoUnlockSingle',            'LOW',  'Single range unlock'),
    0x40: ('FastIoUnlockAll',               'LOW',  'Unlock all ranges'),
    0x48: ('FastIoUnlockAllByKey',          'LOW',  'Unlock by key'),
    0x50: ('FastIoDeviceControl',           'HIGH', 'Fast IOCTL dispatch; parallel to IRP_MJ_DEVICE_CONTROL'),
    0x58: ('AcquireFileForNtCreateSection', 'MEDIUM', 'Section create synchronization'),
    0x60: ('ReleaseFileForNtCreateSection', 'LOW',  'Section create release'),
    0x68: ('FastIoDetachDevice',            'MEDIUM', 'Device detach notification'),
    0x70: ('FastIoQueryNetworkOpenInfo',    'MEDIUM', 'Network open info query'),
    0x78: ('AcquireForModWrite',            'MEDIUM', 'Modified write acquisition'),
    0x80: ('MdlRead',                       'HIGH', 'MDL-based read; MDL buffer management'),
    0x88: ('MdlReadComplete',               'LOW',  'MDL read completion'),
    0x90: ('PrepareMdlWrite',               'HIGH', 'MDL write preparation'),
    0x98: ('MdlWriteComplete',              'LOW',  'MDL write completion'),
    0xA0: ('FastIoReadCompressed',          'MEDIUM', 'Compressed read'),
    0xA8: ('FastIoWriteCompressed',         'MEDIUM', 'Compressed write'),
    0xB0: ('MdlReadCompleteCompressed',     'LOW',  'Compressed MDL read complete'),
    0xB8: ('MdlWriteCompleteCompressed',    'LOW',  'Compressed MDL write complete'),
    0xC0: ('FastIoQueryOpen',               'MEDIUM', 'Fast open query'),
}

_PROBE_APIS = ['ProbeForRead', 'ProbeForWrite']
_SEH_PATS = ['__try', 'try {', '_SEH_TRY', 'except (']

_IOCTL_PATS = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'[u]?==\s*0x([0-9A-Fa-f]{5,})',
]


def _find_fastio_dispatch(bv):
    """Find FAST_IO_DISPATCH assignments. Two patterns:
    1. DriverObject->FastIoDispatch = &fastio_table (named field)
    2. *(drv_obj + 0x58) = &fastio_table (raw offset; 0x58 = FastIoDispatch in DRIVER_OBJECT x64)
    """
    tables = []
    seen = set()

    # Pattern: named field
    named_pat = re.compile(
        r'FastIoDispatch\s*=\s*(?:&\s*)?([A-Za-z_?@][A-Za-z0-9_?@]*)',
        re.IGNORECASE
    )
    # Pattern: raw offset 0x58 in DRIVER_OBJECT
    raw_pat = re.compile(
        r'\*\s*\([^)]*\+\s*0x58\s*\)\s*=\s*(?:&\s*)?([A-Za-z_?@][A-Za-z0-9_?@]*|0x[0-9a-fA-F]+)',
        re.IGNORECASE
    )

    for func in bv.functions:
        dt = get_hlil_text(func)
        for pat in (named_pat, raw_pat):
            for m in pat.finditer(dt):
                target = m.group(1)
                if target.startswith('0x'):
                    try:
                        addr = int(target, 16)
                        if addr not in seen:
                            seen.add(addr)
                            tables.append(('raw_addr', addr, func.name))
                    except Exception:
                        pass
                else:
                    syms = bv.get_symbols_by_name(target)
                    if syms:
                        addr = syms[0].address
                        if addr not in seen:
                            seen.add(addr)
                            tables.append(('symbol', addr, func.name))
                    # Also check as data variable
                    dv = bv.get_data_var_at(bv.get_symbols_by_name(target)[0].address if syms else 0)
                    if not syms:
                        for f2 in bv.functions:
                            if f2.name == target and f2.start not in seen:
                                seen.add(f2.start)
                                tables.append(('func_name', f2.start, func.name))

    return tables


def _resolve_fastio_handlers(bv):
    """Resolve FastIO function pointers. Two approaches:
    1. Named FastIo* symbols in symbol table
    2. Function pointer stores near DRIVER_OBJECT->FastIoDispatch setup
    """
    handlers = {}
    seen = set()

    # Strategy 1: Named symbol lookup
    for offset, (name, risk, desc) in _FASTIO_DISPATCH_OFFSET.items():
        syms = bv.get_symbols_by_name(name)
        if syms:
            f = bv.get_function_at(syms[0].address)
            if f and f.start not in seen:
                seen.add(f.start)
                handlers[offset] = {
                    'name': name, 'func': f, 'risk': risk,
                    'desc': desc, 'source': 'symbol',
                }

    # Strategy 2: scan DriverEntry/init for struct field assignments
    # FastIoDispatch struct fields are set as *(table + offset) = &handler
    fastio_pat = re.compile(
        r'\*\s*\([^)]*\+\s*(0x[0-9a-fA-F]+)\s*\)\s*=\s*(?:&\s*)?([A-Za-z_?@][A-Za-z0-9_?@]*)',
        re.IGNORECASE
    )
    for func in bv.functions:
        dt = get_hlil_text(func)
        if 'FastIo' not in dt and '+ 0x50)' not in dt:
            continue
        for m in fastio_pat.finditer(dt):
            try:
                offset = int(m.group(1), 16)
                if offset not in _FASTIO_DISPATCH_OFFSET:
                    continue
                if offset in handlers:
                    continue
                name, risk, desc = _FASTIO_DISPATCH_OFFSET[offset]
                target = m.group(2)
                tf = None
                syms = bv.get_symbols_by_name(target)
                if syms:
                    tf = bv.get_function_at(syms[0].address)
                else:
                    for f2 in bv.functions:
                        if f2.name == target:
                            tf = f2
                            break
                if tf and tf.start not in seen:
                    seen.add(tf.start)
                    handlers[offset] = {
                        'name': name, 'func': tf, 'risk': risk,
                        'desc': desc, 'source': 'struct_offset',
                    }
            except Exception:
                pass

    # Strategy 3: function name heuristic
    for func in bv.functions:
        nm_lower = func.name.lower().replace('_', '')
        for offset, (name, risk, desc) in _FASTIO_DISPATCH_OFFSET.items():
            if name.lower().replace('_', '') in nm_lower and offset not in handlers:
                if func.start not in seen:
                    seen.add(func.start)
                    handlers[offset] = {
                        'name': name, 'func': func, 'risk': risk,
                        'desc': desc, 'source': 'name_heuristic',
                    }

    return handlers


def _analyze_fastio_handler(bv, func, handler_name):
    """Analyze a FastIO handler for vulnerability patterns."""
    dt = get_hlil_text(func)
    findings = []

    # FastIoDeviceControl-specific checks
    if 'DeviceControl' in handler_name:
        has_probe = any(p in dt for p in _PROBE_APIS)
        has_seh = any(p in dt for p in _SEH_PATS)

        # FastIoDeviceControl receives raw user buffers
        if not has_probe:
            findings.append(('HIGH',
                'FastIoDeviceControl without ProbeForRead/Write on user buffers'))
        if not has_seh:
            findings.append(('HIGH',
                'FastIoDeviceControl without __try/__except for user pointer access'))

        # Extract IOCTL codes
        ioctls = set()
        for pat in _IOCTL_PATS:
            for m in re.finditer(pat, dt, re.IGNORECASE):
                try:
                    val = int(m.group(1), 16)
                    if val >= 0x200000:
                        ioctls.add(val & 0xFFFFFFFF)
                except Exception:
                    pass
        if ioctls:
            findings.append(('INFO',
                'IOCTLs in FastIO path: {}'.format(
                    ", ".join("0x{:08X}".format(c) for c in sorted(ioctls)))))

    # Read/Write handler checks
    if handler_name in ('FastIoRead', 'FastIoWrite'):
        copy_apis = ['memcpy', 'RtlCopyMemory', 'memmove']
        for api in copy_apis:
            if api in dt:
                idx = dt.find(api)
                if not nearby_has_check(dt, idx, _PROBE_APIS + _SEH_PATS, window=400):
                    findings.append(('HIGH',
                        '{} in {} without ProbeFor or SEH'.format(api, handler_name)))

    # MDL handler checks
    if handler_name in ('MdlRead', 'PrepareMdlWrite'):
        if 'MmMapLockedPages' in dt or 'MmGetSystemAddressForMdl' in dt:
            findings.append(('MEDIUM',
                'MDL mapping in FastIO handler - verify IRQL and access mode'))

    # General dangerous operation checks
    dangerous = {
        'MmMapIoSpace': 'Physical memory mapping',
        'MmCopyMemory': 'Physical memory copy',
        '__rdmsr': 'MSR read', '__wrmsr': 'MSR write',
        '__in_': 'Port IO read', '__out_': 'Port IO write',
        'ZwOpenSection': 'Section open',
        'ExAllocatePool': 'Pool allocation',
    }
    for needle, desc in dangerous.items():
        if needle in dt:
            findings.append(('HIGH', '{} in FastIO handler {}'.format(desc, handler_name)))

    return findings


def find_fastio_handlers(bv: BinaryView):
    lines = [
        "=== FastIO Dispatch Table Analysis ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-fastio.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    # Check for FastIoDispatch assignment
    tables = _find_fastio_dispatch(bv)
    if not tables:
        emit("[-] No FastIoDispatch assignment found")
        emit("[*] Driver does not use FastIO path (IRP-only dispatch)")
        return

    emit("[+] FastIoDispatch table(s) found:")
    for source, addr, setter in tables:
        emit("    0x{:x} ({}) set in {}".format(addr, source, setter))

    # Resolve handlers
    handlers = _resolve_fastio_handlers(bv)
    if not handlers:
        emit("[-] No FastIO handlers resolved (table may be data-initialized)")
        return

    emit("\n[+] FastIO handlers ({} resolved):".format(len(handlers)))
    emit("")

    # Sort by risk then offset
    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    for offset in sorted(handlers.keys(),
                         key=lambda o: (risk_order.get(handlers[o]['risk'], 9), o)):
        h = handlers[offset]
        func = h['func']
        emit("  [{}] +0x{:02X} {} -> {} (0x{:x}) [{}]".format(
            h['risk'], offset, h['name'], func.name, func.start, h['source']))
        emit("    {}".format(h['desc']))

        findings = _analyze_fastio_handler(bv, func, h['name'])
        for sev, desc in findings:
            emit("    [{}] {}".format(sev, desc))

        if not findings:
            emit("    (no issues detected)")
        emit("")

    # Cross-reference: does the driver have BOTH IRP and FastIO handlers for DeviceControl?
    has_fastio_dc = any(h['name'] == 'FastIoDeviceControl' for h in handlers.values())
    if has_fastio_dc:
        emit("[!] Driver has FastIoDeviceControl - this path is tried BEFORE IRP_MJ_DEVICE_CONTROL")
        emit("    Vulnerabilities in FastIO are reachable even if IRP handler is hardened")

    emit("\n[+] FastIO analysis complete.")

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write FastIO report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\FastIO Dispatch Analysis",
    "Enumerate FAST_IO_DISPATCH handlers and analyze for vulnerabilities",
    find_fastio_handlers,
)
