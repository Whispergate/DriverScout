"""
Binary Ninja plugin - Windows kernel exploit primitive detection.

Detects exploit primitives per IOCTL handler using HLIL pattern detection,
name-hint matching, and recursive callee analysis (depth 3).

Uses shared modules: dispatch.py, ioctl_shared.py, primitive_db.py, helpers.py

Primitives (23 detectors + name-hint pass):
  Write-What-Where, Arb Kernel Read, MSR R/W, Port IO, Physical Memory Map,
  Control/Debug Register Access, Ring-0 Exec, PCI Config, Stack BOF,
  Pool BOF, NULL Deref, Token-Swap, Type Confusion, Double-Fetch,
  Uninitialized Pool Leak, Virtual Memory R/W, MDL Map, Handle Dup,
  Section-Based Phys, Callback Removal, Process/Thread Manipulation,
  DSE/CI Bypass, ETW Tampering

References:
  connormcgarr.github.io, knifecoat.com, windows-internals.com,
  whiteknightlabs.com, r0keb pool internals + LFH
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text
from ..shared.dispatch import find_dispatch_routines
from ..shared.ioctl_shared import (
    ctl_decode, METHOD_MAP, ioctl_branches_for_dispatcher, resolve_callee_name,
)
from ..shared.primitive_db import (
    NAME_PRIM_HINTS, NAME_HINT_SKIP_PREFIX,
    deep_text, branch_callees, walk_collect_calls,
    MAX_DEEP_CALLEES, MAX_CLASSIFY_DEPTH,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TOKEN_OFFSETS = ['0x4b8', '0x358', '0x208', '+ 0x4b8', '+ 0x358']
_IORING_NAMES = [
    'IoRingCreate', 'NtCreateIoRing', 'NtSubmitIoRing',
    'IoRingRegisterBuffers', 'IoRingRegisterFiles',
    'IopIoRingDispatch', 'IoRingSubmit',
]
_OBJECT_LOOKUP = [
    'ObReferenceObjectByHandle', 'ObReferenceObjectByHandleWithTag',
    'ObReferenceObjectByPointer', 'PsLookupProcessByProcessId',
    'PsLookupThreadByThreadId',
]
_PROBE_NAMES = ['ProbeForRead', 'ProbeForWrite']


def _has_any(text, needles):
    return any(n in text for n in needles)


# ---------------------------------------------------------------------------
# Name hint detection
# ---------------------------------------------------------------------------

def _detect_name_hints(bv, instrs):
    """Walk callees + match descriptive names. Returns list of (sev,label)."""
    hits = []
    seen = set()
    frontier = list(branch_callees(bv, instrs))
    depth = 0
    while frontier and depth < 3:
        next_frontier = []
        for caddr in frontier:
            if caddr in seen:
                continue
            seen.add(caddr)
            f = bv.get_function_at(caddr)
            if not f:
                continue
            nm = f.name
            if not nm or nm.startswith(NAME_HINT_SKIP_PREFIX):
                pass
            else:
                nl = nm.lower().replace('_', '').replace('-', '')
                for needle, sev_label in NAME_PRIM_HINTS.items():
                    if needle in nl:
                        sev, label = sev_label
                        hits.append((sev, label + ' :: ' + nm))
                        break
            try:
                hlil = f.hlil
                if hlil:
                    sub = set()
                    for block in hlil:
                        for instr in block:
                            walk_collect_calls(instr, sub)
                    next_frontier.extend(sub - seen)
            except Exception:
                pass
        frontier = next_frontier
        depth += 1
    return hits


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def _detect_write_what_where(text):
    if not _has_any(text, ['SystemBuffer', '+ 0x18)', 'Type3InputBuffer', 'UserBuffer']):
        return False
    patterns = [
        r'\*\s*\(\s*\*\s*\([^)]*(SystemBuffer|Type3InputBuffer|UserBuffer)',
        r'\*\s*\w+\s*=\s*\*\s*\w+\s*;',
        r'\*\(int(?:32|64)?_t\s*\*\)\s*\(?\*',
    ]
    for p in patterns:
        if re.search(p, text):
            return True
    return False


def _detect_arb_read(text):
    if 'memcpy' not in text and 'RtlCopyMemory' not in text:
        return False
    return bool(re.search(r'(?:memcpy|RtlCopyMemory)\s*\([^,]+,\s*\*\s*\(', text))


def _detect_stack_bof(text):
    if not _has_any(text, ['memcpy', 'RtlCopyMemory', 'strcpy', 'wcscpy']):
        return False
    has_user_len = _has_any(text, ['InputBufferLength', 'OutputBufferLength', '+ 0x8)', '+ 0x10)'])
    has_stack = bool(re.search(r'var_[0-9a-f]+', text))
    return has_user_len and has_stack


def _detect_pool_bof(text):
    if 'ExAllocatePool' not in text:
        return False
    return _has_any(text, ['memcpy', 'RtlCopyMemory']) and _has_any(text, [
        'InputBufferLength', 'OutputBufferLength'])


def _detect_null_deref(text):
    m = re.search(r'(?:Ex)?AllocatePool\w*\([^)]*\)', text)
    if not m:
        return False
    tail = text[m.end(): m.end() + 600]
    if not re.search(r'\*\s*\w+|->\w+', tail):
        return False
    return not re.search(r'if\s*\(\s*!?\w+\s*(?:==|!=)?\s*(?:0|NULL|nullptr)?\s*\)', tail[:200])


def _detect_token_swap_enabler(text):
    if 'PsLookupProcessByProcessId' not in text and 'PsGetCurrentProcess' not in text:
        return False
    return any(off in text for off in _TOKEN_OFFSETS)


def _detect_type_confusion(text):
    if 'ObReferenceObjectByHandle' not in text:
        return False
    return bool(re.search(r'ObReferenceObjectByHandle\s*\([^,]+,[^,]+,\s*(?:0|NULL|nullptr)\s*,', text))


def _detect_ioring(text):
    return [n for n in _IORING_NAMES if n in text]


def _detect_double_fetch(text):
    refs = re.findall(r'\*\s*\(\s*(?:int\d*_t|void)\s*\*\s*\)\s*(\*\s*\([^)]+SystemBuffer[^)]*\))', text)
    if len(refs) < 2:
        return False
    return len(set(refs)) < len(refs)


def _detect_msr_rw(text):
    return '__rdmsr' in text or '__wrmsr' in text or 'Rdmsr' in text or 'Wrmsr' in text


def _detect_port_io(text):
    return ('__in_' in text or '__out_' in text or
            'READ_PORT_' in text or 'WRITE_PORT_' in text)


def _detect_phys_mem(text):
    return ('MmMapIoSpace' in text or 'MmMapIoSpaceEx' in text or
            'MmGetPhysicalAddress' in text or 'MmCopyMemory' in text or
            '\\Device\\PhysicalMemory' in text)


def _detect_cr_access(text):
    return ('__readcr' in text or '__writecr' in text or
            '__readdr' in text or '__writedr' in text)


def _detect_pci_config(text):
    return 'HalGetBusData' in text or 'HalSetBusData' in text


def _detect_ring0_exec(text):
    return bool(re.search(r'\(\s*\*\s*\(\s*\w+\s*\*\s*\)\s*SystemBuffer\s*\)\s*\(', text))


def _detect_uninit_leak(text):
    has_nonzero_alloc = bool(re.search(r'ExAllocatePool(?:WithTag)?\b', text)) and \
                        'ExAllocatePool2' not in text
    if not has_nonzero_alloc:
        return False
    if 'RtlZeroMemory' in text or 'memset' in text:
        return False
    return _has_any(text, ['SystemBuffer', 'UserBuffer', 'Type3InputBuffer'])


def _detect_virtual_mem_rw(text):
    return _has_any(text, [
        'ZwReadVirtualMemory', 'NtReadVirtualMemory',
        'ZwWriteVirtualMemory', 'NtWriteVirtualMemory',
        'MmCopyVirtualMemory',
    ])


def _detect_mdl_map(text):
    has_mdl = 'IoAllocateMdl' in text or 'MmCreateMdl' in text
    if not has_mdl:
        return False
    return 'MmMapLockedPagesSpecifyCache' in text or 'MmMapLockedPages' in text


def _detect_handle_dup(text):
    if 'ZwDuplicateObject' not in text and 'ObDuplicateObject' not in text:
        return False
    return True


def _detect_section_phys(text):
    return 'ZwOpenSection' in text and 'ZwMapViewOfSection' in text


def _detect_callback_removal(text):
    return _has_any(text, [
        'PsSetCreateProcessNotifyRoutine',
        'PsSetCreateProcessNotifyRoutineEx',
        'PsSetCreateThreadNotifyRoutine',
        'PsSetLoadImageNotifyRoutine',
        'CmUnRegisterCallback',
        'ObUnRegisterCallbacks',
    ])


def _detect_process_thread_manip(text):
    return _has_any(text, [
        'ZwTerminateProcess', 'NtTerminateProcess',
        'ZwSuspendProcess', 'NtSuspendProcess',
        'ZwSuspendThread', 'NtSuspendThread',
        'NtSetContextThread', 'ZwSetContextThread',
    ])


def _detect_dse_bypass(text):
    return _has_any(text, [
        'g_CiOptions', 'CiInitialize', 'CiValidateImageHeader',
        'SeValidateImageHeader', 'CiCheckSignedFile',
    ])


def _detect_etw_tamper(text):
    return _has_any(text, [
        'EtwEventWrite', 'EtwpEventWriteFull',
        'NtTraceControl', 'EtwpEventEnabled',
    ])


# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------

_DETECTORS = [
    ('Write-What-Where',          'CRITICAL', _detect_write_what_where),
    ('Arbitrary Kernel Read',     'CRITICAL', _detect_arb_read),
    ('MSR Read/Write Primitive',  'CRITICAL', _detect_msr_rw),
    ('Port IO Primitive',         'CRITICAL', _detect_port_io),
    ('Physical Memory Map',       'CRITICAL', _detect_phys_mem),
    ('Control/Debug Register Access', 'CRITICAL', _detect_cr_access),
    ('Ring-0 Exec (Capcom-style)','CRITICAL', _detect_ring0_exec),
    ('PCI Config Space Access',   'HIGH',     _detect_pci_config),
    ('Stack Buffer Overflow',     'HIGH',     _detect_stack_bof),
    ('Pool Buffer Overflow',      'HIGH',     _detect_pool_bof),
    ('NULL Pointer Deref',        'MEDIUM',   _detect_null_deref),
    ('Token-Swap Primitive',      'CRITICAL', _detect_token_swap_enabler),
    ('Type Confusion (Object)',   'HIGH',     _detect_type_confusion),
    ('Double-Fetch TOCTOU',       'HIGH',     _detect_double_fetch),
    ('Uninitialized Pool Leak',   'MEDIUM',   _detect_uninit_leak),
    ('Virtual Memory R/W',        'CRITICAL', _detect_virtual_mem_rw),
    ('MDL Kernel-to-User Map',    'CRITICAL', _detect_mdl_map),
    ('Handle Duplication',        'HIGH',     _detect_handle_dup),
    ('Section-Based Phys Access', 'CRITICAL', _detect_section_phys),
    ('Callback Removal',          'HIGH',     _detect_callback_removal),
    ('Process/Thread Manipulation','HIGH',    _detect_process_thread_manip),
    ('DSE/CI Manipulation',       'CRITICAL', _detect_dse_bypass),
    ('ETW Tampering',             'HIGH',     _detect_etw_tamper),
]


# ---------------------------------------------------------------------------
# Plugin entry
# ---------------------------------------------------------------------------

def _emit_ioring_imports(bv, emit):
    found = []
    for sym in bv.get_symbols():
        if any(n in sym.name for n in _IORING_NAMES):
            found.append(sym.name)
    if found:
        emit("")
        emit("[>] IORING symbols present (read knifecoat.com / windows-internals.com):")
        for n in sorted(set(found)):
            emit("    {}".format(n))


def find_exploit_primitives(bv: BinaryView):
    lines = [
        "=== Windows Kernel Exploit Primitive Report ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-primitives.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    dispatchers = find_dispatch_routines(bv)
    if not dispatchers:
        emit("[-] No IOCTL dispatcher found. Falling back to whole-binary scan.")
        whole = ""
        for f in bv.functions:
            whole += "\n" + get_hlil_text(f)
        for name, sev, det in _DETECTORS:
            if det(whole):
                emit("    [{}] {} (binary-wide)".format(sev, name))
        _emit_ioring_imports(bv, emit)
        _save(report_path, lines, emit)
        return

    emit("[>] Dispatchers: {}".format(", ".join(d.name for d in dispatchers)))
    emit("")

    findings_by_ioctl = {}
    for df in dispatchers:
        branches = ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, _addr in branches:
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in by_code.items():
            text = deep_text(bv, instrs, max_depth=3)
            hits = []
            for name, sev, det in _DETECTORS:
                try:
                    if det(text):
                        hits.append((sev, name))
                except Exception as e:
                    log_warn("detector {} failed: {}".format(name, e))
            ioring = _detect_ioring(text)
            for n in ioring:
                hits.append(('HIGH', 'IORING reference: ' + n))
            for sev, label in _detect_name_hints(bv, instrs):
                hits.append((sev, label))
            hits = list(dict.fromkeys(hits))
            if hits:
                d = ctl_decode(code)
                method = METHOD_MAP.get(d['method'], str(d['method']))
                callees = sorted({resolve_callee_name(bv, c)
                                  for c in branch_callees(bv, instrs)})
                findings_by_ioctl[(df.name, code)] = (method, hits, callees)

    if not findings_by_ioctl:
        emit("[+] No primitives detected in handlers.")
    else:
        emit("[>] Primitives per IOCTL handler...")
        for (dname, code), (method, hits, callees) in sorted(findings_by_ioctl.items()):
            emit("  IOCTL 0x{:08X} ({}) in {}".format(code, method, dname))
            for sev, name in sorted(hits):
                emit("    [{}] {}".format(sev, name))
            if callees:
                emit("    calls: {}".format(", ".join(callees[:8])))

    _emit_ioring_imports(bv, emit)

    # Probe coverage on METHOD_NEITHER
    emit("")
    emit("[>] Probe coverage on METHOD_NEITHER IOCTLs...")
    for df in dispatchers:
        dt = get_hlil_text(df)
        has_probe = any(p in dt for p in _PROBE_NAMES)
        neither = False
        for code, _i, _a in ioctl_branches_for_dispatcher(df):
            if ctl_decode(code)['method'] == 3:
                neither = True
                break
        if neither and not has_probe:
            emit("    [CRITICAL] {} dispatches METHOD_NEITHER without ProbeForRead/Write".format(df.name))

    _save(report_path, lines, emit)


def _save(report_path, lines, emit):
    try:
        with open(report_path, 'w') as f:
            f.write("\n".join(lines))
        emit("[+] Report saved to: {}".format(report_path))
    except Exception as e:
        log_warn("Could not write primitive report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Exploit Primitive Finder",
    "Detect arb-R/W, write-what-where, token swap, vmem R/W, MDL map, handle dup, callback removal, DSE/ETW tampering primitives",
    find_exploit_primitives,
)