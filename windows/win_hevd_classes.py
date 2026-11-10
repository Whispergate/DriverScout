"""
Binary Ninja plugin - HEVD-style vulnerability classification.

Classifies each IOCTL handler against the HackSysExtremeVulnerableDriver
taxonomy. Extended with privileged-primitive classes for BYOVD coverage.

Uses shared modules: dispatch.py, ioctl_shared.py, primitive_db.py

Ref: github.com/hacksysteam/HackSysExtremeVulnerableDriver, p.ost2.fyi
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text
from ..shared.dispatch import find_dispatch_routines
from ..shared.ioctl_shared import (
    ctl_decode, METHOD_MAP, ioctl_branches_for_dispatcher,
)
from ..shared.primitive_db import (
    NAME_CLASS_HINTS, NAME_HINT_SKIP_PREFIX,
    walk_collect_text, walk_collect_calls, MAX_CLASSIFY_DEPTH, MAX_DEEP_CALLEES,
)


_MAX_DEPTH = 3
_MAX_PER_LEVEL = 16


def _txt(instrs, bv, deep=True):
    parts = []
    callees = set()
    for ins in instrs:
        walk_collect_text(ins, parts)
        walk_collect_calls(ins, callees)
    t = "\n".join(parts)
    if not deep:
        return t, callees
    seen = set()
    frontier = list(callees)
    depth = 0
    while frontier and depth < _MAX_DEPTH:
        nxt = []
        count = 0
        for c in frontier:
            if count >= _MAX_PER_LEVEL:
                break
            if c in seen:
                continue
            seen.add(c)
            count += 1
            f = bv.get_function_at(c)
            if not f:
                continue
            try:
                t += "\n; --- " + f.name + " ---\n" + get_hlil_text(f)
            except Exception:
                continue
            try:
                hlil = f.hlil
                if hlil:
                    sub = set()
                    for block in hlil:
                        for instr in block:
                            walk_collect_calls(instr, sub)
                    nxt.extend(sub - seen)
            except Exception:
                pass
        frontier = nxt
        depth += 1
    return t, callees


def _name_hint_classes(bv, callees):
    """Walk callees and match function names to HEVD bug classes."""
    hits = set()
    seen = set()
    frontier = list(callees)
    depth = 0
    while frontier and depth < _MAX_DEPTH:
        nxt = []
        for c in frontier:
            if c in seen:
                continue
            seen.add(c)
            f = bv.get_function_at(c)
            if not f:
                continue
            nm = f.name
            if not nm or nm.startswith(NAME_HINT_SKIP_PREFIX):
                pass
            else:
                nl = nm.lower().replace('_', '').replace('-', '')
                for needle, cls in NAME_CLASS_HINTS.items():
                    if needle in nl:
                        hits.add(cls)
            try:
                hlil = f.hlil
                if hlil:
                    sub = set()
                    for block in hlil:
                        for instr in block:
                            walk_collect_calls(instr, sub)
                    nxt.extend(sub - seen)
            except Exception:
                pass
        frontier = nxt
        depth += 1
    return hits


# ---------------------------------------------------------------------------
# Individual class detectors
# ---------------------------------------------------------------------------

def _stack_overflow(t):
    return bool(re.search(r'\b(memcpy|RtlCopyMemory|strcpy|wcscpy)\b', t)) and \
           bool(re.search(r'var_[0-9a-f]+', t)) and \
           ('InputBufferLength' in t or '+ 0x8)' in t)


def _stack_gs(t):
    return _stack_overflow(t) and ('__security_cookie' in t or '__security_check_cookie' in t)


def _pool_overflow(t):
    return 'ExAllocatePool' in t and bool(re.search(r'\b(memcpy|RtlCopyMemory)\b', t)) and \
           ('InputBufferLength' in t or 'OutputBufferLength' in t)


def _uaf(t):
    m = re.search(r'ExFreePool\w*\s*\(\s*([a-zA-Z_]\w*)', t)
    if not m:
        return False
    var = m.group(1)
    tail = t[m.end():]
    return bool(re.search(r'\b' + re.escape(var) + r'\s*->|\*\s*' + re.escape(var) + r'\b', tail))


def _double_free(t):
    frees = re.findall(r'ExFreePool\w*\s*\(\s*([a-zA-Z_]\w*)', t)
    return any(frees.count(v) >= 2 for v in set(frees))


def _type_confusion(t):
    return bool(re.search(r'\(\*\s*\(\s*\*\s*\(.*SystemBuffer', t)) or \
           ('ObReferenceObjectByHandle' in t and
            re.search(r'ObReferenceObjectByHandle\([^,]+,[^,]+,\s*(0|NULL)\s*,', t) is not None)


def _arb_overwrite(t):
    if not re.search(r'\*\s*\(.*SystemBuffer', t):
        return False
    return bool(re.search(r'\*\s*\w+\s*=\s*\*', t)) or '*(int64_t*)' in t.lower()


def _insecure_resource(t):
    if not re.search(r'Zw(Open|Create)(File|Key|Section)', t):
        return False
    return 'SeImpersonateClientEx' not in t and 'PsImpersonateClient' not in t


def _null_deref(t):
    m = re.search(r'(?:Ex)?AllocatePool\w*\([^)]*\)', t)
    if not m:
        return False
    tail = t[m.end(): m.end() + 600]
    has_deref = bool(re.search(r'\*\s*\w+|->\w+', tail))
    has_check = bool(re.search(r'==\s*0|!=\s*0|!\s*\w+|NULL', tail[:300]))
    return has_deref and not has_check


def _uninit_stack(t):
    matches = list(re.finditer(r'var_[0-9a-f]+', t))
    if len(matches) < 2:
        return False
    return 'OutputBufferLength' in t and 'RtlZeroMemory' not in t and 'memset' not in t


def _uninit_heap(t):
    if 'ExAllocatePool' not in t or 'ExAllocatePool2' in t:
        return False
    has_user_out = 'SystemBuffer' in t or 'UserBuffer' in t
    return has_user_out and 'RtlZeroMemory' not in t and 'memset' not in t


def _int_overflow(t):
    return bool(re.search(r'(InputBufferLength|OutputBufferLength|\+\s*0x[18])\)\s*\*\s*', t)) or \
           bool(re.search(r'\*\s*(InputBufferLength|OutputBufferLength)', t))


def _double_fetch(t):
    refs = re.findall(r'\*\s*\(\s*[^)]*SystemBuffer[^)]*\)', t)
    return len(refs) >= 2 and 'ProbeForRead' not in t


def _mem_disclosure(t):
    has_copy_out = bool(re.search(r'(memcpy|RtlCopyMemory)\s*\([^,]*(SystemBuffer|UserBuffer|Type3InputBuffer)', t))
    return has_copy_out and ('ExAllocatePool' in t and 'ExAllocatePool2' not in t) and \
           'RtlZeroMemory' not in t


def _race(t):
    has_global = bool(re.search(r'data_[0-9a-f]+\s*=', t)) or bool(re.search(r'\bg_\w+\s*=', t))
    has_sync = bool(re.search(r'(KeAcquireSpinLock|ExAcquireFastMutex|ExAcquirePushLock|Interlocked)', t))
    return has_global and not has_sync


def _gdi_confusion(t):
    return 'EngAllocMem' in t or 'EngCreateBitmap' in t or 'PALOBJ' in t


def _msr_rw(t):
    return '__rdmsr' in t or '__wrmsr' in t


def _port_io(t):
    return '__in_' in t or '__out_' in t or 'READ_PORT_' in t or 'WRITE_PORT_' in t


def _phys_map(t):
    return ('MmMapIoSpace' in t or 'MmGetPhysicalAddress' in t or
            'MmCopyMemory' in t or '\\Device\\PhysicalMemory' in t)


def _cr_access(t):
    return '__readcr' in t or '__writecr' in t or '__readdr' in t or '__writedr' in t


def _ring0_exec(t):
    return bool(re.search(r'\(\s*\*\s*\(\s*\w+\s*\*\s*\)\s*SystemBuffer\s*\)\s*\(', t))


_CLASSES = [
    ('StackOverflow',                _stack_overflow),
    ('StackOverflowGS',              _stack_gs),
    ('PoolOverflow',                 _pool_overflow),
    ('UseAfterFree',                 _uaf),
    ('DoubleFree',                   _double_free),
    ('TypeConfusion',                _type_confusion),
    ('ArbitraryOverwrite',           _arb_overwrite),
    ('InsecureKernelResourceAccess', _insecure_resource),
    ('NullPointerDereference',       _null_deref),
    ('UninitializedStackVariable',   _uninit_stack),
    ('UninitializedHeapVariable',    _uninit_heap),
    ('IntegerOverflow',              _int_overflow),
    ('DoubleFetch',                  _double_fetch),
    ('MemoryDisclosure',             _mem_disclosure),
    ('RaceCondition',                _race),
    ('GdiBitmapPolymorphism',        _gdi_confusion),
    ('MSRReadWrite',                 _msr_rw),
    ('PortIO',                       _port_io),
    ('PhysicalMemoryMap',            _phys_map),
    ('ControlRegisterAccess',        _cr_access),
    ('Ring0Exec',                    _ring0_exec),
]


def _safe(fn, t):
    try:
        return fn(t)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Plugin entry
# ---------------------------------------------------------------------------

def classify_hevd(bv: BinaryView):
    lines = [
        "=== HEVD-Style Vulnerability Classification ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report = os.path.join(log_dir, drv + '-hevd-classes.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    dispatchers = find_dispatch_routines(bv)
    if not dispatchers:
        emit("[-] No dispatcher found.")
        return

    counts = {cls: 0 for cls, _ in _CLASSES}
    for df in dispatchers:
        emit("[>] Dispatcher {} (0x{:x})".format(df.name, df.start))
        branches = ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, _ in branches:
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in sorted(by_code.items()):
            t, callees = _txt(instrs, bv)
            hits = set(cls for cls, det in _CLASSES if _safe(det, t))
            hits |= _name_hint_classes(bv, callees)
            for h in hits:
                counts[h] = counts.get(h, 0) + 1
            d = ctl_decode(code)
            method = METHOD_MAP.get(d['method'], str(d['method']))
            label = ", ".join(sorted(hits)) if hits else "(no class matched)"
            emit("    IOCTL 0x{:08X} ({}): {}".format(code, method, label))
        emit("")

    emit("[>] Summary (class -> handler count):")
    for cls, _ in _CLASSES:
        if counts[cls]:
            emit("    {:35s} {}".format(cls, counts[cls]))

    try:
        with open(report, 'w') as f:
            f.write("\n".join(lines))
        emit("[+] Report: {}".format(report))
    except Exception as e:
        log_warn("write fail: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\HEVD Vulnerability Classifier",
    "Classify each IOCTL against HEVD bug-class taxonomy",
    classify_hevd,
)