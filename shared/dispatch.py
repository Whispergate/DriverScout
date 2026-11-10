"""
Shared dispatch routine discovery for Windows kernel drivers.

Unified S1-S7 strategies used by: win_find_ioctls, win_vuln_finder,
win_primitives, win_hevd_classes, win_chain.

S1: HLIL pattern - MajorFunction[0xe/14] or *(arg + 0xe0) assignments,
    IoSetCompletionRoutine, drv_obj->MajorFunction[14] = handler
S2: Name heuristic - function name contains dispatch keywords + IOCTL codes
S3: C++ class pattern - caller of >= 2 ioctl-named functions
S4: Fallback - individual ioctl-named functions
S5: IOCTL-density scan - >= 3 plausible IOCTL constants in function
S6: WDF KMDF dispatch - WdfIoQueueCreate callbacks (EvtIoDeviceControl)
S7: Sub-dispatch - top-level router calling 2+ functions each with 3+ IOCTLs
"""

import re
from binaryninja import BinaryView, log_info, log_warn

from .helpers import get_hlil_text
from .ioctl_shared import find_ioctls_in_func


# ---------------------------------------------------------------------------
# Dispatch pattern strings
# ---------------------------------------------------------------------------

DISPATCH_PATTERNS = [
    r'\+\s*0xe0\b',                              # untyped: *(arg + 0xe0) = handler
    r'MajorFunction\[(?:0xe|14)\]',               # typed: arg1->MajorFunction[0xe]
    r'MajorFunction\[',                            # any MajorFunction slot assignment
    r'\+\s*0x70\b',                               # untyped: MajorFunction[0]
    r'\[0x1c\]\s*=',                              # int64_t*[28] subscript (0xE0/8)
    r'\[28\]\s*=',                                # decimal subscript form
    r'IoSetCompletionRoutine\s*\(',               # IoSetCompletionRoutine(irp, handler, ...)
    r'->MajorFunction\[\s*(?:0xe|14|IRP_MJ_DEVICE_CONTROL)\s*\]', # arrow-style typed access
]

# WDF symbols indicating KMDF callback dispatch (S6)
_WDF_QUEUE_SYMBOLS = [
    'WdfIoQueueCreate', 'wdfIoQueueCreate',
    'WdfDeviceCreateDeviceInterface', 'wdfDeviceCreateDeviceInterface',
]
_WDF_CALLBACK_HINTS = [
    'EvtIoDeviceControl', 'EvtIoDefault', 'EvtIoRead', 'EvtIoWrite',
    'EvtIoInternalDeviceControl',
]

NAME_HINTS = [
    'devicecontrol', 'dispatchio', 'ioctlhandler', 'ioctldispatch',
    'dispatchioctl', 'irpdevicecontrol', 'ioctlrouter', 'ioctldispatcher',
]

_ENTRY_EXCLUDE = {'driverentry', 'dllmain', 'winmain', '_start', 'driverunload'}


# ---------------------------------------------------------------------------
# Dispatch discovery
# ---------------------------------------------------------------------------

def find_dispatch_routines(bv: BinaryView):
    """Return list of Function objects identified as IRP_MJ_DEVICE_CONTROL dispatch."""
    routines = []
    seen = set()

    # S1: HLIL MajorFunction assignment pattern scan
    s1_lines_scanned = 0
    for func in bv.functions:
        dt = get_hlil_text(func)
        if not dt:
            continue
        for line in dt.splitlines():
            s1_lines_scanned += 1
            for pat in DISPATCH_PATTERNS:
                if not re.search(pat, line, re.IGNORECASE):
                    continue
                m = re.search(r'=\s*(?:&\s*)?([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+)', line)
                if not m:
                    continue
                target = m.group(1)
                tgt = None
                if target.startswith('0x'):
                    try:
                        tgt = bv.get_function_at(int(target, 16))
                    except Exception:
                        pass
                else:
                    syms = bv.get_symbols_by_name(target)
                    if syms:
                        tgt = bv.get_function_at(syms[0].address)
                if tgt and tgt.start not in seen:
                    seen.add(tgt.start)
                    routines.append(tgt)
                    log_info(
                        "[S1] Dispatch via HLIL pattern in {}: -> {} (0x{:x}) line='{}'".format(
                            func.name, tgt.name, tgt.start, line.strip()[:120]))
    log_info("[dispatch] S1 scanned {} HLIL lines, found {} routines".format(
        s1_lines_scanned, len(routines)))

    # S2: name heuristic - require IOCTL codes present
    for func in bv.functions:
        name_norm = func.name.lower().replace('_', '').replace('-', '')
        if any(h in name_norm for h in NAME_HINTS) and func.start not in seen:
            if find_ioctls_in_func(func):
                seen.add(func.start)
                routines.append(func)
                log_info("[S2] Dispatch by name: {} (0x{:x})".format(func.name, func.start))

    # S3: caller of >= 2 ioctl-named functions (C++ class dispatch)
    callee_counts = {}
    for func in bv.functions:
        if 'ioctl' in func.name.lower():
            for ref in bv.get_code_refs(func.start):
                if ref.function:
                    callee_counts[ref.function.start] = callee_counts.get(ref.function.start, 0) + 1
    for addr, count in sorted(callee_counts.items(), key=lambda x: -x[1]):
        if count >= 2 and addr not in seen:
            f = bv.get_function_at(addr)
            if f and f.name.lower() not in _ENTRY_EXCLUDE:
                if find_ioctls_in_func(f):
                    seen.add(addr)
                    routines.append(f)
                    log_info("[S3] Dispatch (calls {} ioctl fns): {} (0x{:x})".format(
                        count, f.name, addr))

    # S4: fallback - individual ioctl-named functions
    if not routines:
        log_warn("[!] No dispatcher via S1-S3 - falling back to ioctl-named functions")
        for func in bv.functions:
            if 'ioctl' in func.name.lower() and func.start not in seen:
                seen.add(func.start)
                routines.append(func)

    # S5: IOCTL-density scan (bulletproof fallback)
    if not routines:
        for func in bv.functions:
            if func.start in seen:
                continue
            codes = find_ioctls_in_func(func)
            if len(codes) >= 3:
                seen.add(func.start)
                routines.append(func)
                log_info("[S5] Dispatcher by IOCTL-density ({} codes): {} (0x{:x})".format(
                    len(codes), func.name, func.start))

    # S6: WDF KMDF dispatch - detect WdfIoQueueCreate callback registration
    # WDF drivers don't use MajorFunction assignments; instead they pass a
    # WDF_IO_QUEUE_CONFIG struct with EvtIoDeviceControl to WdfIoQueueCreate.
    # Also look for functions whose symbol name contains callback hints.
    for wdf_sym in _WDF_QUEUE_SYMBOLS:
        for sym in bv.get_symbols_by_name(wdf_sym):
            for ref in bv.get_code_refs(sym.address):
                caller = ref.function
                if not caller or caller.start in seen:
                    continue
                dt = get_hlil_text(caller)
                if not dt:
                    continue
                # Scan the caller for callback assignments into the config struct
                for line in dt.splitlines():
                    # Look for EvtIo* callback assignments or struct field writes
                    for hint in _WDF_CALLBACK_HINTS:
                        if hint.lower() not in line.lower():
                            continue
                        m = re.search(
                            r'=\s*(?:&\s*)?([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+)',
                            line)
                        if not m:
                            continue
                        target = m.group(1)
                        tgt = None
                        if target.startswith('0x'):
                            try:
                                tgt = bv.get_function_at(int(target, 16))
                            except Exception:
                                pass
                        else:
                            syms_t = bv.get_symbols_by_name(target)
                            if syms_t:
                                tgt = bv.get_function_at(syms_t[0].address)
                        if tgt and tgt.start not in seen:
                            seen.add(tgt.start)
                            routines.append(tgt)
                            log_info(
                                "[S6] WDF callback via {}: {} (0x{:x}) hint={}".format(
                                    wdf_sym, tgt.name, tgt.start, hint))
    # Also check for functions whose name directly contains WDF callback hints
    for func in bv.functions:
        if func.start in seen:
            continue
        name_lower = func.name.lower()
        for hint in _WDF_CALLBACK_HINTS:
            if hint.lower() in name_lower:
                if find_ioctls_in_func(func):
                    seen.add(func.start)
                    routines.append(func)
                    log_info("[S6] WDF callback by name: {} (0x{:x})".format(
                        func.name, func.start))
                break

    # S7: Sub-dispatch detection - find top-level dispatchers that route to
    # sub-dispatchers.  A sub-dispatcher is a callee that itself contains
    # >= 3 IOCTL codes.  If a function calls 2+ sub-dispatchers it is a
    # top-level router (e.g. RTCore64 DriverDispatch -> ReadHandler + WriteHandler).
    _sub_dispatch_threshold = 3   # min IOCTLs for a callee to count
    _router_callees_min = 2       # min sub-dispatcher callees for the router
    sub_dispatchers_cache = {}    # addr -> ioctl count (avoids re-scanning)
    for func in bv.functions:
        if func.start in seen:
            continue
        if func.name.lower() in _ENTRY_EXCLUDE:
            continue
        try:
            hlil = func.hlil
        except Exception:
            continue
        # Collect distinct callees
        callee_addrs = set()
        for block in hlil:
            for instr in block:
                _collect_call_targets(instr, callee_addrs)
        # Count how many callees are sub-dispatchers
        sub_dispatch_callees = []
        for caddr in callee_addrs:
            if caddr not in sub_dispatchers_cache:
                cf = bv.get_function_at(caddr)
                if cf:
                    codes = find_ioctls_in_func(cf)
                    sub_dispatchers_cache[caddr] = len(codes)
                else:
                    sub_dispatchers_cache[caddr] = 0
            if sub_dispatchers_cache[caddr] >= _sub_dispatch_threshold:
                sub_dispatch_callees.append(caddr)
        if len(sub_dispatch_callees) >= _router_callees_min:
            # The router itself is a dispatch routine
            seen.add(func.start)
            routines.append(func)
            log_info("[S7] Sub-dispatch router ({} sub-dispatchers): {} (0x{:x})".format(
                len(sub_dispatch_callees), func.name, func.start))
            # Also add the sub-dispatchers themselves
            for caddr in sub_dispatch_callees:
                if caddr not in seen:
                    cf = bv.get_function_at(caddr)
                    if cf:
                        seen.add(caddr)
                        routines.append(cf)
                        log_info("[S7] Sub-dispatcher: {} (0x{:x}) [{} IOCTLs]".format(
                            cf.name, caddr, sub_dispatchers_cache[caddr]))

    return routines


def _collect_call_targets(instr, out: set):
    """Recursively extract call target addresses from an HLIL instruction tree."""
    try:
        from binaryninja import HighLevelILOperation
        if instr.operation == HighLevelILOperation.HLIL_CALL:
            dest = instr.dest
            if hasattr(dest, 'constant') and isinstance(dest.constant, int):
                out.add(dest.constant)
            elif hasattr(dest, 'value') and hasattr(dest.value, 'value'):
                out.add(dest.value.value)
        # Recurse into sub-expressions / nested statements
        for attr in ('operands',):
            if hasattr(instr, attr):
                for op in getattr(instr, attr):
                    if hasattr(op, 'operation'):
                        _collect_call_targets(op, out)
                    elif isinstance(op, list):
                        for sub in op:
                            if hasattr(sub, 'operation'):
                                _collect_call_targets(sub, out)
    except Exception:
        pass