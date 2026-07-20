"""
Binary Ninja plugin - IRP completion lifecycle audit.

Checks for IRP handling bugs that cause UAF, resource leaks, and info leaks:
  - Missing IoCompleteRequest on error paths
  - Double completion (IoCompleteRequest on forwarded/completed IRP)
  - IoStatus.Information > OutputBufferLength (kernel info leak)
  - IRP completion at elevated IRQL
  - IoCallDriver then IoCompleteRequest on same IRP

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers

# IRP completion APIs
_COMPLETE_APIS = ['IoCompleteRequest', 'IofCompleteRequest']
_FORWARD_APIS = ['IoCallDriver', 'IofCallDriver', 'PoCallDriver']
_STATUS_PATS = [
    r'IoStatus\s*\.\s*Status\s*=\s*(STATUS_\w+|0x[0-9a-fA-F]+)',
    r'IoStatus\.Status\s*=\s*(\w+)',
]
_INFO_PATS = [
    r'IoStatus\s*\.\s*Information\s*=\s*(0x[0-9a-fA-F]+|\d+|[a-zA-Z_]\w*)',
]
_OUTPUT_LEN_PATS = ['OutputBufferLength', 'outlen', 'out_len', 'cbOutput', 'BytesReturned']

# WDF completion APIs (for mixed drivers)
_WDF_COMPLETE = ['WdfRequestComplete', 'WdfRequestCompleteWithInformation']


def _find_irp_handlers(bv):
    """Find IRP dispatch handlers via MajorFunction assignments and known names."""
    handlers = []
    seen = set()

    # Pattern 1: MajorFunction[N] = &handler
    mj_pat = re.compile(
        r'MajorFunction\[(\d+)\]\s*=\s*(?:&\s*)?([A-Za-z_?@][A-Za-z0-9_?@]*)',
        re.IGNORECASE
    )
    # Pattern 2: *(drv + 0x70 + N*8) = &handler (MajorFunction array at +0x70 in x64)
    raw_pat = re.compile(
        r'\*\s*\([^)]*\+\s*(0x[0-9a-fA-F]+)\s*\)\s*=\s*(?:&\s*)?([A-Za-z_?@][A-Za-z0-9_?@]*)',
        re.IGNORECASE
    )

    for func in bv.functions:
        dt = get_hlil_text(func)
        if 'MajorFunction' not in dt and '+ 0x7' not in dt:
            continue

        for m in mj_pat.finditer(dt):
            name = m.group(2)
            _add_handler(bv, handlers, seen, name, 'MajorFunction[{}]'.format(m.group(1)))

        for m in raw_pat.finditer(dt):
            try:
                offset = int(m.group(1), 16)
                if 0x70 <= offset <= 0x70 + 27 * 8:
                    mj_idx = (offset - 0x70) // 8
                    name = m.group(2)
                    _add_handler(bv, handlers, seen, name, 'MajorFunction[{}]'.format(mj_idx))
            except Exception:
                pass

    # Also check by name heuristic
    for func in bv.functions:
        nm = func.name.lower()
        if any(k in nm for k in ['dispatch', 'irphandler', 'devioctl', 'readwrite']):
            if func.start not in seen:
                seen.add(func.start)
                handlers.append({'func': func, 'source': 'name_heuristic'})

    return handlers


def _add_handler(bv, handlers, seen, name, source):
    syms = bv.get_symbols_by_name(name)
    if syms:
        f = bv.get_function_at(syms[0].address)
        if f and f.start not in seen:
            seen.add(f.start)
            handlers.append({'func': f, 'source': source})
    else:
        for f2 in bv.functions:
            if f2.name == name and f2.start not in seen:
                seen.add(f2.start)
                handlers.append({'func': f2, 'source': source})
                break


def _audit_handler(bv, func):
    """Audit IRP lifecycle in a single handler."""
    dt = get_hlil_text(func)
    findings = []

    complete_count = sum(dt.count(api) for api in _COMPLETE_APIS)
    forward_count = sum(dt.count(api) for api in _FORWARD_APIS)

    # Double completion
    if complete_count >= 2:
        findings.append(('HIGH',
            'Multiple IoCompleteRequest calls - potential double completion UAF',
            'CWE-416: Use After Free'))

    # Forward then complete
    if forward_count > 0 and complete_count > 0:
        # Check if they're in the same code path
        for fwd_api in _FORWARD_APIS:
            if fwd_api in dt:
                fwd_idx = dt.find(fwd_api)
                for cmp_api in _COMPLETE_APIS:
                    if cmp_api in dt:
                        cmp_idx = dt.find(cmp_api)
                        if cmp_idx > fwd_idx:
                            # Forward then complete - needs careful path analysis
                            between = dt[fwd_idx:cmp_idx]
                            if 'return' not in between and 'goto' not in between:
                                findings.append(('CRITICAL',
                                    'IoCallDriver followed by IoCompleteRequest on same path - '
                                    'double completion if lower driver completes synchronously',
                                    'CWE-416: Use After Free'))
                                break

    # Missing completion
    if complete_count == 0 and forward_count == 0:
        # Check for WDF completion
        wdf_complete = any(api in dt for api in _WDF_COMPLETE)
        if not wdf_complete:
            # Might be intentional (pending IRP, power handler)
            has_pending = 'IoMarkIrpPending' in dt or 'STATUS_PENDING' in dt
            if not has_pending:
                findings.append(('MEDIUM',
                    'No IoCompleteRequest or IoCallDriver - IRP may leak',
                    'CWE-404: Resource Leak'))

    # IoStatus.Information > OutputBufferLength (info leak)
    for m in re.finditer(r'IoStatus\s*\.\s*Information\s*=\s*(0x[0-9a-fA-F]+|\d+)', dt):
        try:
            info_val = int(m.group(1), 16 if '0x' in m.group(1) else 10)
            # Check if any output length validation nearby
            idx = m.start()
            nearby = dt[max(0, idx - 500):idx + 500]
            has_outlen_check = any(p in nearby for p in _OUTPUT_LEN_PATS)
            if not has_outlen_check and info_val > 0:
                findings.append(('HIGH',
                    'IoStatus.Information set to 0x{:X} without OutputBufferLength validation'.format(info_val),
                    'CWE-200: Information Exposure'))
        except Exception:
            pass

    # Variable-length Information without bounds check
    info_var_pat = re.compile(r'IoStatus\s*\.\s*Information\s*=\s*([a-zA-Z_]\w*)')
    for m in info_var_pat.finditer(dt):
        var_name = m.group(1)
        if var_name in ('0', 'STATUS_SUCCESS'):
            continue
        idx = m.start()
        nearby = dt[max(0, idx - 800):idx + 200]
        has_outlen_check = any(p in nearby for p in _OUTPUT_LEN_PATS)
        has_min_check = 'min(' in nearby or 'MIN(' in nearby or '< ' in nearby
        if not has_outlen_check and not has_min_check:
            findings.append(('MEDIUM',
                'IoStatus.Information = {} without apparent OutputBufferLength bounds check'.format(var_name),
                'CWE-200: Information Exposure'))

    # IRQL concerns: completion at DISPATCH_LEVEL
    if any(api in dt for api in _COMPLETE_APIS):
        if 'KeAcquireSpinLock' in dt or 'DISPATCH_LEVEL' in dt:
            # Check if spinlock is released before completion
            spinlock_idx = dt.find('KeAcquireSpinLock')
            complete_idx = dt.find('IoCompleteRequest') if 'IoCompleteRequest' in dt else dt.find('IofCompleteRequest')
            if spinlock_idx >= 0 and complete_idx > spinlock_idx:
                release_between = 'KeReleaseSpinLock' in dt[spinlock_idx:complete_idx]
                if not release_between:
                    findings.append(('HIGH',
                        'IoCompleteRequest called while spinlock held (DISPATCH_LEVEL)',
                        'CWE-667: Improper Locking'))

    # STATUS_SUCCESS without setting Information
    status_success_pat = re.compile(r'IoStatus\s*\.\s*Status\s*=\s*(?:STATUS_SUCCESS|0(?:x0+)?)\b')
    for m in status_success_pat.finditer(dt):
        idx = m.start()
        nearby = dt[max(0, idx - 200):idx + 400]
        if 'Information' not in nearby:
            findings.append(('LOW',
                'STATUS_SUCCESS set without IoStatus.Information - may leak stale data',
                'CWE-908: Uninitialized Resource'))

    return findings


def audit_irp_completion(bv: BinaryView):
    lines = [
        "=== IRP Completion Lifecycle Audit ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-irp-audit.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    handlers = _find_irp_handlers(bv)
    if not handlers:
        emit("[-] No IRP handlers found")
        return

    emit("[+] Found {} IRP handlers".format(len(handlers)))
    emit("")

    total_findings = []
    for h in handlers:
        func = h['func']
        emit("  {} -> {} (0x{:x})".format(h['source'], func.name, func.start))

        findings = _audit_handler(bv, func)
        for sev, desc, cwe in findings:
            emit("    [{}] {} ({})".format(sev, desc, cwe))
            total_findings.append((sev, desc, cwe))

        if not findings:
            emit("    (no lifecycle issues detected)")
        emit("")

    # Also check IoCompleteRequest callers globally for patterns
    emit("[>] Global IoCompleteRequest analysis...")
    for api in _COMPLETE_APIS:
        callers_list = list(get_callers(bv, api))
        if callers_list:
            emit("    {} called from {} functions".format(api, len(callers_list)))

    crit = sum(1 for s, _, _ in total_findings if s == 'CRITICAL')
    high = sum(1 for s, _, _ in total_findings if s == 'HIGH')
    med = sum(1 for s, _, _ in total_findings if s == 'MEDIUM')

    emit("\n[>] Summary: {} handlers audited, {} CRITICAL, {} HIGH, {} MEDIUM".format(
        len(handlers), crit, high, med))

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write IRP audit report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\IRP Completion Audit",
    "Audit IRP lifecycle: double completion, missing completion, info leaks",
    audit_irp_completion,
)
