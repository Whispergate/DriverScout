"""
Binary Ninja plugin - Pool spray feasibility analysis.

For pool overflow and UAF primitives, analyzes:
  - Pool type (Paged, NonPaged, NonPagedNx, Session)
  - Allocation size and tag
  - Segment Heap vs legacy pool allocator impact
  - Viable spray objects for the allocation size
  - Pool grooming strategy recommendations

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text, get_callers, get_mlil_text, const_value
from .win_vuln_finder import _find_dispatch_routines, _ioctl_branches_for_dispatcher, _ctl_decode

# Pool types
_POOL_TYPES = {
    0: 'NonPagedPool',
    1: 'PagedPool',
    2: 'NonPagedPoolMustSucceed',
    4: 'NonPagedPoolCacheAligned',
    5: 'PagedPoolCacheAligned',
    32: 'NonPagedPoolSession',
    33: 'PagedPoolSession',
    512: 'NonPagedPoolNx',
    516: 'NonPagedPoolNxCacheAligned',
    544: 'NonPagedPoolSessionNx',
}

# ExAllocatePool* API patterns
_POOL_ALLOC_APIS = [
    'ExAllocatePool',
    'ExAllocatePoolWithTag',
    'ExAllocatePoolWithQuota',
    'ExAllocatePoolWithQuotaTag',
    'ExAllocatePool2',
    'ExAllocatePool3',
    'ExAllocatePoolZero',
]

# Known spray objects by size bucket (NonPagedPoolNx, x64)
# Format: (min_size, max_size, object_name, spray_method, notes)
_SPRAY_OBJECTS = [
    # Small pool (< 0x100)
    (0x20, 0x30, '_WNF_STATE_DATA', 'NtUpdateWnfStateData', 'Flexible size 0x20-0x1000'),
    (0x30, 0x40, '_NAMED_PIPE_CREATE_PARAMETERS', 'NtCreateNamedPipeFile', 'Fixed 0x38'),
    (0x40, 0x50, '_IO_COMPLETION_OBJECT', 'NtCreateIoCompletion', 'Fixed 0x48 NonPagedPoolNx'),
    (0x50, 0x60, '_KALPC_MESSAGE', 'NtAlpcSendWaitReceivePort', 'Variable size'),
    (0x60, 0x70, '_TOKEN (fast ref)', 'NtDuplicateToken', 'Controlled via group count'),
    (0x80, 0xA0, '_KEVENT', 'NtCreateEvent', 'Fixed 0x88'),
    (0xA0, 0xC0, '_POOL_HEADER + NtFsControlFile', 'NtFsControlFile', 'FSCTL_PIPE_PEEK spray'),

    # Medium pool (0x100 - 0x400)
    (0x100, 0x110, '_KENUMERATIONCONTEXT', 'NtQueryDirectoryObject', 'Size 0x108'),
    (0x150, 0x160, '_OBJECT_TYPE_INITIALIZER', 'ObCreateObjectType', 'Kernel only'),
    (0x200, 0x210, '_PIPE_ATTRIBUTE', 'NtFsControlFile(FSCTL_PIPE_INTERNAL_WRITE)', 'Classic 0x200 spray'),
    (0x280, 0x290, '_KMUTANT', 'NtCreateMutant', 'Fixed 0x288 NonPagedPoolNx'),
    (0x300, 0x400, '_ALPC_HANDLE_TABLE', 'NtAlpcSendWaitReceivePort', 'Variable'),

    # Large pool (0x400+)
    (0x400, 0x500, '_KQUEUE', 'NtCreateIoCompletion', 'Fixed 0x480'),
    (0x500, 0x600, '_WNF_STATE_DATA (large)', 'NtUpdateWnfStateData', 'Controllable up to 0x1000'),
    (0x1000, 0x2000, 'Pipe data', 'NtFsControlFile + write', 'Page-aligned pipe data spray'),
]

# Paged pool spray objects
_PAGED_SPRAY = [
    (0x20, 0x100, '_OBJECT_NAME_INFORMATION', 'NtQueryObject', 'PagedPool'),
    (0x200, 0x210, '_PIPE_ATTRIBUTE', 'NtFsControlFile', 'PagedPool variant'),
    (0x100, 0x1000, 'Registry key value', 'NtSetValueKey', 'Controllable size PagedPool'),
]


def _find_pool_allocations(bv):
    """Find all pool allocation sites with type, size, and tag."""
    allocs = []

    for api in _POOL_ALLOC_APIS:
        for func, ref_addr in get_callers(bv, api):
            entry = {
                'api': api,
                'func': func.name,
                'func_addr': func.start,
                'ref_addr': ref_addr,
                'pool_type': None,
                'pool_type_name': None,
                'size': None,
                'tag': None,
            }

            # Try MLIL parameter extraction
            try:
                from ..shared.helpers import get_call_params_at
                params = get_call_params_at(func, ref_addr)
                if params:
                    if api == 'ExAllocatePool2':
                        # ExAllocatePool2(Flags, Size, Tag)
                        if len(params) >= 2:
                            size_val = const_value(params[1])
                            if size_val is not None:
                                entry['size'] = size_val
                        if len(params) >= 3:
                            tag_val = const_value(params[2])
                            if tag_val is not None:
                                entry['tag'] = _tag_to_str(tag_val)
                    elif 'WithTag' in api or 'WithQuotaTag' in api:
                        # ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag)
                        if len(params) >= 1:
                            pt = const_value(params[0])
                            if pt is not None:
                                entry['pool_type'] = pt
                                entry['pool_type_name'] = _POOL_TYPES.get(pt, 'Unknown({})'.format(pt))
                        if len(params) >= 2:
                            size_val = const_value(params[1])
                            if size_val is not None:
                                entry['size'] = size_val
                        if len(params) >= 3:
                            tag_val = const_value(params[2])
                            if tag_val is not None:
                                entry['tag'] = _tag_to_str(tag_val)
                    else:
                        # ExAllocatePool(PoolType, NumberOfBytes)
                        if len(params) >= 1:
                            pt = const_value(params[0])
                            if pt is not None:
                                entry['pool_type'] = pt
                                entry['pool_type_name'] = _POOL_TYPES.get(pt, 'Unknown({})'.format(pt))
                        if len(params) >= 2:
                            size_val = const_value(params[1])
                            if size_val is not None:
                                entry['size'] = size_val
            except Exception:
                pass

            # Fallback: HLIL text scan for size/tag
            if entry['size'] is None or entry['tag'] is None:
                dt = get_hlil_text(func)
                if entry['size'] is None:
                    # Look for size near call site
                    size_pat = re.compile(r'{}[^;]*?(?:,\s*)(0x[0-9a-fA-F]+|\d+)'.format(
                        re.escape(api)))
                    for m in size_pat.finditer(dt):
                        try:
                            v = int(m.group(1), 16 if '0x' in m.group(1) else 10)
                            if 0 < v < 0x100000:
                                entry['size'] = v
                                break
                        except Exception:
                            pass

                if entry['tag'] is None:
                    # Look for 4-char tag near call
                    tag_pat = re.compile(r"'([A-Za-z0-9 ]{4})'")
                    idx = dt.find(api)
                    if idx >= 0:
                        nearby = dt[max(0, idx - 100):idx + 200]
                        m = tag_pat.search(nearby)
                        if m:
                            entry['tag'] = m.group(1)

            allocs.append(entry)

    return allocs


def _tag_to_str(val):
    """Convert 4-byte integer pool tag to string."""
    try:
        return struct.pack('<I', val & 0xFFFFFFFF).decode('ascii', errors='replace').rstrip('\x00')
    except Exception:
        return '0x{:08X}'.format(val)


import struct as _struct


def _find_spray_candidates(size, pool_type):
    """Find spray objects matching the allocation size bucket."""
    candidates = []
    is_paged = pool_type is not None and pool_type in (1, 5, 33)

    spray_list = _PAGED_SPRAY if is_paged else _SPRAY_OBJECTS

    for min_sz, max_sz, obj_name, method, notes in spray_list:
        if size is not None and min_sz <= size < max_sz:
            candidates.append((obj_name, method, notes, 'exact'))
        elif size is not None and abs(size - min_sz) <= 0x20:
            candidates.append((obj_name, method, notes, 'near'))

    # Also check NonPaged objects even for paged allocations (adjacent chunk)
    if is_paged and size is not None:
        for min_sz, max_sz, obj_name, method, notes in _SPRAY_OBJECTS:
            if min_sz <= size < max_sz:
                candidates.append((obj_name, method, notes + ' (cross-pool adjacent)', 'adjacent'))

    return candidates


def _assess_exploitability(alloc):
    """Assess pool overflow/UAF exploitability for a single allocation."""
    findings = []
    size = alloc['size']
    pt = alloc['pool_type']
    pt_name = alloc['pool_type_name'] or 'Unknown'

    if size is None:
        findings.append(('INFO', 'Size not resolved - manual analysis needed'))
        return findings

    # Segment Heap impact
    if size < 0x200:
        findings.append(('INFO',
            'Small allocation (0x{:X}) - Segment Heap LFH bucket on Win10 2004+'.format(size)))
        findings.append(('MEDIUM',
            'LFH randomization makes adjacent chunk control harder than legacy pool'))
    elif size < 0x1000:
        findings.append(('INFO',
            'Medium allocation (0x{:X}) - Segment Heap VS allocation on 2004+'.format(size)))
    else:
        findings.append(('INFO',
            'Large allocation (0x{:X}) - direct VA allocation on both legacy and segment heap'.format(size)))

    # Pool type assessment
    if pt is not None:
        if pt == 0:  # NonPagedPool (executable!)
            findings.append(('HIGH',
                'NonPagedPool (EXECUTABLE) - if overflow, can overwrite adjacent code'))
            findings.append(('INFO',
                'Legacy NonPagedPool is RWX - modern drivers should use NonPagedPoolNx'))
        elif pt == 512:  # NonPagedPoolNx
            findings.append(('INFO',
                'NonPagedPoolNx - non-executable; data-only corruption viable'))
        elif pt == 1:  # PagedPool
            findings.append(('INFO',
                'PagedPool - pageable; available spray objects differ from NonPaged'))

    # Size-specific spray recommendations
    if size == 0x40 or size == 0x48:
        findings.append(('HIGH',
            'Size 0x{:X} is a golden size for pool overflow on legacy allocator'.format(size)))
        findings.append(('INFO', 'Classic: corrupt POOL_HEADER.PoolTag for pool corruption'))
    elif size == 0x200:
        findings.append(('HIGH',
            'Size 0x200 matches _PIPE_ATTRIBUTE - classic spray target'))

    return findings


def analyze_pool_spray(bv: BinaryView):
    lines = [
        "=== Pool Spray Feasibility Analysis ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-pool-spray.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    # Find pool allocations
    allocs = _find_pool_allocations(bv)
    if not allocs:
        emit("[-] No pool allocation calls found")
        return

    emit("[+] Pool allocations: {} found".format(len(allocs)))
    emit("")

    for alloc in allocs:
        emit("  {} in {} (0x{:x})".format(alloc['api'], alloc['func'], alloc['ref_addr']))
        if alloc['pool_type_name']:
            emit("    Pool type: {} ({})".format(alloc['pool_type_name'], alloc['pool_type']))
        if alloc['size'] is not None:
            emit("    Size: 0x{:X} ({})".format(alloc['size'], alloc['size']))
        if alloc['tag']:
            emit("    Tag: '{}'".format(alloc['tag']))

        # Exploitability assessment
        findings = _assess_exploitability(alloc)
        for sev, desc in findings:
            emit("    [{}] {}".format(sev, desc))

        # Spray candidates
        candidates = _find_spray_candidates(alloc['size'], alloc['pool_type'])
        if candidates:
            emit("    Spray candidates:")
            for obj, method, notes, match_type in candidates:
                emit("      [{}] {} via {} ({})".format(match_type, obj, method, notes))

        emit("")

    # Summary
    sized = [a for a in allocs if a['size'] is not None]
    emit("[>] Summary: {} allocations ({} with resolved size)".format(len(allocs), len(sized)))

    # Group by size bucket
    if sized:
        buckets = {}
        for a in sized:
            bucket = (a['size'] // 0x10) * 0x10
            buckets.setdefault(bucket, []).append(a)
        emit("[>] Size distribution:")
        for bucket in sorted(buckets.keys()):
            emit("    0x{:X}: {} allocations".format(bucket, len(buckets[bucket])))

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write pool spray report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Pool Spray Feasibility",
    "Analyze pool allocations for overflow/UAF exploitation and spray viability",
    analyze_pool_spray,
)
