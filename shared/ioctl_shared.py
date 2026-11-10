"""
Shared IOCTL decoding and switch-case extraction for Windows kernel drivers.

Provides CTL_CODE decode, HLIL AST-based code extraction, text-pattern
fallback extraction, and IOCTL branch resolution for dispatchers.

Used by: win_find_ioctls, win_vuln_finder, win_primitives, win_hevd_classes, win_chain,
         win_poc_gen, win_irp_audit.
"""

import re
from binaryninja import BinaryView


# ---------------------------------------------------------------------------
# CTL_CODE lookup tables
# ---------------------------------------------------------------------------

FILE_DEVICE_MAP = {
    0x0: 'FILE_DEVICE_UNKNOWN',         0x1: 'FILE_DEVICE_BEEP',
    0x2: 'FILE_DEVICE_CD_ROM',          0x3: 'FILE_DEVICE_CD_ROM_FILE_SYSTEM',
    0x4: 'FILE_DEVICE_CONTROLLER',      0x5: 'FILE_DEVICE_DATALINK',
    0x6: 'FILE_DEVICE_DFS',             0x7: 'FILE_DEVICE_DISK',
    0x8: 'FILE_DEVICE_DISK_FILE_SYSTEM', 0x9: 'FILE_DEVICE_FILE_SYSTEM',
    0xa: 'FILE_DEVICE_INPORT_PORT',     0xb: 'FILE_DEVICE_KEYBOARD',
    0xc: 'FILE_DEVICE_MAILSLOT',        0xd: 'FILE_DEVICE_MIDI_IN',
    0xe: 'FILE_DEVICE_MIDI_OUT',        0xf: 'FILE_DEVICE_MOUSE',
    0x10: 'FILE_DEVICE_MULTI_UNC_PROVIDER', 0x11: 'FILE_DEVICE_NAMED_PIPE',
    0x12: 'FILE_DEVICE_NETWORK',        0x13: 'FILE_DEVICE_NETWORK_BROWSER',
    0x14: 'FILE_DEVICE_NETWORK_FILE_SYSTEM', 0x15: 'FILE_DEVICE_NULL',
    0x16: 'FILE_DEVICE_PARALLEL_PORT',  0x17: 'FILE_DEVICE_PHYSICAL_NETCARD',
    0x18: 'FILE_DEVICE_PRINTER',        0x19: 'FILE_DEVICE_SCANNER',
    0x1a: 'FILE_DEVICE_SERIAL_MOUSE_PORT', 0x1b: 'FILE_DEVICE_SERIAL_PORT',
    0x1c: 'FILE_DEVICE_SCREEN',         0x1d: 'FILE_DEVICE_SOUND',
    0x1e: 'FILE_DEVICE_STREAMS',        0x1f: 'FILE_DEVICE_TAPE',
    0x20: 'FILE_DEVICE_TAPE_FILE_SYSTEM', 0x21: 'FILE_DEVICE_TRANSPORT',
    0x22: 'FILE_DEVICE_UNKNOWN',        0x23: 'FILE_DEVICE_VIDEO',
    0x24: 'FILE_DEVICE_VIRTUAL_DISK',   0x25: 'FILE_DEVICE_WAVE_IN',
    0x26: 'FILE_DEVICE_WAVE_OUT',       0x27: 'FILE_DEVICE_8042_PORT',
    0x28: 'FILE_DEVICE_NETWORK_REDIRECTOR', 0x29: 'FILE_DEVICE_BATTERY',
    0x2a: 'FILE_DEVICE_BUS_EXTENDER',   0x2b: 'FILE_DEVICE_MODEM',
    0x2c: 'FILE_DEVICE_VDM',            0x2d: 'FILE_DEVICE_MASS_STORAGE',
    0x2e: 'FILE_DEVICE_SMB',            0x2f: 'FILE_DEVICE_KS',
    0x30: 'FILE_DEVICE_CHANGER',        0x31: 'FILE_DEVICE_SMARTCARD',
    0x32: 'FILE_DEVICE_ACPI',           0x33: 'FILE_DEVICE_DVD',
    0x34: 'FILE_DEVICE_FULLSCREEN_VIDEO', 0x35: 'FILE_DEVICE_DFS_FILE_SYSTEM',
    0x36: 'FILE_DEVICE_DFS_VOLUME',     0x37: 'FILE_DEVICE_SERENUM',
    0x38: 'FILE_DEVICE_TERMSRV',        0x39: 'FILE_DEVICE_KSEC',
    0x3a: 'FILE_DEVICE_FIPS',           0x3b: 'FILE_DEVICE_INFINIBAND',
}

METHOD_MAP = {
    0: 'METHOD_BUFFERED',
    1: 'METHOD_IN_DIRECT',
    2: 'METHOD_OUT_DIRECT',
    3: 'METHOD_NEITHER',
}

ACCESS_MAP = {
    0: 'FILE_ANY_ACCESS',
    1: 'FILE_READ_ACCESS',
    2: 'FILE_WRITE_ACCESS',
    3: 'FILE_READ_WRITE_ACCESS',
}

# Hex-prefixed patterns - ordered from specific to broad
IOCTL_PATS_HEX = [
    r'case\s+0x([0-9A-Fa-f]+)\s*:',
    r'ioControlCode\s*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'(?:if|else\s+if)\s*\([^)]*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'\w+\s*[u]?==\s*0x([0-9A-Fa-f]+)',
    r'[u]?==\s*0x([0-9A-Fa-f]{5,})',
]

# Bare decimal patterns - floor 0x200000 == 2097152 (7 digits)
IOCTL_PATS_DEC = [
    r'case\s+(\d{7,})\s*:',
    r'(?:if|else\s+if)\s*\([^)]*[u]?==\s*(\d{7,})\b',
    r'\w+\s*[u]?==\s*(\d{7,})\b',
    r'[u]?==\s*(\d{7,})\b',
]

# Backward compat alias
IOCTL_PATTERNS = IOCTL_PATS_HEX


# ---------------------------------------------------------------------------
# CTL_CODE helpers
# ---------------------------------------------------------------------------

def ctl_decode(v):
    """Decode a CTL_CODE into {raw, device, access, function, method}."""
    v = v & 0xFFFFFFFF
    return {
        'raw': v,
        'device': (v >> 16) & 0xFFFF,
        'access': (v >> 14) & 0x3,
        'function': (v >> 2) & 0xFFF,
        'method': v & 0x3,
    }


def plausible_ioctl(v):
    """Heuristic: does this 32-bit constant look like a CTL_CODE?"""
    v &= 0xFFFFFFFF
    # Reject all-bits-set sentinels (used as refcount compare)
    if v == 0xFFFFFFFF or (v >> 16) == 0xFFFF:
        return False
    d = ctl_decode(v)
    return d['method'] in (0, 1, 2, 3) and d['function'] != 0 and d['device'] != 0


def format_ioctl(code):
    """Format a CTL_CODE as a human-readable string."""
    d = ctl_decode(code)
    device = FILE_DEVICE_MAP.get(d['device'], "0x{:X}".format(d['device']))
    method = METHOD_MAP.get(d['method'], str(d['method']))
    access = ACCESS_MAP.get(d['access'], str(d['access']))
    return (
        "0x{:08X}  Device={} (0x{:X})  Function=0x{:X}  "
        "Method={}  Access={}".format(
            d['raw'], device, d['device'], d['function'], method, access)
    )


def fmt_ioctl_row(addr, code):
    """Format a CTL_CODE as a tabular row for report output."""
    d = ctl_decode(code)
    device = FILE_DEVICE_MAP.get(d['device'], "0x{:X}".format(d['device']))
    method = METHOD_MAP.get(d['method'], str(d['method']))
    access = ACCESS_MAP.get(d['access'], str(d['access']))
    return "0x{:016x}  0x{:06X}  {:35s}  0x{:X}  0x{:<8X}  {}  {}".format(
        addr, d['raw'], device, d['device'], d['function'], method, access)


# ---------------------------------------------------------------------------
# IOCTL constant extraction
# ---------------------------------------------------------------------------

def extract_const(node):
    """Extract an integer constant from an HLIL/MLIL node (Binja 3.x - 6.x)."""
    if isinstance(node, int):
        return node
    try:
        c = getattr(node, 'constant', None)
        if isinstance(c, int):
            return c
    except Exception:
        pass
    try:
        v = getattr(node, 'value', None)
        if isinstance(v, int):
            return v
        if v is not None:
            inner = getattr(v, 'value', None)
            if isinstance(inner, int):
                return inner
            # BN 6.0: RegisterValue may expose .offset for ConstantDataValue
            off = getattr(v, 'offset', None)
            if isinstance(off, int):
                return off
    except Exception:
        pass
    try:
        return int(node)
    except Exception:
        return None


def iter_case_consts(case):
    """Yield masked integer values for a HLIL switch case (Binja 3.x + 4.x)."""
    vals = getattr(case, 'values', None)
    if vals is not None:
        try:
            for v in vals:
                c = extract_const(v)
                if c is not None:
                    yield c & 0xFFFFFFFF
            return
        except Exception:
            pass
    sv = getattr(case, 'value', None)
    if sv is not None:
        c = extract_const(sv)
        if c is not None:
            yield c & 0xFFFFFFFF


def collect_switch_cases(instr, codes):
    """Recursively walk one HLIL instruction, collecting switch case IOCTL values."""
    try:
        opname = instr.operation.name
        # BN 6.0: skip struct initializers - they contain field values, not IOCTL codes
        if opname == 'HLIL_STRUCT_INIT':
            return
        if opname == 'HLIL_SWITCH':
            for case in instr.cases:
                for v in iter_case_consts(case):
                    if v >= 0x200000 and plausible_ioctl(v):
                        codes.add(v)
                body = getattr(case, 'body', None)
                if body is not None:
                    if hasattr(body, 'operation'):
                        collect_switch_cases(body, codes)
                    elif hasattr(body, '__iter__') and not isinstance(body, (str, bytes)):
                        for it in body:
                            if hasattr(it, 'operation'):
                                collect_switch_cases(it, codes)
        elif opname == 'HLIL_IF':
            for attr in ('true', 'false'):
                branch = getattr(instr, attr, None)
                if branch is None:
                    continue
                if hasattr(branch, 'operation'):
                    collect_switch_cases(branch, codes)
                elif hasattr(branch, '__iter__') and not isinstance(branch, (str, bytes)):
                    for it in branch:
                        if hasattr(it, 'operation'):
                            collect_switch_cases(it, codes)
        for operand in getattr(instr, 'operands', []):
            if hasattr(operand, 'operation'):
                collect_switch_cases(operand, codes)
            elif hasattr(operand, '__iter__') and not isinstance(operand, (str, bytes)):
                for item in operand:
                    if hasattr(item, 'operation'):
                        collect_switch_cases(item, codes)
    except Exception:
        pass


def find_ioctls_via_ast(func):
    """Walk HLIL AST to extract switch case IOCTL values - catches text misses."""
    codes = set()
    try:
        hlil = func.hlil
        if hlil:
            for block in hlil:
                for instr in block:
                    collect_switch_cases(instr, codes)
    except Exception:
        pass
    return codes


def find_ioctls_in_text(hlil_text):
    """Extract IOCTL constants from serialized HLIL text (fallback)."""
    codes = set()
    normalized = re.sub(r'\s+', ' ', hlil_text)
    for pat in IOCTL_PATS_HEX:
        for m in re.finditer(pat, normalized, re.IGNORECASE | re.DOTALL):
            try:
                val = int(m.group(1), 16)
                if val >= 0x200000 and plausible_ioctl(val):
                    codes.add(val & 0xFFFFFFFF)
            except Exception:
                pass
    for pat in IOCTL_PATS_DEC:
        for m in re.finditer(pat, normalized, re.IGNORECASE | re.DOTALL):
            try:
                val = int(m.group(1), 10)
                if val >= 0x200000 and plausible_ioctl(val):
                    codes.add(val & 0xFFFFFFFF)
            except Exception:
                pass
    return sorted(codes)


def find_ioctls_in_func(func):
    """Combined: AST walk (primary) + text scan (fallback). Returns sorted list."""
    from .helpers import get_hlil_text
    codes = find_ioctls_via_ast(func)
    codes |= set(find_ioctls_in_text(get_hlil_text(func)))
    return sorted(codes)


# ---------------------------------------------------------------------------
# IOCTL branch resolution
# ---------------------------------------------------------------------------

def _all_under(instr, bucket):
    """Collect all nested instructions under a node into bucket."""
    try:
        bucket.append(instr)
        for op in getattr(instr, 'operands', []):
            if hasattr(op, 'operation'):
                _all_under(op, bucket)
            elif hasattr(op, '__iter__') and not isinstance(op, (str, bytes)):
                for it in op:
                    if hasattr(it, 'operation'):
                        _all_under(it, bucket)
    except Exception:
        pass


def _const_from_condition(cond):
    """If cond is `var == const` or OR-chain, return list of int(const)."""
    results = []
    try:
        opname = cond.operation.name
        if opname in ('HLIL_CMP_E', 'HLIL_CMP_NE'):
            for op in cond.operands:
                c = extract_const(op)
                if c is None:
                    continue
                v = c & 0xFFFFFFFF
                if v >= 0x200000 and plausible_ioctl(v):
                    results.append(v)
        elif opname in ('HLIL_OR', 'HLIL_AND'):
            for op in cond.operands:
                if hasattr(op, 'operation'):
                    results.extend(_const_from_condition(op))
    except Exception:
        pass
    return results


def _visit_body(branch, visitor):
    """Descend into if/switch branch (Binja 3.x and 4.x layouts)."""
    if branch is None:
        return
    if hasattr(branch, 'operation'):
        visitor(branch)
    elif hasattr(branch, '__iter__') and not isinstance(branch, (str, bytes)):
        for it in branch:
            if hasattr(it, 'operation'):
                visitor(it)


def ioctl_branches_for_dispatcher(dispatcher):
    """Return list of (ioctl_const, [HLIL_instrs], compare_addr).

    Handles both HLIL_SWITCH cases and HLIL_IF (== const) bodies.
    """
    out = []
    try:
        hlil = dispatcher.hlil
        if not hlil:
            return out
    except Exception:
        return out

    def _visit(instr):
        try:
            opname = instr.operation.name
            # BN 6.0: skip struct initializers in branch resolution
            if opname == 'HLIL_STRUCT_INIT':
                return
            if opname == 'HLIL_SWITCH':
                for case in instr.cases:
                    case_consts = []
                    for cv in iter_case_consts(case):
                        if cv >= 0x200000 and plausible_ioctl(cv):
                            case_consts.append(cv)
                    body_instrs = []
                    body = getattr(case, 'body', None)
                    if body is not None:
                        _all_under(body, body_instrs)
                    for cv in case_consts:
                        out.append((cv, body_instrs, "0x{:x}".format(instr.address)))
                    _visit_body(body, _visit)
            elif opname == 'HLIL_IF':
                consts = _const_from_condition(instr.condition)
                if consts:
                    body_instrs = []
                    if instr.true:
                        _all_under(instr.true, body_instrs)
                    for cv in consts:
                        out.append((cv, body_instrs, "0x{:x}".format(instr.address)))
                _visit_body(getattr(instr, 'true', None), _visit)
                _visit_body(getattr(instr, 'false', None), _visit)
            for op in getattr(instr, 'operands', []):
                if hasattr(op, 'operation'):
                    _visit(op)
                elif hasattr(op, '__iter__') and not isinstance(op, (str, bytes)):
                    for it in op:
                        if hasattr(it, 'operation'):
                            _visit(it)
        except Exception:
            pass

    try:
        for block in hlil:
            for instr in block:
                _visit(instr)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Callee resolution
# ---------------------------------------------------------------------------

def resolve_callee_name(bv, addr):
    """Resolve an address to function/symbol name, following IAT thunks."""
    f = bv.get_function_at(addr)
    if f and f.name and not f.name.startswith('sub_'):
        return f.name
    sym = bv.get_symbol_at(addr)
    if sym and sym.name:
        return sym.name
    try:
        for ref in bv.get_data_refs_from(addr):
            ds = bv.get_symbol_at(ref)
            if ds and ds.name:
                return ds.name
    except Exception:
        pass
    if f:
        return f.name
    return "0x{:x}".format(addr)