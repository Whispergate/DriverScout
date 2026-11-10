"""
Shared helpers for kernel driver analysis plugins.

Provides HLIL/MLIL text extraction with LRU caching, cross-reference
helpers, MLIL call-parameter extraction, and heuristic text checks.

Caching strategy: functions (and their HLIL text) are cached keyed by
(bv_id, func_start) so repeated analysis across plugins reuses cached
text without re-serializing HLIL every time.
"""

import re
from collections import OrderedDict
from binaryninja import BinaryView


# ---------------------------------------------------------------------------
# HLIL / MLIL text extraction (cached)
# ---------------------------------------------------------------------------

# Per-session LRU caches keyed by (id(bv), func.start), using OrderedDict
# so that recently-accessed entries are moved to the end on each hit.
_hlil_cache: OrderedDict = OrderedDict()
_mlil_cache: OrderedDict = OrderedDict()
_CACHE_MAX = 1024       # hard cap
_CACHE_LOW = int(_CACHE_MAX * 0.8)  # evict down to 80% when cap is hit


def _evict_lru(cache: OrderedDict):
    """Evict least-recently-used entries until the cache is at 80% capacity."""
    while len(cache) > _CACHE_MAX:
        cache.popitem(last=False)       # remove oldest (front)
        if len(cache) <= _CACHE_LOW:
            break


def cache_stats() -> dict:
    """Return current cache sizes for monitoring / diagnostics."""
    return {
        'hlil_entries': len(_hlil_cache),
        'mlil_entries': len(_mlil_cache),
        'max': _CACHE_MAX,
        'low_watermark': _CACHE_LOW,
    }


def get_hlil_text(func):
    """Return serialized HLIL text for a function. Cached per-session.

    Each call is cached by (id(bv), func.start). First call per function
    walks all HLIL blocks; subsequent calls return the cached string.
    """
    if func is None:
        return ""
    try:
        bv = func.view
    except Exception:
        return ""
    if bv is None:
        return ""

    cache_key = (id(bv), func.start)
    if cache_key in _hlil_cache:
        _hlil_cache.move_to_end(cache_key)   # mark as recently used
        return _hlil_cache[cache_key]

    lines = []
    try:
        hlil = func.hlil
        if hlil:
            for block in hlil:
                for instr in block:
                    lines.append(str(instr))
    except Exception:
        pass

    text = "\n".join(lines)
    _hlil_cache[cache_key] = text
    _evict_lru(_hlil_cache)
    return text


def get_mlil_text(func):
    """Return serialized MLIL text for a function. Cached per-session."""
    if func is None:
        return ""
    try:
        bv = func.view
    except Exception:
        return ""
    if bv is None:
        return ""

    cache_key = (id(bv), func.start)
    if cache_key in _mlil_cache:
        _mlil_cache.move_to_end(cache_key)   # mark as recently used
        return _mlil_cache[cache_key]

    lines = []
    try:
        mlil = func.mlil
        if mlil:
            for block in mlil:
                for instr in block:
                    lines.append(str(instr))
    except Exception:
        pass

    text = "\n".join(lines)
    _mlil_cache[cache_key] = text
    _evict_lru(_mlil_cache)
    return text


def clear_hlil_cache():
    """Clear all cached HLIL/MLIL text. Call when bv is reanalyzed."""
    _hlil_cache.clear()
    _mlil_cache.clear()


# ---------------------------------------------------------------------------
# Cross-reference helpers
# ---------------------------------------------------------------------------

def get_callers(bv: BinaryView, sym_name: str):
    """Return list of (caller_func, ref_addr) for every call to sym_name."""
    results = []
    for sym in bv.get_symbols_by_name(sym_name):
        for ref in bv.get_code_refs(sym.address):
            if ref.function:
                results.append((ref.function, ref.address))
    return results


def get_symbol_address(bv: BinaryView, name: str):
    syms = bv.get_symbols_by_name(name)
    return syms[0].address if syms else None


# ---------------------------------------------------------------------------
# MLIL call-parameter extraction
# ---------------------------------------------------------------------------

def get_call_params_at(func, ref_addr):
    """Return the MLIL params list for the call instruction at ref_addr, or []."""
    try:
        mlil = func.mlil
        if not mlil:
            return []
        idx = mlil.get_instruction_start(ref_addr)
        if idx is None:
            return []
        instr = mlil[idx]
        return list(getattr(instr, 'params', []))
    except Exception:
        return []


def const_value(param):
    """Try to extract a constant integer from an MLIL parameter."""
    try:
        return param.constant
    except Exception:
        pass
    try:
        if hasattr(param, 'operands'):
            for op in param.operands:
                try:
                    return op.constant
                except Exception:
                    pass
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Heuristic text checks
# ---------------------------------------------------------------------------

def nearby_has_check(text, idx, checks, window=400):
    """True if any string in checks appears within window chars of idx in text."""
    chunk = text[max(0, idx - window): min(len(text), idx + window)]
    return any(c in chunk for c in checks)


# User-space data indicators in HLIL text
_USER_KEYS = [
    'copy_from_user', '__copy_from_user', 'get_user', '__get_user',
    'copy_to_user', '__copy_to_user', 'put_user',
    'arg', 'uarg', 'ubuf', 'user_buf', 'user_data', 'user_ptr',
    'from_user', 'to_user',
]


def looks_user_driven(text):
    return any(k in text for k in _USER_KEYS)


_VALIDATION_CHECKS = [
    'access_ok', 'verify_area',
    'check_mem_region',
    'capable(', 'ns_capable(',
    'if (', 'if(!', 'if (!',
    'WARN_ON', 'BUG_ON',
]


def nearby_has_validation(text, idx, window=400):
    return nearby_has_check(text, idx, _VALIDATION_CHECKS, window)


# ---------------------------------------------------------------------------
# Linux IOCTL _IOC decode
# ---------------------------------------------------------------------------

_IOC_NRSHIFT   = 0
_IOC_TYPESHIFT = 8
_IOC_SIZESHIFT = 16
_IOC_DIRSHIFT  = 30

IOC_DIR_NAMES = {0: '_IO (none)', 1: '_IOW (write->drv)', 2: '_IOR (read<-drv)', 3: '_IOWR (read+write)'}


def decode_linux_ioctl(code):
    code = code & 0xFFFFFFFF
    return {
        'raw':  code,
        'nr':   (code >> _IOC_NRSHIFT)   & 0xFF,
        'type': (code >> _IOC_TYPESHIFT)  & 0xFF,
        'size': (code >> _IOC_SIZESHIFT)  & 0x3FFF,
        'dir':  (code >> _IOC_DIRSHIFT)   & 0x3,
    }


def plausible_linux_ioctl(code):
    code = code & 0xFFFFFFFF
    if code < 0x100:
        return False
    d = decode_linux_ioctl(code)
    type_ok = (d['type'] == 0) or (0x20 <= d['type'] <= 0x7E)
    size_ok = d['size'] <= 4096
    return type_ok and size_ok


def format_linux_ioctl(code):
    d = decode_linux_ioctl(code)
    type_ch = chr(d['type']) if 0x20 <= d['type'] <= 0x7E else '?'
    dir_str = IOC_DIR_NAMES.get(d['dir'], str(d['dir']))
    return (
        "0x{:08X}  dir={} ({})  type=0x{:02X} ('{}')  nr=0x{:02X} ({})  size={} bytes".format(
            d['raw'], d['dir'], dir_str,
            d['type'], type_ch,
            d['nr'], d['nr'],
            d['size']
        )
    )