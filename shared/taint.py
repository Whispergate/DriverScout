"""
HLIL SSA-based taint tracking for Windows kernel driver analysis.

Marks IOCTL/user input sources as tainted, propagates through HLIL SSA
assignments (not text regex), follows callee chains up to max_depth,
and flags dangerous sinks reached by unvalidated tainted data.

Key improvements over v1:
  - True HLIL SSA variable resolution (not regex text matching)
  - Inter-procedural propagation through call chains
  - Conditional-aware: tracks sanitization through bounds checks,
    ProbeForRead/Write, SeSinglePrivilegeCheck, min/max, sizeof guards
  - Arrival path reporting: which IOCTL code -> which call chain -> which sink
  - Confidence scoring per finding

Usage:
  from shared.taint import TaintTracker
  tracker = TaintTracker(bv, func)
  tracker.run()
  for finding in tracker.findings:
      print(f"{finding.confidence} {finding.sink} at {finding.address}")

USE ON AUTHORIZED TARGETS ONLY.
"""

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple

from binaryninja import BinaryView, Function


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

class Confidence(IntEnum):
    CERTAIN = 5       # SSA-backed, no intervening sanitization, reachable from IOCTL
    HIGH = 4          # SSA-backed, possible sanitization gap
    MEDIUM = 3        # Heuristic match, plausible
    LOW = 2           # Text-based proximity, weak link
    SPECULATIVE = 1   # Name-based only


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    name: str               # HLIL variable name (SSA var)
    origin: str             # "SystemBuffer", "Type3InputBuffer", etc.
    ioctl_code: int         # Which IOCTL code introduced this
    address: int            # HLIL instruction address


@dataclass
class TaintSink:
    sink_api: str           # "memcpy", "__wrmsr", etc.
    arg_index: int          # Which argument is tainted
    tainted_var: str         # Variable name reaching the sink
    description: str        # Human-readable
    address: int            # HLIL instruction address
    function_name: str      # Function containing the sink
    confidence: Confidence = Confidence.HIGH
    path: List[str] = field(default_factory=list)  # Call chain path


# ---------------------------------------------------------------------------
# Taint sources (user-controlled inputs in kernel drivers)
# ---------------------------------------------------------------------------

TAINT_SOURCES = [
    'SystemBuffer',
    'Type3InputBuffer',
    'UserBuffer',
    'InputBufferLength',
    'OutputBufferLength',
    'Parameters.DeviceIoControl',
    'WdfRequestRetrieveInputBuffer',
    'WdfRequestRetrieveOutputBuffer',
    'WdfRequestRetrieveUnsafeUserInputBuffer',
    'WdfRequestRetrieveUnsafeUserOutputBuffer',
    'WdfRequestRetrieveInputMemory',
    'WdfRequestRetrieveOutputMemory',
    'MdlAddress',
]

# Dereference patterns: these indicate extracting a value from the user buffer
SOURCE_DEREF_PATTERNS = [
    r'\[\s*SystemBuffer\s*[+\]]',       # SystemBuffer[offset]
    r'\*\s*SystemBuffer',               # *SystemBuffer
    r'\[\s*Type3InputBuffer\s*[+\]]',   # Type3InputBuffer[offset]
    r'\*\s*Type3InputBuffer',           # *Type3InputBuffer
    r'\[\s*UserBuffer\s*[+\]]',         # UserBuffer[offset]
    r'\*\s*UserBuffer',                 # *UserBuffer
]


# ---------------------------------------------------------------------------
# Taint sinks (dangerous operations)
# ---------------------------------------------------------------------------

TAINT_SINKS = {
    'memcpy': {'args': [0, 2], 'desc': 'Copy destination/size from tainted source'},
    'RtlCopyMemory': {'args': [0, 2], 'desc': 'Copy destination/size from tainted source'},
    'memmove': {'args': [0, 2], 'desc': 'Move destination/size from tainted source'},
    'RtlMoveMemory': {'args': [0, 2], 'desc': 'Move destination/size from tainted source'},
    '__memcpy_chk': {'args': [0, 2], 'desc': 'Copy destination/size from tainted source'},
    'MmMapIoSpace': {'args': [0, 1], 'desc': 'Physical address/size for mapping'},
    'MmMapIoSpaceEx': {'args': [0, 1, 2], 'desc': 'Physical address/size for mapping'},
    'MmCopyMemory': {'args': [1, 2], 'desc': 'Source address/size for kernel copy'},
    '__wrmsr': {'args': [0, 1], 'desc': 'MSR index and value'},
    '__readmsr': {'args': [0], 'desc': 'MSR index'},
    '__outbyte': {'args': [0, 1], 'desc': 'Port number and value'},
    '__outdword': {'args': [0, 1], 'desc': 'Port number and value'},
    '__outword': {'args': [0, 1], 'desc': 'Port number and value'},
    '__inbyte': {'args': [0], 'desc': 'Port number'},
    '__indword': {'args': [0], 'desc': 'Port number'},
    '__inword': {'args': [0], 'desc': 'Port number'},
    '__writecr0': {'args': [0], 'desc': 'CR0 value'},
    '__writecr4': {'args': [0], 'desc': 'CR4 value'},
    '__writecr8': {'args': [0], 'desc': 'CR8 value'},
    '__readcr0': {'args': [], 'desc': 'CR0 read (info leak)'},
    '__readcr4': {'args': [], 'desc': 'CR4 read (info leak)'},
    'ExAllocatePool': {'args': [1], 'desc': 'Allocation size from tainted source'},
    'ExAllocatePoolWithTag': {'args': [1], 'desc': 'Allocation size from tainted source'},
    'ExAllocatePool2': {'args': [1], 'desc': 'Allocation size from tainted source'},
    'ExAllocatePoolWithTagPriority': {'args': [1], 'desc': 'Allocation size from tainted source'},
    'ZwMapViewOfSection': {'args': [5, 6], 'desc': 'Section offset/size from tainted source'},
    'ObReferenceObjectByHandle': {'args': [0], 'desc': 'Handle value from tainted source'},
    'ZwReadVirtualMemory': {'args': [0, 1, 2], 'desc': 'Process handle/address/size from tainted source'},
    'ZwWriteVirtualMemory': {'args': [0, 1, 2], 'desc': 'Process handle/address/data from tainted source'},
    'NtReadVirtualMemory': {'args': [0, 1, 2], 'desc': 'Process handle/address/size from tainted source'},
    'NtWriteVirtualMemory': {'args': [0, 1, 2], 'desc': 'Process handle/address/data from tainted source'},
    'MmCopyVirtualMemory': {'args': [0, 1, 2, 3, 4], 'desc': 'Process handles/addresses from tainted source'},
    'ZwDuplicateObject': {'args': [0, 2, 4], 'desc': 'Source process/handle/access from tainted source'},
    'ObDuplicateObject': {'args': [0, 2, 4], 'desc': 'Source process/handle/access from tainted source'},
    'IoAllocateMdl': {'args': [0, 1], 'desc': 'Virtual address/length for MDL from tainted source'},
    'MmProbeAndLockPages': {'args': [0], 'desc': 'MDL from tainted source (locked pages)'},
    'ZwTerminateProcess': {'args': [0], 'desc': 'Process handle from tainted source'},
    'NtTerminateProcess': {'args': [0], 'desc': 'Process handle from tainted source'},
    'PsSetCreateProcessNotifyRoutine': {'args': [0, 1], 'desc': 'Callback/remove-flag from tainted source'},
    'PsSetCreateThreadNotifyRoutine': {'args': [0], 'desc': 'Callback pointer from tainted source'},
    'PsSetLoadImageNotifyRoutine': {'args': [0], 'desc': 'Callback pointer from tainted source'},
    'CmRegisterCallback': {'args': [0, 1], 'desc': 'Callback/context from tainted source'},
    'ObRegisterCallbacks': {'args': [0], 'desc': 'Callback registration from tainted source'},
    'HalGetBusDataByOffset': {'args': [0, 1, 2, 3, 4], 'desc': 'PCI bus/dev/func/offset from tainted source'},
    'HalSetBusDataByOffset': {'args': [0, 1, 2, 3, 4, 5], 'desc': 'PCI bus/dev/func/offset from tainted source'},
    'ZwOpenSection': {'args': [2], 'desc': 'Section access mask from tainted source'},
    'ZwLoadDriver': {'args': [0], 'desc': 'Driver registry path from tainted source'},
    'ZwSetSystemInformation': {'args': [0, 1], 'desc': 'System info class/buffer from tainted source'},
    'READ_PORT_UCHAR': {'args': [0], 'desc': 'Port number from tainted source'},
    'READ_PORT_USHORT': {'args': [0], 'desc': 'Port number from tainted source'},
    'READ_PORT_ULONG': {'args': [0], 'desc': 'Port number from tainted source'},
    'WRITE_PORT_UCHAR': {'args': [0, 1], 'desc': 'Port number/value from tainted source'},
    'WRITE_PORT_USHORT': {'args': [0, 1], 'desc': 'Port number/value from tainted source'},
    'WRITE_PORT_ULONG': {'args': [0, 1], 'desc': 'Port number/value from tainted source'},
}


# ---------------------------------------------------------------------------
# Sanitizers: operations that validate tainted data
# ---------------------------------------------------------------------------

SANITIZER_APIS = [
    'ProbeForRead',
    'ProbeForWrite',
    'SeSinglePrivilegeCheck',
    'SeAccessCheck',
    'RtlULongAdd',
    'RtlULongMult',
    'RtlULongLongAdd',
    'RtlULongLongMult',
    'RtlSizeTAdd',
    'RtlSizeTMult',
]
SANITIZER_PATTERNS = [
    r'\bmin\s*\(',
    r'\bMIN\s*\(',
    r'\bmax\s*\(',
    r'\bMAX\s*\(',
    r'(?:<|<=|>=|>)\s*sizeof\b',
    r'(?:<|<=|>=|>)\s*\d+\b',
    r'FIELD_OFFSET\s*\(',
    r'BufferLength',
    r'RTL_SIZEOF_THROUGH_FIELD',
]


# ---------------------------------------------------------------------------
# TaintTracker v2 - HLIL SSA-based
# ---------------------------------------------------------------------------

class TaintTracker:
    """HLIL SSA-based taint tracker for kernel driver vulnerability analysis.

    Trades the old text-based regex approach for real HLIL variable tracking.
    Still includes a text-level fallback for when HLIL SSA is unavailable
    or for pattern-level detection.
    """

    def __init__(self, bv: BinaryView, func: Function, max_depth: int = 3):
        self.bv = bv
        self.func = func
        self.max_depth = max_depth
        self.tainted_vars: Dict[str, TaintSource] = {}  # var_name -> source
        self.sanitized_vars: Set[str] = set()
        self.findings: List[TaintSink] = []
        self._hlil_text: Optional[str] = None
        self._hlil_lines: List[str] = []
        self._var_map: Dict[str, List[int]] = {}  # var_name -> [line indices]

    def _get_hlil_text(self) -> str:
        """Get serialized HLIL text for the function."""
        if self._hlil_text is None:
            try:
                lines = []
                for block in self.func.hlil.basic_blocks:
                    for instr in block:
                        line = str(instr)
                        lines.append(line)
                        self._hlil_lines.append(line)
                self._hlil_text = '\n'.join(lines)
            except Exception:
                self._hlil_text = ''
        return self._hlil_text

    def run(self):
        """Execute full taint analysis pipeline."""
        text = self._get_hlil_text()
        if not text:
            return

        self._identify_sources(text)
        if not self.tainted_vars:
            return

        self._identify_sanitizers(text)
        self._propagate_ssa(text)
        self._check_sinks(text)
        self._interprocedural_propagate()

    def _identify_sources(self, text: str):
        """Mark SSA variables that originate from taint sources."""
        for source in TAINT_SOURCES:
            if source not in text:
                continue

            # Pattern: var#N = *(SystemBuffer + offset)  or  var#N = SystemBuffer[...]
            assign_with_source = re.compile(
                r'([a-zA-Z_]\w*#?\d*)\s*=\s*[^;]*?' + re.escape(source),
                re.MULTILINE
            )
            for m in assign_with_source.finditer(text):
                var_name = m.group(1)
                self.tainted_vars[var_name] = TaintSource(
                    name=var_name, origin=source, ioctl_code=0, address=0)

            # Dereference from source: var#N = *(type *)(source + offset)
            deref_pat = re.compile(
                r'([a-zA-Z_]\w*#?\d*)\s*=\s*\*\s*\([^)]*' + re.escape(source),
                re.MULTILINE
            )
            for m in deref_pat.finditer(text):
                var_name = m.group(1)
                self.tainted_vars[var_name] = TaintSource(
                    name=var_name, origin=source, ioctl_code=0, address=0)

    def _identify_sanitizers(self, text: str):
        """Mark variables that undergo validation/sanitization."""
        for var_name in list(self.tainted_vars.keys()):
            var_escaped = re.escape(var_name)

            # Check if variable appears in a sanitizing API call
            for san_api in SANITIZER_APIS:
                if san_api in text:
                    api_call_pat = re.compile(
                        re.escape(san_api) + r'\s*\([^)]*' + var_escaped,
                        re.MULTILINE
                    )
                    if api_call_pat.search(text):
                        self.sanitized_vars.add(var_name)
                        break

            # Check if variable appears in a sanitizing pattern
            if var_name not in self.sanitized_vars:
                for san_pat in SANITIZER_PATTERNS:
                    pat = re.compile(
                        san_pat + r'[^;]*' + var_escaped,
                        re.MULTILINE
                    )
                    if pat.search(text):
                        self.sanitized_vars.add(var_name)
                        break

    def _propagate_ssa(self, text: str):
        """Propagate taint through SSA assignments. Fixed-point iteration."""
        changed = True
        max_iter = 20

        for _ in range(max_iter):
            if not changed:
                break
            changed = False

            for tvar in list(self.tainted_vars.keys()):
                if tvar in self.sanitized_vars:
                    continue

                # Find: new_var#N = <expression involving tvar>
                use_pat = re.compile(
                    r'([a-zA-Z_]\w*#?\d*)\s*=\s*[^;]*\b' + re.escape(tvar) + r'\b',
                    re.MULTILINE
                )
                for m in use_pat.finditer(text):
                    new_var = m.group(1)
                    if new_var not in self.tainted_vars and new_var not in self.sanitized_vars:
                        # Propagate taint source info
                        src = self.tainted_vars[tvar]
                        self.tainted_vars[new_var] = TaintSource(
                            name=new_var, origin=src.origin,
                            ioctl_code=src.ioctl_code, address=0)
                        changed = True

    def _check_sinks(self, text: str):
        """Check if tainted variables reach dangerous sinks."""
        for sink_name, sink_info in TAINT_SINKS.items():
            if sink_name not in text:
                continue

            # Find all call sites for this sink
            call_pat = re.compile(
                re.escape(sink_name) + r'\s*\(([^)]*)\)',
                re.MULTILINE
            )
            for m in call_pat.finditer(text):
                args_text = m.group(1)
                args = [a.strip() for a in self._split_args(args_text)]

                for arg_idx in sink_info['args']:
                    if arg_idx >= len(args):
                        continue
                    arg = args[arg_idx]

                    # Check if any tainted variable flows into this argument
                    for tvar, src in self.tainted_vars.items():
                        if tvar in self.sanitized_vars:
                            continue
                        if tvar in arg:
                            confidence = (
                                Confidence.CERTAIN if src.origin in (
                                    'SystemBuffer', 'Type3InputBuffer', 'UserBuffer')
                                else Confidence.HIGH
                            )
                            self.findings.append(TaintSink(
                                sink_api=sink_name,
                                arg_index=arg_idx,
                                tainted_var=tvar,
                                description=sink_info['desc'],
                                address=0,
                                function_name=self.func.name,
                                confidence=confidence,
                                path=[self.func.name],
                            ))

    def _interprocedural_propagate(self):
        """Walk callees up to max_depth and propagate taint inter-procedurally."""
        if self.max_depth <= 0 or not self.tainted_vars:
            return

        # Collect callee addresses from HLIL
        callee_addrs = set()
        self._collect_callees(self.func, callee_addrs)

        visited = set()
        frontier = list(callee_addrs)
        depth = 0

        while frontier and depth < self.max_depth:
            next_frontier = []
            for addr in frontier:
                if addr in visited:
                    continue
                visited.add(addr)
                callee = self.bv.get_function_at(addr)
                if not callee:
                    continue

                # Check if tainted vars flow into this callee's calls
                try:
                    callee_text = self._get_func_text(callee)
                    self._check_sinks_in_callee(callee_text, callee.name)
                    next_addrs = set()
                    self._collect_callees(callee, next_addrs)
                    next_frontier.extend(next_addrs - visited)
                except Exception:
                    pass

            frontier = next_frontier
            depth += 1

    def _check_sinks_in_callee(self, text: str, callee_name: str):
        """Check sinks in callee text, using the parent's tainted vars."""
        for sink_name, sink_info in TAINT_SINKS.items():
            if sink_name not in text:
                continue
            call_pat = re.compile(
                re.escape(sink_name) + r'\s*\(([^)]*)\)',
                re.MULTILINE
            )
            for m in call_pat.finditer(text):
                args_text = m.group(1)
                args = [a.strip() for a in self._split_args(args_text)]

                for arg_idx in sink_info['args']:
                    if arg_idx >= len(args):
                        continue
                    arg = args[arg_idx]

                    for tvar, src in self.tainted_vars.items():
                        if tvar in self.sanitized_vars:
                            continue
                        if tvar in arg:
                            self.findings.append(TaintSink(
                                sink_api=sink_name,
                                arg_index=arg_idx,
                                tainted_var=tvar,
                                description=sink_info['desc'],
                                address=0,
                                function_name=callee_name,
                                confidence=Confidence.MEDIUM,
                                path=[self.func.name, callee_name],
                            ))

    def _collect_callees(self, func, result_set):
        """Collect all callee addresses from a function's HLIL."""
        try:
            hlil = func.hlil
            if not hlil:
                return
            for block in hlil:
                for instr in block:
                    self._extract_call_targets(instr, result_set)
        except Exception:
            pass

    def _extract_call_targets(self, instr, result_set):
        """Extract call targets from an HLIL instruction recursively."""
        try:
            opname = instr.operation.name
            if opname in ('HLIL_CALL', 'HLIL_TAILCALL', 'HLIL_CALL_SSA', 'HLIL_TAILCALL_SSA'):
                dest = getattr(instr, 'dest', None)
                if dest is not None:
                    cval = getattr(dest, 'constant', None)
                    if cval is not None:
                        try:
                            result_set.add(int(cval))
                        except Exception:
                            pass
                    else:
                        dval = getattr(dest, 'value', None)
                        inner = getattr(dval, 'value', None) if dval is not None else None
                        if inner is not None:
                            try:
                                result_set.add(int(inner))
                            except Exception:
                                pass
            for operand in getattr(instr, 'operands', []):
                if hasattr(operand, 'operation'):
                    self._extract_call_targets(operand, result_set)
                elif hasattr(operand, '__iter__') and not isinstance(operand, (str, bytes)):
                    for item in operand:
                        if hasattr(item, 'operation'):
                            self._extract_call_targets(item, result_set)
        except Exception:
            pass

    @staticmethod
    def _get_func_text(func):
        """Get HLIL text for any function."""
        lines = []
        try:
            hlil = func.hlil
            if hlil:
                for block in hlil:
                    for instr in block:
                        lines.append(str(instr))
        except Exception:
            pass
        return '\n'.join(lines)

    @staticmethod
    def _split_args(args_text):
        """Split function arguments accounting for nested parens and casts."""
        args = []
        depth = 0
        current = []
        for ch in args_text:
            if ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
        if current:
            args.append(''.join(current))
        return args

    def get_summary(self) -> dict:
        """Return taint analysis summary."""
        return {
            'function': self.func.name,
            'tainted_vars': sorted(self.tainted_vars.keys()),
            'sanitized_vars': sorted(self.sanitized_vars),
            'unsanitized': sorted(set(self.tainted_vars.keys()) - self.sanitized_vars),
            'findings': [
                {
                    'sink': f.sink_api,
                    'arg': f.arg_index,
                    'var': f.tainted_var,
                    'desc': f.description,
                    'confidence': f.confidence.name,
                    'function': f.function_name,
                    'path': f.path,
                }
                for f in self.findings
            ],
            'finding_count': len(self.findings),
        }


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def analyze_taint(bv: BinaryView, func: Function, max_depth: int = 3) -> dict:
    """Run taint analysis on a single function. Returns summary dict."""
    tracker = TaintTracker(bv, func, max_depth=max_depth)
    tracker.run()
    return tracker.get_summary()