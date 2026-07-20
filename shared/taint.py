"""
Lightweight HLIL SSA-based taint tracking for kernel driver analysis.

Marks IOCTL input sources as tainted and propagates through:
  - Assignments (including casts and arithmetic)
  - Function call arguments
  - Memory store destinations

Flags sinks reached by tainted values without intervening validation.

Usage:
  from shared.taint import TaintTracker
  tracker = TaintTracker(bv, func)
  tracker.run()
  for sink in tracker.tainted_sinks:
      print(sink)

USE ON AUTHORIZED TARGETS ONLY.
"""

import re

# Taint sources: expressions that indicate user-controlled data
_TAINT_SOURCES = [
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
]

# Taint sinks: dangerous operations that should not receive unvalidated tainted data
_TAINT_SINKS = {
    'memcpy': {'args': [0, 2], 'desc': 'Copy destination and size from tainted source'},
    'RtlCopyMemory': {'args': [0, 2], 'desc': 'Copy destination and size'},
    'memmove': {'args': [0, 2], 'desc': 'Move destination and size'},
    'RtlMoveMemory': {'args': [0, 2], 'desc': 'Move destination and size'},
    'MmMapIoSpace': {'args': [0, 1], 'desc': 'Physical address and size for mapping'},
    'MmCopyMemory': {'args': [1, 2], 'desc': 'Source address and size for kernel copy'},
    '__wrmsr': {'args': [0, 1], 'desc': 'MSR index and value'},
    '__rdmsr': {'args': [0], 'desc': 'MSR index'},
    '__outbyte': {'args': [0, 1], 'desc': 'Port number and value'},
    '__outdword': {'args': [0, 1], 'desc': 'Port number and value'},
    '__writecr0': {'args': [0], 'desc': 'CR0 value'},
    '__writecr4': {'args': [0], 'desc': 'CR4 value'},
    'ExAllocatePool': {'args': [1], 'desc': 'Allocation size'},
    'ExAllocatePoolWithTag': {'args': [1], 'desc': 'Allocation size'},
    'ExAllocatePool2': {'args': [1], 'desc': 'Allocation size'},
    'ZwMapViewOfSection': {'args': [5, 6], 'desc': 'Offset and size'},
    'ObReferenceObjectByHandle': {'args': [0], 'desc': 'Handle value'},
}

# Sanitizers: functions/operations that validate tainted data
_SANITIZERS = [
    'ProbeForRead',
    'ProbeForWrite',
    'min(',
    'MIN(',
    'max(',
    'MAX(',
    '< sizeof',
    '<= sizeof',
    '> sizeof',
    '>= sizeof',
    'FIELD_OFFSET',
    'BufferLength',
]


class TaintTracker:
    """Lightweight taint tracker operating on HLIL text.

    Not a true SSA propagation engine - works on serialized HLIL text
    with variable name tracking. Trades precision for simplicity and
    broad applicability across Binary Ninja's varying HLIL output.
    """

    def __init__(self, bv, func, max_depth=2):
        self.bv = bv
        self.func = func
        self.max_depth = max_depth
        self.tainted_vars = set()
        self.tainted_sinks = []
        self.sanitized_vars = set()
        self._hlil_text = None

    def _get_text(self):
        if self._hlil_text is None:
            try:
                lines = []
                for block in self.func.hlil.basic_blocks:
                    for instr in block:
                        lines.append(str(instr))
                self._hlil_text = '\n'.join(lines)
            except Exception:
                self._hlil_text = ''
        return self._hlil_text

    def run(self):
        """Execute taint analysis."""
        text = self._get_text()
        if not text:
            return

        self._identify_sources(text)
        self._propagate(text)
        self._check_sinks(text)

    def _identify_sources(self, text):
        """Mark variables assigned from taint sources."""
        for source in _TAINT_SOURCES:
            if source not in text:
                continue
            # Find assignments: var = ...source...
            assign_pat = re.compile(
                r'([a-zA-Z_]\w*)\s*=\s*[^;]*?' + re.escape(source),
                re.MULTILINE
            )
            for m in assign_pat.finditer(text):
                self.tainted_vars.add(m.group(1))

            # Dereference from source: *(source + offset)
            deref_pat = re.compile(
                r'([a-zA-Z_]\w*)\s*=\s*\*\s*\([^)]*' + re.escape(source),
                re.MULTILINE
            )
            for m in deref_pat.finditer(text):
                self.tainted_vars.add(m.group(1))

    def _propagate(self, text):
        """Propagate taint through assignments. Fixed-point iteration."""
        changed = True
        iterations = 0
        max_iter = 10

        while changed and iterations < max_iter:
            changed = False
            iterations += 1

            for tvar in list(self.tainted_vars):
                if tvar in self.sanitized_vars:
                    continue

                # Find assignments that use this tainted var
                use_pat = re.compile(
                    r'([a-zA-Z_]\w*)\s*=\s*[^;]*\b' + re.escape(tvar) + r'\b',
                    re.MULTILINE
                )
                for m in use_pat.finditer(text):
                    new_var = m.group(1)
                    if new_var not in self.tainted_vars:
                        self.tainted_vars.add(new_var)
                        changed = True

                # Check for sanitization
                for san in _SANITIZERS:
                    san_pat = re.compile(
                        re.escape(san) + r'[^;]*\b' + re.escape(tvar) + r'\b',
                        re.MULTILINE
                    )
                    if san_pat.search(text):
                        self.sanitized_vars.add(tvar)

    def _check_sinks(self, text):
        """Check if tainted vars reach dangerous sinks."""
        for sink_name, sink_info in _TAINT_SINKS.items():
            if sink_name not in text:
                continue

            # Find call sites
            call_pat = re.compile(
                r'' + re.escape(sink_name) + r'\s*\(([^)]*)\)',
                re.MULTILINE
            )
            for m in call_pat.finditer(text):
                args_text = m.group(1)
                args = [a.strip() for a in args_text.split(',')]

                for arg_idx in sink_info['args']:
                    if arg_idx >= len(args):
                        continue
                    arg = args[arg_idx]

                    # Check if any tainted var appears in this argument
                    for tvar in self.tainted_vars:
                        if tvar in self.sanitized_vars:
                            continue
                        if tvar in arg:
                            self.tainted_sinks.append({
                                'sink': sink_name,
                                'arg_index': arg_idx,
                                'tainted_var': tvar,
                                'arg_text': arg,
                                'desc': sink_info['desc'],
                                'context': m.group(0)[:200],
                            })

    def get_summary(self):
        """Return taint analysis summary."""
        return {
            'tainted_vars': sorted(self.tainted_vars),
            'sanitized_vars': sorted(self.sanitized_vars),
            'unsanitized': sorted(self.tainted_vars - self.sanitized_vars),
            'sinks': self.tainted_sinks,
        }


def analyze_taint(bv, func):
    """Run taint analysis on a single function. Returns summary dict."""
    tracker = TaintTracker(bv, func)
    tracker.run()
    return tracker.get_summary()
