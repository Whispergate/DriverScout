"""
Shared primitive detection database and name-hint matching.

Unified name-hint patterns used by: win_primitives, win_hevd_classes,
win_chain, win_vuln_finder, win_poc_gen.

Provides: name-hint databases, detector registry, callee walk helpers,
          and vulnerability API/intrinsic label mapping.
"""

import re


# ---------------------------------------------------------------------------
# Vulnerability API labels (used by win_vuln_finder for IOCTL->vuln mapping)
# ---------------------------------------------------------------------------

VULN_API_LABELS = {
    'MmMapIoSpace': 'MmMapIoSpace',
    'MmMapIoSpaceEx': 'MmMapIoSpaceEx',
    'MmUnmapIoSpace': 'MmUnmapIoSpace',
    'MmCopyMemory': 'MmCopyMemory',
    'MmGetPhysicalAddress': 'MmGetPhysicalAddress',
    'MmMapLockedPagesSpecifyCache': 'MmMapLockedPagesSpecifyCache',
    'ZwOpenSection': 'ZwOpenSection',
    'ZwMapViewOfSection': 'ZwMapViewOfSection',
    'HalGetBusDataByOffset': 'HalGetBusDataByOffset',
    'HalSetBusDataByOffset': 'HalSetBusDataByOffset',
    'memcpy': 'memcpy',
    'memmove': 'memmove',
    'RtlCopyMemory': 'RtlCopyMemory',
}

VULN_INTRINSIC_LABELS = {
    '__rdmsr': 'rdmsr', '__wrmsr': 'wrmsr',
    '_rdpmc': 'rdpmc', '__rdpmc': 'rdpmc',
    '__in_': 'in (port-IO read)', '__out_': 'out (port-IO write)',
    '__halt': 'hlt', 'trap(0xd)': 'hlt/trap',
    '__readcr': 'mov from CRx', '__writecr': 'mov to CRx',
    '__readdr': 'mov from DRx', '__writedr': 'mov to DRx',
    '__swapgs': 'swapgs', '__invd': 'invd', '__wbinvd': 'wbinvd',
}


def scan_text_for_vulns(text):
    """Return set of vuln labels found in given HLIL text."""
    # BN 6.0: strip type fragment notation that could cause false API matches
    text = re.sub(r'__frag(?:_be)?\s*\([^)]*\)', '', text)
    hits = set()
    for needle, label in VULN_API_LABELS.items():
        if needle in text:
            hits.add(label)
    for needle, label in VULN_INTRINSIC_LABELS.items():
        if needle in text:
            hits.add(label)
    return hits


# ---------------------------------------------------------------------------
# Unified name-hint database for primitive detection
# Maps normalized function name substring -> (severity, primitive_label)
# ---------------------------------------------------------------------------

NAME_PRIM_HINTS = {
    # HEVD-style (memory corruption)
    'bufferoverflowstack':        ('HIGH',     'Stack Buffer Overflow (name)'),
    'bufferoverflownonpagedpool': ('HIGH',     'Pool Buffer Overflow (name)'),
    'bufferoverflowpagedpool':    ('HIGH',     'Pool Buffer Overflow (name)'),
    'stackoverflow':              ('HIGH',     'Stack Buffer Overflow (name)'),
    'heapoverflow':               ('HIGH',     'Heap/Pool Overflow (name)'),
    'pooloverflow':               ('HIGH',     'Pool Overflow (name)'),
    'integeroverflow':            ('HIGH',     'Integer Overflow (name)'),
    'uafobject':                  ('HIGH',     'Use-After-Free (name)'),
    'useafterfree':               ('HIGH',     'Use-After-Free (name)'),
    'doublefree':                 ('HIGH',     'Double Free (name)'),
    'doublefetch':                ('HIGH',     'Double-Fetch TOCTOU (name)'),
    'racecondition':              ('HIGH',     'Race Condition (name)'),
    'typeconfusion':              ('HIGH',     'Type Confusion (name)'),
    'fakeobject':                 ('HIGH',     'Type Confusion / Fake Object (name)'),
    'uninitializedmemory':        ('MEDIUM',   'Uninitialized Memory Leak (name)'),
    'uninit':                     ('MEDIUM',   'Uninitialized Memory Leak (name)'),
    'memorydisclosure':           ('MEDIUM',   'Memory Disclosure (name)'),
    'infoleak':                   ('MEDIUM',   'Info Leak (name)'),
    'nullpointer':                ('MEDIUM',   'NULL Pointer Deref (name)'),
    'nullderef':                  ('MEDIUM',   'NULL Pointer Deref (name)'),
    'writenull':                  ('HIGH',     'Write to NULL (name)'),

    # Arbitrary R/W primitives
    'arbitrarywrite':             ('CRITICAL', 'Write-What-Where (name)'),
    'arbitraryread':              ('CRITICAL', 'Arbitrary Kernel Read (name)'),
    'arbitraryreadwrite':         ('CRITICAL', 'Arb R/W Primitive (name)'),
    'arbitraryincrement':         ('HIGH',     'Arbitrary Increment (name)'),
    'arbwrite':                   ('CRITICAL', 'Write-What-Where (name)'),
    'arbread':                    ('CRITICAL', 'Arbitrary Kernel Read (name)'),
    'readkernel':                 ('CRITICAL', 'Arbitrary Kernel Read (name)'),
    'writekernel':                ('CRITICAL', 'Arbitrary Kernel Write (name)'),
    'readvirtual':                ('CRITICAL', 'Virtual Memory Read (name)'),
    'writevirtual':               ('CRITICAL', 'Virtual Memory Write (name)'),
    'readmemory':                 ('HIGH',     'Memory Read (name)'),
    'writememory':                ('HIGH',     'Memory Write (name)'),
    'readprocessmemory':          ('HIGH',     'Process Memory Read (name)'),
    'writeprocessmemory':         ('HIGH',     'Process Memory Write (name)'),

    # MSR
    'rdmsr':                      ('CRITICAL', 'MSR Read (name)'),
    'wrmsr':                      ('CRITICAL', 'MSR Write (name)'),
    'readmsr':                    ('CRITICAL', 'MSR Read (name)'),
    'writemsr':                   ('CRITICAL', 'MSR Write (name)'),
    'msrread':                    ('CRITICAL', 'MSR Read (name)'),
    'msrwrite':                   ('CRITICAL', 'MSR Write (name)'),

    # Port IO
    'readioport':                 ('CRITICAL', 'Port IO Read (name)'),
    'writeioport':                ('CRITICAL', 'Port IO Write (name)'),
    'readport':                   ('CRITICAL', 'Port IO Read (name)'),
    'writeport':                  ('CRITICAL', 'Port IO Write (name)'),
    'inport':                     ('CRITICAL', 'Port IN (name)'),
    'outport':                    ('CRITICAL', 'Port OUT (name)'),
    'ioread':                     ('HIGH',     'IO Read (name)'),
    'iowrite':                    ('HIGH',     'IO Write (name)'),

    # Physical memory
    'readphysical':               ('CRITICAL', 'Physical Memory Read (name)'),
    'writephysical':              ('CRITICAL', 'Physical Memory Write (name)'),
    'mapphysical':                ('CRITICAL', 'Physical Memory Map (name)'),
    'physmem':                    ('CRITICAL', 'Physical Memory Access (name)'),
    'physicalmemory':             ('CRITICAL', 'Physical Memory Access (name)'),
    'mapmemory':                  ('HIGH',     'Memory Map (name)'),
    'mapio':                      ('HIGH',     'IO Space Map (name)'),

    # PCI / Hal
    'pciconfig':                  ('HIGH',     'PCI Config Access (name)'),
    'readpci':                    ('HIGH',     'PCI Read (name)'),
    'writepci':                   ('HIGH',     'PCI Write (name)'),
    'halgetbus':                  ('HIGH',     'PCI Bus Access (name)'),
    'halsetbus':                  ('HIGH',     'PCI Bus Access (name)'),

    # Control / Debug registers
    'readcr':                     ('CRITICAL', 'CRx Read (name)'),
    'writecr':                    ('CRITICAL', 'CRx Write (name)'),
    'readdr':                     ('HIGH',     'DRx Read (name)'),
    'writedr':                    ('HIGH',     'DRx Write (name)'),
    'gdt':                        ('HIGH',     'GDT Access (name)'),
    'idt':                        ('HIGH',     'IDT Access (name)'),

    # Ring-0 exec / shellcode
    'shellcode':                  ('CRITICAL', 'Ring-0 Shellcode (name)'),
    'execpayload':                ('CRITICAL', 'Ring-0 Exec (name)'),
    'kernelexec':                 ('CRITICAL', 'Ring-0 Exec (name)'),
    'callkernel':                 ('CRITICAL', 'Ring-0 Exec (name)'),

    # Process / token tampering
    'terminateprocess':           ('HIGH',     'Process Kill (name)'),
    'killprocess':                ('HIGH',     'Process Kill (name)'),
    'suspendprocess':             ('HIGH',     'Process Suspend (name)'),
    'protectprocess':             ('HIGH',     'Process Protection Toggle (name)'),
    'unprotectprocess':           ('HIGH',     'Process Protection Toggle (name)'),
    'stealtoken':                 ('CRITICAL', 'Token Steal (name)'),
    'swaptoken':                  ('CRITICAL', 'Token Swap (name)'),
    'elevatetoken':               ('CRITICAL', 'Token Elevation (name)'),
    'tokenswap':                  ('CRITICAL', 'Token Swap (name)'),

    # Kernel callback / ETW / SSDT tampering
    'disablecallback':            ('HIGH',     'Callback Removal (name)'),
    'removecallback':             ('HIGH',     'Callback Removal (name)'),
    'unregistercallback':         ('HIGH',     'Callback Removal (name)'),
    'patchetw':                   ('HIGH',     'ETW Tampering (name)'),
    'disableetw':                 ('HIGH',     'ETW Tampering (name)'),
    'ssdt':                       ('HIGH',     'SSDT Tampering (name)'),
    'hookssdt':                   ('HIGH',     'SSDT Hook (name)'),
    'patchssdt':                  ('HIGH',     'SSDT Hook (name)'),

    # File / registry from kernel ctx
    'insecurekernelfileaccess':   ('HIGH',     'Insecure File Access (name)'),
    'kernelfileread':             ('HIGH',     'Kernel Regstry Access (name)'),
    'kernelfilewrite':            ('HIGH',     'Kernel File Access (name)'),
    'kernelregistry':             ('HIGH',     'Kernel Registry Access (name)'),

    # Driver load / section
    'loaddriver':                 ('HIGH',     'Driver Load Primitive (name)'),
    'mapdriver':                  ('HIGH',     'Driver Map Primitive (name)'),
    'opensection':                ('HIGH',     'Section Open (name)'),
    'mapsection':                 ('HIGH',     'Section Map (name)'),
}

# HEVD class mapping from name hints
NAME_CLASS_HINTS = {
    # HEVD memory corruption
    'bufferoverflowstack':         'StackOverflow',
    'bufferoverflownonpagedpool':  'PoolOverflow',
    'bufferoverflowpagedpool':     'PoolOverflow',
    'stackoverflow':               'StackOverflow',
    'heapoverflow':                'PoolOverflow',
    'pooloverflow':                'PoolOverflow',
    'writenull':                   'NullPointerDereference',
    'nullpointer':                 'NullPointerDereference',
    'nullderef':                   'NullPointerDereference',
    'uninitializedmemorystack':    'UninitializedStackVariable',
    'uninitializedmemorypaged':    'UninitializedHeapVariable',
    'uninitializedmemory':         'UninitializedHeapVariable',
    'uninit':                      'UninitializedHeapVariable',
    'memorydisclosure':            'MemoryDisclosure',
    'infoleak':                    'MemoryDisclosure',
    'integeroverflow':             'IntegerOverflow',
    'typeconfusion':               'TypeConfusion',
    'fakeobject':                  'TypeConfusion',
    'uafobject':                   'UseAfterFree',
    'useafterfree':                'UseAfterFree',
    'doublefree':                  'UseAfterFree',
    'doublefetch':                 'DoubleFetch',
    'racecondition':               'RaceCondition',
    'insecurekernelfileaccess':    'InsecureKernelResourceAccess',
    # arbitrary R/W
    'arbitrarywrite':              'ArbitraryOverwrite',
    'arbitraryread':               'MemoryDisclosure',
    'arbitraryincrement':          'ArbitraryOverwrite',
    'arbitraryreadwrite':          'ArbitraryOverwrite',
    'arbwrite':                    'ArbitraryOverwrite',
    'arbread':                     'MemoryDisclosure',
    'readkernel':                  'MemoryDisclosure',
    'writekernel':                 'ArbitraryOverwrite',
    'readvirtual':                 'MemoryDisclosure',
    'writevirtual':                'ArbitraryOverwrite',
    'readmemory':                  'MemoryDisclosure',
    'writememory':                 'ArbitraryOverwrite',
    'readprocessmemory':           'MemoryDisclosure',
    'writeprocessmemory':          'ArbitraryOverwrite',
    # privileged intrinsics
    'rdmsr':                       'MSRReadWrite',
    'wrmsr':                       'MSRReadWrite',
    'readmsr':                     'MSRReadWrite',
    'writemsr':                    'MSRReadWrite',
    'msrread':                     'MSRReadWrite',
    'msrwrite':                    'MSRReadWrite',
    'readioport':                  'PortIO',
    'writeioport':                 'PortIO',
    'readport':                    'PortIO',
    'writeport':                   'PortIO',
    'inport':                      'PortIO',
    'outport':                     'PortIO',
    'readphysical':                'PhysicalMemoryMap',
    'writephysical':               'PhysicalMemoryMap',
    'mapphysical':                 'PhysicalMemoryMap',
    'physmem':                     'PhysicalMemoryMap',
    'physicalmemory':              'PhysicalMemoryMap',
    'mapmemory':                   'PhysicalMemoryMap',
    'mapio':                       'PhysicalMemoryMap',
    'pciconfig':                   'PciConfigAccess',
    'readpci':                     'PciConfigAccess',
    'writepci':                    'PciConfigAccess',
    'readcr':                      'ControlRegisterAccess',
    'writecr':                     'ControlRegisterAccess',
    'readdr':                      'ControlRegisterAccess',
    'writedr':                     'ControlRegisterAccess',
    'gdt':                         'ControlRegisterAccess',
    'idt':                         'ControlRegisterAccess',
    # ring-0 exec
    'shellcode':                   'Ring0Exec',
    'execpayload':                 'Ring0Exec',
    'kernelexec':                  'Ring0Exec',
    'callkernel':                  'Ring0Exec',
    # process / token tampering
    'terminateprocess':            'ProcessTampering',
    'killprocess':                 'ProcessTampering',
    'suspendprocess':              'ProcessTampering',
    'protectprocess':              'ProcessTampering',
    'unprotectprocess':            'ProcessTampering',
    'stealtoken':                  'TokenManipulation',
    'swaptoken':                   'TokenManipulation',
    'elevatetoken':                'TokenManipulation',
    'tokenswap':                   'TokenManipulation',
    # callback / ETW / SSDT
    'disablecallback':             'CallbackTampering',
    'removecallback':              'CallbackTampering',
    'unregistercallback':          'CallbackTampering',
    'patchetw':                    'EtwTampering',
    'disableetw':                  'EtwTampering',
    'ssdt':                        'SsdtTampering',
    'hookssdt':                    'SsdtTampering',
    'patchssdt':                   'SsdtTampering',
    # file / driver
    'kernelfileread':              'InsecureKernelResourceAccess',
    'kernelfilewrite':             'InsecureKernelResourceAccess',
    'kernelregistry':              'InsecureKernelResourceAccess',
    'loaddriver':                  'DriverLoadPrimitive',
    'mapdriver':                   'DriverLoadPrimitive',
    'opensection':                 'InsecureKernelResourceAccess',
    'mapsection':                  'InsecureKernelResourceAccess',
}

# Vuln label -> short name used in win_vuln_finder reports
NAME_VULN_HINTS = {
    # HEVD-style
    'bufferoverflowstack':        'Stack BoF (name)',
    'bufferoverflownonpagedpool': 'Pool BoF (name)',
    'bufferoverflowpagedpool':    'Pool BoF (name)',
    'stackoverflow':              'Stack BoF (name)',
    'heapoverflow':               'Heap/Pool BoF (name)',
    'pooloverflow':               'Pool BoF (name)',
    'integeroverflow':            'Integer Overflow (name)',
    'arbitrarywrite':             'Arbitrary Write (name)',
    'arbitraryread':              'Arbitrary Read (name)',
    'arbitraryincrement':         'Arbitrary Increment (name)',
    'arbitraryreadwrite':         'Arb R/W (name)',
    'arbwrite':                   'Arbitrary Write (name)',
    'arbread':                    'Arbitrary Read (name)',
    'readkernel':                 'Arbitrary Kernel Read (name)',
    'writekernel':                'Arbitrary Kernel Write (name)',
    'readvirtual':                'Virtual Mem Read (name)',
    'writevirtual':               'Virtual Mem Write (name)',
    'readmemory':                 'Memory Read (name)',
    'writememory':                'Memory Write (name)',
    'readprocessmemory':          'Process Mem Read (name)',
    'writeprocessmemory':         'Process Mem Write (name)',
    'writenull':                  'Write to NULL (name)',
    'nullpointer':                'NULL Deref (name)',
    'nullderef':                  'NULL Deref (name)',
    'uninitialized':              'Uninitialized Mem (name)',
    'uninit':                     'Uninitialized Mem (name)',
    'memorydisclosure':           'Memory Disclosure (name)',
    'infoleak':                   'Info Leak (name)',
    'typeconfusion':              'Type Confusion (name)',
    'uafobject':                  'Use-After-Free (name)',
    'useafterfree':               'Use-After-Free (name)',
    'doublefree':                 'Double Free (name)',
    'doublefetch':                'Double-Fetch (name)',
    'racecondition':              'Race Condition (name)',
    'insecurekernelfileaccess':   'Insecure File Access (name)',
    'fakeobject':                 'Fake Object / Type Confusion (name)',
    'rdmsr':                      'MSR Read (name)',
    'wrmsr':                      'MSR Write (name)',
    'readmsr':                    'MSR Read (name)',
    'writemsr':                   'MSR Write (name)',
    'msrread':                    'MSR Read (name)',
    'msrwrite':                   'MSR Write (name)',
    'readioport':                 'Port IO Read (name)',
    'writeioport':                'Port IO Write (name)',
    'readport':                   'Port IO Read (name)',
    'writeport':                  'Port IO Write (name)',
    'inport':                     'Port IN (name)',
    'outport':                    'Port OUT (name)',
    'readphysical':               'Phys Mem Read (name)',
    'writephysical':              'Phys Mem Write (name)',
    'mapphysical':                'Phys Mem Map (name)',
    'physmem':                    'Phys Mem Access (name)',
    'physicalmemory':             'Phys Mem Access (name)',
    'mapmemory':                  'Memory Map (name)',
    'mapio':                      'IO Space Map (name)',
    'pciconfig':                  'PCI Config (name)',
    'readpci':                    'PCI Read (name)',
    'writepci':                   'PCI Write (name)',
    'readcr':                     'CRx Read (name)',
    'writecr':                    'CRx Write (name)',
    'readdr':                     'DRx Read (name)',
    'writedr':                    'DRx Write (name)',
    'gdt':                        'GDT Access (name)',
    'idt':                        'IDT Access (name)',
    'shellcode':                  'Ring-0 Shellcode (name)',
    'execpayload':                'Ring-0 Exec (name)',
    'kernelexec':                 'Ring-0 Exec (name)',
    'callkernel':                 'Ring-0 Exec (name)',
    'terminateprocess':           'Process Kill (name)',
    'killprocess':                'Process Kill (name)',
    'suspendprocess':             'Process Suspend (name)',
    'protectprocess':             'Process Protection (name)',
    'unprotectprocess':           'Process Protection (name)',
    'stealtoken':                 'Token Steal (name)',
    'swaptoken':                  'Token Swap (name)',
    'elevatetoken':               'Token Elevation (name)',
    'tokenswap':                  'Token Swap (name)',
    'disablecallback':            'Callback Removal (name)',
    'removecallback':             'Callback Removal (name)',
    'unregistercallback':         'Callback Removal (name)',
    'patchetw':                   'ETW Tampering (name)',
    'disableetw':                 'ETW Tampering (name)',
    'ssdt':                       'SSDT Tampering (name)',
    'hookssdt':                   'SSDT Hook (name)',
    'patchssdt':                  'SSDT Hook (name)',
    'kernelfileread':             'Kernel File Access (name)',
    'kernelfilewrite':            'Kernel File Access (name)',
    'kernelregistry':             'Kernel Registry Access (name)',
    'loaddriver':                 'Driver Load Primitive (name)',
    'mapdriver':                  'Driver Map Primitive (name)',
    'opensection':                'Section Open (name)',
    'mapsection':                 'Section Map (name)',
}

# POC tag mapping: label substring -> primitive tag
NAME_TAG_MAP = {
    'stack buffer overflow': 'stack_bof',
    'pool buffer overflow':  'pool_bof',
    'pool overflow':         'pool_bof',
    'heap/pool':             'pool_bof',
    'write-what-where':      'write_what_where',
    'arbitrary kernel read': 'arb_read',
    'arbitrary kernel write':'write_what_where',
    'arbitrary write':       'write_what_where',
    'arbitrary read':        'arb_read',
    'arbitrary increment':   'arb_increment',
    'arb r/w':               'arb_rw',
    'virtual mem read':      'arb_read',
    'virtual mem write':     'write_what_where',
    'process mem read':      'process_read',
    'process mem write':     'process_write',
    'write to null':         'null_deref',
    'null pointer deref':    'null_deref',
    'null deref':            'null_deref',
    'uninitialized':         'uninit_leak',
    'memory disclosure':     'uninit_leak',
    'info leak':             'uninit_leak',
    'integer overflow':      'int_overflow',
    'type confusion':        'type_confusion',
    'fake object':           'type_confusion',
    'use-after-free':        'uaf',
    'double free':           'uaf',
    'double-fetch':          'double_fetch',
    'race condition':        'race',
    'insecure file':         'insecure_file',
    'msr read':              'msr_rw',
    'msr write':             'msr_rw',
    'port io':               'port_io',
    'port in':               'port_io',
    'port out':              'port_io',
    'phys mem':              'phys_mem',
    'physical memory':       'phys_mem',
    'memory map':            'phys_mem',
    'io space map':          'phys_mem',
    'pci':                   'pci_config',
    'crx read':              'cr_access',
    'crx write':             'cr_access',
    'drx read':              'cr_access',
    'drx write':             'cr_access',
    'gdt':                   'cr_access',
    'idt':                   'cr_access',
    'ring-0':                'ring0_exec',
    'shellcode':             'ring0_exec',
    'process kill':          'process_kill',
    'process suspend':       'process_kill',
    'process protection':    'process_protect',
    'token':                 'token_swap',
    'callback removal':      'callback_removal',
    'etw tampering':         'etw_tamper',
    'ssdt':                  'ssdt_tamper',
    'driver load':           'driver_load',
    'driver map':            'driver_load',
    'section open':          'section_access',
    'section map':           'section_access',
    'virtual memory read':   'vmem_rw',
    'virtual memory write':  'vmem_rw',
    'virtual mem r/w':       'vmem_rw',
    'mmcopyvirtualmemory':   'vmem_rw',
    'mdl map':               'mdl_rw',
    'mdl read':              'mdl_rw',
    'mdl write':             'mdl_rw',
    'mdl kernel-to-user':    'mdl_rw',
    'handle dup':            'handle_dup',
    'duplicate object':      'handle_dup',
    'dse bypass':            'dse_bypass',
    'dse/ci':                'dse_bypass',
    'code integrity':        'dse_bypass',
}

# HLIL intrinsic -> POC tag direct mapping
HLIL_INTRINSIC_TAGS = {
    '__rdmsr': 'msr_rw', '__wrmsr': 'msr_rw',
    '_rdpmc': 'msr_rw',
    '__in_': 'port_io', '__out_': 'port_io',
    '__inbyte': 'port_io', '__outbyte': 'port_io',
    '__indword': 'port_io', '__outdword': 'port_io',
    '__inword': 'port_io', '__outword': 'port_io',
    'MmMapIoSpace': 'phys_mem', 'MmMapIoSpaceEx': 'phys_mem',
    'MmCopyMemory': 'phys_mem',
    'ZwMapViewOfSection': 'phys_mem',
    'HalGetBusDataByOffset': 'pci_config', 'HalSetBusDataByOffset': 'pci_config',
    'HalGetBusData': 'pci_config', 'HalSetBusData': 'pci_config',
    '__readcr': 'cr_access', '__writecr': 'cr_access',
    '__readdr': 'cr_access', '__writedr': 'cr_access',
    '__sidt': 'cr_access', '__lidt': 'cr_access',
    '__sgdt': 'cr_access', '__lgdt': 'cr_access',
    'ZwReadVirtualMemory': 'vmem_rw', 'NtReadVirtualMemory': 'vmem_rw',
    'ZwWriteVirtualMemory': 'vmem_rw', 'NtWriteVirtualMemory': 'vmem_rw',
    'MmCopyVirtualMemory': 'vmem_rw',
    'IoAllocateMdl': 'mdl_rw',
    'ZwDuplicateObject': 'handle_dup', 'ObDuplicateObject': 'handle_dup',
    'ZwOpenSection': 'section_access',
}

# Name hints to ignore (stubs carry no info)
NAME_HINT_SKIP_PREFIX = ('sub_', 'nullsub_', 'j_')


# ---------------------------------------------------------------------------
# Callee walk helpers
# ---------------------------------------------------------------------------

MAX_DEEP_CALLEES = 16
MAX_CLASSIFY_DEPTH = 3
MAX_CALLEES_PER_LEVEL = 12


def walk_collect_calls(instr, callee_starts):
    """Recursively collect call destination addresses from one HLIL instr."""
    try:
        opname = instr.operation.name
        # BN 6.0: struct initializers have no call targets
        if opname == 'HLIL_STRUCT_INIT':
            return
        if opname in ('HLIL_CALL', 'HLIL_TAILCALL', 'HLIL_CALL_SSA', 'HLIL_TAILCALL_SSA'):
            dest = getattr(instr, 'dest', None)
            if dest is not None:
                cval = getattr(dest, 'constant', None)
                if cval is not None:
                    try:
                        callee_starts.add(int(cval))
                    except Exception:
                        pass
                else:
                    dval = getattr(dest, 'value', None)
                    inner = getattr(dval, 'value', None) if dval is not None else None
                    if inner is not None:
                        try:
                            callee_starts.add(int(inner))
                        except Exception:
                            pass
        for operand in getattr(instr, 'operands', []):
            if hasattr(operand, 'operation'):
                walk_collect_calls(operand, callee_starts)
            elif hasattr(operand, '__iter__') and not isinstance(operand, (str, bytes)):
                for item in operand:
                    if hasattr(item, 'operation'):
                        walk_collect_calls(item, callee_starts)
    except Exception:
        pass


def walk_collect_text(instr, parts):
    """Collect string forms of every nested instruction."""
    try:
        parts.append(str(instr))
        for operand in getattr(instr, 'operands', []):
            if hasattr(operand, 'operation'):
                walk_collect_text(operand, parts)
            elif hasattr(operand, '__iter__') and not isinstance(operand, (str, bytes)):
                for item in operand:
                    if hasattr(item, 'operation'):
                        walk_collect_text(item, parts)
    except Exception:
        pass


def branch_text(instrs):
    """Get combined HLIL text for a list of branch instructions."""
    parts = []
    for ins in instrs:
        walk_collect_text(ins, parts)
    return "\n".join(parts)


def branch_callees(bv, instrs):
    """Get set of callee addresses called from branch instructions."""
    starts = set()
    for ins in instrs:
        walk_collect_calls(ins, starts)
    return starts


def walk_callees_recursive(bv, start_addr, depth, visited):
    """Yield (callee_func, None) pairs up to depth levels deep."""
    if depth <= 0 or start_addr in visited:
        return
    visited.add(start_addr)
    f = bv.get_function_at(start_addr)
    if not f:
        return
    try:
        hlil = f.hlil
        if not hlil:
            return
    except Exception:
        return
    sub_callees = set()
    try:
        for block in hlil:
            for instr in block:
                walk_collect_calls(instr, sub_callees)
    except Exception:
        return
    count = 0
    for caddr in sub_callees:
        if count >= MAX_CALLEES_PER_LEVEL:
            break
        count += 1
        sub_f = bv.get_function_at(caddr)
        if sub_f:
            yield sub_f
        yield from walk_callees_recursive(bv, caddr, depth - 1, visited)


def deep_text(bv, instrs, max_depth=3):
    """Branch text + recursive callee text up to max_depth.

    Catches wrapper chains like HEVD's IrpHandler -> Trigger -> primitive.
    """
    from .helpers import get_hlil_text
    t = branch_text(instrs)
    seen = set()
    frontier = list(branch_callees(bv, instrs))
    depth = 0
    while frontier and depth < max_depth:
        next_frontier = []
        count = 0
        for caddr in frontier:
            if count >= MAX_DEEP_CALLEES:
                break
            if caddr in seen:
                continue
            seen.add(caddr)
            count += 1
            f = bv.get_function_at(caddr)
            if not f:
                continue
            try:
                t += "\n; --- callee " + f.name + " ---\n" + get_hlil_text(f)
            except Exception:
                continue
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
    return t