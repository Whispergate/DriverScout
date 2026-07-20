"""
Binary Ninja plugin - Cross-driver exploit chain detection.

When multiple drivers are analyzed (or a single driver with multiple
primitives), identifies escalation chains:
  Read + Write → full LPE
  Read → KASLR defeat → Write target
  Physical map → PTE manipulation → arbitrary exec
  MSR write → LSTAR hijack → code exec

Capability model:
  INFO_LEAK    - Read kernel addresses (KASLR defeat)
  ARB_READ     - Read arbitrary kernel memory
  ARB_WRITE    - Write arbitrary kernel memory
  PHYS_MAP     - Map physical memory
  CODE_EXEC    - Execute arbitrary code in ring-0
  MSR_RW       - Read/write MSRs
  PORT_IO      - Read/write IO ports
  CR_ACCESS    - Read/write control registers
  TOKEN_SWAP   - Modify process token
  POOL_CORRUPT - Corrupt pool memory

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.helpers import get_hlil_text
from .win_vuln_finder import (
    _find_dispatch_routines, _ioctl_branches_for_dispatcher, _ctl_decode, METHOD_MAP,
)

# Capability types
CAP_INFO_LEAK = 'INFO_LEAK'
CAP_ARB_READ = 'ARB_READ'
CAP_ARB_WRITE = 'ARB_WRITE'
CAP_PHYS_MAP = 'PHYS_MAP'
CAP_CODE_EXEC = 'CODE_EXEC'
CAP_MSR_RW = 'MSR_RW'
CAP_PORT_IO = 'PORT_IO'
CAP_CR_ACCESS = 'CR_ACCESS'
CAP_TOKEN_SWAP = 'TOKEN_SWAP'
CAP_POOL_CORRUPT = 'POOL_CORRUPT'

# Primitive label → capability mapping
_PRIM_TO_CAP = {
    'Write-What-Where': CAP_ARB_WRITE,
    'Arbitrary Kernel Read': CAP_ARB_READ,
    'MSR Read/Write Primitive': CAP_MSR_RW,
    'Port IO Primitive': CAP_PORT_IO,
    'Physical Memory Map': CAP_PHYS_MAP,
    'Control/Debug Register Access': CAP_CR_ACCESS,
    'Ring-0 Exec (Capcom-style)': CAP_CODE_EXEC,
    'PCI Config Space Access': CAP_PORT_IO,
    'Stack Buffer Overflow': CAP_CODE_EXEC,
    'Pool Buffer Overflow': CAP_POOL_CORRUPT,
    'Token-Swap Primitive': CAP_TOKEN_SWAP,
    'Type Confusion (Object)': CAP_POOL_CORRUPT,
    'Uninitialized Pool Leak': CAP_INFO_LEAK,
    'Double-Fetch TOCTOU': CAP_ARB_WRITE,
}

# Name hint → capability mapping (from win_primitives._NAME_PRIM_HINTS patterns)
_NAME_TO_CAP = {
    'readmsr': CAP_MSR_RW,
    'writemsr': CAP_MSR_RW,
    'mapphys': CAP_PHYS_MAP,
    'readphys': CAP_ARB_READ,
    'writephys': CAP_ARB_WRITE,
    'readport': CAP_PORT_IO,
    'writeport': CAP_PORT_IO,
    'readpci': CAP_PORT_IO,
    'writepci': CAP_PORT_IO,
    'mapmem': CAP_PHYS_MAP,
    'readmem': CAP_ARB_READ,
    'writemem': CAP_ARB_WRITE,
    'readkernel': CAP_ARB_READ,
    'writekernel': CAP_ARB_WRITE,
    'allocexec': CAP_CODE_EXEC,
    'execcode': CAP_CODE_EXEC,
    'callfunction': CAP_CODE_EXEC,
}

# Exploit chain definitions: (required_caps, chain_name, technique, steps)
_CHAINS = [
    # Classic read + write LPE
    ({CAP_ARB_READ, CAP_ARB_WRITE},
     'Token Overwrite LPE',
     'Data-only attack - works with HVCI',
     [
         'ARB_READ: Leak ntoskrnl base via NtQuerySystemInformation',
         'ARB_READ: Read PsInitialSystemProcess to get SYSTEM EPROCESS',
         'ARB_READ: Walk ActiveProcessLinks to find current process EPROCESS',
         'ARB_READ: Read SYSTEM token value',
         'ARB_WRITE: Overwrite current process Token with SYSTEM token',
         'Spawn elevated cmd.exe',
     ]),

    # Physical memory → PTE → code exec
    ({CAP_PHYS_MAP},
     'PTE Manipulation via Physical Map',
     'Physical-to-virtual translation + page permission flip',
     [
         'PHYS_MAP: Read PML4 self-reference to find page table base',
         'PHYS_MAP: Walk page tables to find target PTE',
         'PHYS_MAP: Flip NX bit to make user page executable from ring-0',
         'Trigger kernel execution on user-controlled page',
     ]),

    # Physical memory → read/write anything
    ({CAP_PHYS_MAP},
     'Physical Memory Full Read/Write',
     'Map physical backing of any virtual address',
     [
         'PHYS_MAP: Translate target VA to physical via page tables',
         'PHYS_MAP: Map physical page with RW access',
         'Read/write any kernel data structure',
     ]),

    # MSR → LSTAR hijack
    ({CAP_MSR_RW},
     'LSTAR Hijack',
     'Requires: no HVCI (hypervisor traps MSR writes with HVCI)',
     [
         'MSR_RW: Read IA32_LSTAR (0xC0000082) to save original syscall handler',
         'MSR_RW: Write user-controlled address as new LSTAR',
         'Trigger syscall instruction to redirect to payload',
         'Payload: token steal, then restore original LSTAR',
     ]),

    # MSR → SYSENTER hijack (x86)
    ({CAP_MSR_RW},
     'SYSENTER Hijack (x86)',
     'Legacy path - x86 mode only',
     [
         'MSR_RW: Read IA32_SYSENTER_EIP (0x176)',
         'MSR_RW: Overwrite with payload address',
         'Trigger int 0x2E or sysenter',
     ]),

    # CR access → SMEP/SMAP disable → user page exec
    ({CAP_CR_ACCESS},
     'SMEP/SMAP Disable',
     'Requires: no HVCI (hypervisor traps CR4 writes)',
     [
         'CR_ACCESS: Read CR4',
         'CR_ACCESS: Clear bit 20 (SMEP) and bit 21 (SMAP)',
         'CR_ACCESS: Write modified CR4',
         'Execute ring-0 shellcode from user page',
     ]),

    # Port IO → PCI config → BIOS/SMM
    ({CAP_PORT_IO},
     'PCI Config Access via IO Ports',
     'CF8/CFC port access for PCI device manipulation',
     [
         'PORT_IO: Write target BDF + register to port 0xCF8',
         'PORT_IO: Read/write PCI config via port 0xCFC',
         'Use for SPI flash access, SMM trigger, or UEFI variable manipulation',
     ]),

    # Direct code exec
    ({CAP_CODE_EXEC},
     'Direct Kernel Code Execution',
     'Capcom-style or stack overflow with ROP',
     [
         'CODE_EXEC: Allocate user buffer with PIC token-steal shellcode',
         'CODE_EXEC: Trigger driver to call user-controlled function pointer',
         'Shellcode: walk EPROCESS list, steal SYSTEM token',
     ]),

    # Info leak + write
    ({CAP_INFO_LEAK, CAP_ARB_WRITE},
     'Info Leak to Write LPE',
     'Two-stage: defeat KASLR then write',
     [
         'INFO_LEAK: Obtain kernel base address',
         'INFO_LEAK: Calculate target offset (PsInitialSystemProcess)',
         'ARB_WRITE: Overwrite token or callback pointer',
     ]),

    # Pool corrupt → code exec
    ({CAP_POOL_CORRUPT},
     'Pool Corruption to Code Exec',
     'Requires pool spray setup + suitable adjacent object',
     [
         'POOL_CORRUPT: Trigger overflow to corrupt adjacent pool chunk',
         'Spray target objects (pipe attributes, WNF state data, etc.)',
         'Gain controlled write or function pointer overwrite',
         'Redirect execution flow',
     ]),

    # Token swap alone
    ({CAP_TOKEN_SWAP},
     'Direct Token Manipulation',
     'Driver directly exposes token modification primitive',
     [
         'TOKEN_SWAP: Use driver primitive to modify process token',
         'Set SeDebugPrivilege or copy SYSTEM token',
     ]),

    # Read + physical = everything
    ({CAP_ARB_READ, CAP_PHYS_MAP},
     'Read + Physical Map Complete Control',
     'Read kernel state, then modify via physical mapping',
     [
         'ARB_READ: Leak kernel data structure addresses',
         'PHYS_MAP: Convert VA to PA via page table walk',
         'PHYS_MAP: Map and modify any kernel structure',
     ]),
]


def _detect_capabilities(bv):
    """Detect driver capabilities from primitives and function patterns."""
    caps = {}  # cap_type -> [(ioctl, detail)]

    # Import and run primitive detection
    try:
        from .win_primitives import _DETECTORS, _deep_text, _detect_name_hints
    except ImportError:
        pass

    dispatchers = _find_dispatch_routines(bv)
    for df in dispatchers:
        branches = _ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, addr in branches:
            by_code.setdefault(code, []).extend(instrs)

        for code, instrs in by_code.items():
            # Check HLIL text for capability indicators
            texts = []
            for instr in instrs:
                try:
                    texts.append(str(instr))
                except Exception:
                    pass
            combined = ' '.join(texts)

            # Direct API detection
            api_caps = {
                '__rdmsr': CAP_MSR_RW, '__wrmsr': CAP_MSR_RW,
                'MmMapIoSpace': CAP_PHYS_MAP, 'MmCopyMemory': CAP_ARB_READ,
                'ZwMapViewOfSection': CAP_PHYS_MAP,
                '__readcr': CAP_CR_ACCESS, '__writecr': CAP_CR_ACCESS,
                '__inbyte': CAP_PORT_IO, '__outbyte': CAP_PORT_IO,
                '__indword': CAP_PORT_IO, '__outdword': CAP_PORT_IO,
            }
            for api, cap in api_caps.items():
                if api in combined:
                    caps.setdefault(cap, []).append(
                        ('0x{:08X}'.format(code), api))

            # Name-based detection on callee functions
            for instr in instrs:
                try:
                    for op in instr.operands:
                        if hasattr(op, 'name'):
                            nm = op.name.lower().replace('_', '')
                            for pat, cap in _NAME_TO_CAP.items():
                                if pat in nm:
                                    caps.setdefault(cap, []).append(
                                        ('0x{:08X}'.format(code), op.name))
                except Exception:
                    pass

    # Vuln-label based detection
    try:
        from .win_vuln_finder import _classify_branch_vulns
        for df in dispatchers:
            branches = _ioctl_branches_for_dispatcher(df)
            by_code = {}
            for code, instrs, addr in branches:
                by_code.setdefault(code, []).extend(instrs)
            for code, instrs in by_code.items():
                vulns, _ = _classify_branch_vulns(bv, instrs)
                for vlabel in vulns:
                    base = vlabel.split(' (via ')[0] if ' (via ' in vlabel else vlabel
                    cap = _PRIM_TO_CAP.get(base)
                    if cap:
                        caps.setdefault(cap, []).append(
                            ('0x{:08X}'.format(code), vlabel))
    except Exception:
        pass

    return caps


def _find_chains(caps):
    """Find viable exploit chains given detected capabilities."""
    available = set(caps.keys())
    viable = []

    for required, name, technique, steps in _CHAINS:
        if required.issubset(available):
            # Collect IOCTL evidence
            evidence = {}
            for cap in required:
                evidence[cap] = caps[cap][:3]  # First 3 IOCTLs per cap
            viable.append({
                'name': name,
                'technique': technique,
                'steps': steps,
                'required': required,
                'evidence': evidence,
            })

    return viable


def detect_chains(bv: BinaryView):
    lines = [
        "=== Cross-Driver Exploit Chain Detection ===",
        "Binary: {}".format(bv.file.filename),
        "",
    ]
    drv_name = os.path.splitext(os.path.basename(bv.file.filename))[0]
    log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, drv_name + '-chains.txt')

    def emit(s):
        lines.append(s)
        log_info(s)

    # Detect capabilities
    caps = _detect_capabilities(bv)
    if not caps:
        emit("[-] No exploit capabilities detected")
        return

    emit("[+] Detected capabilities:")
    for cap, evidence_list in sorted(caps.items()):
        emit("    {} ({} IOCTLs):".format(cap, len(evidence_list)))
        for ioctl, detail in evidence_list[:5]:
            emit("      IOCTL {} - {}".format(ioctl, detail))

    # Find chains
    chains = _find_chains(caps)
    if not chains:
        emit("\n[-] No complete exploit chains found")
        emit("[*] Driver has individual primitives but no chain to full LPE")
        emit("[*] May be chainable with another driver's primitives")
        return

    emit("\n[+] Viable exploit chains ({} found):".format(len(chains)))
    emit("")

    for i, chain in enumerate(chains, 1):
        emit("  Chain {}: {}".format(i, chain['name']))
        emit("    Technique: {}".format(chain['technique']))
        emit("    Required: {}".format(', '.join(sorted(chain['required']))))
        emit("    Steps:")
        for step in chain['steps']:
            emit("      -> {}".format(step))

        emit("    Evidence:")
        for cap, evs in chain['evidence'].items():
            for ioctl, detail in evs:
                emit("      [{}] IOCTL {} - {}".format(cap, ioctl, detail))
        emit("")

    # Operational summary
    emit("[>] Operational Summary:")
    has_data_only = any('Data-only' in c['technique'] or 'Token' in c['name'] for c in chains)
    has_code_exec = any(CAP_CODE_EXEC in c['required'] or CAP_MSR_RW in c['required'] for c in chains)

    if has_data_only:
        emit("    [+] Data-only attack chain available - works WITH HVCI enabled")
    if has_code_exec:
        emit("    [!] Code execution chain available - requires HVCI DISABLED")
    if len(chains) >= 2:
        emit("    [+] Multiple chain options - flexibility for different target configs")

    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(lines))
        emit('[+] Report saved to: {}'.format(report_path))
    except Exception as e:
        log_warn("Could not write chain report: {}".format(e))


PluginCommand.register(
    "Windows Driver Analysis\\Exploit Chain Detection",
    "Detect viable exploit chains from combined driver capabilities",
    detect_chains,
)
