"""
MITRE ATT&CK technique mapping for kernel driver vulnerabilities.

Maps detected exploit primitives to MITRE ATT&CK Enterprise tactics and
techniques. Provides the mapping both as a Python dict and as exportable
JSON for integration with threat intel platforms.

Covers:
  - T1068: Exploitation for Privilege Escalation
  - T1543.003: Windows Service (driver load)
  - T1562.001: Disable or Modify Tools (EDR blinding)
  - T1562.006: Indicator Blocking (ETW tampering)
  - T1548.002: Authentication Package (token manipulation)
  - T1055: Process Injection (via kernel primitives)
  - T1014: Rootkit (persistence via driver)
  - T1202: Indirect Command Execution
  - T1553.006: Subvert Trust Controls (DSE/CI bypass)
  - T1490: Inhibit System Recovery (process termination)

USE ON AUTHORIZED TARGETS ONLY.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class AttackTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    detection_ref: str


MITRE_TECHNIQUES = {
    'T1068': AttackTechnique(
        'T1068', 'Exploitation for Privilege Escalation',
        'Privilege Escalation',
        'Kernel driver vulnerability exploited to escalate from user to SYSTEM',
        'Sysmon Event 1 (process creation) + Event 3 (network connection) from '
        'unusual parent; DriverFrameworks/Operational log; '
        'Microsoft-Windows-Kernel-PnP/Device Configuration events for driver load'
    ),
    'T1543.003': AttackTechnique(
        'T1543.003', 'Create or Modify System Process: Windows Service',
        'Persistence / Privilege Escalation',
        'Loading a kernel driver (BYOVD) to establish kernel-level persistence',
        'Sysmon Event 6 (driver loaded); Event 7045 (service created). '
        'Monitor sc.exe, osquery driver table, LOLDrivers hash matches.'
    ),
    'T1562.001': AttackTechnique(
        'T1562.001', 'Disable or Modify Tools',
        'Defense Evasion',
        'Removing EDR kernel callbacks (PsSetCreateProcessNotifyRoutine, '
        'CmUnRegisterCallback) to blind security products',
        'Periodic integrity check of kernel callback arrays via LiveKD/Volatility; '
        'Microsoft-Windows-Threat-Intelligence ETW provider (Event 3 for '
        'ObUnRegisterCallbacks). Unexpected drop in telemetry volume.'
    ),
    'T1562.006': AttackTechnique(
        'T1562.006', 'Indicator Blocking',
        'Defense Evasion',
        'Patching ETW providers (EtwEventWrite, NtTraceControl) to suppress '
        'telemetry generation at the source',
        'Microsoft-Windows-Threat-Intelligence Event 1 (ETW tampering detected). '
        'Monitor EtwThreatIntProvRegHandle value changes.'
    ),
    'T1548.002': AttackTechnique(
        'T1548.002', 'Abuse Elevation Control Mechanism: ByPass User Access Control',
        'Privilege Escalation',
        'Token manipulation (steal/swap SYSTEM token) via kernel primitive to '
        'bypass UAC and integrity level controls',
        'Sysmon Event 10 (ProcessAccess to SYSTEM process). '
        'Windows Security Event 4672 (Special privileges assigned).'
    ),
    'T1055': AttackTechnique(
        'T1055', 'Process Injection',
        'Privilege Escalation / Defense Evasion',
        'Using kernel primitives (Virtual Memory R/W, MDL map) to inject code '
        'into privileged processes without user-mode API detection',
        'Sysmon Event 8 (CreateRemoteThread), Event 10 (ProcessAccess). '
        'VadSuspension ETW provider. Memory forensics gap detection.'
    ),
    'T1014': AttackTechnique(
        'T1014', 'Rootkit',
        'Defense Evasion / Persistence',
        'Kernel driver loaded for persistent stealth (DKOM, callback removal, '
        'SSDT hooking). Survives reboots via service registration.',
        'Secure Boot logs, Measured Boot PCR values. Kernel Integrity Monitor. '
        'Microsoft-Windows-CodeIntegrity Operational Event 3001/3002/3003/3004.'
    ),
    'T1202': AttackTechnique(
        'T1202', 'Indirect Command Execution',
        'Execution',
        'Using IOCTL interface as an indirect command channel to execute '
        'arbitrary kernel operations (MSR writes, port IO, physical memory access)',
        'Monitor IOCTL patterns via ETW (Microsoft-Windows-Kernel-IO). '
        'Anomalous DeviceIoControl call patterns from low-privilege processes.'
    ),
    'T1553.006': AttackTechnique(
        'T1553.006', 'Subvert Trust Controls: Code Signing Policy Modification',
        'Defense Evasion',
        'Patching ci!g_CiOptions to disable driver signature enforcement (DSE/CI bypass) '
        'followed by loading unsigned malicious driver',
        'Microsoft-Windows-CodeIntegrity Operational Event 3004 (CI policy change). '
        'Kernel patch protection (PatchGuard) violation detection. '
        'Monitor writes to ci.dll .data region.'
    ),
    'T1490': AttackTechnique(
        'T1490', 'Inhibit System Recovery',
        'Impact',
        'Using process/thread manipulation primitives (ZwTerminateProcess) to '
        'kill security products, backup agents, and recovery services',
        'Windows Security Event 4689 (process terminated). Monitor for bulk '
        'process termination of security-related services.'
    ),
    'T1574.002': AttackTechnique(
        'T1574.002', 'Hijack Execution Flow: DLL Side-Loading',
        'Persistence / Privilege Escalation',
        'Loading driver via DLL side-loading into legitimate signed process '
        'that loads unsigned kernel module',
        'Sysmon Event 7 (image loaded). Monitor for DLLs loaded from unexpected '
        'paths by signed binaries. Code Integrity Event 3033.'
    ),
    'T1082': AttackTechnique(
        'T1082', 'System Information Discovery',
        'Discovery',
        'Using MSR reads, control register reads, and physical memory reads to '
        'enumerate system configuration (SMEP/SMAP state, KASLR base, HVCI status)',
        'Monitor for unusual __rdmsr instruction usage from user-mode via '
        'kernel driver proxy. CPU performance counters for MSR access patterns.'
    ),
    'T1098': AttackTechnique(
        'T1098', 'Account Manipulation',
        'Persistence',
        'Modifying token privileges to add SeDebugPrivilege, SeLoadDriverPrivilege, '
        'or other sensitive rights to compromised account',
        'Windows Security Event 4670 (permissions on object changed) for token '
        'objects. Event 4703 (token right adjusted).'
    ),
}


# Primitive -> MITRE technique mapping
PRIMITIVE_TO_MITRE: Dict[str, List[str]] = {
    # Memory corruption
    'Stack Buffer Overflow':         ['T1068', 'T1202'],
    'Pool Buffer Overflow':          ['T1068'],
    'Write-What-Where':              ['T1068', 'T1548.002'],
    'Arbitrary Kernel Read':         ['T1068', 'T1082'],
    'Arbitrary Kernel Write':        ['T1068', 'T1548.002', 'T1553.006'],

    # Privileged primitives
    'MSR Read/Write Primitive':      ['T1068', 'T1082'],
    'Port IO Primitive':             ['T1068', 'T1202'],
    'Physical Memory Map':           ['T1068', 'T1082', 'T1553.006'],
    'Control/Debug Register Access': ['T1068', 'T1082'],
    'Ring-0 Exec (Capcom-style)':    ['T1068', 'T1202'],
    'PCI Config Space Access':       ['T1068'],

    # Token/process
    'Token-Swap Primitive':          ['T1548.002', 'T1098'],
    'Process/Thread Manipulation':   ['T1490', 'T1055'],

    # Defensive evasion
    'Callback Removal':              ['T1562.001'],
    'ETW Tampering':                 ['T1562.006'],
    'DSE/CI Manipulation':           ['T1553.006', 'T1543.003'],
    'SSDT Tampering':                ['T1014', 'T1562.001'],

    # Advanced primitives
    'Virtual Memory R/W':            ['T1055', 'T1548.002'],
    'MDL Kernel-to-User Map':        ['T1068', 'T1055'],
    'Handle Duplication':            ['T1548.002', 'T1055'],
    'Section-Based Phys Access':     ['T1068', 'T1082'],
    'Driver Load Primitive':         ['T1543.003', 'T1014'],

    # Bug classes
    'Type Confusion (Object)':       ['T1068'],
    'Use-After-Free':                ['T1068'],
    'Double-Fetch TOCTOU':           ['T1068'],
    'Integer Overflow':              ['T1068'],
    'Race Condition':                ['T1068'],
    'Uninitialized Pool Leak':       ['T1082'],
    'NULL Pointer Deref':            ['T1068'],
}


def map_primitive_to_mitre(primitive_name: str) -> List[AttackTechnique]:
    """Return ATT&CK techniques for a given exploit primitive."""
    technique_ids = PRIMITIVE_TO_MITRE.get(primitive_name, ['T1068'])
    return [MITRE_TECHNIQUES[tid] for tid in technique_ids if tid in MITRE_TECHNIQUES]


def generate_sigma_rule(driver_name: str, primitive_name: str,
                        ioctl_codes: List[int]) -> str:
    """Generate a Sigma detection rule for a driver primitive.

    Returns a YAML-format Sigma rule string suitable for SIEM ingestion.
    """
    techniques = map_primitive_to_mitre(primitive_name)
    tech_ids = [t.technique_id for t in techniques]
    tech_refs = "\n".join(f"        - {t.technique_id}: {t.technique_name}" for t in techniques)

    # Derive Sysmon Event ID based on primitive type
    event_id = 6  # default: driver loaded
    if 'Token' in primitive_name or 'Privilege' in primitive_name:
        event_id = 10  # ProcessAccess
    elif 'Callback' in primitive_name or 'ETW' in primitive_name:
        event_id = 1   # Process creation (for detection only)
    elif 'Write' in primitive_name or 'Read' in primitive_name:
        event_id = 3   # Network connection (exfiltration path)

    ioctl_hex = ', '.join(f'0x{c:08X}' for c in ioctl_codes[:10])

    rule = f"""title: Kernel Driver Exploit Primitive - {driver_name} - {primitive_name}
id: {hash(driver_name + primitive_name) & 0xFFFFFFFF:08x}
status: experimental
description: Detects exploitation of {primitive_name} primitive in {driver_name}.sys
references:
    - https://attack.mitre.org/techniques/{tech_ids[0].replace('.', '/')}
author: Whispergate / BinjaKernelTools
date: 2026-08-17
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.{primitive_name.lower().replace(' ', '-').replace('/', '-')[:40]}
logsource:
    product: windows
    service: sysmon
detection:
    selection_driver:
        EventID: 6
        ImageLoaded|endswith: '\\\\{driver_name}.sys'
    selection_ioctl:
        EventID: {event_id}
    condition: selection_driver or selection_ioctl
falsepositives:
    - Legitimate driver operations during normal system usage
    - Driver development and testing environments
level: high
mitre_attck:
{tech_refs}
ioctl_codes:
    - {ioctl_hex}
"""
    return rule


def generate_yara_rule(driver_name: str, primitives: List[str],
                       ioctl_codes: List[int]) -> str:
    """Generate a YARA rule for fingerprinting a vulnerable driver.

    Returns a YARA rule string for driver identification and hunting.
    """
    sortable = sorted(set(ioctl_codes))
    ioctl_hex_patterns = ' '.join(
        f'${c:08X}' for c in sortable[:15]
    )

    # Build IOCTL condition
    ioctl_condition = ' or '.join(
        f'${c:08X}' for c in sortable[:15]
    ) if sortable else 'false'

    primitives_str = ', '.join(primitives[:8])

    rule = f"""rule Mal_Vulnerable_Driver_{driver_name.replace('.', '_')}
{{
    meta:
        description = "Detects {driver_name}.sys - known vulnerable kernel driver"
        author = "Whispergate / BinjaKernelTools"
        date = "2026-08-17"
        reference = "https://github.com/Whispergate"
        hash_sha256 = "SEE_README"
        severity = "CRITICAL"
        driver_name = "{driver_name}"
        primitives = "{primitives_str}"
        detected_ioctls = "{ioctl_hex_patterns}"

    strings:
        $device_1 = "\\\\Device\\\\{driver_name}" ascii wide
        $device_2 = "\\\\??\\\\{driver_name}" ascii wide
        $device_3 = "\\\\DosDevices\\\\{driver_name}" ascii wide
        $drv_name = "{driver_name}.sys" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        any of ($device_*, $drv_name)
        and filesize < 50MB
}}
"""
    return rule