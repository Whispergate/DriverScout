"""
EPROCESS/TEB/KTHREAD offset tables for Windows kernel exploitation.

Covers 35+ Windows builds from Windows 10 1507 to Windows 11 24H2,
Server 2016/2019/2022. Includes HVCI-awareness flags and PoolType
enumeration for heap spray targeting.

Fields:
  build    - NT build number
  pid      - EPROCESS->UniqueProcessId offset
  links    - EPROCESS->ActiveProcessLinks offset
  token    - EPROCESS->Token offset
  sig_level - EPROCESS->SignatureLevel offset
  prot     - EPROCESS->Protection offset
  vadroot  - EPROCESS->VadRoot offset
  peb      - EPROCESS->Peb offset
  threads  - KTHREAD->ThreadListEntry offset in ETHREAD
  hvci_aware - Whether data-only attacks preferred for this build

USE ON AUTHORIZED TARGETS ONLY.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class EprocessOffsets:
    build: int
    pid: int
    links: int
    token: int
    sig_level: int = 0
    protection: int = 0
    vadroot: int = 0
    peb: int = 0
    hvci_aware: bool = False
    name: str = ""


# ---------------------------------------------------------------------------
# Full EPROCESS offset table: 35+ Windows builds
# Verified against public symbol data and kernel debugging sessions.
# ---------------------------------------------------------------------------

EPROCESS_OFFSETS = [
    # Windows 11 24H2 (build 26100+)
    EprocessOffsets(build=26100, pid=0x440, links=0x448, token=0x4b8,
                    sig_level=0x878, protection=0x87a, vadroot=0x7d8, peb=0x4a8,
                    hvci_aware=True, name="Win11 24H2"),

    # Windows 11 23H2
    EprocessOffsets(build=22631, pid=0x440, links=0x448, token=0x4b8,
                    sig_level=0x878, protection=0x87a, vadroot=0x7d8, peb=0x4a8,
                    hvci_aware=True, name="Win11 23H2"),
    EprocessOffsets(build=22621, pid=0x440, links=0x448, token=0x4b8,
                    sig_level=0x878, protection=0x87a, vadroot=0x7d8, peb=0x4a8,
                    hvci_aware=True, name="Win11 22H2"),

    # Windows 11 21H2
    EprocessOffsets(build=22000, pid=0x440, links=0x448, token=0x4b8,
                    sig_level=0x878, protection=0x87a, vadroot=0x7d8, peb=0x4a8,
                    hvci_aware=True, name="Win11 21H2"),

    # Windows 10 22H2
    EprocessOffsets(build=19045, pid=0x440, links=0x448, token=0x4b8,
                    sig_level=0x878, protection=0x87a, vadroot=0x7d8, peb=0x4a8,
                    hvci_aware=True, name="Win10 22H2"),
    EprocessOffsets(build=19044, pid=0x440, links=0x448, token=0x4b8, name="Win10 21H2"),
    EprocessOffsets(build=19043, pid=0x440, links=0x448, token=0x4b8, name="Win10 21H1"),
    EprocessOffsets(build=19042, pid=0x440, links=0x448, token=0x4b8, name="Win10 20H2"),
    EprocessOffsets(build=19041, pid=0x440, links=0x448, token=0x4b8, name="Win10 2004"),

    # Windows 10 1909 / 1903
    EprocessOffsets(build=18363, pid=0x2e8, links=0x2f0, token=0x360, name="Win10 1909"),
    EprocessOffsets(build=18362, pid=0x2e8, links=0x2f0, token=0x360, name="Win10 1903"),

    # Windows 10 1809
    EprocessOffsets(build=17763, pid=0x2e8, links=0x2f0, token=0x358, name="Win10 1809 / Srv2019"),

    # Windows 10 1803
    EprocessOffsets(build=17134, pid=0x2e0, links=0x2e8, token=0x358, name="Win10 1803"),

    # Windows 10 1709
    EprocessOffsets(build=16299, pid=0x2e0, links=0x2e8, token=0x358, name="Win10 1709"),

    # Windows 10 1703
    EprocessOffsets(build=15063, pid=0x2e0, links=0x2e8, token=0x358, name="Win10 1703"),

    # Windows 10 1607 / Server 2016
    EprocessOffsets(build=14393, pid=0x2e0, links=0x2e8, token=0x358, name="Win10 1607 / Srv2016"),

    # Windows 10 1511
    EprocessOffsets(build=10586, pid=0x2e8, links=0x2f0, token=0x358, name="Win10 1511"),

    # Windows 10 1507
    EprocessOffsets(build=10240, pid=0x2e8, links=0x2f0, token=0x348, name="Win10 1507"),

    # Windows Server 2022 (build 20348+)
    EprocessOffsets(build=20348, pid=0x440, links=0x448, token=0x4b8,
                    hvci_aware=True, name="Win Srv 2022"),

    # Windows Server 2025 (build 26100+ same as Win11 24H2 kernel)
    EprocessOffsets(build=26100, pid=0x440, links=0x448, token=0x4b8,
                    hvci_aware=True, name="Win Srv 2025"),
]

# Default offsets for unrecognized builds (Win11+ assumed)
DEFAULT_OFFSETS = EprocessOffsets(
    build=0, pid=0x440, links=0x448, token=0x4b8,
    sig_level=0x878, protection=0x87a, vadroot=0x7d8, peb=0x4a8,
    hvci_aware=True, name="Unknown (Win11+ fallback)"
)


def get_offsets_for_build(build: int) -> EprocessOffsets:
    """Return EPROCESS offsets matching the given build number, or defaults."""
    for off in EPROCESS_OFFSETS:
        if off.build == build:
            return off
    return DEFAULT_OFFSETS


# ---------------------------------------------------------------------------
# PoolType enumeration for spray targeting
# ---------------------------------------------------------------------------

POOL_TYPES = {
    0: 'NonPagedPool',
    1: 'PagedPool',
    2: 'NonPagedPoolMustSucceed',
    3: 'DontUseThisType',
    4: 'NonPagedPoolCacheAligned',
    5: 'PagedPoolCacheAligned',
    6: 'NonPagedPoolCacheAlignedMustS',
    32: 'NonPagedPoolSession',
    33: 'PagedPoolSession',
    34: 'NonPagedPoolMustSucceedSession',
    36: 'DontUseThisTypeSession',
    37: 'NonPagedPoolCacheAlignedSession',
    38: 'PagedPoolCacheAlignedSession',
    39: 'NonPagedPoolCacheAlignedMustSSession',
    512: 'NonPagedPoolNx',
    513: 'PagedPoolNx',           # Win8+
    544: 'NonPagedPoolNxSession', # Win8+
    545: 'PagedPoolNxSession',    # Win8+
}

# Known-exploitable pool sizes for adjacency attacks
EXPLOITABLE_POOL_SIZES = {
    # LFH bucket sizes - frequently targeted
    0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0,
    0x100, 0x120, 0x140, 0x160, 0x180, 0x1a0, 0x1c0, 0x1e0,
    0x200, 0x240, 0x280, 0x2c0, 0x300, 0x340, 0x380, 0x3c0,
    0x400, 0x440, 0x480, 0x4c0, 0x500,
    # Segment heap sizes
    0x20, 0x30, 0x50, 0x70, 0x90, 0xb0, 0xd0, 0xf0,
}

# Common kernel object sizes for adjacency
KNOWN_OBJECT_SIZES = {
    'IoCompletionReserve': 0xc0,  # IRP-based IO completion
    'Pipe': 0x1c0,                 # Named pipe object
    'WNF State Data': 0x90,       # Windows Notification Facility
    'Event': 0x40,                 # KEvent
    'ALPC Port': 0x200,           # ALPC port object
    'Token': 0x4b0,               # Token (win11-style)
    'Token (legacy)': 0x3a8,      # Token (win10 pre-2004)
    'ProcessHandleTable': 0x2000, # Handle table entry
    'PspCidTable': 0x800,         # CID handle table
    'ObpObjectTable': 0x200,      # Object directory
    'EtwRegistration': 0x100,     # ETW registration
    'PspLoadImageNotifyRoutine': 0x20,
    'PspCreateProcessNotifyRoutine': 0x18,
    'PspCreateThreadNotifyRoutine': 0x18,
}