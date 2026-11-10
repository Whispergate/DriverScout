"""
Binary Ninja plugin - Find and decode Windows driver IOCTL codes.

Detection strategy (5-stage, from shared/dispatch.py):
  S1: HLIL MajorFunction[0xe/14] or *(arg + 0xe0) assignment pattern
  S2: Name heuristic - function name contains dispatch keywords + IOCTL codes
  S3: C++ class pattern - caller of >= 2 ioctl-named functions
  S4: Fallback - individual Ioctl-named functions directly
  S5: IOCTL-density scan - >= 3 plausible CTL_CODEs in function

Uses shared modules: dispatch.py, ioctl_shared.py, helpers.py
"""

from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.dispatch import find_dispatch_routines
from ..shared.ioctl_shared import (
    find_ioctls_in_func, ctl_decode, format_ioctl, METHOD_MAP,
)


def find_ioctls(bv: BinaryView):
    log_info("[+] Windows driver IOCTL enumeration: {}".format(bv.file.filename))

    routines = find_dispatch_routines(bv)
    if not routines:
        log_warn("[-] No dispatch routine found. Manually identify IRP_MJ_DEVICE_CONTROL handler.")
        return

    log_info("[+] Found {} dispatch routine(s)".format(len(routines)))
    total = 0

    for func in routines:
        log_info("\n[*] Dispatch routine: {} at 0x{:x}".format(func.name, func.start))
        codes = find_ioctls_in_func(func)
        if not codes:
            log_warn("    [-] No IOCTLs found in {}".format(func.name))
            continue
        for code in codes:
            total += 1
            d = ctl_decode(code)
            log_info("  [{:02d}] {}".format(total, format_ioctl(code)))
            if d['method'] == 3:
                log_info("        *** METHOD_NEITHER - no kernel buffering, raw user pointer ***")

    log_info("\n[+] Found {} valid IOCTL(s) total".format(total))


PluginCommand.register(
    "Windows Driver Analysis\\Find IOCTLs",
    "Find and decode Windows driver IOCTL codes (CTL_CODE) from dispatch routines",
    find_ioctls
)