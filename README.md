# BinjaKernelTools

Static analysis plugins for Binary Ninja targeting Linux and Windows kernel driver vulnerability research.

## Installation

Copy the `BinjaKernelTools/` directory into your Binary Ninja plugins folder:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\Binary Ninja\plugins\` |
| Linux | `~/.binaryninja/plugins/` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |

Requires Binary Ninja >= 6.0 (Krypton) with Python 3 API.

A standalone CLI (`analyze_pe.py`) provides basic driver analysis via pefile + capstone when Binary Ninja is unavailable.

## Plugin Reference

### Linux Driver Analysis

Commands registered under **Linux Driver Analysis\\**

#### Find Module Entry (`linux/find_module_entry.py`)

Locates `init_module` / `cleanup_module` and infers driver type (char device, misc, PCI, USB, network, platform, block, input). Uses symbol lookup, `.init.text`/`.exit.text` section scan, and API scoring heuristic.

#### Find Character Devices (`linux/find_char_dev.py`)

Enumerates character device registrations and recovers `file_operations` function pointer tables. Traces `register_chrdev`, `cdev_init`, `misc_register` arguments. Renames `sub_*` functions to `fops_<field>` where resolved.

#### Find IOCTLs (`linux/find_ioctls.py`)

Multi-strategy IOCTL handler detection with full `_IOC(dir, type, nr, size)` decode. Flags `copy_from_user` without `access_ok` and missing `capable()` checks.

#### Find Netlink Interfaces (`linux/find_netlink.py`)

Finds classic and generic netlink handlers. Detects `nla_parse()` with NULL policy, missing `nlmsg_ok()`, unchecked `nla_get_*`, and missing `CAP_NET_ADMIN` gates.

#### Find Procfs/Sysfs Interfaces (`linux/find_procfs.py`)

Finds procfs, sysfs, and debugfs write handlers. Detects `copy_from_user` without count cap, `kmalloc(count)` without bound, ignored `kstrtol` return values, missing PAGE_SIZE cap, and `seq_printf` format string injection.

#### Vulnerability Finder (`linux/vuln_finder.py`)

19-check static triage across all functions. Saves report to `~/.logs/LKDriverVulns/`. Covers `copy_from_user` misuse, integer overflows in `kmalloc`, missing capability checks, `remap_pfn_range` flaws, UAF patterns, GFP_KERNEL in IRQ context, double-fetch TOCTOU, signedness confusion, and kernel pointer leaks.

---

### Windows Driver Analysis

Commands registered under **Windows Driver Analysis\\**

#### Find Device Names (`windows/win_find_device_name.py`)

Scans for `\Device\`, `\DosDevices\`, `\\.\`, `\??\` strings and HLIL references in callers of `IoCreateSymbolicLink`, `RtlInitUnicodeString`, `IoCreateDevice`.

#### Find IOCTLs (`windows/win_find_ioctls.py`)

Enumerates `IRP_MJ_DEVICE_CONTROL` dispatch routines and decodes `CTL_CODE`. 7-strategy dispatch detection:

| Strategy | Method |
|---|---|
| S1 | HLIL `MajorFunction[0xe]` assignment, `*(arg + 0xe0)`, `IoSetCompletionRoutine`, arrow-style typed access |
| S2 | Name heuristic (dispatch keywords + IOCTL codes present) |
| S3 | C++ class pattern (caller of 2+ ioctl-named functions) |
| S4 | Fallback to individual ioctl-named functions |
| S5 | IOCTL-density scan (3+ plausible CTL_CODEs in function) |
| S6 | WDF/KMDF callback resolution (`WdfIoQueueCreate` `EvtIoDeviceControl`) |
| S7 | Sub-dispatch detection (functions calling 2+ sub-dispatchers with 3+ IOCTLs each) |

#### Find IRP Handlers (`windows/find_irp_handlers.py`)

Enumerates all 28 `IRP_MJ_*` dispatch slots. Deep `METHOD_NEITHER` analysis: missing `ProbeForRead`/`ProbeForWrite`, missing SEH, unvalidated `OutputBufferLength`, unprobed `Type3InputBuffer` copies.

#### Vulnerability Finder (`windows/win_vuln_finder.py`)

Full static triage. DriverEntry detection, device names, pool tags, dangerous opcodes/functions, kernel API inventory, IOCTL enumeration, physical memory/IO patterns, user copy without probe, integer overflow in pool sizing, missing privilege gates. Recursive call-graph classification (depth 3) catches HEVD-style wrapper chains. Name-hint fallback across call chain. Report saved to `~/.logs/WinDriverVulns/`.

#### Exploit Primitive Finder (`windows/win_primitives.py`)

23 runtime detectors + name-hint pass (depth 3, ~80 patterns) against BYOVD primitive patterns:

**CRITICAL**: Write-What-Where, Arbitrary Read, MSR R/W, Port IO, Physical Memory Map, CR/DR Access, Ring-0 Exec, Token-Swap, Virtual Memory R/W, MDL Map, Section-Based Phys, DSE/CI Bypass

**HIGH**: PCI Config, Stack/Pool BOF, Type Confusion, Double-Fetch, IORING, Handle Dup, Callback Removal, Process/Thread Manipulation, ETW Tampering

**MEDIUM**: NULL Deref, Uninitialized Pool Leak

#### HEVD Vulnerability Classifier (`windows/win_hevd_classes.py`)

Classifies IOCTL handlers against the HEVD bug-class taxonomy plus extended BYOVD classes (MSRReadWrite, PortIO, PhysicalMemoryMap, ControlRegisterAccess, Ring0Exec, TokenManipulation, ProcessTampering, CallbackTampering, EtwTampering, SsdtTampering, DriverLoadPrimitive, PciConfigAccess).

#### LOLDrivers Check (`windows/win_loldrivers.py`)

Cross-references binary against [loldrivers.io](https://www.loldrivers.io/): SHA256 hash lookup, filename match, IOCTL overlap against ~37 curated entries, device-name match. Falls back to embedded mini-DB offline.

#### WDF Deep Analysis (`windows/win_wdf_analysis.py`)

WDF/KMDF callback resolution. `WDF_IO_QUEUE_CONFIG` callback table, dispatch type detection (Sequential/Parallel/Manual), WDF buffer access API tracing, missing size validation, parallel queue race warnings.

#### DACL Analysis (`windows/win_dacl_analysis.py`)

SDDL decode from `IoCreateDeviceSecure`. Flags `D:(A;;GA;;;WD)` (Everyone), `D:(A;;GA;;;BU)` (Users), null DACL. Cross-references permissiveness against detected primitives.

#### FastIO Dispatch Analysis (`windows/win_fastio.py`)

Enumerates `FAST_IO_DISPATCH` handlers. Same vulnerability checks as IRP handlers. Flags FastIO handlers with weaker validation than their IRP counterparts.

#### IRP Completion Audit (`windows/win_irp_audit.py`)

Missing `IoCompleteRequest` on error paths, double completion (UAF), `IoStatus.Information` larger than `OutputBufferLength` (info leak), `IoCallDriver` then completing same IRP.

#### Signing & Certificate Analysis (`windows/win_signing.py`)

Authenticode analysis for BYOVD viability. Signer chain, cross-signed vs WHQL, hash algorithm, EV presence, blocklist cross-reference, revocation status, known-abused signer match.

#### Version-Aware Analysis (`windows/win_version.py`)

PE metadata version detection. Flags deprecated APIs per Windows version. Mitigation awareness (VBS, HVCI, KDP, KVAS). EPROCESS offset adjustment for POC generation.

#### Pool Spray Feasibility (`windows/win_pool_spray.py`)

Pool type classification, allocation size/tag extraction, known-exploitable size flagging, spray technique recommendation, adjacency targeting against known kernel object sizes.

#### Minifilter Callback Analysis (`windows/win_minifilter.py`)

`FLT_REGISTRATION` / `FLT_OPERATION_REGISTRATION` parsing. Pre/post callback enumeration, buffer validation, IRQL awareness, reentrancy checks.

#### Exploit Chain Detection (`windows/win_chain.py`)

20 chain definitions across 16 capability types. Sequences primitives in exploitation order. HVCI-aware (steers toward data-only attacks when code exec is blocked).

#### Generate Report (`windows/win_report.py`)

JSON + SARIF 2.1.0 output with CWE mapping, severity, HLIL evidence, differential analysis. Saved to `~/.logs/WinDriverReports/`.

#### Generate POC (`windows/win_poc_gen.py`)

Up to 12 output files per driver: C, Python, Rust, C# POCs, inferred buffer structs, per-primitive exploit templates, MASM x64 LSTAR trampoline, PIC kernel shellcode (token steal, privilege enable, PPL bypass), EPROCESS finder (35+ Windows builds), crash-safe probe, chain orchestrator.

MSR elevation architecture: thin IOCTL wrappers, ntoskrnl gadget scanner, `WriteKernel8`/`ReadKernel8` via LSTAR hijack + iretq return. Build with `ml64` + `cl`.

CLI: `poc.exe` (probe all), `poc.exe list`, `poc.exe <index>`, `poc.exe fuzz [n]`, `poc.exe shell`.

---

### Shared Modules

| Module | Purpose |
|---|---|
| `shared/dispatch.py` | 7-strategy dispatcher detection (WDM, WDF, sub-dispatch) |
| `shared/ioctl_shared.py` | CTL_CODE decode, HLIL AST switch case extraction, branch resolution |
| `shared/taint.py` | HLIL SSA-based taint propagation (sources, sinks, sanitizers) |
| `shared/eprocess_offsets.py` | EPROCESS offset table (35+ builds, Win10 1507 to Win11 24H2, Server 2016-2025) |
| `shared/primitive_db.py` | ~80 name-hint patterns, vuln API labels, callee walk helpers |
| `shared/helpers.py` | HLIL/MLIL text caching, xref helpers, MLIL param extraction |

---

## License

BSD 2-Clause - Copyright (c) 2026, Whispergate
