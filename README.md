# BinjaKernelTools

Static analysis plugins for Binary Ninja targeting Linux and Windows kernel driver vulnerability research.

## Installation

Copy the `BinjaKernelTools/` directory into your Binary Ninja plugins folder:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\Binary Ninja\plugins\` |
| Linux | `~/.binaryninja/plugins/` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |

Requires Binary Ninja >= 3164 with Python 3 API.

## Plugin Reference

### Linux Driver Analysis

Commands registered under **Linux Driver Analysis\\**

---

#### Find Module Entry
**`linux/find_module_entry.py`**

Locates `init_module` / `cleanup_module` and infers driver type.

- Symbol lookup (`init_module`, `cleanup_module`)
- Section scan (`.init.text`, `.exit.text`)
- API scoring heuristic - ranks all functions by registration API calls
- Driver type inference: char device, misc, PCI, USB, network, platform, block, input

---

#### Find Character Devices
**`linux/find_char_dev.py`**

Enumerates character device registrations and recovers `file_operations` function pointer tables.

- Traces `register_chrdev`, `cdev_init`, `misc_register` arguments to `file_operations` struct
- Reads all function pointer slots at known x86_64 offsets (`+0x48` `unlocked_ioctl`, etc.)
- Renames `sub_*` functions to `fops_<field>` where resolved
- Data symbol scan for structs named `*fops*` / `*file_operations*`

---

#### Find IOCTLs
**`linux/find_ioctls.py`**

Enumerates IOCTL handlers and decodes Linux `_IOC(dir, type, nr, size)` codes.

- Multi-strategy handler detection: name pattern → data symbol → switch constant scan
- Full `_IOC` decode: direction (`_IO`/`_IOR`/`_IOW`/`_IOWR`), type byte, nr, size
- Per-IOCTL: flags `copy_from_user` without `access_ok`, missing `capable()` check

---

#### Find Netlink Interfaces
**`linux/find_netlink.py`**

Finds classic netlink and generic netlink handlers; detects attribute validation failures.

- `netlink_kernel_create` → `.input()` callback resolution
- `genl_register_family` → `genl_ops.doit` / `.dumpit` enumeration
- `nla_parse()` with NULL policy - no attribute type/length enforcement
- Missing `nlmsg_ok()` before payload access (OOB read on truncated message)
- `nla_get_*` on unchecked `tb[]` entries after failed / unchecked `nla_parse`
- Missing `CAP_NET_ADMIN` / `netlink_capable()` gate in privileged handlers

---

#### Find Procfs/Sysfs Interfaces
**`linux/find_procfs.py`**

Finds procfs, sysfs, and debugfs write/store/show handlers; detects missing bounds checks.

- `proc_create` / `proc_create_data` / `debugfs_create_file` handler resolution
- `sysfs_create_file` / `device_create_file` registration tracking
- Write handler: `copy_from_user` without count cap → stack/heap overflow
- Write handler: `kmalloc(count)` without bound → user-controlled allocation size
- `kstrtol` / `kstrtoul` return value ignored → stale value in subsequent logic
- sysfs `.store()` missing PAGE_SIZE cap on `count`
- `seq_printf` with non-literal format string → format string injection

---

#### Vulnerability Finder
**`linux/vuln_finder.py`**

Comprehensive static triage across all functions. Saves report to `~/.logs/LKDriverVulns/`.

| # | Check | Severity |
|---|---|---|
| 1 | `copy_from_user` with user-controlled size, no bounds check | HIGH |
| 2 | `__copy_from_user` without prior `access_ok()` | HIGH |
| 3 | `copy_from_user` return value ignored | MEDIUM |
| 4 | Integer overflow in `kmalloc`: `count * size` without safe arithmetic | HIGH |
| 5 | `kmalloc` result not NULL-checked before dereference | MEDIUM |
| 6 | `kmalloc` (not `kzalloc`) buffer passed to `copy_to_user` - info leak | HIGH |
| 7 | `commit_creds(prepare_kernel_cred(0))` - privilege escalation primitive | HIGH |
| 8 | Sensitive ops without `capable()` / `ns_capable()` gate | HIGH/MEDIUM |
| 9 | `remap_pfn_range` without `vm_area` size bounds check | HIGH |
| 10 | `vm_pgoff` in `remap_pfn_range` without validation - arbitrary pfn | HIGH |
| 11 | `ioremap` with user-derived size/address | HIGH |
| 12 | `kfree` followed by potential use of freed pointer | MEDIUM |
| 13 | `printk %p` (not `%pK`) - kernel address leak to dmesg | MEDIUM |
| 14 | `copy_to_user(&struct, sizeof)` - padding/pointer field leak | LOW |
| 15 | Dangerous functions: `sprintf`, `strcpy`, `strcat`, `vsprintf` | HIGH/MEDIUM |
| 16 | `GFP_KERNEL` inside `spin_lock_irqsave` context - must use `GFP_ATOMIC` | HIGH |
| 17 | Double-fetch TOCTOU: same user pointer fetched 2+ times without lock | HIGH |
| 18 | Signedness confusion: `(int)user_len` or signed `< 0` check before copy/alloc | MEDIUM |
| 19 | `kref_put` / `kobject_put` followed by object use - refcount UAF | HIGH/LOW |

---

### Windows Driver Analysis

Commands registered under **Windows Driver Analysis\\**

---

#### Find Device Names
**`windows/win_find_device_name.py`**

Scans for Windows device name strings.

- Binary string scan: `\Device\`, `\DosDevices\`, `\\.\`, `\??\`
- HLIL scan in callers of `IoCreateSymbolicLink`, `RtlInitUnicodeString`, `IoCreateDevice`

---

#### Find IOCTLs
**`windows/win_find_ioctls.py`**

Enumerates `IRP_MJ_DEVICE_CONTROL` dispatch routines and decodes `CTL_CODE`.

- 4-strategy dispatch detection: HLIL `MajorFunction[0xe]` assignment → name heuristic → C++ class pattern → fallback
- Full `CTL_CODE` decode: `DeviceType`, `Access`, `Function`, `Method`
- `METHOD_NEITHER` flagged explicitly - raw user pointer, no kernel buffering

---

#### Find IRP Handlers
**`windows/find_irp_handlers.py`**

Enumerates all 28 `IRP_MJ_*` dispatch slots and performs deep `METHOD_NEITHER` analysis.

- Scans HLIL for `*(drv_obj + 0xNN) = &handler` at all `MajorFunction[]` offsets
- Risk-ranked output per IRP type with security notes
- `IRP_MJ_READ` / `IRP_MJ_WRITE`: flags `UserBuffer` access without `ProbeForRead/Write`
- **METHOD_NEITHER deep analysis:**
  - Missing `ProbeForRead` / `ProbeForWrite` on `Type3InputBuffer`
  - Missing `__try` / `__except` - invalid pointer causes BSOD
  - `OutputBufferLength` not validated before write-back - kernel overflow
  - `memcpy` / `RtlCopyMemory` from `Type3InputBuffer` without probe

---

#### Vulnerability Finder
**`windows/win_vuln_finder.py`**

Full static triage for Windows kernel drivers. Saves report to `~/.logs/WinDriverVulns/`.

- DriverEntry detection (exact + heuristic scoring)
- Device name discovery
- Pool tag extraction via MLIL argument analysis
- Dangerous opcodes: `rdmsr`, `wrmsr`, `rdpmc`
- Dangerous C functions: `sprintf`, `strcpy`, `memcpy`, `RtlCopyMemory`
- Windows kernel API inventory: `Mm*`, `Zw*`, `Io*`, `Flt*`, `Se*`, `ProbeFor*`
- IOCTL enumeration (dispatch heuristic)
- Physical memory / IO space: `MmMapIoSpace`, `MmCopyMemory`, `ZwOpenSection`, MDL mapping
- Port/register IO from IOCTL context: `READ_PORT_*`, `WRITE_PORT_*`
- User copy without `ProbeForRead/Write`: `memcpy` / `RtlCopyMemory` near user buffers
- Integer overflow in `ExAllocatePool` sizing from user input without `RtlULong*`
- Missing `SeSinglePrivilegeCheck` / `SeAccessCheck` before sensitive operations
- Driver type detection: Standard WDM vs Mini-Filter
- Recursive call-graph classification (depth 3, ~12 callees/level) - catches HEVD-style `Handler -> Trigger -> Primitive` wrapper chains; each finding tagged `(via <fn>)`
- Name-hint fallback across call chain. Function names like `TriggerStackOverflow`, `ArbitraryWrite`, `ReadMsr`, `WriteCR4`, `MapPhysicalMemory`, `StealToken`, `DisableEtw`, `RemoveCallback`, `LoadDriver`, `OpenSection` flagged even when HLIL pattern misses

---

#### Exploit Primitive Finder
**`windows/win_primitives.py`**

| Primitive | Severity |
|---|---|
| Write-What-Where (user-controlled dst + value) | CRITICAL |
| Arbitrary Kernel Read (`memcpy(out, *user_ptr, len)`) | CRITICAL |
| Token-Swap Primitive (`PsLookupProcessByProcessId` + Token offset 0x4b8/0x358) | CRITICAL |
| Stack Buffer Overflow (user-len `memcpy` to `var_*`) | HIGH |
| Pool Buffer Overflow (`ExAllocatePool` + user-len copy) | HIGH |
| Type Confusion (`ObReferenceObjectByHandle` ObjectType=NULL) | HIGH |
| Double-Fetch TOCTOU (same user ptr deref 2+ times no Probe) | HIGH |
| Uninitialized Pool Leak (non-zero alloc -> user, no `RtlZeroMemory`) | MEDIUM |
| NULL Pointer Deref (unchecked alloc result) | MEDIUM |
| IORING reference (`IoRingCreate`, `NtSubmitIoRing`, ...) | HIGH |
| METHOD_NEITHER dispatcher with no `ProbeForRead/Write` | CRITICAL |
| MSR Read/Write Primitive (`__rdmsr` / `__wrmsr` reachable from IOCTL) | CRITICAL |
| Port IO Primitive (`READ_PORT_*` / `WRITE_PORT_*`, `__in_*` / `__out_*`) | CRITICAL |
| Physical Memory Map (`MmMapIoSpace[Ex]`, `MmCopyMemory`, `\Device\PhysicalMemory`) | CRITICAL |
| Control/Debug Register Access (`__readcr*` / `__writecr*` / `__readdr*` / `__writedr*`) | CRITICAL |
| Ring-0 Exec / Capcom-style (`(*(fn*)SystemBuffer)()` user-pointer call in kernel) | CRITICAL |
| PCI Config Space Access (`HalGetBusData` / `HalSetBusData`) | HIGH |
| Virtual Memory R/W (`ZwReadVirtualMemory`, `MmCopyVirtualMemory`, ...) | CRITICAL |
| MDL Kernel-to-User Map (`IoAllocateMdl` + `MmMapLockedPages`) | CRITICAL |
| Handle Duplication (`ZwDuplicateObject`, `ObDuplicateObject`) | HIGH |
| Section-Based Physical Memory (`ZwOpenSection` + `ZwMapViewOfSection`) | CRITICAL |
| Callback Removal / EDR Blinding (`PsSetCreateProcessNotifyRoutine`, `ObUnRegisterCallbacks`) | HIGH |
| Process/Thread Manipulation (`ZwTerminateProcess`, `NtSetContextThread`) | HIGH |
| DSE/CI Bypass (`g_CiOptions`, `CiValidateImageHeader`) | CRITICAL |
| ETW Tampering (`EtwEventWrite`, `NtTraceControl`) | HIGH |

23 runtime detectors + name-hint pass (depth 3, dedup, skips `sub_*` / `nullsub_*` / `j_*`) against ~80 BYOVD primitive patterns. Each hit emitted with severity + `:: <fn name>` for triage.

---

#### HEVD Vulnerability Classifier
**`windows/win_hevd_classes.py`**

Classifies each IOCTL handler against the HackSysExtremeVulnerableDriver bug-class taxonomy: StackOverflow, StackOverflowGS, PoolOverflow, UseAfterFree, DoubleFree, TypeConfusion, ArbitraryOverwrite, InsecureKernelResourceAccess, NullPointerDereference, UninitializedStack/Heap, IntegerOverflow, DoubleFetch, MemoryDisclosure, RaceCondition, GdiBitmapPolymorphism.

Extended privileged-primitive classes (BYOVD coverage): **MSRReadWrite**, **PortIO**, **PhysicalMemoryMap**, **ControlRegisterAccess**, **Ring0Exec**, plus name-hint classes **TokenManipulation**, **ProcessTampering**, **CallbackTampering**, **EtwTampering**, **SsdtTampering**, **DriverLoadPrimitive**, **PciConfigAccess**.

- 23 HLIL pattern detectors + recursive callee walk (depth 3, ~16/level)
- Name-hint pass against ~80 substrings - matches handler names like `TriggerArbitraryWrite`, `MsrWrite64`, `WriteCr4`, `MapPhysicalAddress`, `EnableShellcodeExec`, `UnregisterCallback`, `DisableThreatIntel`

Useful for CTFs, training, and triaging unknown drivers against known exploit classes (ref: p.ost2.fyi).

---

#### LOLDrivers Check
**`windows/win_loldrivers.py`**

Cross-references binary against [loldrivers.io](https://www.loldrivers.io/) dataset:

- SHA256 file-hash lookup against live API (cached 7d at `~/.cache/loldrivers/drivers.json`)
- Original-filename / on-disk filename match
- IOCTL-overlap match against embedded curated DB (~37 high-impact entries: RTCore64, gdrv, AsrDrv, dbutil_2_3, Capcom, mhyprot2, WinRing0, iqvw64, Dell PCDoctor, nvoclock, atillk64, elrawdsk, winio64, dbk64, ene, inpoutx64, hwrwdrv, ...)
- Device-name lexical match to known vulnerable drivers
- Fallback to embedded mini-DB if network + cache unavailable

---

#### WDF Deep Analysis
**`windows/win_wdf_analysis.py`**

Full WDF/KMDF callback resolution beyond basic `WdfVersionBind` detection.

- Resolves `WDF_IO_QUEUE_CONFIG` callback table: `EvtIoDefault`, `EvtIoRead`, `EvtIoWrite`, `EvtIoDeviceControl`, `EvtIoInternalDeviceControl`, `EvtIoStop`, `EvtIoCanceledOnQueue`
- Dispatch type detection: Sequential (serialized), Parallel (race-prone), Manual
- Traces buffer access through WDF wrapper APIs: `WdfRequestRetrieveInputBuffer`, `WdfRequestRetrieveOutputBuffer`, `WdfRequestRetrieveInputMemory`, `WdfRequestRetrieveOutputMemory`, `WdfRequestRetrieveUnsafeUserInputBuffer`
- Flags missing size validation on `WdfRequestRetrieveInputBuffer` calls
- Parallel queue + shared state = race condition warning

---

#### DACL Analysis
**`windows/win_dacl_analysis.py`**

Parses device object security descriptors and SDDL strings to assess access control.

- `IoCreateDeviceSecure` SDDL extraction and decode
- Flags overly permissive DACLs: `D:(A;;GA;;;WD)` (Everyone), `D:(A;;GA;;;BU)` (Users), null DACL
- `IoCreateDevice` without `IoCreateDeviceSecure` flagged
- Manual ACL setup detection: `ObSetSecurityDescriptorInfo`, `RtlCreateSecurityDescriptor`
- Cross-references DACL permissiveness against detected primitives for risk scoring

---

#### FastIO Dispatch Analysis
**`windows/win_fastio.py`**

Enumerates `FAST_IO_DISPATCH` handlers - the parallel dispatch path to IRP.

- Detects `DriverObject->FastIoDispatch` assignment
- Resolves function pointers: `FastIoCheckIfPossible`, `FastIoRead`, `FastIoWrite`, `FastIoDeviceControl`, `MdlRead`, `MdlWrite`
- Applies vulnerability analysis to FastIO handlers (same checks as IRP handlers)
- Flags FastIO handlers with weaker validation than their IRP counterparts

---

#### IRP Completion Audit
**`windows/win_irp_audit.py`**

Audits IRP lifecycle for completion bugs.

- Missing `IoCompleteRequest` on error paths
- Double completion: `IoCompleteRequest` on already-completed or forwarded IRP (UAF)
- `IoStatus.Information` larger than `OutputBufferLength` (kernel info leak)
- `STATUS_SUCCESS` without setting `IoStatus.Information`
- `IoCallDriver`/`IofCallDriver` then completing same IRP

---

#### Signing & Certificate Analysis
**`windows/win_signing.py`**

Analyzes Authenticode signatures for BYOVD viability assessment.

- Signer name, certificate chain, and timestamp extraction
- Cross-signed vs. WHQL-signed detection
- SHA-1 vs SHA-256 hash algorithm identification
- EV certificate presence
- Microsoft Vulnerable Driver Blocklist (DriverSiPolicy.p7b) cross-reference
- Revocation status and timestamp-based bypass detection
- Known-abused signer cross-reference against LOLDrivers database

---

#### Version-Aware Analysis
**`windows/win_version.py`**

Detects target Windows version from PE metadata and adjusts analysis.

- `IMAGE_OPTIONAL_HEADER` OS version + linker version detection
- Version-conditional code path identification
- Flags deprecated/removed APIs for specific Windows versions
- Mitigation awareness: VBS, HVCI, KDP, KVAS/KVA Shadow impact on exploit viability
- EPROCESS offset table adjustment for POC generation per detected build

---

#### Pool Spray Feasibility
**`windows/win_pool_spray.py`**

Analyzes pool allocation characteristics for overflow/UAF exploitation.

- Pool type classification: `NonPagedPool`, `PagedPool`, `NonPagedPoolNx`, `ExAllocatePool2` (segment heap)
- Allocation size and pool tag extraction
- Known-exploitable size flagging (0x40, 0x60, 0x200 on segment heap vs. pre-segment-heap)
- Spray technique recommendation per pool type + size combination
- Maps allocations against known Windows pool object sizes for adjacency targeting

---

#### Minifilter Callback Analysis
**`windows/win_minifilter.py`**

Parses `FLT_REGISTRATION` and `FLT_OPERATION_REGISTRATION` structures for minifilter drivers.

- `FltRegisterFilter` detection and registration structure resolution
- Pre/post callback enumeration per `IRP_MJ_*` code
- Buffer validation analysis on `PFLT_CALLBACK_DATA` handlers
- IRQL awareness and reentrancy safety checks
- `FltObjects` parameter usage tracking

---

#### Exploit Chain Detection
**`windows/win_chain.py`**

Identifies viable exploit chains from combined driver capabilities.

- Capability graph model: `INFO_LEAK`, `ARB_READ`, `ARB_WRITE`, `PHYS_MAP`, `CODE_EXEC`, `MSR_RW`, `PORT_IO`, `CR_ACCESS`, `TOKEN_SWAP`, `POOL_CORRUPT`, `VMEM_RW`, `HANDLE_DUP`, `CALLBACK_RM`, `DSE_BYPASS`, `ETW_TAMPER`, `MDL_MAP`
- 20 chain definitions: Read+Write → LPE, MSR → LSTAR hijack, PhysMem → PTE manipulation, Port IO → PCI config, VMemRW → token overwrite (HVCI-safe), MDL map → kernel access, Handle dup → privilege escalation, Callback+Write → EDR blind + LPE, DSE bypass → unsigned driver load, ETW+Callback → full EDR/ETW blind
- Sequences primitives in correct exploitation order
- HVCI-aware: steers toward data-only attacks when code exec is blocked

---

#### Generate Report (JSON + SARIF)
**`windows/win_report.py`**

Exports all findings as structured output. Saves to `~/.logs/WinDriverReports/`.

- JSON output: findings, primitives, IOCTL map, IRP handlers, device names, LOLDrivers matches
- SARIF 2.1.0 output: CWE mapping, severity, evidence (HLIL snippets), affected addresses
- Per-finding: confidence level, primitive type, IOCTL code, remediation guidance
- Differential analysis support: compare two runs for new/fixed/changed findings

---

#### Generate POC (C + Python + Rust + C# + Exploit Templates)
**`windows/win_poc_gen.py`**

Multi-language POC scaffolding with exploit templates. Saves to `~/.logs/WinDriverPOCs/`.

**Output files** (up to 12 per driver):

| File | Contents |
|---|---|
| `<driver>-poc.c` | C POC with per-IOCTL stubs, METHOD-aware buffering, primitive-tagged payloads |
| `<driver>-poc.py` | Python `ctypes` harness with structured fuzzer and probe-all |
| `<driver>-poc.rs` | Rust POC using `windows-sys` crate |
| `<driver>-poc.cs` | C# P/Invoke POC for execute-assembly (Cobalt Strike, Sliver, Havoc) |
| `<driver>-structs.h` | Auto-inferred IOCTL input buffer structures from HLIL dereference patterns |
| `<driver>-exploit.c` | Per-primitive exploit templates (LSTAR hijack, PCI config, token overwrite, etc.) |
| `<driver>-trampoline.asm` | MASM x64 syscall trampoline: `DoKernelWrite8`/`DoKernelRead8` via LSTAR ROP chain + iretq return |
| `<driver>-shellcode.h` | PIC kernel shellcode: token steal, privilege enable, PPL bypass, ETW blind, DSE disable |
| `<driver>-eprocess-finder.c` | EPROCESS/token locator with hardcoded offset table |
| `<driver>-eprocess-finder-v2.c` | v2 finder: HVCI detection, `EnumDeviceDrivers` fallback, Win11 24H2 offsets |
| `<driver>-probe-safe.c` | Crash-safe IOCTL probing via child-process isolation |
| `<driver>-chain.c` | Exploit chain orchestrator when viable multi-primitive chain detected |

**Driver-agnostic MSR elevation architecture** (emitted when MSR R/W primitives detected):
- Bottom layer: `ReadMSR()`/`WriteMSR()` - thin IOCTL wrappers (only driver-specific code)
- Middle layer: `InitWritePrimitive()`/`InitReadPrimitive()` - scans ntoskrnl .text for ROP gadgets (`pop rcx;ret`, `pop rax;ret`, `pop rdx;ret`, `wrmsr;ret`, `iretq`, `mov [rdx],rax;ret`, `mov rax,[rdx];ret`)
- Top layer: `WriteKernel8()`/`ReadKernel8()` - calls MASM trampoline procs that hijack LSTAR, execute ROP chain in ring-0, return via iretq
- FMASK clearing (MSR 0xC0000084) for SMAP bypass, thread affinity pinning + REALTIME priority for race window minimization
- Build: `ml64 /c /Fo trampoline.obj <driver>-trampoline.asm` then `cl poc.c trampoline.obj`

**Primitive classification** uses HLIL intrinsic matching (`__rdmsr`, `__wrmsr`, `__in_*`, `__out_*`, `MmMapIoSpace`, `HalGetBusDataByOffset`, etc.), depth-3 callee walk, and ~80 name-hint patterns. Covers ~30 primitive types: write-what-where, arb-read, arb-increment, MSR R/W, port IO, phys-mem, PCI config, CR/DR access, ring-0 exec, token swap, process kill/protect, callback removal, ETW/SSDT tamper, driver load, section map, IORING chain.

**CLI verbs** (C POC):
- `poc.exe` - `probe_all`: send zero buffer to every IOCTL, report success/winerr
- `poc.exe list` - print IOCTL index with tags
- `poc.exe <index>` - trigger single IOCTL
- `poc.exe fuzz [iters]` - structured fuzzer
- `poc.exe shell` / `cmd` - spawn `cmd.exe` post-exploit

---

### Shared Utilities

#### Taint Tracker
**`shared/taint.py`**

Lightweight HLIL SSA-based taint propagation for kernel driver analysis.

- Marks IOCTL input sources as tainted: `SystemBuffer`, `Type3InputBuffer`, `UserBuffer`, `InputBufferLength`
- Propagates through assignments, casts, arithmetic, function call arguments
- Flags dangerous sinks reached by tainted values without validation: `memcpy` dst/size, `MmMapIoSpace` addr/size, `__wrmsr` index/value, pointer write destinations, `ExAllocatePool` size, `ZwReadVirtualMemory`, `ZwWriteVirtualMemory`, `MmCopyVirtualMemory`, `ZwDuplicateObject`, `IoAllocateMdl`, `ZwTerminateProcess`, `PsSetCreateProcessNotifyRoutine`
- Used internally by vulnerability finders for improved accuracy over text-proximity checks

---

## License

BSD 2-Clause - Copyright (c) 2026, Whispergate
