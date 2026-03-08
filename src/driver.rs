//! Driver lifecycle management — load/unload via Service Control Manager
//! All SCM API calls resolved dynamically at runtime via PEB walk + DJB2 hash.

use crate::resolver::*;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::*;

// Type aliases for dynamically resolved SCM functions
type FnOpenSCManagerW = unsafe extern "system" fn(*const u16, *const u16, u32) -> HANDLE;
type FnCreateServiceW = unsafe extern "system" fn(
    HANDLE,
    *const u16,
    *const u16,
    u32,
    u32,
    u32,
    u32,
    *const u16,
    *const u16,
    *mut u32,
    *const u16,
    *const u16,
    *const u16,
) -> HANDLE;
type FnStartServiceW = unsafe extern "system" fn(HANDLE, u32, *const *const u16) -> BOOL;
type FnOpenServiceW = unsafe extern "system" fn(HANDLE, *const u16, u32) -> HANDLE;
type FnControlService = unsafe extern "system" fn(HANDLE, u32, *mut [u8; 36]) -> BOOL;
type FnDeleteService = unsafe extern "system" fn(HANDLE) -> BOOL;
type FnCloseServiceHandle = unsafe extern "system" fn(HANDLE) -> BOOL;

const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
const SERVICE_KERNEL_DRIVER: u32 = 0x00000001;
const SERVICE_DEMAND_START: u32 = 0x00000003;
const SERVICE_ERROR_IGNORE: u32 = 0x00000000;
const SERVICE_CONTROL_STOP: u32 = 0x00000001;

/// RAII guard — auto-unloads driver on drop
pub struct DriverGuard {
    service_name: Vec<u16>,
    advapi32_base: *mut u8,
}

impl Drop for DriverGuard {
    fn drop(&mut self) {
        let _ = unload_driver_inner(self.advapi32_base, &self.service_name);
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Load a kernel driver as a Windows service using dynamically resolved APIs
pub fn load_driver(
    api: &ApiResolver,
    service_name: &str,
    driver_path: &str,
) -> Result<DriverGuard, String> {
    let name_wide = to_wide(service_name);
    let path_wide = to_wide(driver_path);

    // Resolve SCM APIs dynamically from advapi32
    let open_sc_mgr: FnOpenSCManagerW = unsafe {
        std::mem::transmute(
            api.advapi32(HASH_OPEN_SC_MANAGER_W)
                .ok_or("Failed to resolve OpenSCManagerW")?,
        )
    };
    let create_svc: FnCreateServiceW = unsafe {
        std::mem::transmute(
            api.advapi32(HASH_CREATE_SERVICE_W)
                .ok_or("Failed to resolve CreateServiceW")?,
        )
    };
    let start_svc: FnStartServiceW = unsafe {
        std::mem::transmute(
            api.advapi32(HASH_START_SERVICE_W)
                .ok_or("Failed to resolve StartServiceW")?,
        )
    };
    let open_svc: FnOpenServiceW = unsafe {
        std::mem::transmute(
            api.advapi32(HASH_OPEN_SERVICE_W)
                .ok_or("Failed to resolve OpenServiceW")?,
        )
    };
    let close_svc: FnCloseServiceHandle = unsafe {
        std::mem::transmute(
            api.advapi32(HASH_CLOSE_SERVICE_HANDLE)
                .ok_or("Failed to resolve CloseServiceHandle")?,
        )
    };

    unsafe {
        let sc_manager = open_sc_mgr(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if sc_manager.is_invalid() {
            return Err(format!("OpenSCManagerW failed: {}", GetLastError().0));
        }

        // Try to create the service
        let service = create_svc(
            sc_manager,
            name_wide.as_ptr(),
            name_wide.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            path_wide.as_ptr(),
            std::ptr::null(),     // no group
            std::ptr::null_mut(), // no tag
            std::ptr::null(),     // no deps
            std::ptr::null(),     // LocalSystem
            std::ptr::null(),     // no password
        );

        let service = if service.is_invalid() {
            // Service might exist — try to open it
            let existing = open_svc(sc_manager, name_wide.as_ptr(), SERVICE_ALL_ACCESS);
            if existing.is_invalid() {
                close_svc(sc_manager);
                return Err(format!(
                    "CreateServiceW/OpenServiceW failed: {}",
                    GetLastError().0
                ));
            }
            existing
        } else {
            service
        };

        // Start the service
        let started = start_svc(service, 0, std::ptr::null());
        if !started.as_bool() {
            let err = GetLastError();
            // 1056 = ERROR_SERVICE_ALREADY_RUNNING (driver loaded this session)
            // 1058 = ERROR_SERVICE_DISABLED (leftover service from --no-unload run)
            if err.0 != 1056 && err.0 != 1058 {
                let del_svc: FnDeleteService =
                    std::mem::transmute(api.advapi32(HASH_DELETE_SERVICE).unwrap());
                del_svc(service);
                close_svc(service);
                close_svc(sc_manager);
                return Err(format!("StartServiceW failed: {}", err.0));
            }
        }

        close_svc(service);
        close_svc(sc_manager);
    }

    Ok(DriverGuard {
        service_name: name_wide,
        advapi32_base: api.advapi32_base,
    })
}

/// Internal unload
fn unload_driver_inner(advapi32_base: *mut u8, name_wide: &[u16]) -> Result<(), String> {
    unsafe {
        let open_sc_mgr: FnOpenSCManagerW = std::mem::transmute(
            get_export_by_hash_pub(advapi32_base, HASH_OPEN_SC_MANAGER_W).ok_or("resolve")?,
        );
        let open_svc: FnOpenServiceW = std::mem::transmute(
            get_export_by_hash_pub(advapi32_base, HASH_OPEN_SERVICE_W).ok_or("resolve")?,
        );
        let ctrl_svc: FnControlService = std::mem::transmute(
            get_export_by_hash_pub(advapi32_base, HASH_CONTROL_SERVICE).ok_or("resolve")?,
        );
        let del_svc: FnDeleteService = std::mem::transmute(
            get_export_by_hash_pub(advapi32_base, HASH_DELETE_SERVICE).ok_or("resolve")?,
        );
        let close_svc: FnCloseServiceHandle = std::mem::transmute(
            get_export_by_hash_pub(advapi32_base, HASH_CLOSE_SERVICE_HANDLE).ok_or("resolve")?,
        );

        let sc_manager = open_sc_mgr(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if sc_manager.is_invalid() {
            return Ok(());
        }

        let service = open_svc(sc_manager, name_wide.as_ptr(), SERVICE_ALL_ACCESS);
        if !service.is_invalid() {
            let mut status = [0u8; 36]; // SERVICE_STATUS
            ctrl_svc(service, SERVICE_CONTROL_STOP, &mut status);
            del_svc(service);
            close_svc(service);
        }
        close_svc(sc_manager);
    }
    Ok(())
}

/// Public wrapper for export resolution (used by DriverGuard::drop)
fn get_export_by_hash_pub(base: *mut u8, hash: u32) -> Option<*mut std::ffi::c_void> {
    let resolver = ApiResolver {
        kernel32_base: std::ptr::null_mut(),
        ntdll_base: std::ptr::null_mut(),
        advapi32_base: base,
    };
    resolver.resolve(base, hash)
}
