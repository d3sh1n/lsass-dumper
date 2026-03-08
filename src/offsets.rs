//! Windows-version-dependent EPROCESS offsets
//!
//! EPROCESS is an opaque kernel structure whose field offsets change between Windows builds.
//! Offsets sourced from the Vergilius Project: https://www.vergiliusproject.com/kernels/x64/

/// EPROCESS field offsets for a specific Windows build
#[derive(Debug, Clone)]
pub struct EprocessOffsets {
    pub build_number: u32,
    pub active_process_links: u64,
    pub unique_process_id: u64,
    pub image_file_name: u64,
    pub protection: u64,
    pub token: u64,
}

/// Detect current Windows version and return matching EPROCESS offsets
pub fn detect_offsets() -> Option<EprocessOffsets> {
    let build = get_build_number()?;
    get_offsets_for_build(build)
}

/// Get Windows build number by reading KUSER_SHARED_DATA
fn get_build_number() -> Option<u32> {
    // KUSER_SHARED_DATA is a kernel structure mapped into every user-mode process at 0x7FFE0000.
    // NtBuildNumber is a ULONG at offset 0x0260.
    // Reading it directly avoids API call overhead and circumvents the application manifest shim
    // which causes GetVersionExW to return Windows 8 (Build 9200) for non-manifested Rust binaries.
    let build_number = unsafe { std::ptr::read_volatile(0x7FFE0260 as *const u32) };
    if build_number > 0 {
        Some(build_number)
    } else {
        None
    }
}

/// Map Windows build numbers to EPROCESS offsets
fn get_offsets_for_build(build: u32) -> Option<EprocessOffsets> {
    // Offsets from Vergilius Project (x64)
    // https://www.vergiliusproject.com/kernels/x64/
    //
    // Fields we need:
    //   ActiveProcessLinks: LIST_ENTRY — doubly-linked list connecting all EPROCESS
    //   UniqueProcessId: HANDLE — PID
    //   ImageFileName: UCHAR[15] — process name
    //   Protection: _PS_PROTECTION — 1 byte, Type(3bits) | Audit(1bit) | Signer(4bits)
    //   Token: EX_FAST_REF — process token

    let offsets = match build {
        // Windows 10 1809 (Build 17763)
        17763 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x2F0,
            unique_process_id: 0x2E8,
            image_file_name: 0x450,
            protection: 0x6CA,
            token: 0x360,
        },

        // Windows 10 1903/1909 (Build 18362/18363)
        18362 | 18363 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x2F0,
            unique_process_id: 0x2E8,
            image_file_name: 0x450,
            protection: 0x6CA,
            token: 0x360,
        },

        // Windows 10 2004/20H2/21H1 (Build 19041/19042/19043)
        19041 | 19042 | 19043 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x448,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            protection: 0x87A,
            token: 0x4B8,
        },

        // Windows 10 21H2/22H2 (Build 19044/19045)
        19044 | 19045 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x448,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            protection: 0x87A,
            token: 0x4B8,
        },

        // Windows 11 21H2 (Build 22000)
        22000 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x448,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            protection: 0x87A,
            token: 0x4B8,
        },

        // Windows 11 22H2 (Build 22621)
        22621 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x448,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            protection: 0x87A,
            token: 0x4B8,
        },

        // Windows 11 23H2 (Build 22631)
        22631 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x448,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            protection: 0x87A,
            token: 0x4B8,
        },

        // Windows 11 24H2 (Build 26100)
        26100 => EprocessOffsets {
            build_number: build,
            active_process_links: 0x448,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            protection: 0x87A,
            token: 0x4B8,
        },

        // Try common offsets for unknown builds in the 19041+ range
        b if b >= 19041 => {
            eprintln!(
                "[!] Warning: Unknown build {}. Using Win10 20H1+ offsets (may crash!)",
                b
            );
            Some(EprocessOffsets {
                build_number: build,
                active_process_links: 0x448,
                unique_process_id: 0x440,
                image_file_name: 0x5A8,
                protection: 0x87A,
                token: 0x4B8,
            })
            .unwrap()
        }

        _ => return None,
    };

    Some(offsets)
}
