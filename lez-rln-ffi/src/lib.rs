use rln_layouts::{TreeMainLayout, ROOT_HISTORY_SIZE};

#[repr(C)]
pub enum Error {
    Success = 0,
    NullPointer = 1,
    DataTooShort = 2,
}

/// Parse tree-main account data and write valid roots into `out_roots`.
///
/// `out_roots`: caller buffer, at least 160 bytes (5 x 32).
/// `out_count`: set to number of valid roots written (1..=5).
///
/// Slot 0 = current root. Slots 1..N = non-zero history entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rln_ffi_get_valid_roots(
    data_ptr: *const u8,
    data_len: usize,
    out_roots: *mut u8,
    out_count: *mut u32,
) -> Error {
    if data_ptr.is_null() || out_roots.is_null() || out_count.is_null() {
        return Error::NullPointer;
    }
    if data_len < TreeMainLayout::SIZE {
        return Error::DataTooShort;
    }

    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };
    let header = TreeMainLayout::parse(data);

    let out = unsafe { core::slice::from_raw_parts_mut(out_roots, (1 + ROOT_HISTORY_SIZE) * 32) };
    out[0..32].copy_from_slice(&header.current_root);
    let mut count: u32 = 1;

    let zero = [0u8; 32];
    for entry in &header.root_history {
        if *entry != zero {
            let off = (count as usize) * 32;
            out[off..off + 32].copy_from_slice(entry);
            count += 1;
        }
    }

    unsafe { *out_count = count };
    Error::Success
}
