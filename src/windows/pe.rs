use std::ffi::{CStr, c_str};

use super::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_IMPORT_DESCRIPTOR, IMAGE_EXPORT_DIRECTORY};

pub fn find_export(base: usize, target_name: String) -> Option<usize> {
    unsafe {
        let dos = *(base as *const IMAGE_DOS_HEADER);
        let nt = *((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

        let export_dir = nt.OptionalHeader.DataDirectory[0];
        let export = (base + export_dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let name_rvas = (base + (*export).AddressOfNames as usize) as *const u32;
        let name_ordinals = (base + (*export).AddressOfNameOrdinals as usize) as *const u16;
        let func_rvas = (base + (*export).AddressOfFunctions as usize) as *const u32;
        let num_names =  (*export).NumberOfNames as usize;
        for i in 0..num_names {
            let name_rva = *name_rvas.add(i);
            let name = CStr::from_ptr((base + name_rva as usize) as *const i8);
            let name_str = name.to_string_lossy().to_owned();

            if name_str == target_name {
                let ordinal = *name_ordinals.add(i) as usize;
                let func_rva = *func_rvas.add(ordinal);
                return Some(base + func_rva as usize);
            }
        }

        return None;
    }
}