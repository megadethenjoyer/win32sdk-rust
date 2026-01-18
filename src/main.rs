mod windows;

use std::ffi::c_void;

use windows::{find_module, pe};

use crate::windows::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

type NtAllocateVirtualMemory = extern "C" fn(h_proc: usize, p_base: *mut usize, zero_bits: usize, p_size: *mut usize, alloc_type: u32, protection: u32) -> u32;


fn main() {
    let ntdll = find_module(&String::from("ntdll.dll")).unwrap();
    let nt_alloc_vm = pe::find_export(ntdll.base, String::from("NtAllocateVirtualMemory")).unwrap();
    unsafe {
        let fn_nt_alloc_vm: NtAllocateVirtualMemory = std::mem::transmute(nt_alloc_vm);
        let mut base = 0;
        let mut size = 128;
        let status = fn_nt_alloc_vm(0xFFFFFFFFFFFFFFFFusize, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        println!("status {}", status);
        println!("base {:X}", base);
    }
}
