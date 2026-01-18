use crate::windows::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, STATUS_SUCCESS};

pub type NtAllocateVirtualMemory = extern "C" fn(h_proc: usize, p_base: *mut usize, zero_bits: usize, p_size: *mut usize, alloc_type: u32, protection: u32) -> u32;
pub type NtFreeVirtualMemory = extern "C" fn(h_proc: usize, p_base: *mut usize, p_size: *mut usize, free_type: u32) -> u32;

pub fn alloc(size: usize) -> Option<usize> {
    unsafe {
        let mut base = 0usize;
        let mut size_copy = size;
        let status = (super::nt_alloc_vm.unwrap())(super::H_CURR_PROC, &mut base, 0, &mut size_copy, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if status != STATUS_SUCCESS {
            return None;
        }

        return Some(base);
    }
}

pub fn free(base: usize) -> Option<()> {
    unsafe {
        let mut base_copy = base;
        let mut size = 0usize;
        let status = (super::nt_free_vm.unwrap())(super::H_CURR_PROC, &mut base_copy, &mut size, MEM_RELEASE);
        if status != STATUS_SUCCESS {
            return None;
        }

        return Some(());
    }
}