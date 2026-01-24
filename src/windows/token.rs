use crate::windows::H_CURR_PROC;

use super::{STATUS_SUCCESS, TOKEN_QUERY, HANDLE, SID, TOKEN_MANDATORY_LABEL, is_buf_too_small, nt_query_info_token, vm};

pub type NtOpenProcessToken = extern "C" fn(h_proc: usize, access: u32, p_out_handle: *mut usize) -> u32;
pub type NtQueryInformationToken = extern "C" fn(h_token: usize, token_info_class: u32, info: usize, info_size: u32, p_out_size: *mut u32) -> u32;

pub fn open_token(h_proc: usize) -> Option<usize> {
    unsafe {

        let mut token = 0usize;
        let status = (super::nt_open_token.unwrap())(h_proc, TOKEN_QUERY, &mut token);

        if status != STATUS_SUCCESS {
            return None;
        }

        return Some(token);
    }

    return None;
}

pub fn get_curr_proc_token() -> usize {
    return open_token(H_CURR_PROC).unwrap();
}

fn get_integrity_from_sid(sid: *const SID) -> usize {
    unsafe {
        let count = (*sid).SubAuthorityCount as usize;
        let last = (*(*sid).SubAuthority.as_ptr().add(count - 1));
        return last as usize;
    }
}

pub fn get_integrity(h_token: usize) -> Option<usize> {
    unsafe {

        let mut buffer = 0;
        let mut size = 0;

        loop {
            let status = (nt_query_info_token.unwrap())(h_token, 25, buffer, size, &mut size);
            if is_buf_too_small(status) {
                if buffer != 0 {
                    vm::free(buffer);
                }
                buffer = vm::alloc(size as usize).unwrap();
                continue;
            }

            if status != STATUS_SUCCESS {
                vm::free(buffer);
                return None;
            }

            break;
        }

        let label = buffer as *const TOKEN_MANDATORY_LABEL;
        let sid = (*label).Label.Sid;

        
        let integrity = get_integrity_from_sid(sid);
        vm::free(buffer);

        return Some(integrity);
    }
    return None;
}

pub fn get_curr_proc_integrity() -> usize {
    return get_integrity(get_curr_proc_token()).unwrap();
}