#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::{arch::asm, mem::offset_of};

pub fn get_peb() -> *const PEB {
    unsafe {
        let mut peb: usize;
        asm!(
            "mov {peb}, gs:[0x60]",
            peb = out(reg) peb
        );
        peb as *const PEB
    }
}

impl From<UNICODE_STRING> for String {
    fn from(s: UNICODE_STRING) -> Self {
        convert_unicode_string(&s)
    }
}

fn convert_unicode_string(unicode_string: &UNICODE_STRING) -> String {
    let mut rust_str = String::new();

    let len = unicode_string.Length as usize;

    let mut i = 0;
    while i != len {
        let ch = unsafe { *unicode_string.Buffer.add(i) };
        if ch == 0 {
            break;
        }

        if let Some(c) = char::from_u32(ch.into()) {
            rust_str.push(c);
        }

        i += 1;
    }

    rust_str
}

pub struct Module {
    pub base: usize,
    pub size: usize,
    pub name: String,
    pub full_name: String,
}

impl Module {
    fn construct(entry: LDR_DATA_TABLE_ENTRY) -> Module {
        Module {
            base: entry.DllBase as usize,
            size: entry.SizeOfImage as usize,
            name: entry.BaseDllName.into(),
            full_name: entry.FullDllName.into()
        }
    }
}

pub fn find_module(target_name: &String) -> Option<Module> {
    unsafe {
        let ldr = (*get_peb()).Ldr;
        let head = (*(*ldr).InLoadOrderModuleList.Flink).Blink;
        let mut curr = head;
        loop {
            curr = (*curr).Flink;
            if curr == head {
                break;
            }

            let entry = *(((curr as usize) - offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)) as *const LDR_DATA_TABLE_ENTRY);

            let name = entry.BaseDllName;

            if target_name.to_lowercase() == String::from(name).to_lowercase() {
                return Some(Module::construct(entry));
            }
        }
    }

    return None;
}
