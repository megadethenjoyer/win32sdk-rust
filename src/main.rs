mod windows;

fn main() {
    let ntdll = windows::find_module(&String::from("ntdll.dll")).unwrap();
    let x = ntdll.base;
    let m = unsafe { *(x as *const u8) };
    let z = unsafe { *((x +1) as *const u8) };
    println!("{}{}", unsafe { char::from_u32_unchecked(m.into()) }, unsafe { char::from_u32_unchecked(z.into()) });
}
