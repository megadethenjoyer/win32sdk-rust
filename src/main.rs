mod windows;

fn main() {
    windows::init();

    println!("{:X}", windows::vm::alloc(128).unwrap());
    let b2= windows::vm::alloc(128).unwrap();
    println!("{:X}", b2);
    windows::vm::free(b2);
    println!("{:X}", windows::vm::alloc(128).unwrap());
}
