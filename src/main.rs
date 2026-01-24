mod windows;

fn main() {
    windows::init();
    println!("{:X}", windows::token::get_curr_proc_integrity());
}
