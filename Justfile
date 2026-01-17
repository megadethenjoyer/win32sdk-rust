all:
    just build
    just run

build:
    cargo build --target x86_64-pc-windows-gnu

run:
    wine ./target/x86_64-pc-windows-gnu/debug/win32sdk-rust.exe