# Keepass-cli

## Build and Run

```bash
$ RUSTFLAGS="-C target-cpu=native" cargo build --release
$ cargo run --release
```

## KDBX4 file format

![KDBX4 Keepass2 file format](/docs/kdbx4.drawio.svg)

### References

https://github.com/sseemayer/keepass-rs/blob/master/src/parse/kdbx4.rs
https://github.com/lgg/awesome-keepass
https://github.com/keepassxreboot/keepassxc/discussions/6229

https://github.com/keepassx/keepassx/blob/master/src/format/KeePass2Reader.cpp
https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KdbxReader.cpp
https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/Kdbx4Reader.cpp
https://gist.github.com/msmuenchen/9318327
https://keepass.info/help/kb/kdbx_4.html

bulding composite key:
https://github.com/keepassxreboot/keepassxc/blob/develop/src/gui/DatabaseOpenWidget.cpp#L263
Get key for HMAC:
https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass2.cpp#L61

Sample password file (password is Q12345):
example-AES-256-KDF-Q12345.kdbx