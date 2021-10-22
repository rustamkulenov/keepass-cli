# Keepass-cli

The idea of this repo/application is to provide CLI tool with minimal dependencies for reading and writing Keepass2 KDBX files with passwords.

### Usecases
* Read passwords from KDBX files in shell scripts for automation;
* Provisioning of new services/inventories (e.g. with Ansible or Terraform) and storing new passwords in a kdbx file;

## Current Version Limitations 

Work is in progress.

Current implementation can only parse kdbx files (version 4) created with Keepass2. It checks SHA256 and HMAC signatures.

Only AES256 is supported as KDF (Key Derivation Function).

[Argon2](https://www.cryptolux.org/index.php/Argon2) is not supported yet.

## Build and Run

When built with the folowing flags and in release mode the application will provide the best performance for calculating AES256.

```bash
$ RUSTFLAGS="-C target-cpu=native" cargo build --release
$ cargo run --release
```

Sample password file (password is Q12345):
example-AES-256-KDF-Q12345.kdbx

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
