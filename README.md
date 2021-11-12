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

### Bulding and running with Cargo:
```bash
$ cargo --version
cargo 1.55.0 (32da73ab1 2021-08-23)
$ RUSTFLAGS="-C target-cpu=native" cargo build --release
$ cargo run --release -- -f testfiles/AES-256-KDF-zip-Q12345.kdbx -p Q12345
```

### Bulding and running with Docker:
```bash
$ docker build -t keepass-cli .
$ docker image ls | grep keepass-cli
keepass-cli                            latest        4a3cbd786fd8   22 minutes ago   73.6MB
$ docker run -it --rm --name keepass-cli-container -v "$PWD":/usr/src/keepass-cli -w /usr/src/keepass-cli keepass-cli keepass-cli -f testfiles/AES-256-KDF-zip-Q12345.kdbx -p Q12345
```

In the above example an image with a tag (-t keepass-cli) is built.
Then a container with a name (--name keepass-cli-container) is run. ".. keepass-cli keepass-cli .." is written twice because the 1st one is an image name, the 2nd one is command to execute.

The resulting image size is around 80Mb.

In order to access kdbx file locating on a local drive from the container a volume (-v "$PWD":/usr/src/keepass-cli) is mounted and working directory is set (-w /usr/src/keepass-cli).

The "-f" and "-p" parameters are provided to keepass-cli executable.



Sample kdbx files (password is Q12345):

* testfiles/example-AES-256-KDF-zip-Q12345.kdbx - with zipped payload

* testfiles/example-AES-256-KDF-nonzip-Q12345.kdbx - payload is not compressed

Usage:

```bash
$ cargo run --release -- --help
USAGE:
    keepass-cli --file <file> --password <password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f, --file <file>            
    -p, --password <password> 
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
