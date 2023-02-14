/*
   Copyright 2021 Rustam Kulenov

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

mod kdbx;

use std::fs::OpenOptions;
use std::io;
use kdbx::content::Content;
use structopt::StructOpt;

use kdbx::kdbx_reader::*;

// Command line args.
// #cargo run -- -f=<kdbx_file> -p=<secure_password>
#[derive(StructOpt)]
struct Cli {
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    file: std::path::PathBuf,

    #[structopt(short = "p", long = "password")]
    password: String,
}

fn main() -> io::Result<()> {
    let args = Cli::from_args();

    let f = OpenOptions::new().read(true).open(args.file);

    let mut file = match f {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open file: {}", e);
            panic!();
        }
    };

    match KdbxReader::read_from(&mut file, &args.password) {
        Ok(doc) => {
            let content = Content::new(doc);
            println!("\r\n--------------------------\r\nRoot entries:");
            println!("{:?}", content);
        },
        Err(e) => println!("{:?}", e),
    };

    Ok(())
}

#[cfg(test)]
mod tests {

    use minidom::ElementBuilder;

    use crate::kdbx::crypt::ciphers::AES256Cipher;
    use crate::kdbx::decompress::NoCompression;
    use crate::kdbx::kdbx_writer::KdbxWriter;

    use super::kdbx::kdbx_reader::*;
    use std::fs::OpenOptions;
    use std::io;

    const ZIPPED_FILE: &str = "testfiles/AES-256-KDF-zip-Q12345.kdbx";
    const NONZIPPED_FILE: &str = "testfiles/AES-256-KDF-nonzip-Q12345.kdbx";
    const PASSWORD: &str = "Q12345";

    /// Tests KDBX4 reader with AES256 encrypted, zipped payload.
    #[test]
    fn reader_aes256_zipped() {
        let f = OpenOptions::new().read(true).open(ZIPPED_FILE);

        let mut file = match f {
            Ok(f) => f,
            Err(e) => {
                println!("Failed to open file: {}", e);
                panic!();
            }
        };

        let _ = KdbxReader::read_from(&mut file, PASSWORD).unwrap();
    }

    /// Tests KDBX4 reader with AES256 encrypted, nonzipped payload.
    #[test]
    fn reader_aes256_unzipped() {
        let f = OpenOptions::new().read(true).open(NONZIPPED_FILE);

        let mut file = match f {
            Ok(f) => f,
            Err(e) => {
                println!("Failed to open file: {}", e);
                panic!();
            }
        };

        let _ = KdbxReader::read_from(&mut file, PASSWORD).unwrap();
    }

    #[test]
    fn writer_and_reader_test() {
        let mut stream = <Vec<u8>>::with_capacity(1024 * 1024 * 10);
        let payload = minidom::Element::builder("name", "namespace")
            .attr("name", "value")
            .append("inner")
            .build();
        let cipher = AES256Cipher::new(&[0u8; 32], &[0u8; 32]).unwrap();
        let compression = NoCompression {};
        KdbxWriter::write(&mut stream, PASSWORD, payload, &cipher, &compression).unwrap();

        KdbxReader::read_from(&mut stream.as_slice(), PASSWORD).unwrap();
    }
}
