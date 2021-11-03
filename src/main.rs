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

use kdbx::kdbx_reader::*;

fn main() -> io::Result<()> {
    let f = OpenOptions::new().read(true).open("testfiles/AES-256-KDF-nonzip-Q12345.kdbx");

    let mut file = match f {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open file: {}", e);
            panic!();
        }
    };

    match KdbxReader::read_from(&mut file, "Q12345") {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    };

    Ok(())
}

mod test {

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
}
