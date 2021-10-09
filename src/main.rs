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

use std::fs::File;
use std::io;
use std::io::prelude::*;

use kdbx::kdbx_reader::*;

const FILE_PATH: &str = "example-AES-256-KDF-Q12345.kdbx";

fn main() -> io::Result<()> {

    let f = File::open(FILE_PATH);

    let mut file = match f {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open file: {}", e);
            panic!();
        }
    };

    let k = KdbxReader::new(&mut file);

    println!("Hello, world!");

    Ok(())
}

