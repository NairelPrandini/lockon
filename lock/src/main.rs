use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};

use sha2::{Digest, Sha256};
use std::{fs, fs::OpenOptions, path::Path};
use std::env;
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom, Result, Error, ErrorKind};


fn main() {
    println!("Hello, world!");
}


fn write_buffer_to_file(path: &Path, buffer: &Vec<u8>) -> Result<()> {

    // Open file for reading
    let mut file = OpenOptions::new()
    .write(true)
    .truncate(true)
    .open(path)
    .unwrap();

    file.write_all(&buffer)?;

    Ok(())
}


fn read_file_to_buffer(path: &Path) -> Result<Vec<u8>> {
    // Open file for reading
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();

    // Get file metadata
    let metadata = file.metadata().unwrap();

    let mut reader = BufReader::new(file);
    let mut buffer = Vec::with_capacity(metadata.len() as usize);

    // Read contents into buffer
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)
}
