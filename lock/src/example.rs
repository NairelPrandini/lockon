use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};

use sha2::{Digest, Sha256};
use std::{fs, fs::OpenOptions, path::Path};
use std::env;
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom, Result, Error, ErrorKind};


const MAX_SIZE: u64 = 32 * 1024 * 1024; // 32 MB
const ENC_MARKER: &[u8] = b"ENCRYPTED_BY_NAIREL_USING_AES_GCM";

fn main() -> Result<()> {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    // Ensure the required arguments are provided
    if args.len() < 3 {
        eprintln!("Usage: {} <file_path> <password>", args[0]);
        return Err(Error::new(ErrorKind::InvalidInput, "Missing arguments"));
    }

    let file_path = Path::new(&args[1]); // First argument: file path
    let password_input = &args[2];       // Second argument: password


    let program_path = env::current_exe().unwrap();
    let current_dir = env::current_dir().unwrap();
    //let files_list = fs::read_dir(current_dir).unwrap();
    

    println!("Executable path: {}", program_path.to_str().unwrap());
    println!("Current directory: {}", env::current_dir().unwrap().to_str().unwrap());

   
    //println!("{}", file_path.unwrap().path().display());

    toggle_encrypt_file(file_path, password_input).unwrap();
    Ok(())
}


fn toggle_encrypt_file(file_path: &Path, pwd: &str) -> Result<()> {

     // Check if file exists first
     if !file_path.exists() {
        return Err(Error::new(ErrorKind::NotFound, "File not found!"));
    }

    // Check if file has valid size
    if fs::metadata(file_path)?.len() > MAX_SIZE {
        return Err(Error::new(
            ErrorKind::FileTooLarge,
            format!("File size exceeds {} MB file size limit!", MAX_SIZE / (1024 * 1024)),
        ));
    }

    // Read the file into a buffer
    let plain_buffer = read_file_to_buffer(&file_path)?;

    // Generate the encryption key from the password
    let key = string_to_key(pwd);

    // Check if the file is encrypted or not and process accordingly
    if is_encrypted(&plain_buffer) {
        println!("encrypted! decrypting...");
        let (decrypted_buffer, original_extension) = decrypt_buffer(&key, &plain_buffer)?;
        write_buffer_to_file(&file_path, &decrypted_buffer)?;

        // Rename the file back to its original extension
        let new_file_path = file_path.with_extension(original_extension);
        fs::rename(&file_path, &new_file_path)?;
        println!("File renamed to: {}", new_file_path.display());
    } else {
        println!("not encrypted! encrypting...");
        let original_extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_string();

        let encrypted_buffer = encrypt_buffer(&key, &plain_buffer, &original_extension)?;
        write_buffer_to_file(&file_path, &encrypted_buffer)?;

        // Rename the file to have a `.lock` extension
        let new_file_path = file_path.with_extension("lock");
        fs::rename(&file_path, &new_file_path)?;
        println!("File renamed to: {}", new_file_path.display());
    }

    Ok(())
}




fn is_encrypted(buffer: &Vec<u8>) -> bool{

    if buffer.len() > ENC_MARKER.len() && &buffer[..ENC_MARKER.len()] == ENC_MARKER {
        return true;
    }

    return false;
}


fn string_to_key(input: &str) -> Key<aes_gcm::Aes256Gcm> {
    // Hash the input string using SHA-256
    let hash = Sha256::digest(input.as_bytes());

    // Convert the hash into a 32-byte array
    let key_bytes: [u8; 32] = hash.as_slice().try_into().expect("Hash length mismatch");

    // Create the AES-256 key
    Key::<aes_gcm::Aes256Gcm>::from_slice(&key_bytes).clone()
}

fn decrypt_buffer(key: &Key<aes_gcm::Aes256Gcm>, buffer: &Vec<u8>) -> Result<(Vec<u8>, String)> {
    if !is_encrypted(&buffer) {
        return Err(Error::new(ErrorKind::InvalidData, "File is not encrypted"));
    }

    // Remove the marker
    let buffer = &buffer[ENC_MARKER.len()..];

    // Extract the nonce (first 12 bytes after the marker)
    let nonce = Nonce::from_slice(&buffer[..12]);

    // Extract the original file extension length and extension
    let extension_length = buffer[12] as usize; // The next byte stores the extension length
    let extension_start = 13;
    let extension_end = extension_start + extension_length;
    let original_extension = String::from_utf8(buffer[extension_start..extension_end].to_vec())
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid file extension"))?;

    // Extract the ciphertext
    let ciphertext = &buffer[extension_end..];

    // Initialize the cipher
    let cipher = Aes256Gcm::new(key);

    // Decrypt the ciphertext
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Decryption failed"))?;

    Ok((plaintext, original_extension))
}



//Encrypt buffer with AES-GCM
fn encrypt_buffer(key: &Key<aes_gcm::Aes256Gcm>, buffer: &Vec<u8>, original_extension: &str) -> Result<Vec<u8>> {
    if is_encrypted(&buffer) {
        return Err(Error::new(ErrorKind::InvalidData, "File already encrypted"));
    }

    let cipher = Aes256Gcm::new(key);

    // Generate a random nonce (96 bits)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the buffer
    let ciphertext = cipher
        .encrypt(&nonce, buffer.as_ref())
        .map_err(|_| Error::new(ErrorKind::Other, "Encryption failed"))?;

    // Prepend the marker, nonce, and original file extension to the ciphertext
    let mut result = ENC_MARKER.to_vec(); // Marker
    result.extend_from_slice(&nonce);

    // Add the original file extension length and extension as bytes
    let extension_bytes = original_extension.as_bytes();
    result.push(extension_bytes.len() as u8); // Store the length of the extension
    result.extend_from_slice(extension_bytes); // Store the extension itself

    result.extend_from_slice(&ciphertext);

    Ok(result)
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


