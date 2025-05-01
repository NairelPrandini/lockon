# LockOn

LockOn is a file encryption tool written in Rust. It allows you to encrypt files in a directory using AES-256-GCM symetric encryption. The program ensures that files are securely encrypted.

## Features

- Encrypts files using AES-256-GCM encryption.
- Skips files larger than 32 MB.
- Prevents re-encrypting already encrypted files.

## Usage

Run the program with the following command:

```bash
./lock <directory> <password>
```

This will encrypt all eligible files in the specified directory.

## How It Works

1. The program scans the current directory for files.
2. It skips:
   - Files larger than 32 MB.
   - Files already encrypted (with a `.locked` extension).
   - The executable file itself.
3. Eligible files are encrypted using AES-256-GCM with a key derived from the provided password.
4. Encrypted files are renamed with a `.locked` extension.

## Decryption

To decrypt files, you can use a complementary program (e.g., `unlock`) that reverses the encryption process with the key used for encryption.

## Disclaimer

This program is provided as-is without any guarantees. It might screw you up use it at your own risk.
*Dont forget the password there is no "Forgot my password" if you did good luck trying to recover them*