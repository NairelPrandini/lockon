# LockOn

LockOn is a file encryption tool written in Rust. It allows you to encrypt files in the current directory using AES-256-GCM encryption. The program ensures that files are securely encrypted and renamed with a `.locked` extension.

## Features

- Encrypts files using AES-256-GCM encryption.
- Skips files larger than 32 MB.
- Prevents re-encrypting already encrypted files.
- Excludes the executable file from encryption.

## Usage

Run the program with the following command:

```bash
./lock <dir> <password>
```

This will encrypt all eligible files in the current directory.

## How It Works

1. The program scans the current directory for files.
2. It skips:
   - Files larger than 32 MB.
   - Files already encrypted (with a `.locked` extension).
   - The executable file itself.
3. Eligible files are encrypted using AES-256-GCM with a key derived from the provided password.
4. Encrypted files are renamed with a `.locked` extension.

## Decryption

To decrypt files, you can create a complementary program (e.g., `unlock`) that reverses the encryption process. A basic structure for this is already included in the `unlock` directory.

## Disclaimer

This program is provided as-is without any guarantees. Use it at your own risk.