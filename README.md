# CypherVault

A secure file locker and password manager built with Python, featuring strong encryption and user-friendly interface.

## Features

- Secure file encryption and decryption
- Password management with encryption
- Master password protection
- Clipboard support for easy password copying
- Progress bars for file operations
- Color-coded console interface

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the program:
```bash
python cyphervault.py
```

### Commands
- `add`: Add a new password entry
- `get`: Retrieve a stored password
- `list`: List all stored entries
- `encrypt`: Encrypt a file
- `decrypt`: Decrypt a file
- `exit`: Exit the program

## Security

- Uses Fernet symmetric encryption from the cryptography library
- Passwords are never stored in plain text
- Master password is required for all operations
- Secure key derivation using PBKDF2

## License

MIT License 