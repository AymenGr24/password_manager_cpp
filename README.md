# Password Manager - C++ Console Application

A secure password manager application built with C++ using Object-Oriented Programming principles.

## Features

- Multi-user account support with login system
- Normal users and admin roles
- Storing and managing credentials for websites, desktop applications, and games
- Add, edit, and delete credentials
- Audit trail (date created and last updated)
- Secure password storage with encryption and decryption
- Random password generation
- Search credentials by name
- Sort credentials by last updated date
- Masked display of passwords with option to reveal

## Architecture

### Class Structure

The application follows Object-Oriented Programming principles with clear separation of concerns:

1. **Utilities** - Static utility functions for encryption, hashing, validation, and formatting
2. **Credential** - Represents a single password entry with encryption and timestamp tracking
3. **PasswordGenerator** - Generates random secure passwords with customizable options
4. **User** - Manages user accounts, authentication, and credential collections
5. **FileManager** - Handles all file I/O operations for data persistence
6. **PasswordManager** - Main application controller managing menus and user interactions

## Security

- User passwords are hashed with salt (1000 rounds)
- Credential passwords are encrypted using multi-round XOR encryption
- Input validation for all user inputs
- Category validation (only Website, Desktop, Game allowed)

## Compilation

bash
g++ -o password_manager password_manager.cpp -std=c++17


## Usage

bash
./password_manager

### Default Users

- **Admin:** username=`admin`, password=`admin123`
- **User:** username=`aymen`, password=`12345678`

## 📁 Project Structure
.
├── password_manager.cpp   # Main source code
├── README.md              # This file
└── data/                  # Data directory (user credentials - not committed)
    ├── users.dat          # User accounts data
    └── credentials_*.dat  # Individual user credential files

## Requirements

- C++17 or higher
- Standard C++ libraries (iostream, string, vector, fstream, filesystem, etc.)

## Notes

- Data files are stored in the `data/` directory
- Each user's credentials are stored in separate files (`credentials_<username>.dat`)

## Features in Detail

### User Management
- **Login System:** Secure authentication with password hashing and maximum attempt limits
- **User Roles:** Admin and normal user accounts with different permission levels
- **Registration:** New user creation with password strength validation and optional random generation
- **Admin Features:** Complete user management (create, edit, delete), system statistics, and credential management

### Credential Management
- **Categories:** Strict validation for Website, Desktop Application, or Game only
- **CRUD Operations:** Full create, read, update, delete functionality with confirmation prompts
- **Audit Trail:** Automatic tracking of creation date and last update timestamp for each credential
- **Search & Sort:** 
  - Search by name (case-insensitive partial matching)
  - Sort by last updated date (newest first)
  - Sort alphabetically by name
- **Password Display:** Masked with asterisks by default, with option to reveal in plain text

### Security
- **Password Hashing:** User passwords hashed with unique salt using 1000 iterations
- **Encryption:** Credential passwords encrypted using multi-round XOR encryption with obfuscation
- **Input Validation:** Comprehensive validation for all user inputs (categories, passwords, usernames)
- **Password Generation:** Secure random password generator with configurable length (8-50 chars) and character sets
