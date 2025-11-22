# Password Manager - C++ Console Application

A secure password manager application built with C++ using Object-Oriented Programming principles.

## 📋 Features

- ✅ Multi-user account support with login system
- ✅ Normal users and admin roles
- ✅ Storing and managing credentials for websites, desktop applications, and games
- ✅ Add, edit, and delete credentials
- ✅ Audit trail (date created and last updated)
- ✅ Secure password storage with encryption and decryption
- ✅ Random password generation
- ✅ Search credentials by name
- ✅ Sort credentials by last updated date
- ✅ Masked display of passwords with option to reveal

## 🏗️ Architecture

### Classes

1. **Utilities** - Static utility functions for encryption, hashing, and validation
2. **Credential** - Represents a single password entry
3. **PasswordGenerator** - Generates random secure passwords
4. **User** - Represents a user with multiple credentials
5. **FileManager** - Handles file I/O operations for data persistence
6. **PasswordManager** - Main application controller

## 🔒 Security

- User passwords are hashed with salt (1000 rounds)
- Credential passwords are encrypted using multi-round XOR encryption
- Input validation for all user inputs
- Category validation (only Website, Desktop, Game allowed)

## 🚀 Compilation

```bash
g++ -o password_manager password_manager.cpp -std=c++17
```

## 💻 Usage

```bash
./password_manager
```

### Default Users

- **Admin:** username=`admin`, password=`admin123`
- **User:** username=`aymen`, password=`12345678`

## 📁 Project Structure

```
.
├── password_manager.cpp    # Main source code
├── password_manager        # Compiled executable
├── README.md              # This file
├── FINAL_REVIEW.md        # Comprehensive code review
└── data/                  # Data directory (user credentials - not committed)
    ├── users.dat          # User accounts data
    └── credentials_*.dat  # Individual user credential files
```

## 🎯 Requirements

- C++17 or higher
- Standard C++ libraries (iostream, string, vector, fstream, filesystem, etc.)

## 📝 Notes

- Data files are stored in the `data/` directory
- Each user's credentials are stored in separate files (`credentials_<username>.dat`)
- The application automatically creates default users on first run
- All data is automatically saved on logout or credential changes
- See `FINAL_REVIEW.md` for detailed code review and requirement coverage

## 🔍 Features in Detail

### User Management
- **Login System:** Secure authentication with password hashing
- **User Roles:** Admin and normal user accounts with different permissions
- **Registration:** New user creation with password strength validation
- **Admin Features:** User management, system statistics, credential management

### Credential Management
- **Categories:** Website, Desktop Application, or Game
- **CRUD Operations:** Full create, read, update, delete functionality
- **Audit Trail:** Automatic tracking of creation and last update timestamps
- **Search & Sort:** Search by name, sort by date or name
- **Password Display:** Masked by default with option to reveal

### Security
- **Password Hashing:** User passwords hashed with salt (1000 rounds)
- **Encryption:** Credential passwords encrypted using multi-round XOR encryption
- **Input Validation:** Comprehensive validation for all user inputs
- **Password Generation:** Secure random password generator with customizable options

## 👤 Author

Aymen Griri

## 📄 License

This project is for educational purposes.
