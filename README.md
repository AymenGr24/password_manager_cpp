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
g++ -o password_manager password_manager.cpp -std=c++14
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
├── README.md              # This file
├── CLASS_DIAGRAM.txt      # Class structure diagram
├── CODE_REVIEW.md         # Code review document
├── COMPREHENSIVE_REVIEW.md # Comprehensive review
├── EXPLANATION_GUIDE.md   # Explanation guide for presentation
└── data/                  # Data directory (user credentials - not committed)
```

## 🎯 Requirements

- C++14 or higher
- Standard C++ libraries (iostream, string, vector, fstream, etc.)

## 📝 Notes

- Data files are stored in the `data/` directory
- Each user's credentials are stored in separate files
- The application automatically creates default users on first run

## 👤 Author

Aymen Griri

## 📄 License

This project is for educational purposes.
