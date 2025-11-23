//Password Manager - C++ Console Application
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <algorithm>
#include <limits>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <memory>
#include <functional>
#include <filesystem>
#include <stdexcept>

using namespace std;
namespace fs = std::filesystem;

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================
namespace Constants {
    const vector<string> VALID_CATEGORIES = {"Website", "Desktop", "Game"};
    const int MIN_PASSWORD_LENGTH = 8;
    const int MAX_PASSWORD_LENGTH = 50;
    const string DATA_DIR = "data";
    const string USERS_FILE = DATA_DIR + "/users.dat";
    const string CREDENTIALS_FILE_PREFIX = DATA_DIR + "/credentials_";
    const string MASTER_KEY = "PasswordManager2024SecureKey!@#";
    const int SALT_SIZE = 16;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
class Utilities {
public:
    // Encrypts plaintext using multi-round XOR encryption with obfuscation
    static string encrypt(const string &plaintext) {
        string result = plaintext;
        string key = Constants::MASTER_KEY;
        
        // Multi-round encryption for enhanced security
        for (size_t round = 0; round < 3; ++round) {
            for (size_t i = 0; i < result.length(); ++i) {
                char keyChar = key[i % key.length()];
                result[i] = result[i] ^ keyChar ^ (char)((i + round) % 256);
            }
        }
        
        // Obfuscate encrypted data
        string obfuscated;
        for (unsigned char c : result) {
            obfuscated += to_string((int)c + 100) + "|";
        }
        return obfuscated;
    }

    // Decrypts ciphertext by reversing the encryption process
    static string decrypt(const string &ciphertext) {
        string result;
        istringstream iss(ciphertext);
        string token;
        while (getline(iss, token, '|')) {
            if (!token.empty()) {
                try {
                    int val = stoi(token) - 100;
                    result += (char)val;
                } catch (...) {
                    continue;
                }
            }
        }

        string key = Constants::MASTER_KEY;

        // Reverse encryption rounds
        for (int round = 2; round >= 0; --round) {
            for (size_t i = 0; i < result.length(); ++i) {
                char keyChar = key[i % key.length()];
                result[i] = result[i] ^ keyChar ^ (char)((i + round) % 256);
            }
        }
        
        return result;
    }

    // Returns current system time as time_t
    static time_t getCurrentTimeT() {
        return time(nullptr);
    }

    // Validates if category is one of the allowed categories (Website, Desktop, Game)
    static bool isValidCategory(const string& category) {
        return find(Constants::VALID_CATEGORIES.begin(),
                   Constants::VALID_CATEGORIES.end(), category) != Constants::VALID_CATEGORIES.end();
    }

    // Checks if password meets minimum length requirement
    static bool isStrongPassword(const string& password) {
        return static_cast<int>(password.length()) >= Constants::MIN_PASSWORD_LENGTH;
    }

    // Converts string to lowercase for case-insensitive comparisons
    static string toLower(const string& str) {
        string lowerStr = str;
        transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
        return lowerStr;
    }

    // Removes leading and trailing whitespace from string
    static string trim(const string& str) {
        size_t start = str.find_first_not_of(" \t\n\r");
        size_t end = str.find_last_not_of(" \t\n\r");
        return (start == string::npos) ? "" : str.substr(start, end - start + 1);
    }

    // Generates a random salt value for password hashing (hexadecimal format)
    static string generateSalt() {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, 255);

        string salt;
        for (int i = 0; i < Constants::SALT_SIZE; ++i) {
            salt += static_cast<char>(dis(gen));
        }
        ostringstream oss;
        for (unsigned char c : salt) {
            oss << hex << setw(2) << setfill('0') << (int)c;
        }
        return oss.str();
    }

    // Hashes password with salt using 1000 iterations for security
    static string hashPassword(const string& password, const string& salt) {
        string combined = password + salt + Constants::MASTER_KEY;
        hash<string> hasher;
        size_t hashValue = hasher(combined);
        for (int i = 0; i < 1000; ++i) {
            string temp = to_string(hashValue) + salt;
            hashValue = hasher(temp);
        }
        return to_string(hashValue);
    }

    // Formats time_t to readable string (cross-platform compatible)
    static string formatTime(time_t t) {
        if (t <= 0) return "Unknown";
        tm tmBuf;
#if defined(_MSC_VER)
        localtime_s(&tmBuf, &t);
#else
        tm *tmp = localtime(&t);
        if (!tmp) return "Invalid time";
        tmBuf = *tmp;
#endif
        char buffer[64];
        if (strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmBuf)) {
            return string(buffer);
        }
        return "Invalid time";
    }
};

// ============================================================================
// CREDENTIAL CLASS
// ============================================================================
class Credential {
private:
    string name;
    string encryptedPassword;
    string category;
    time_t dateCreated;
    time_t lastUpdated;

public:
    // Constructor for new credential (encrypts password)
    Credential(string n, string p, string c)
        : name(Utilities::trim(n)), category(Utilities::trim(c)) {

        if (name.empty()) {
            throw invalid_argument("Name cannot be empty");
        }

        if (!Utilities::isValidCategory(category)) {
            throw invalid_argument("Invalid category");
        }

        encryptedPassword = Utilities::encrypt(p);
        dateCreated = lastUpdated = Utilities::getCurrentTimeT();
    }

    // Constructor for loading from file (password already encrypted)
    Credential(string n, string encryptedP, string c, time_t created, time_t updated)
        : name(n), encryptedPassword(encryptedP), category(c),
          dateCreated(created), lastUpdated(updated) {}

    // Getters for credential properties
    string getName() const { return name; }
    string getCategory() const { return category; }
    time_t getLastUpdated() const { return lastUpdated; }

    // Decrypts and returns the password (used for display)
    string getDecryptedPassword() const {
        try {
            return Utilities::decrypt(encryptedPassword);
        } catch (...) {
            return "*** DECRYPTION ERROR ***";
        }
    }

    string getFormattedDateCreated() const {
        return Utilities::formatTime(dateCreated);
    }

    string getFormattedLastUpdated() const {
        return Utilities::formatTime(lastUpdated);
    }

    // Updates password and automatically updates lastUpdated timestamp
    void updatePassword(const string &newPass) {
        encryptedPassword = Utilities::encrypt(newPass);
        lastUpdated = Utilities::getCurrentTimeT();
    }

    // Updates name and automatically updates lastUpdated timestamp
    void setName(const string &n) {
        if (Utilities::trim(n).empty()) {
            throw invalid_argument("Name cannot be empty");
        }
        name = Utilities::trim(n);
        lastUpdated = Utilities::getCurrentTimeT();
    }

    // Updates category and automatically updates lastUpdated timestamp
    void setCategory(const string &c) {
        if (!Utilities::isValidCategory(c)) {
            throw invalid_argument("Invalid category");
        }
        category = Utilities::trim(c);
        lastUpdated = Utilities::getCurrentTimeT();
    }

    // Displays credential information (password masked by default)
    void display(bool showPassword = false) const {
        cout << "\n" << string(50, '=') << endl;
        cout << "Name: " << name << endl;
        cout << string(50, '=') << endl;
        cout << " Password: ";
        string decryptedPwd = getDecryptedPassword();
        if (showPassword) {
            cout << decryptedPwd << endl;
        } else {
            if (decryptedPwd.find("DECRYPTION ERROR") != string::npos) {
                cout << "***" << endl;
            } else {
                cout << string(decryptedPwd.length(), '*') << endl;
            }
        }
        cout << " Category: " << category;
        cout << "\n Created: " << getFormattedDateCreated();
        cout << " Updated: " << getFormattedLastUpdated() << endl;
    }

    // Serializes credential data to string for file storage
    string serialize() const {
        ostringstream oss;
        // Use ||| delimiter to avoid collision with | in encrypted password
        oss << name << "|||" << encryptedPassword << "|||" << category << "|||"
            << dateCreated << "|||" << lastUpdated;
        return oss.str();
    }

    // Deserializes credential data from string (with error handling)
    static Credential deserialize(const string& data) {
        const string delimiter = "|||";
        vector<string> parts;
        size_t pos = 0;
        while (pos < data.size()) {
            size_t found = data.find(delimiter, pos);
            if (found == string::npos) {
                parts.push_back(data.substr(pos));
                break;
            } else {
                parts.push_back(data.substr(pos, found - pos));
                pos = found + delimiter.size();
            }
        }

        if (parts.size() >= 5) {
            try {
                string name = parts[0];
                string encryptedPassword = parts[1];
                string category = parts[2];
                time_t created = static_cast<time_t>(stol(parts[3]));
                time_t updated = static_cast<time_t>(stol(parts[4]));
                return Credential(name, encryptedPassword, category, created, updated);
            } catch (...) {
                // Fallback: create credential with default values if parsing fails
                string name = parts.size() > 0 ? parts[0] : "Unnamed";
                string encryptedPassword = parts.size() > 1 ? parts[1] : Utilities::encrypt("");
                string category = (parts.size() > 2 && Utilities::isValidCategory(parts[2])) ? parts[2] : "Website";
                time_t now = Utilities::getCurrentTimeT();
                return Credential(name, encryptedPassword, category, now, now);
            }
        }

        throw runtime_error("Invalid credential data format");
    }
};

// ============================================================================
// PASSWORD GENERATOR CLASS
// ============================================================================
class PasswordGenerator {
private:
    random_device rd;
    mt19937 generator;

public:
    PasswordGenerator() : generator(rd()) {}

    // Generates random password with configurable length and character sets
    string generate(int length = 16, bool useUpper = true, bool useLower = true,
                    bool useNumbers = true, bool useSpecial = true) {

        // Validate password length constraints
        if (length < Constants::MIN_PASSWORD_LENGTH || length > Constants::MAX_PASSWORD_LENGTH) {
            throw invalid_argument("Password length must be between " +
                                   to_string(Constants::MIN_PASSWORD_LENGTH) + " and " +
                                   to_string(Constants::MAX_PASSWORD_LENGTH));
        }

        // Build character set based on selected options
        string charSet;
        if (useUpper) charSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (useLower) charSet += "abcdefghijklmnopqrstuvwxyz";
        if (useNumbers) charSet += "0123456789";
        if (useSpecial) charSet += "!@#$%^&*";

        if (charSet.empty()) {
            throw invalid_argument("At least one character type must be selected");
        }

        // Generate random password from character set
        uniform_int_distribution<size_t> dist(0, charSet.size() - 1);
        string password;

        for (int i = 0; i < length; i++) {
            password += charSet[dist(generator)];
        }

        return password;
    }
};

// ============================================================================
// USER CLASS
// ============================================================================
class User {
private:
    string username;
    string hashedPassword;
    string salt;
    string userType;
    vector<Credential> credentials;

public:
    User() = default;

    // Constructor for new user (hashes password with salt)
    User(string u, string p, string type)
        : username(Utilities::trim(u)), userType(type) {

        if (username.empty() || p.empty()) {
            throw invalid_argument("Username and password cannot be empty");
        }

        salt = Utilities::generateSalt();
        hashedPassword = Utilities::hashPassword(p, salt);
    }

    // Constructor for loading user from file
    User(string u, string hp, string s, string type, const vector<Credential>& creds)
        : username(u), hashedPassword(hp), salt(s), userType(type), credentials(creds) {}

    string getUsername() const { return username; }
    string getUserType() const { return userType; }
    const vector<Credential>& getCredentials() const { return credentials; }

    // Setters for user properties
    void setUsername(const string &u) { username = Utilities::trim(u); }
    void setUserType(const string &type) { userType = type; }

    // Verifies if input password matches stored hash
    bool verifyPassword(const string &input) const {
        return hashedPassword == Utilities::hashPassword(input, salt);
    }

    // Allows user to change their own password (requires old password verification)
    void changePassword(const string& oldPassword, const string& newPassword) {
        if (!verifyPassword(oldPassword)) {
            throw invalid_argument("Current password is incorrect");
        }
        if (!Utilities::isStrongPassword(newPassword)) {
            throw invalid_argument("New password must be at least " +
                                   to_string(Constants::MIN_PASSWORD_LENGTH) + " characters long");
        }
        salt = Utilities::generateSalt();
        hashedPassword = Utilities::hashPassword(newPassword, salt);
    }

    void resetPasswordByAdmin(const string& newPassword) {
        if (!Utilities::isStrongPassword(newPassword)) {
            throw invalid_argument("Password must be at least " +
                                   to_string(Constants::MIN_PASSWORD_LENGTH) + " characters long");
        }
        salt = Utilities::generateSalt();
        hashedPassword = Utilities::hashPassword(newPassword, salt);
    }

    // Adds a new credential (prevents duplicates by name and category)
    void addCredential(const Credential& cred) {
        for (const auto& existing : credentials) {
            if (Utilities::toLower(existing.getName()) == Utilities::toLower(cred.getName()) &&
                existing.getCategory() == cred.getCategory()) {
                throw invalid_argument("A credential with this name and category already exists");
            }
        }
        credentials.push_back(cred);
    }

    // Displays all credentials (with optional password reveal)
    void viewCredentials(bool showPasswords = false) const {
        if (credentials.empty()) {
            cout << "\nNo credentials found.\n";
            return;
        }

        cout << "\n" << string(60, '=') << endl;
        cout << "YOUR CREDENTIALS (" << credentials.size() << " found)" << endl;
        cout << string(60, '=') << endl;

        for (size_t i = 0; i < credentials.size(); i++) {
            try {
                cout << "\n[" << (i + 1) << " of " << credentials.size() << "]";
                credentials[i].display(showPasswords);
                if (i < credentials.size() - 1) {
                    cout << "\n" << string(60, '-') << endl;
                }
            } catch (...) {
            }
        }
        cout << "\n" << string(60, '=') << endl;
    }

    // Sorts credentials by last updated date
    void sortByDate() {
        sort(credentials.begin(), credentials.end(),
             [](const Credential &a, const Credential &b) {
                 return a.getLastUpdated() > b.getLastUpdated();
             });
    }

    // Sorts credentials alphabetically by name (case-insensitive)
    void sortByName() {
        sort(credentials.begin(), credentials.end(),
             [](const Credential &a, const Credential &b) {
                 return Utilities::toLower(a.getName()) < Utilities::toLower(b.getName());
             });
    }

    // Searches credentials by name (case-insensitive)
    vector<Credential> searchCredentialsByName(const string& searchTerm) const {
        vector<Credential> results;
        string lowerSearch = Utilities::toLower(searchTerm);

        for (const auto& cred : credentials) {
            string lowerName = Utilities::toLower(cred.getName());
            if (lowerName.find(lowerSearch) != string::npos) {
                results.push_back(cred);
            }
        }

        return results;
    }

    // Returns the number of credentials for this user
    int getCredentialCount() const { return static_cast<int>(credentials.size()); }

    // Returns pointer to credential at given index (nullptr if invalid)
    Credential* getCredentialByIndex(int index) {
        if (index < 0 || index >= static_cast<int>(credentials.size())) return nullptr;
        return &credentials[index];
    }

    // Removes credential at specified index
    void deleteCredential(int index) {
        if (index < 0 || index >= static_cast<int>(credentials.size())) {
            throw out_of_range("Invalid credential index");
        }
        credentials.erase(credentials.begin() + index);
    }

    // Serializes user data to string for file storage
    string serialize() const {
        ostringstream oss;
        oss << username << "|" << hashedPassword << "|" << salt << "|" << userType;
        return oss.str();
    }

    // Deserializes user data from string (supports legacy format without salt)
    static User deserialize(const string& data, const vector<Credential>& creds) {
        istringstream iss(data);
        string username, hashedPassword, saltOrType, userType;
        getline(iss, username, '|');
        getline(iss, hashedPassword, '|');
        getline(iss, saltOrType, '|');
        if (getline(iss, userType, '|')) {
            // Current format: username|hash|salt|type
            return User(username, hashedPassword, saltOrType, userType, creds);
        } else {
            // Legacy format: username|hash|type (generate new salt)
            string salt = Utilities::generateSalt();
            return User(username, hashedPassword, salt, saltOrType, creds);
        }
    }

    void saveCredentialsToFile() const;
    void loadCredentialsFromFile();
};

// ============================================================================
// FILE MANAGER CLASS
// ============================================================================
class FileManager {
public:
    // Creates data directory if it doesn't exist
    static void ensureDataDirectory() {
        try {
            if (!fs::exists(Constants::DATA_DIR)) {
                fs::create_directories(Constants::DATA_DIR);
            }
        } catch (const exception&) {
        }
    }

    // Loads all users from file and their associated credentials
    static vector<User> loadUsers() {
        vector<User> users;
        ensureDataDirectory();

        ifstream file(Constants::USERS_FILE);
        if (!file.is_open()) {
            return users; // no users file yet
        }

        string line;
        while (getline(file, line)) {
            if (!line.empty()) {
                try {
                    User user = User::deserialize(line, {});
                    // now load their credentials from their file
                    user.loadCredentialsFromFile();
                    users.push_back(user);
                } catch (...) {
                }
            }
        }

        file.close();
        return users;
    }

    // Saves all users to file and triggers credential file saves for each user
    static void saveUsers(const vector<User>& users) {
        ensureDataDirectory();
        ofstream file(Constants::USERS_FILE, ios::trunc);
        if (!file.is_open()) {
            throw runtime_error("Cannot open users file for writing: " + Constants::USERS_FILE);
        }

        for (const auto& user : users) {
            file << user.serialize() << "\n";
            // write user's credentials file
            user.saveCredentialsToFile();
        }

        file.close();
    }

    // Loads credentials for a specific user from their individual credential file
    static vector<Credential> loadCredentials(const string& username) {
        vector<Credential> credentials;
        string filename = Constants::CREDENTIALS_FILE_PREFIX + username + ".dat";
        ifstream file(filename);
        if (!file.is_open()) {
            return credentials;
        }

        string line;
        while (getline(file, line)) {
            if (!line.empty()) {
                try {
                    credentials.push_back(Credential::deserialize(line));
                } catch (...) {
                }
            }
        }

        file.close();
        return credentials;
    }

    // Saves credentials for a specific user to their individual credential file
    static void saveCredentials(const string& username, const vector<Credential>& credentials) {
        ensureDataDirectory();
        string filename = Constants::CREDENTIALS_FILE_PREFIX + username + ".dat";
        ofstream file(filename, ios::trunc);
        if (!file.is_open()) {
            throw runtime_error("Cannot open credentials file for writing: " + filename);
        }

        for (const auto& cred : credentials) {
            file << cred.serialize() << "\n";
        }

        file.close();
    }
};

void User::saveCredentialsToFile() const {
    FileManager::saveCredentials(username, credentials);
}

void User::loadCredentialsFromFile() {
    credentials = FileManager::loadCredentials(username);
}

// ============================================================================
// PASSWORD MANAGER CLASS (Main Application)
// ============================================================================
class PasswordManager {
private:
    vector<User> users;
    unique_ptr<User> currentUser;
    bool isRunning = true;
    PasswordGenerator pwdGenerator;

    // Creates default admin and normal users if no users exist in the system
    void initializeDefaultUsers() {
        if (users.empty()) {
            users.push_back(User("admin", "admin123", "admin"));
            users.push_back(User("aymen", "12345678", "normal"));
            try {
                FileManager::saveUsers(users);
            } catch (...) {
            }
            cout << "✅ Default users created (admin/admin123, aymen/12345678)\n";
        }
    }

    // Synchronizes current user changes back to users vector
    void syncCurrentUserToVector() {
        if (!currentUser) return;
        for (auto& user : users) {
            if (user.getUsername() == currentUser->getUsername()) {
                user = *currentUser;
                return;
            }
        }
        // If user not found in vector, add them (shouldn't happen in normal flow)
        users.push_back(*currentUser);
    }

    // Prompts user for yes/no answer with validation
    bool askYesNo(const string &prompt) {
        while (true) {
            cout << prompt;
            char answer;
            if (!(cin >> answer)) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                continue;
            }
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            if (answer == 'y' || answer == 'Y') return true;
            if (answer == 'n' || answer == 'N') return false;
            cout << "❌ Please answer with 'y' or 'n'.\n";
        }
    }

    // Displays category menu and returns selected category
    string selectCategory() {
        cout << "\nSelect Category:\n";
        cout << "1. Website\n";
        cout << "2. Desktop\n";
        cout << "3. Game\n";
        cout << "Choice: ";
        
        int choice = getValidatedInput(1, 3);
        return Constants::VALID_CATEGORIES[choice - 1];
    }

    // Displays user type menu and returns selected type (admin or normal)
    string selectUserType() {
        cout << "\nSelect User Type:\n";
        cout << "1. Admin\n";
        cout << "2. Normal\n";
        cout << "Choice: ";
        
        int choice = getValidatedInput(1, 2);
        return (choice == 1) ? "admin" : "normal";
    }

    // Displays a compact list of credentials (name and category only)
    void listCredentialsCompact() const {
        const auto &creds = currentUser->getCredentials();
        if (creds.empty()) {
            cout << "\nNo credentials found.\n";
            return;
        }
        cout << "\n=== YOUR CREDENTIALS ===\n";
        for (size_t i = 0; i < creds.size(); ++i) {
            cout << "[" << (i + 1) << "] Name: " << creds[i].getName()
                 << " | Category: " << creds[i].getCategory() << "\n";
        }
    }

    // Displays login menu and handles user selection
    void showLoginMenu() {
        cout << "\n" << string(40, '=') << endl;
        cout << "PASSWORD MANAGER - LOGIN MENU" << endl;
        cout << string(40, '=') << endl;
        cout << "1. Login\n2. Register\n3. Exit\n";
        cout << "Choice: ";

        int choice = getValidatedInput(1, 3);

        switch (choice) {
            case 1: login(); break;
            case 2: registerUser(); break;
            case 3: cout << "Goodbye!\n"; isRunning = false; break;
        }
    }

    // Handles user login with maximum attempt limit
    void login() {
        const int MAX_ATTEMPTS = 3;
        int attempts = 0;

        while (attempts < MAX_ATTEMPTS) {
            string username, password;
            cout << "\n--- Login ---\n";
            cout << "Username: ";
            getline(cin, username);
            cout << "Password: ";
            getline(cin, password);

            User* foundUser = nullptr;
            for (auto &user : users) {
                if (user.getUsername() == username) {
                    foundUser = &user;
                    break;
                }
            }

            if (foundUser == nullptr) {
                attempts++;
                cout << "❌ User not found: " << username << ".\n";
                if (attempts < MAX_ATTEMPTS) {
                    cout << "⚠️ Attempt " << attempts << " of " << MAX_ATTEMPTS << ". Please try again.\n";
                }
            } else {
                if (foundUser->verifyPassword(password)) {
                    currentUser = make_unique<User>(*foundUser);
                    currentUser->loadCredentialsFromFile();
                    cout << "✅ Login successful! Welcome, " << username << ".\n";
                    return;
                } else {
                    attempts++;
                    cout << "❌ Invalid password for user: " << username << ".\n";
                    if (attempts < MAX_ATTEMPTS) {
                        cout << "⚠️ Attempt " << attempts << " of " << MAX_ATTEMPTS << ". Please try again.\n";
                    }
                }
            }
        }

        cout << "Maximum login attempts reached. Returning to main menu.\n";
    }

    // Handles new user registration with password validation
    void registerUser() {
        string username, password, userType = "normal";
        cout << "\n--- User Registration ---\n";

        cout << "Enter username: ";
        getline(cin, username);
        username = Utilities::trim(username);

        if (username.empty()) {
            cout << "❌ Username cannot be empty.\n";
            return;
        }

        for (const auto &user : users) {
            if (user.getUsername() == username) {
                cout << "❌ Username already exists!\n";
                return;
            }
        }

        bool generateChoice = askYesNo("\nGenerate random password? (y/n): ");

        if (generateChoice) {
            cout << "Password length (" << Constants::MIN_PASSWORD_LENGTH << "-" << Constants::MAX_PASSWORD_LENGTH << "): ";
            int length = getValidatedInput(Constants::MIN_PASSWORD_LENGTH, Constants::MAX_PASSWORD_LENGTH);

            password = pwdGenerator.generate(length);
            cout << "\nGenerated Password: " << password << endl;
        } else {
            while (true) {
                cout << "Enter password: ";
                getline(cin, password);

                if (Utilities::isStrongPassword(password)) {
                    break;
                } else {
                    cout << "❌ Password must be at least " << Constants::MIN_PASSWORD_LENGTH << " characters long.\n";
                    cout << "Please try again.\n";
                }
            }
        }

        // If an admin is logged in, allow choosing user type
        if (currentUser && currentUser->getUserType() == "admin") {
            userType = selectUserType();
        }

        users.push_back(User(username, password, userType));
        try {
            FileManager::saveUsers(users);
            cout << "✅ Registration successful!";
            if (currentUser && currentUser->getUserType() == "admin") {
                cout << " User '" << username << "' created as " << userType << " user.\n";
            } else {
                cout << " You can now login.\n";
            }
        } catch (const exception& e) {
            cout << "❌ Error saving user: " << e.what() << endl;
        }
    }

    // Displays menu for normal users with credential management options
    void showUserMenu() {
        cout << "\n" << string(40, '=') << endl;
        cout << "USER DASHBOARD - " << currentUser->getUsername() << endl;
        cout << string(40, '=') << endl;
        cout << "1. Add Credential\n2. View All Credentials\n3. Search Credentials\n";
        cout << "4. Edit Credential\n5. Delete Credential\n6. Change Password\n7. Logout\n";
        cout << "Choice: ";

        int choice = getValidatedInput(1, 7);

        switch (choice) {
            case 1: addCredential(); break;
            case 2: viewCredentialsMenu(); break;
            case 3: searchCredentials(); break;
            case 4: editCredential(); break;
            case 5: deleteCredential(); break;
            case 6: changePassword(); break;
            case 7: logout(); break;
        }
    }

    // Displays menu for admin users with additional system management options
    void showAdminMenu() {
        cout << "\n" << string(40, '=') << endl;
        cout << "⚡ ADMIN DASHBOARD" << endl;
        cout << string(40, '=') << endl;
        cout << "1. Credentials\n";
        cout << "2. Users\n";
        cout << "3. System Statistics\n";
        cout << "4. Logout\n";
        cout << "Choice: ";

        int choice = getValidatedInput(1, 4);

        switch (choice) {
            case 1: adminCredentialMenu(); break;
            case 2: adminUserMenu(); break;
            case 3: showSystemStats(); break;
            case 4: logout(); break;
        }
    }

    // Admin submenu for credential management
    void adminCredentialMenu() {
        cout << "\n=== CREDENTIALS ===" << endl;
        cout << "1. Add Credential\n2. View All Credentials\n3. Search Credentials\n";
        cout << "4. Edit Credential\n5. Delete Credential\n6. Back\n";
        cout << "Choice: ";

        int choice = getValidatedInput(1, 6);

        switch (choice) {
            case 1: addCredential(); break;
            case 2: viewCredentialsMenu(); break;
            case 3: searchCredentials(); break;
            case 4: editCredential(); break;
            case 5: deleteCredential(); break;
            case 6: return;
        }

        if (choice != 6) {
            adminCredentialMenu();
        }
    }

    // Admin submenu for user management
    void adminUserMenu() {
        cout << "\n=== USERS ===" << endl;
        cout << "1. Register User\n2. Search User\n3. Edit User\n4. Delete User\n5. Back\n";
        cout << "Choice: ";

        int choice = getValidatedInput(1, 5);

        switch (choice) {
            case 1: registerUser(); break;
            case 2: searchUserMenu(); break;
            case 3: editUser(); break;
            case 4: deleteUser(); break;
            case 5: return;
        }

        if (choice != 5) {
            adminUserMenu();
        }
    }

    // Adds a new credential with optional random password generation
    void addCredential() {
        try {
            string name, password, category;

            cout << "\n--- Add New Credential ---\n";
            cout << "Name: ";
            getline(cin, name);

            bool generateChoice = askYesNo("\nGenerate random password? (y/n): ");

            if (generateChoice) {
                cout << "Password length (" << Constants::MIN_PASSWORD_LENGTH << "-" << Constants::MAX_PASSWORD_LENGTH << "): ";
                int length = getValidatedInput(Constants::MIN_PASSWORD_LENGTH, Constants::MAX_PASSWORD_LENGTH);

                password = pwdGenerator.generate(length);
                cout << "\nGenerated Password: " << password << endl;
                cout << "Strength: " << (length >= 12 ? "Strong" : "Good") << endl;
            } else {
                cout << "Password: ";
                getline(cin, password);
            }

            category = selectCategory();

            Credential newCred(name, password, category);
            currentUser->addCredential(newCred);

            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Credential added successfully!\n";

        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    // Menu for viewing credentials with password reveal option
    void viewCredentialsMenu() {
        cout << "\n=== VIEW ALL CREDENTIALS ===" << endl;
        cout << "1. View masked (passwords hidden)\n2. View with passwords revealed\n3. Back\n";
        cout << "Choice: ";

        int choice = getValidatedInput(1, 3);

        if (choice == 3) return;

        currentUser->viewCredentials(choice == 2);
    }

    // Provides search and sort functionality for credentials
    void searchCredentials() {
        if (currentUser->getCredentialCount() == 0) {
            cout << "\nNo credentials to search.\n";
            return;
        }

        cout << "\n=== SEARCH CREDENTIALS ===" << endl;
        cout << "1. Search by name\n2. Sort by last updated (show all)\n3. Sort by name (show all)\n4. Back\n";
        cout << "Choice: ";

        int choice = getValidatedInput(1, 4);

        switch (choice) {
            case 1: {
                string searchTerm;
                cout << "\nEnter name to search: ";
                getline(cin, searchTerm);
                searchTerm = Utilities::trim(searchTerm);

                if (searchTerm.empty()) {
                    cout << "❌ Search term cannot be empty.\n";
                    return;
                }

                vector<Credential> results = currentUser->searchCredentialsByName(searchTerm);

                if (results.empty()) {
                    cout << "\n❌ No credentials found matching '" << searchTerm << "'.\n";
                    return;
                }

                cout << "\n" << string(60, '=') << endl;
                cout << "SEARCH RESULTS (" << results.size() << " found for '" << searchTerm << "')" << endl;
                cout << string(60, '=') << endl;

                bool reveal = askYesNo("\nReveal passwords? (y/n): ");
                bool showPasswords = reveal;

                for (size_t i = 0; i < results.size(); i++) {
                    try {
                        cout << "\n[" << (i + 1) << " of " << results.size() << "]";
                        results[i].display(showPasswords);
                        if (i < results.size() - 1) {
                            cout << "\n" << string(60, '-') << endl;
                        }
                    } catch (...) {
                    }
                }
                cout << "\n" << string(60, '=') << endl;
                break;
            }
            case 2:
                currentUser->sortByDate();
                cout << "\n✅ Sorted by last updated date. Showing all credentials:\n";
                currentUser->viewCredentials();
                break;
            case 3:
                currentUser->sortByName();
                cout << "\n✅ Sorted by name. Showing all credentials:\n";
                currentUser->viewCredentials();
                break;
            case 4:
                return;
        }

        syncCurrentUserToVector();
    }

    // Allows editing of credential name, password, and category
    void editCredential() {
        if (currentUser->getCredentialCount() == 0) {
            cout << "\nNo credentials to edit.\n";
            return;
        }
        listCredentialsCompact();
        cout << "\nEnter credential number to edit (0 to cancel): ";
        int choice = getValidatedInput(0, currentUser->getCredentialCount());

        if (choice == 0) return;

        Credential* cred = currentUser->getCredentialByIndex(choice - 1);
        if (!cred) {
            cout << "❌ Invalid credential selection.\n";
            return;
        }

        try {
            string newName, newPassword, newCategory;

            cout << "\nEditing: Name = " << cred->getName() << ", Category = " << cred->getCategory() << endl;
            cout << "Leave fields blank to keep current values.\n";

            cout << "New Name: ";
            getline(cin, newName);
            if (!Utilities::trim(newName).empty()) cred->setName(newName);

            bool changePassword = askYesNo("\nChange password? (y/n): ");
            if (changePassword) {
                bool generateChoice = askYesNo("Generate new random password? (y/n): ");

                if (generateChoice) {
                    cout << "Password length (" << Constants::MIN_PASSWORD_LENGTH << "-" << Constants::MAX_PASSWORD_LENGTH << "): ";
                    int length = getValidatedInput(Constants::MIN_PASSWORD_LENGTH, Constants::MAX_PASSWORD_LENGTH);

                    newPassword = pwdGenerator.generate(length);
                    cout << "\nGenerated Password: " << newPassword << endl;
                    cred->updatePassword(newPassword);
                } else {
                    cout << "New Password: ";
                    getline(cin, newPassword);
                    if (!newPassword.empty()) cred->updatePassword(newPassword);
                }
            }
            bool changeCategory = askYesNo("\nChange category? (y/n): ");
            if (changeCategory) {
                newCategory = selectCategory();
                cred->setCategory(newCategory);
            }
            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Credential updated successfully!\n";
        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    // Deletes a credential with confirmation prompt
    void deleteCredential() {
        if (currentUser->getCredentialCount() == 0) {
            cout << "\n📭 No credentials to delete.\n";
            return;
        }
        listCredentialsCompact();
        cout << "\nEnter credential number to delete (0 to cancel): ";
        int choice = getValidatedInput(0, currentUser->getCredentialCount());
        if (choice == 0) return;
        Credential* credToDelete = currentUser->getCredentialByIndex(choice - 1);
        string name = credToDelete->getName();
        string category = credToDelete->getCategory();
        bool confirm = askYesNo("⚠️ Are you sure you want to delete credential (Name: " + name + ", Category: " + category + ")? (y/n): ");
        if (confirm) {
            currentUser->deleteCredential(choice - 1);
            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Credential deleted successfully!\n";
        } else {
            cout << "Deletion cancelled.\n";
        }
    }

    // Allows user to change their own password (requires current password)
    void changePassword() {
        try {
            string currentPwd, newPwd;
            cout << "\n--- Change Password ---\n";
            cout << "Current Password: ";
            getline(cin, currentPwd);
            cout << "New Password: ";
            getline(cin, newPwd);
            currentUser->changePassword(currentPwd, newPwd);
            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Password changed successfully!\n";
        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    // Displays all users in the system (admin only)
    void viewAllUsers() {
        cout << "\n=== SYSTEM USERS ===\n";
        for (size_t i = 0; i < users.size(); i++) {
            cout << "[" << (i + 1) << "] 👤 " << users[i].getUsername()
                 << " | Type: " << users[i].getUserType()
                 << " | Credentials: " << users[i].getCredentialCount() << endl;
        }
    }

    // Provides search and sort functionality for users (admin only)
    void searchUserMenu() {
        if (users.empty()) {
            cout << "\n📭 No users to search.\n";
            return;
        }
        cout << "\n=== SEARCH USERS ===" << endl;
        cout << "1. By username\n2. By credential count\n3. Back\n";
        cout << "Choice: ";
        int choice = getValidatedInput(1, 3);
        switch (choice) {
            case 1: {
                sort(users.begin(), users.end(),
                     [](const User &a, const User &b) {
                         return Utilities::toLower(a.getUsername()) < Utilities::toLower(b.getUsername());
                     });
                cout << "✅ Sorted by username.\n";
                viewAllUsers();
                break;
            }
            case 2: {
                sort(users.begin(), users.end(),
                     [](const User &a, const User &b) {
                         return a.getCredentialCount() > b.getCredentialCount();
                     });
                cout << "✅ Sorted by credential count.\n";
                viewAllUsers();
                break;
            }
            case 3:
                return;
        }
        FileManager::saveUsers(users);
    }

    // Allows admin to edit user properties (username, password, type)
    void editUser() {
        if (users.empty()) {
            cout << "\n📭 No users to edit.\n";
            return;
        }
        viewAllUsers();
        cout << "\nEnter user number to edit (0 to cancel): ";
        int choice = getValidatedInput(0, static_cast<int>(users.size()));
        if (choice == 0) return;
        if (choice < 1 || choice > static_cast<int>(users.size())) {
            cout << "❌ Invalid user selection.\n";
            return;
        }
        User* userToEdit = &users[choice - 1];
        if (currentUser && userToEdit->getUsername() == currentUser->getUsername()) {
            cout << "❌ You cannot edit your own account from here. Use 'Change Password' instead.\n";
            return;
        }
        try {
            string newUsername, newUserType;
            cout << "\nEditing user: " << userToEdit->getUsername() << endl;
            cout << "Leave fields blank to keep current values.\n";
            cout << "New Username: ";
            getline(cin, newUsername);
            if (!Utilities::trim(newUsername).empty()) {
                newUsername = Utilities::trim(newUsername);
                for (const auto& user : users) {
                    if (user.getUsername() == newUsername && &user != userToEdit) {
                        cout << "❌ Username already exists!\n";
                        return;
                    }
                }

                userToEdit->setUsername(newUsername);
                cout << "✅ Username updated to: " << newUsername << endl;
            }
            bool resetPassword = askYesNo("\nReset password? (y/n): ");
            if (resetPassword) {
                bool generateChoice = askYesNo("Generate random password? (y/n): ");
                string newPassword;
                if (generateChoice) {
                    cout << "Password length (" << Constants::MIN_PASSWORD_LENGTH << "-" << Constants::MAX_PASSWORD_LENGTH << "): ";
                    int length = getValidatedInput(Constants::MIN_PASSWORD_LENGTH, Constants::MAX_PASSWORD_LENGTH);
                    newPassword = pwdGenerator.generate(length);
                    cout << "\nGenerated Password: " << newPassword << endl;
                } else {
                    while (true) {
                        cout << "Enter new password: ";
                        getline(cin, newPassword);

                        if (Utilities::isStrongPassword(newPassword)) {
                            break;
                        } else {
                            cout << "❌ Password must be at least " << Constants::MIN_PASSWORD_LENGTH << " characters long.\n";
                        }
                    }
                }
                userToEdit->resetPasswordByAdmin(newPassword);
                for (auto& user : users) {
                    if (user.getUsername() == userToEdit->getUsername()) {
                        user = *userToEdit;
                        break;
                    }
                }
                cout << "✅ Password reset successfully!\n";
            }
            bool changeUserType = askYesNo("\nChange user type? (y/n): ");
            if (changeUserType) {
                newUserType = selectUserType();
                userToEdit->setUserType(newUserType);
                cout << "✅ User type updated to: " << newUserType << endl;
            }
            FileManager::saveUsers(users);
            cout << "✅ User updated successfully!\n";
        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    // Deletes a user and all associated credentials (admin only)
    void deleteUser() {
        if (users.empty()) {
            cout << "\nNo users to delete.\n";
            return;
        }
        viewAllUsers();
        cout << "\nEnter user number to delete (0 to cancel): ";
        int choice = getValidatedInput(0, static_cast<int>(users.size()));
        if (choice == 0) return;
        if (choice < 1 || choice > static_cast<int>(users.size())) {
            cout << "❌ Invalid user selection.\n";
            return;
        }
        User* userToDelete = &users[choice - 1];
        if (currentUser && userToDelete->getUsername() == currentUser->getUsername()) {
            cout << "❌ You cannot delete your own account!\n";
            return;
        }
        string username = userToDelete->getUsername();
        int credentialCount = userToDelete->getCredentialCount();

        string confirmMsg = "⚠️ Are you sure you want to delete user '" + username + "'?\n";
        confirmMsg += "This will also delete " + to_string(credentialCount) + " associated credentials. (y/n): ";
        bool confirm = askYesNo(confirmMsg);
        if (confirm) {
            string filename = Constants::CREDENTIALS_FILE_PREFIX + username + ".dat";
            try {
                fs::remove(filename);
            } catch (...) {
            }
            users.erase(users.begin() + choice - 1);
            FileManager::saveUsers(users);
            cout << "✅ User '" << username << "' and all associated credentials deleted successfully!\n";
        } else {
            cout << "Deletion cancelled.\n";
        }
    }

    // Displays system statistics (total users, credentials, averages)
    void showSystemStats() {
        cout << "\n=== SYSTEM STATISTICS ===\n";
        cout << "Total Users: " << users.size() << endl;
        int totalCredentials = 0;
        int adminCount = 0;
        int normalCount = 0;
        for (const auto& user : users) {
            totalCredentials += user.getCredentialCount();
            if (user.getUserType() == "admin") adminCount++;
            else normalCount++;
        }
        cout << "Admin Users: " << adminCount << endl;
        cout << "Normal Users: " << normalCount << endl;
        cout << "Total Credentials: " << totalCredentials << endl;
        cout << "Average Credentials per User: "
             << (users.empty() ? 0.0 : static_cast<double>(totalCredentials) / users.size()) << endl;
    }

    // Logs out current user and saves all data to files
    void logout() {
        try {
            FileManager::saveUsers(users);
            currentUser.reset();
            cout << "✅ Logged out successfully. Data saved.\n";
        } catch (const exception& e) {
            cout << "❌ Error saving data on logout: " << e.what() << endl;
        }
    }

    // Validates and returns integer input within specified range
    int getValidatedInput(int min, int max) {
        int input;
        string line;
        while (true) {
            if (!getline(cin, line)) {
                cin.clear();
                continue;
            }

            try {
                size_t pos;
                input = stoi(line, &pos);
                string remaining = Utilities::trim(line.substr(pos));
                if (!remaining.empty()) {
                    cout << "❌ Invalid input. Enter a whole number between " 
                         << (min == 0 ? "0" : to_string(min)) << " and " << max << ": ";
                    continue;
                }
                if (input < min || input > max) {
                    cout << "❌ Invalid input. Enter a number between " 
                         << (min == 0 ? "0" : to_string(min)) << " and " << max << ": ";
                    continue;
                }
                return input;
            } catch (...) {
                cout << "❌ Invalid input. Enter a whole number between " 
                     << (min == 0 ? "0" : to_string(min)) << " and " << max << ": ";
            }
        }
    }
public:
    PasswordManager() {
        try {
            FileManager::ensureDataDirectory();
            users = FileManager::loadUsers();
            initializeDefaultUsers();
        } catch (...) {
            initializeDefaultUsers();
        }
    }

    void run() {
        cout << "\n*** WELCOME TO PASSWORD MANAGER ***\n";
        cout << "Secure Credential Management System\n";

        while (isRunning) {
            try {
                if (!currentUser)
                    showLoginMenu();
                else if (currentUser->getUserType() == "admin")
                    showAdminMenu();
                else
                    showUserMenu();
            } catch (const exception& e) {
                cout << "⚠️ Error: " << e.what() << endl;
            }
        }

        // Save on exit
        try {
            FileManager::saveUsers(users);
        } catch (...) {
        }
    }
};

// ============================================================================
// MAIN FUNCTION
// ============================================================================
int main() {
    try {
        PasswordManager app;
        app.run();
    } catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }

    return 0;
}