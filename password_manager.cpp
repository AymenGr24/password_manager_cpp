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

using namespace std;

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================
namespace Constants {
    const vector<string> VALID_CATEGORIES = {"Website", "Desktop", "Game"};
    const int MIN_PASSWORD_LENGTH = 8;
    const int MAX_PASSWORD_LENGTH = 50;
    const string USERS_FILE = "data/users.dat";
    const string CREDENTIALS_FILE_PREFIX = "data/credentials_";
    const string MASTER_KEY = "PasswordManager2024SecureKey!@#";
    const int SALT_SIZE = 16;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
class Utilities {
public:
    static string encrypt(const string &plaintext) {
        string result = plaintext;
        string key = Constants::MASTER_KEY;
        
        // Simple but more secure than XOR - using multiple rounds with different keys
        for (size_t round = 0; round < 3; ++round) {
            for (size_t i = 0; i < result.length(); ++i) {
                char keyChar = key[i % key.length()];
                result[i] = result[i] ^ keyChar ^ (char)((i + round) % 256);
            }
        }
        
        // Add some obfuscation
        string obfuscated;
        for (char c : result) {
            obfuscated += to_string((int)c + 100) + "|";
        }
        
        return obfuscated;
    }
    
    static string decrypt(const string &ciphertext) {
        // Remove obfuscation
        string result;
        istringstream iss(ciphertext);
        string token;
        
        while (getline(iss, token, '|')) {
            if (!token.empty()) {
                try {
                    int val = stoi(token) - 100;
                    result += (char)val;
                } catch (const exception& e) {
                    // If we can't parse, just continue
                    continue;
                }
            }
        }
        
        string key = Constants::MASTER_KEY;
        
        // Reverse the encryption rounds
        for (int round = 2; round >= 0; --round) {
            for (size_t i = 0; i < result.length(); ++i) {
                char keyChar = key[i % key.length()];
                result[i] = result[i] ^ keyChar ^ (char)((i + round) % 256);
            }
        }
        
        return result;
    }

    static time_t getCurrentTimeT() {
        return time(0);
    }

    static bool isValidCategory(const string& category) {
        return find(Constants::VALID_CATEGORIES.begin(), 
                   Constants::VALID_CATEGORIES.end(), category) != Constants::VALID_CATEGORIES.end();
    }

    static bool isStrongPassword(const string& password) {
        return password.length() >= Constants::MIN_PASSWORD_LENGTH;
    }

    static string toLower(const string& str) {
        string lowerStr = str;
        transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
        return lowerStr;
    }

    static string trim(const string& str) {
        size_t start = str.find_first_not_of(" \t\n\r");
        size_t end = str.find_last_not_of(" \t\n\r");
        return (start == string::npos) ? "" : str.substr(start, end - start + 1);
    }
    
    static string generateSalt() {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, 255);
        
        string salt;
        for (int i = 0; i < Constants::SALT_SIZE; ++i) {
            salt += (char)dis(gen);
        }
        
        // Convert to hex string
        ostringstream oss;
        for (unsigned char c : salt) {
            oss << hex << setw(2) << setfill('0') << (int)c;
        }
        return oss.str();
    }
    
    static string hashPassword(const string& password, const string& salt) {
        // Simple but more secure hashing with salt
        string combined = password + salt + Constants::MASTER_KEY;
        
        // Multiple rounds of hashing
        hash<string> hasher;
        size_t hashValue = hasher(combined);
        
        // Additional rounds for security
        for (int i = 0; i < 1000; ++i) {
            string temp = to_string(hashValue) + salt;
            hashValue = hasher(temp);
        }
        
        return to_string(hashValue);
    }
};

// ============================================================================
// CLASS 1: Credential
// ============================================================================
class Credential {
private:
    string id;
    string title;
    string username;
    string encryptedPassword;
    string category;
    time_t dateCreated;
    time_t lastUpdated;

public:
    Credential(string t, string u, string p, string c)
        : title(Utilities::trim(t)), username(Utilities::trim(u)), 
          category(Utilities::trim(c)) {
        
        if (!Utilities::isValidCategory(category)) {
            throw invalid_argument("Invalid category");
        }

        encryptedPassword = Utilities::encrypt(p);
        dateCreated = lastUpdated = Utilities::getCurrentTimeT();
        generateId();
    }

    // For loading from file
    Credential(string i, string t, string u, string p, string c, time_t created, time_t updated)
        : id(i), title(t), username(u), encryptedPassword(p), category(c), 
          dateCreated(created), lastUpdated(updated) {}

private:
    void generateId() {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(1000, 9999);
        id = to_string(dis(gen)) + "_" + to_string(dateCreated);
    }

public:
    // Getters
    string getId() const { return id; }
    string getTitle() const { return title; }
    string getUsername() const { return username; }
    string getCategory() const { return category; }
    time_t getDateCreated() const { return dateCreated; }
    time_t getLastUpdated() const { return lastUpdated; }
    
    string getDecryptedPassword() const { 
        try {
            return Utilities::decrypt(encryptedPassword);
        } catch (const exception& e) {
            return "*** DECRYPTION ERROR ***";
        }
    }

    string getFormattedDateCreated() const {
        char buffer[26];
        ctime_r(&dateCreated, buffer);
        return string(buffer);
    }

    string getFormattedLastUpdated() const {
        char buffer[26];
        ctime_r(&lastUpdated, buffer);
        return string(buffer);
    }

    // Update methods
    void updatePassword(const string &newPass) {
        // No length restriction for credential passwords - they can be any length
        encryptedPassword = Utilities::encrypt(newPass);
        lastUpdated = Utilities::getCurrentTimeT();
    }

    void setTitle(const string &t) { 
        title = Utilities::trim(t); 
        lastUpdated = Utilities::getCurrentTimeT(); 
    }

    void setUsername(const string &u) { 
        username = Utilities::trim(u); 
        lastUpdated = Utilities::getCurrentTimeT(); 
    }

    void setCategory(const string &c) { 
        if (!Utilities::isValidCategory(c)) {
            throw invalid_argument("Invalid category");
        }
        category = Utilities::trim(c); 
        lastUpdated = Utilities::getCurrentTimeT(); 
    }

    // Display
    void display(bool showPassword = false) const {
        cout << "\n" << string(50, '=') << endl;
        cout << title << endl;
        cout << string(50, '=') << endl;
        cout << " Username: " << username << endl;
        cout << " Password: ";
        
        string decryptedPwd = getDecryptedPassword();
        if (showPassword) {
            cout << decryptedPwd << endl;
        } else {
            // Show asterisks for password length, but handle decryption errors
            if (decryptedPwd.find("DECRYPTION ERROR") != string::npos) {
                cout << "***" << endl;
            } else {
                cout << string(decryptedPwd.length(), '*') << endl;
            }
        }
        cout << " Category: " << category;
        cout << "\n Created: " << getFormattedDateCreated();
        cout << " Updated: " << getFormattedLastUpdated();
    }

    // Serialization for file storage
    string serialize() const {
        ostringstream oss;
        // Use ||| as field delimiter to avoid conflict with | in encrypted password
        oss << id << "|||" << title << "|||" << username << "|||" 
            << encryptedPassword << "|||" << category << "|||"
            << dateCreated << "|||" << lastUpdated;
        return oss.str();
    }

    static Credential deserialize(const string& data) {
        // Try new format first (using ||| as delimiter)
        size_t pos = 0;
        vector<string> tokens;
        string delimiter = "|||";
        
        // Check if this is the new format (has ||| delimiter)
        if (data.find(delimiter) != string::npos) {
            // New format: id|||title|||username|||encryptedPassword|||category|||dateCreated|||lastUpdated
            while (pos < data.length()) {
                size_t found = data.find(delimiter, pos);
                if (found == string::npos) {
                    tokens.push_back(data.substr(pos));
                    break;
                }
                tokens.push_back(data.substr(pos, found - pos));
                pos = found + delimiter.length();
            }
            
            if (tokens.size() >= 7) {
                string id = tokens[0];
                string title = tokens[1];
                string username = tokens[2];
                string encryptedPassword = tokens[3];
                string category = tokens[4];
                time_t created = stol(tokens[5]);
                time_t updated = stol(tokens[6]);
                return Credential(id, title, username, encryptedPassword, category, created, updated);
            }
        }
        
        // Old format: use | as delimiter (backward compatibility)
        // The encrypted password contains | characters, so we need to reconstruct it
        istringstream iss(data);
        tokens.clear();
        string token;
        
        // Read all tokens
        while (getline(iss, token, '|')) {
            tokens.push_back(token);
        }
        
        if (tokens.size() < 4) {
            throw runtime_error("Invalid credential data format: insufficient tokens");
        }
        
        string id = tokens[0];
        string title = tokens[1];
        string username = tokens[2];
        string encryptedPassword = tokens[3];
        string category = "Website"; // default
        time_t created = Utilities::getCurrentTimeT();
        time_t updated = Utilities::getCurrentTimeT();
        
        // Find category by looking for valid category names
        size_t categoryIdx = tokens.size();
        for (size_t i = 4; i < tokens.size(); i++) {
            if (find(Constants::VALID_CATEGORIES.begin(), Constants::VALID_CATEGORIES.end(), tokens[i]) != Constants::VALID_CATEGORIES.end()) {
                categoryIdx = i;
                category = tokens[i];
                break;
            }
        }
        
        // Reconstruct encrypted password: join tokens from index 3 to categoryIdx-1
        // If category not found, try to find it before timestamps
        if (categoryIdx < tokens.size()) {
            // Reconstruct password from tokens[3] to tokens[categoryIdx-1]
            encryptedPassword = tokens[3];
            for (size_t i = 4; i < categoryIdx; i++) {
                encryptedPassword += "|" + tokens[i];
            }
            
            // Check for timestamps after category
            // Format: category|created|updated or category|url|created|updated (old format with URL)
            if (categoryIdx + 2 < tokens.size()) {
                // Check if we have URL field (old format) - next token might be URL or timestamp
                // Try to parse as timestamp first
                try {
                    time_t testCreated = stol(tokens[categoryIdx + 1]);
                    time_t testUpdated = stol(tokens[categoryIdx + 2]);
                    if (testCreated > 1000000000 && testUpdated > 1000000000) {
                        // These are timestamps, no URL field
                        created = testCreated;
                        updated = testUpdated;
                    } else if (categoryIdx + 3 < tokens.size()) {
                        // Might have URL field (old format)
                        created = stol(tokens[categoryIdx + 2]);
                        updated = stol(tokens[categoryIdx + 3]);
                    }
                } catch (...) {
                    // Not timestamps, try with URL field (old format)
                    if (categoryIdx + 3 < tokens.size()) {
                        try {
                            created = stol(tokens[categoryIdx + 2]);
                            updated = stol(tokens[categoryIdx + 3]);
                        } catch (...) {
                            // Use defaults
                        }
                    }
                }
            } else if (categoryIdx + 1 < tokens.size()) {
                // Only one token after category, might be timestamp or URL (unlikely)
                try {
                    created = stol(tokens[categoryIdx + 1]);
                    updated = created;
                } catch (...) {
                    // Use defaults
                }
            }
        } else {
            // Category not found, try to reconstruct password by checking for timestamps at the end
            // Old format: id|title|username|pwd_part1|pwd_part2|...|pwd_partN|category|created|updated
            // or with URL: id|title|username|pwd_part1|pwd_part2|...|pwd_partN|category|url|created|updated
            
            // Try to find timestamps (last 2 tokens should be numeric and large)
            if (tokens.size() >= 6) {
                try {
                    time_t testUpdated = stol(tokens[tokens.size() - 1]);
                    time_t testCreated = stol(tokens[tokens.size() - 2]);
                    
                    // If these look like timestamps (reasonable values), use them
                    if (testCreated > 1000000000 && testUpdated > 1000000000) {
                        updated = testUpdated;
                        created = testCreated;
                        
                        // Check if token before timestamps is a valid category
                        if (tokens.size() >= 7) {
                            string possibleCategory = tokens[tokens.size() - 3];
                            if (find(Constants::VALID_CATEGORIES.begin(), Constants::VALID_CATEGORIES.end(), possibleCategory) != Constants::VALID_CATEGORIES.end()) {
                                category = possibleCategory;
                                categoryIdx = tokens.size() - 3;
                            } else if (tokens.size() >= 8) {
                                // Might have URL field (old format), check token before that
                                string possibleCategory2 = tokens[tokens.size() - 4];
                                if (find(Constants::VALID_CATEGORIES.begin(), Constants::VALID_CATEGORIES.end(), possibleCategory2) != Constants::VALID_CATEGORIES.end()) {
                                    category = possibleCategory2;
                                    categoryIdx = tokens.size() - 4;
                                }
                            }
                        }
                        
                        // Reconstruct password up to category
                        encryptedPassword = tokens[3];
                        for (size_t i = 4; i < categoryIdx; i++) {
                            encryptedPassword += "|" + tokens[i];
                        }
                    }
                } catch (...) {
                    // Timestamps not found, reconstruct all tokens from 3 to end as password
                    encryptedPassword = tokens[3];
                    for (size_t i = 4; i < tokens.size(); i++) {
                        encryptedPassword += "|" + tokens[i];
                    }
                }
            } else {
                // Very short format, reconstruct password from remaining tokens
                encryptedPassword = tokens[3];
                for (size_t i = 4; i < tokens.size(); i++) {
                    encryptedPassword += "|" + tokens[i];
                }
            }
        }
        
        return Credential(id, title, username, encryptedPassword, category, created, updated);
    }
};

// ============================================================================
// CLASS 2: PasswordGenerator
// ============================================================================
class PasswordGenerator {
private:
    random_device rd;
    mt19937 generator;

public:
    PasswordGenerator() : generator(rd()) {}

    string generate(int length = 16, bool useUpper = true, bool useLower = true, 
                   bool useNumbers = true, bool useSpecial = true) {
        
        if (length < Constants::MIN_PASSWORD_LENGTH || length > Constants::MAX_PASSWORD_LENGTH) {
            throw invalid_argument("Password length must be between " + 
                                 to_string(Constants::MIN_PASSWORD_LENGTH) + " and " + 
                                 to_string(Constants::MAX_PASSWORD_LENGTH));
        }

        string charSet;
        if (useUpper) charSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (useLower) charSet += "abcdefghijklmnopqrstuvwxyz";
        if (useNumbers) charSet += "0123456789";
        if (useSpecial) charSet += "!@#$%^&*";

        if (charSet.empty()) {
            throw invalid_argument("At least one character type must be selected");
        }

        uniform_int_distribution<size_t> dist(0, charSet.size() - 1);
        string password;
        
        for (int i = 0; i < length; i++) {
            password += charSet[dist(generator)];
        }

        return password;
    }
};

// ============================================================================
// CLASS 3: User
// ============================================================================
class User {
private:
    string username;
    string hashedPassword;
    string salt;
    string userType;
    vector<Credential> credentials;

public:
    User(string u, string p, string type)
        : username(Utilities::trim(u)), userType(type) {
        
        if (username.empty() || p.empty()) {
            throw invalid_argument("Username and password cannot be empty");
        }
        
        salt = Utilities::generateSalt();
        hashedPassword = Utilities::hashPassword(p, salt);
    }

    // For loading from file
    User(string u, string hp, string s, string type, const vector<Credential>& creds)
        : username(u), hashedPassword(hp), salt(s), userType(type), credentials(creds) {}

    string getUsername() const { return username; }
    string getUserType() const { return userType; }
    const vector<Credential>& getCredentials() const { return credentials; }

    void setUsername(const string &u) { username = Utilities::trim(u); }
    void setUserType(const string &type) { userType = type; }

    bool verifyPassword(const string &input) const {
        return hashedPassword == Utilities::hashPassword(input, salt);
    }

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

    void addCredential(const Credential& cred) {
        // Check for duplicate titles
        for (const auto& existing : credentials) {
            if (Utilities::toLower(existing.getTitle()) == Utilities::toLower(cred.getTitle())) {
                throw invalid_argument("A credential with this title already exists");
            }
        }
        credentials.push_back(cred);
    }

    void viewCredentials(bool showPasswords = false) const {
        if (credentials.empty()) {
            cout << "\nNo credentials found.\n";
            return;
        }

        cout << "\n" << string(60, '=') << endl;
        cout << "YOUR CREDENTIALS (" << credentials.size() << " found)" << endl;
        cout << string(60, '=') << endl;
        
        int displayedCount = 0;
        for (size_t i = 0; i < credentials.size(); i++) {
            try {
                cout << "\n[" << (i + 1) << " of " << credentials.size() << "]";
                credentials[i].display(showPasswords);
                displayedCount++;
                
                // Add separator between credentials (except for the last one)
                if (i < credentials.size() - 1) {
                    cout << "\n" << string(60, '-') << endl;
                }
            } catch (const exception& e) {
                cout << "\n❌ Error displaying credential '" << credentials[i].getTitle() 
                     << "': " << e.what() << endl;
                cout << "Skipping this credential...\n";
            }
        }
        cout << "\n" << string(60, '=') << endl;
        cout << "Total: " << displayedCount << " of " << credentials.size() 
             << " credential(s) displayed successfully\n";
        
        if (displayedCount < credentials.size()) {
            cout << "⚠️  " << (credentials.size() - displayedCount) 
                 << " credential(s) could not be displayed due to errors\n";
        }
    }

    void searchCredentials(const string& searchTerm) const {
        if (credentials.empty()) {
            cout << "\n No credentials available to search.\n";
            return;
        }

        string lowerSearch = Utilities::toLower(searchTerm);
        vector<Credential> results;

        for (const auto& cred : credentials) {
            if (Utilities::toLower(cred.getTitle()).find(lowerSearch) != string::npos ||
                Utilities::toLower(cred.getUsername()).find(lowerSearch) != string::npos ||
                Utilities::toLower(cred.getCategory()).find(lowerSearch) != string::npos) {
                results.push_back(cred);
            }
        }

        if (results.empty()) {
            cout << "\n No matching credentials found for '" << searchTerm << "'\n";
            return;
        }

        cout << "\n SEARCH RESULTS (" << results.size() << " found for '" << searchTerm << "')\n";
        for (size_t i = 0; i < results.size(); i++) {
            cout << "\n[" << (i + 1) << "]";
            results[i].display();
        }
    }

    void sortByDate() {
        sort(credentials.begin(), credentials.end(),
             [](const Credential &a, const Credential &b) {
                 return a.getLastUpdated() > b.getLastUpdated();
             });
    }

    void sortByTitle() {
        sort(credentials.begin(), credentials.end(),
             [](const Credential &a, const Credential &b) {
                 return Utilities::toLower(a.getTitle()) < Utilities::toLower(b.getTitle());
             });
    }

    int getCredentialCount() const { return credentials.size(); }

    Credential* getCredentialByIndex(int index) {
        if (index < 0 || index >= (int)credentials.size()) return nullptr;
        return &credentials[index];
    }

    void deleteCredential(int index) {
        if (index < 0 || index >= (int)credentials.size()) {
            throw out_of_range("Invalid credential index");
        }
        credentials.erase(credentials.begin() + index);
    }

    // Serialization
    string serialize() const {
        ostringstream oss;
        oss << username << "|" << hashedPassword << "|" << salt << "|" << userType;
        return oss.str();
    }

    static User deserialize(const string& data, const vector<Credential>& creds) {
        istringstream iss(data);
        string username, hashedPassword, salt, userType;
        
        getline(iss, username, '|');
        getline(iss, hashedPassword, '|');
        
        // Check if salt field exists (backward compatibility)
        string temp;
        getline(iss, temp, '|');
        if (getline(iss, userType, '|')) {
            // New format: username|hashedPassword|salt|userType
            salt = temp;
        } else {
            // Old format: username|hashedPassword|userType
            userType = temp;
            salt = Utilities::generateSalt(); // Generate new salt for old users
        }

        return User(username, hashedPassword, salt, userType, creds);
    }

    void saveCredentialsToFile() const;
    void loadCredentialsFromFile();
};

// ============================================================================
// CLASS 4: FileManager
// ============================================================================
class FileManager {
public:
    static vector<User> loadUsers() {
        vector<User> users;
        ifstream file(Constants::USERS_FILE);
        
        if (!file.is_open()) {
            return users; // Return empty vector if file doesn't exist
        }

        string line;
        while (getline(file, line)) {
            if (!line.empty()) {
                try {
                    User user = User::deserialize(line, {});
                    user.loadCredentialsFromFile();
                    users.push_back(user);
                } catch (const exception& e) {
                    cerr << "❌ Error loading user: " << e.what() << endl;
                }
            }
        }
        
        file.close();
        return users;
    }

    static void saveUsers(const vector<User>& users) {
        ofstream file(Constants::USERS_FILE);
        
        if (!file.is_open()) {
            throw runtime_error("Cannot open users file for writing");
        }

        for (const auto& user : users) {
            file << user.serialize() << endl;
            user.saveCredentialsToFile();
        }
        
        file.close();
    }

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
                } catch (const exception& e) {
                    cerr << "❌ Error loading credential for " << username << ": " << e.what() << endl;
                }
            }
        }
        
        file.close();
        return credentials;
    }

    static void saveCredentials(const string& username, const vector<Credential>& credentials) {
        string filename = Constants::CREDENTIALS_FILE_PREFIX + username + ".dat";
        ofstream file(filename);
        
        if (!file.is_open()) {
            throw runtime_error("Cannot open credentials file for writing");
        }

        for (const auto& cred : credentials) {
            file << cred.serialize() << endl;
        }
        
        file.close();
    }
};

// Implement these after FileManager definition
void User::saveCredentialsToFile() const {
    FileManager::saveCredentials(username, credentials);
}

void User::loadCredentialsFromFile() {
    credentials = FileManager::loadCredentials(username);
}

// ============================================================================
// CLASS 5: PasswordManager (Main Application)
// ============================================================================
class PasswordManager {
private:
    vector<User> users;
    unique_ptr<User> currentUser;
    bool isRunning = true;
    PasswordGenerator pwdGenerator;

    void initializeDefaultUsers() {
        // Only create default users if no users exist
        if (users.empty()) {
            users.push_back(User("admin", "admin123", "admin"));
            users.push_back(User("aymen", "12345678", "normal"));
            cout << "✅ Default users created (admin/admin123, aymen/12345678)\n";
        }
    }

    void syncCurrentUserToVector() {
        // Update the current user in the users vector
        for (auto& user : users) {
            if (user.getUsername() == currentUser->getUsername()) {
                user = *currentUser;
                break;
            }
        }
    }

    // Yes/No helper that normalizes input handling
    bool askYesNo(const string &prompt) {
        while (true) {
            cout << prompt;
            char answer;
            cin >> answer;
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            if (answer == 'y' || answer == 'Y') return true;
            if (answer == 'n' || answer == 'N') return false;
            cout << "❌ Please answer with 'y' or 'n'.\n";
        }
    }

    // Compact credentials list for selection screens
    void listCredentialsCompact() const {
        const auto &creds = currentUser->getCredentials();
        if (creds.empty()) {
            cout << "\nNo credentials found.\n";
            return;
        }
        cout << "\n=== YOUR CREDENTIALS ===\n";
        for (size_t i = 0; i < creds.size(); ++i) {
            cout << "[" << (i + 1) << "] " << creds[i].getTitle() 
                 << " | " << creds[i].getUsername() 
                 << " | " << creds[i].getCategory() << "\n";
        }
    }

    void showLoginMenu() {
        cout << "\n" << string(40, '=') << endl;
        cout << "PASSWORD MANAGER - LOGIN MENU" << endl;
        cout << string(40, '=') << endl;
        cout << "1. Login\n2. Exit\n";
        cout << "Choice: ";
        
        int choice = getValidatedInput(1, 2);

        switch (choice) {
            case 1: login(); break;
            case 2: cout << "Goodbye!\n"; isRunning = false; break;
        }
    }

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

            // Check if user exists
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
                // User exists, check password
                if (foundUser->verifyPassword(password)) {
                    currentUser = make_unique<User>(*foundUser);
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
        
        cout << " Maximum login attempts reached. Returning to main menu.\n";
    }

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

        // Check if username exists
        for (const auto &user : users) {
            if (user.getUsername() == username) {
                cout << "❌ Username already exists!\n";
                return;
            }
        }

        // Ask if admin wants to generate a random password
        bool generateChoice = askYesNo("\nGenerate random password? (y/n): ");
        
        if (generateChoice) {
            // Generate random password
            cout << "Password length (" << Constants::MIN_PASSWORD_LENGTH << "-" << Constants::MAX_PASSWORD_LENGTH << "): ";
            int length = getValidatedInput(Constants::MIN_PASSWORD_LENGTH, Constants::MAX_PASSWORD_LENGTH);
            
            password = pwdGenerator.generate(length);
            cout << "\nGenerated Password: " << password << endl;
        } else {
            // Manual password input with retry
            while (true) {
                cout << "Enter password: ";
                getline(cin, password);

                if (Utilities::isStrongPassword(password)) {
                    break; // Valid password, exit loop
                } else {
                    cout << "❌ Password must be at least " << Constants::MIN_PASSWORD_LENGTH << " characters long.\n";
                    cout << "Please try again.\n";
                }
            }
        }

        // If admin is registering, allow them to specify user type
        if (currentUser && currentUser->getUserType() == "admin") {
            while (true) {
                cout << "User type (admin/normal): ";
                getline(cin, userType);
                if (userType == "admin" || userType == "normal") {
                    break;
                } else {
                    cout << "❌ Invalid user type! Must be 'admin' or 'normal'.\n";
                }
            }
        }

        users.push_back(User(username, password, userType));
        FileManager::saveUsers(users);
        cout << "✅ Registration successful!";
        if (currentUser && currentUser->getUserType() == "admin") {
            cout << " User '" << username << "' created as " << userType << " user.\n";
        } else {
            cout << " You can now login.\n";
        }
    }

    void showUserMenu() {
        cout << "\n" << string(40, '=') << endl;
        cout << "USER DASHBOARD - " << currentUser->getUsername() << endl;
        cout << string(40, '=') << endl;
        cout << "1. Add Credential\n2. View All Credentials\n3. Search Credentials\n";
        cout << "4. Edit Credential\n5. Delete Credential\n6. Logout\n";
        cout << "Choice: ";
        
        int choice = getValidatedInput(1, 6);

        switch (choice) {
            case 1: addCredential(); break;
            case 2: viewCredentialsMenu(); break;
            case 3: searchCredentials(); break;
            case 4: editCredential(); break;
            case 5: deleteCredential(); break;
            case 6: logout(); break;
        }
    }

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
        
        // Show menu again after action (except back)
        if (choice != 6) {
            adminCredentialMenu();
        }
    }

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
        
        // Show menu again after action (except back)
        if (choice != 5) {
            adminUserMenu();
        }
    }

    void addCredential() {
        try {
            string title, username, password, category;

            cout << "\n--- Add New Credential ---\n";
            cout << "Title: ";
            getline(cin, title);
            
            cout << "Username: ";
            getline(cin, username);
            
            // Ask if user wants to generate a random password
            bool generateChoice = askYesNo("\nGenerate random password? (y/n): ");
            
            if (generateChoice) {
                // Generate random password
                cout << "Password length (" << Constants::MIN_PASSWORD_LENGTH << "-" << Constants::MAX_PASSWORD_LENGTH << "): ";
                int length = getValidatedInput(Constants::MIN_PASSWORD_LENGTH, Constants::MAX_PASSWORD_LENGTH);
                
                password = pwdGenerator.generate(length);
                cout << "\nGenerated Password: " << password << endl;
                cout << "Strength: " << (length >= 12 ? "Strong" : "Good") << endl;
            } else {
                // Manual password input - no length restriction for credential passwords
                cout << "Password: ";
                getline(cin, password);
            }

            // Category input with retry
            while (true) {
                cout << "Category (Website/Desktop/Game): ";
                getline(cin, category);
                
                if (Utilities::isValidCategory(category)) {
                    break; // Valid category, exit loop
                } else {
                    cout << "❌ Invalid category! Must be Website, Desktop, or Game.\n";
                    cout << "Please try again.\n";
                }
            }

            Credential newCred(title, username, password, category);
            currentUser->addCredential(newCred);
            
            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Credential added successfully!\n";

        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    void viewCredentialsMenu() {
        cout << "\n=== VIEW ALL CREDENTIALS ===" << endl;
        cout << "1. View masked (passwords hidden)\n2. View with passwords revealed\n3. Back\n";
        cout << "Choice: ";
        
        int choice = getValidatedInput(1, 3);
        
        if (choice == 3) return;
        
        currentUser->viewCredentials(choice == 2);
    }

    void searchCredentials() {
        if (currentUser->getCredentialCount() == 0) {
            cout << "\nNo credentials to search.\n";
            return;
        }

        cout << "\n=== SEARCH CREDENTIALS ===" << endl;
        cout << "1. Sort by last updated (show all)\n2. Sort by title (show all)\n3. Back\n";
        cout << "Choice: ";
        
        int choice = getValidatedInput(1, 3);
        
        switch (choice) {
            case 1: 
                currentUser->sortByDate();
                cout << "\n✅ Sorted by last updated date. Showing all credentials:\n";
                currentUser->viewCredentials();
                break;
            case 2:
                currentUser->sortByTitle();
                cout << "\n✅ Sorted by title. Showing all credentials:\n";
                currentUser->viewCredentials();
                break;
            case 3:
                return;
        }
        
        syncCurrentUserToVector();
    }

    void editCredential() {
        if (currentUser->getCredentialCount() == 0) {
            cout << "\nNo credentials to edit.\n";
            return;
        }

        // Show a compact list for better readability
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
            string newTitle, newUsername, newPassword, newCategory;

            cout << "\nEditing: " << cred->getTitle() << endl;
            cout << "Leave fields blank to keep current values.\n";

            cout << "New Title: ";
            getline(cin, newTitle);
            if (!newTitle.empty()) cred->setTitle(newTitle);

            cout << "New Username: ";
            getline(cin, newUsername);
            if (!newUsername.empty()) cred->setUsername(newUsername);

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

            // Always ask about category
            bool changeCategory = askYesNo("\nChange category? (y/n): ");
            if (changeCategory) {
                // Category input with retry - same validation as add credential
                while (true) {
                    cout << "New Category (Website/Desktop/Game): ";
                    getline(cin, newCategory);
                    
                    if (Utilities::isValidCategory(newCategory)) {
                        cred->setCategory(newCategory);
                        break; // Valid category, exit loop
                    } else {
                        cout << "❌ Invalid category! Must be Website, Desktop, or Game.\n";
                        cout << "Please try again.\n";
                    }
                }
            }

            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Credential updated successfully!\n";

        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    void deleteCredential() {
        if (currentUser->getCredentialCount() == 0) {
            cout << "\n📭 No credentials to delete.\n";
            return;
        }

        listCredentialsCompact();
        cout << "\nEnter credential number to delete (0 to cancel): ";
        int choice = getValidatedInput(0, currentUser->getCredentialCount());
        
        if (choice == 0) return;

        string title = currentUser->getCredentialByIndex(choice - 1)->getTitle();
        bool confirm = askYesNo("⚠️ Are you sure you want to delete '" + title + "'? (y/n): ");
        
        if (confirm) {
            currentUser->deleteCredential(choice - 1);
            
            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Credential deleted successfully!\n";
        } else {
            cout << "Deletion cancelled.\n";
        }
    }

    void changePassword() {
        try {
            string currentPwd, newPwd;
            cout << "\n--- Change Password ---\n";
            cout << "Current Password: ";
            getline(cin, currentPwd);
            
            cout << "New Password: ";
            getline(cin, newPwd);

            // Update current user
            currentUser->changePassword(currentPwd, newPwd);
            
            syncCurrentUserToVector();
            FileManager::saveUsers(users);
            cout << "✅ Password changed successfully!\n";
            
        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    void viewAllUsers() {
        cout << "\n=== SYSTEM USERS ===\n";
        for (size_t i = 0; i < users.size(); i++) {
            cout << "[" << (i + 1) << "] 👤 " << users[i].getUsername() 
                 << " | Type: " << users[i].getUserType()
                 << " | Credentials: " << users[i].getCredentialCount() << endl;
        }
    }

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
                // Sort by username alphabetically
                sort(users.begin(), users.end(),
                     [](const User &a, const User &b) {
                         return Utilities::toLower(a.getUsername()) < Utilities::toLower(b.getUsername());
                     });
                cout << "✅ Sorted by username.\n";
                viewAllUsers();
                break;
            }
            case 2: {
                // Sort by credential count (descending)
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

    void editUser() {
        if (users.empty()) {
            cout << "\n📭 No users to edit.\n";
            return;
        }

        viewAllUsers();
        cout << "\nEnter user number to edit (0 to cancel): ";
        int choice = getValidatedInput(0, (int)users.size());
        
        if (choice == 0) return;
        if (choice < 1 || choice > (int)users.size()) {
            cout << "❌ Invalid user selection.\n";
            return;
        }

        User* userToEdit = &users[choice - 1];
        
        // Prevent admin from editing themselves
        if (userToEdit->getUsername() == currentUser->getUsername()) {
            cout << "❌ You cannot edit your own account from here. Use 'Change Password' instead.\n";
            return;
        }

        try {
            string newUsername, newUserType;
            
            cout << "\nEditing user: " << userToEdit->getUsername() << endl;
            cout << "Leave fields blank to keep current values.\n";

            cout << "New Username: ";
            getline(cin, newUsername);
            if (!newUsername.empty()) {
                newUsername = Utilities::trim(newUsername);
                
                // Check if new username already exists
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
                    // Manual password input with retry
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
                
                // Reset password using admin method
                userToEdit->resetPasswordByAdmin(newPassword);
                
                // Update in users vector
                for (auto& user : users) {
                    if (user.getUsername() == userToEdit->getUsername()) {
                        user = *userToEdit;
                        break;
                    }
                }
                
                cout << "✅ Password reset successfully!\n";
            }

            cout << "New User Type (admin/normal): ";
            getline(cin, newUserType);
            if (!newUserType.empty()) {
                if (newUserType == "admin" || newUserType == "normal") {
                    userToEdit->setUserType(newUserType);
                    cout << "✅ User type updated to: " << newUserType << endl;
                } else {
                    cout << "❌ Invalid user type! Must be 'admin' or 'normal'.\n";
                    return;
                }
            }

            FileManager::saveUsers(users);
            cout << "✅ User updated successfully!\n";

        } catch (const exception& e) {
            cout << "❌ Error: " << e.what() << endl;
        }
    }

    void deleteUser() {
        if (users.empty()) {
            cout << "\n No users to delete.\n";
            return;
        }

        viewAllUsers();
        cout << "\nEnter user number to delete (0 to cancel): ";
        int choice = getValidatedInput(0, (int)users.size());
        
        if (choice == 0) return;
        if (choice < 1 || choice > (int)users.size()) {
            cout << "❌ Invalid user selection.\n";
            return;
        }

        User* userToDelete = &users[choice - 1];
        
        // Prevent admin from deleting themselves
        if (userToDelete->getUsername() == currentUser->getUsername()) {
            cout << "❌ You cannot delete your own account!\n";
            return;
        }

        string username = userToDelete->getUsername();
        int credentialCount = userToDelete->getCredentialCount();
        
        string confirmMsg = "⚠️ Are you sure you want to delete user '" + username + "'?\n";
        confirmMsg += "This will also delete " + to_string(credentialCount) + " associated credentials. (y/n): ";
        bool confirm = askYesNo(confirmMsg);
        
        if (confirm) {
            // Delete user's credential file
            string filename = Constants::CREDENTIALS_FILE_PREFIX + username + ".dat";
            remove(filename.c_str());
            
            // Remove user from vector
            users.erase(users.begin() + choice - 1);
            
            FileManager::saveUsers(users);
            cout << "✅ User '" << username << "' and all associated credentials deleted successfully!\n";
        } else {
            cout << "Deletion cancelled.\n";
        }
    }

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
             << (users.empty() ? 0 : (double)totalCredentials / users.size()) << endl;
    }

    void logout() {
        FileManager::saveUsers(users);
        currentUser.reset();
        cout << "✅ Logged out successfully. Data saved.\n";
    }

    int getValidatedInput(int min, int max) {
        int input;
        while (true) {
            cin >> input;
            if (cin.fail() || input < min || input > max) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                // Show human-friendly range: include 0 only when allowed
                if (min == 0) {
                    cout << "❌ Invalid input. Enter a number between 0 and " << max << ": ";
                } else {
                    cout << "❌ Invalid input. Enter a number between " << min << " and " << max << ": ";
                }
            } else {
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                return input;
            }
        }
    }

public:
    PasswordManager() {
        try {
            users = FileManager::loadUsers();
            initializeDefaultUsers();
        } catch (const exception& e) {
            cerr << "❌ Error loading data: " << e.what() << endl;
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
                cout << "❌ Unexpected error: " << e.what() << endl;
            }
        }
        
        // Save on exit
        FileManager::saveUsers(users);
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
        cerr << "Critical error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}