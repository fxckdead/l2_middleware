#include "auth_login_packet.hpp"
#include "../responses/init_packet.hpp"
#include "../../../core/encryption/rsa_manager.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <random>

// Constructor
AuthLoginPacket::AuthLoginPacket(const std::string &username, const std::string &password)
    : m_username(username), m_password(password), m_isNewAuth(false)
{
}

// ReadablePacket interface implementation
uint8_t AuthLoginPacket::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> AuthLoginPacket::getExPacketId() const
{
    return std::nullopt;
}

void AuthLoginPacket::read(ReadablePacketBuffer &buffer)
{
    // This method would be used for reading from network buffer
    // For RSA decrypted data, use fromRsaDecryptedData instead
    throw PacketException("AuthLoginPacket::read() not implemented - use fromRsaDecryptedData()");
}

// Factory method for RSA decrypted data (primary use case)
AuthLoginPacket AuthLoginPacket::fromRsaDecryptedData(const std::vector<uint8_t> &decryptedData)
{
    auto [username, password] = extractCredentials(decryptedData);

    AuthLoginPacket packet(username, password);
    packet.m_isNewAuth = decryptedData.size() >= 256;

    return packet;
}

// Extract credentials from raw decrypted bytes (matches Rust read_bytes function)
std::pair<std::string, std::string> AuthLoginPacket::extractCredentials(const std::vector<uint8_t> &data)
{
    bool isNewAuth = data.size() >= 256;
    std::string username;
    std::string password;

    if (isNewAuth)
    {
        // New auth format (256 bytes)
        // Username is split into two parts: 0x4E + 0xCE
        std::string part1 = extractStringFromBytes(data, 0x4E, 50); // 0x4E..0x4E+50
        std::string part2 = extractStringFromBytes(data, 0xCE, 14); // 0xCE..0xCE+14

        username = trimNullBytes(part1) + trimNullBytes(part2);
        password = trimNullBytes(extractStringFromBytes(data, 0xDC, 16)); // 0xDC..0xDC+16
    }
    else
    {
        // Old auth format (128 bytes)
        username = trimNullBytes(extractStringFromBytes(data, 0x5E, 14)); // 0x5E..0x5E+14
        password = trimNullBytes(extractStringFromBytes(data, 0x6C, 16)); // 0x6C..0x6C+16
    }

    return std::make_pair(username, password);
}

// Validation
bool AuthLoginPacket::isValid() const
{
    return !m_username.empty() && !m_password.empty() &&
           m_username.length() <= 64 && m_password.length() <= 32;
}

// Helper functions for credential extraction
std::string AuthLoginPacket::extractStringFromBytes(const std::vector<uint8_t> &data,
                                                    size_t offset, size_t maxLength)
{
    if (offset >= data.size())
    {
        return "";
    }

    size_t endPos = std::min(offset + maxLength, data.size());
    std::string result;
    result.reserve(maxLength);

    // Extract bytes as string (assuming UTF-8/ASCII encoding)
    for (size_t i = offset; i < endPos; ++i)
    {
        if (data[i] == 0)
        {
            break; // Stop at null terminator
        }
        result += static_cast<char>(data[i]);
    }

    return result;
}

std::string AuthLoginPacket::trimNullBytes(const std::string &str)
{
    // Remove null bytes and whitespace from both ends
    size_t start = 0;
    size_t end = str.length();

    // Find first non-null, non-whitespace character
    while (start < end && (str[start] == '\0' || std::isspace(str[start])))
    {
        ++start;
    }

    // Find last non-null, non-whitespace character
    while (end > start && (str[end - 1] == '\0' || std::isspace(str[end - 1])))
    {
        --end;
    }

    return str.substr(start, end - start);
}

// Test function
void AuthLoginPacket::runTests()
{
    std::cout << "\n=== Testing AuthLoginPacket ===" << std::endl;

    bool allPassed = true;

    // Test 1: New auth format (EXACT Rust test data)
    std::cout << "Test 1: New auth format extraction" << std::endl;
    {
        // EXACT test data from Rust test_read_bytes_login()
        std::vector<uint8_t> loginBytes = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 0, 0, 97, 100, 109, 105, 110, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1};

        try
        {
            AuthLoginPacket packet = AuthLoginPacket::fromRsaDecryptedData(loginBytes);

            if (packet.getUsername() == "admin" &&
                packet.getPassword() == "admin" &&
                packet.isNewAuthFormat() &&
                packet.isValid())
            {
                std::cout << "  ✅ Test 1 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 1 FAILED!" << std::endl;
                std::cout << "    Username: '" << packet.getUsername() << "' (expected 'admin')" << std::endl;
                std::cout << "    Password: '" << packet.getPassword() << "' (expected 'admin')" << std::endl;
                std::cout << "    IsNewAuth: " << packet.isNewAuthFormat() << " (expected true)" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 1 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 2: Old auth format
    std::cout << "\nTest 2: Old auth format extraction" << std::endl;
    {
        // Create 128-byte old format data with "test"/"pass"
        std::vector<uint8_t> oldAuthData(128, 0);

        // Place "test" at offset 0x5E
        const char *testUser = "test";
        std::memcpy(&oldAuthData[0x5E], testUser, strlen(testUser));

        // Place "pass" at offset 0x6C
        const char *testPass = "pass";
        std::memcpy(&oldAuthData[0x6C], testPass, strlen(testPass));

        try
        {
            AuthLoginPacket packet = AuthLoginPacket::fromRsaDecryptedData(oldAuthData);

            if (packet.getUsername() == "test" &&
                packet.getPassword() == "pass" &&
                !packet.isNewAuthFormat() &&
                packet.isValid())
            {
                std::cout << "  ✅ Test 2 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 2 FAILED!" << std::endl;
                std::cout << "    Username: '" << packet.getUsername() << "' (expected 'test')" << std::endl;
                std::cout << "    Password: '" << packet.getPassword() << "' (expected 'pass')" << std::endl;
                std::cout << "    IsNewAuth: " << packet.isNewAuthFormat() << " (expected false)" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 2 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 3: Extract credentials function directly
    std::cout << "\nTest 3: Direct credential extraction" << std::endl;
    {
        // Simple test data
        std::vector<uint8_t> testData(256, 0);

        // Set up new auth format data
        const char *user1 = "user";
        const char *user2 = "name";
        const char *passwd = "secret";

        std::memcpy(&testData[0x4E], user1, strlen(user1));
        std::memcpy(&testData[0xCE], user2, strlen(user2));
        std::memcpy(&testData[0xDC], passwd, strlen(passwd));

        auto [username, password] = AuthLoginPacket::extractCredentials(testData);

        if (username == "username" && password == "secret")
        {
            std::cout << "  ✅ Test 3 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 3 FAILED!" << std::endl;
            std::cout << "    Username: '" << username << "' (expected 'username')" << std::endl;
            std::cout << "    Password: '" << password << "' (expected 'secret')" << std::endl;
            allPassed = false;
        }
    }

    // Test 4: Validation
    std::cout << "\nTest 4: Validation tests" << std::endl;
    {
        // Valid packet
        AuthLoginPacket validPacket("validuser", "validpass");

        // Invalid packets
        AuthLoginPacket emptyUser("", "password");
        AuthLoginPacket emptyPass("username", "");
        AuthLoginPacket tooLongUser(std::string(70, 'x'), "password");

        if (validPacket.isValid() &&
            !emptyUser.isValid() &&
            !emptyPass.isValid() &&
            !tooLongUser.isValid())
        {
            std::cout << "  ✅ Test 4 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 4 FAILED! Validation logic incorrect" << std::endl;
            allPassed = false;
        }
    }

    // Overall result
    if (allPassed)
    {
        std::cout << "\n🎉 ALL AuthLoginPacket tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some AuthLoginPacket tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}

// Demo function showing L2 authentication flow
void AuthLoginPacket::demoL2AuthFlow()
{
    std::cout << "\n=== L2 Authentication Flow Demo ===" << std::endl;

    try
    {
        // Step 1: Server creates RSA keys and Blowfish key
        std::cout << "Step 1: Server generates RSA keys and Blowfish key" << std::endl;
        RSAManager rsaManager(1);
        const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

        // Generate random Blowfish key
        std::vector<uint8_t> blowfishKey(16);
        std::random_device rd;
        std::mt19937 gen(rd());
        for (auto &byte : blowfishKey)
        {
            byte = static_cast<uint8_t>(gen() & 0xFF);
        }

        int32_t sessionId = static_cast<int32_t>(gen());

        // Step 2: Server sends Init packet to client
        std::cout << "Step 2: Server creates Init packet" << std::endl;
        InitPacket initPacket(sessionId, rsaPair, blowfishKey);
        auto initData = initPacket.serialize();
        std::cout << "  Init packet size: " << initData.size() << " bytes" << std::endl;
        std::cout << "  Contains scrambled RSA modulus and Blowfish key" << std::endl;

        // Step 3: Client creates login credentials (simulate)
        std::cout << "\nStep 3: Client prepares login credentials" << std::endl;
        std::string username = "testuser";
        std::string password = "testpass";
        std::cout << "  Username: '" << username << "'" << std::endl;
        std::cout << "  Password: '" << password << "'" << std::endl;

        // Step 4: Simulate client RSA encryption (create fake encrypted data)
        std::cout << "\nStep 4: Client would RSA encrypt credentials..." << std::endl;
        std::cout << "  (In real flow, client encrypts with server's public RSA key)" << std::endl;

        // Create simulated decrypted data (what server would get after RSA decryption)
        std::vector<uint8_t> simulatedDecrypted(256, 0);

        // Place username in new auth format locations
        std::memcpy(&simulatedDecrypted[0x4E], username.c_str(), username.length());
        std::memcpy(&simulatedDecrypted[0xDC], password.c_str(), password.length());

        // Step 5: Server receives and decrypts login packet
        std::cout << "\nStep 5: Server RSA decrypts and parses login packet" << std::endl;
        AuthLoginPacket authPacket = AuthLoginPacket::fromRsaDecryptedData(simulatedDecrypted);

        std::cout << "  Extracted username: '" << authPacket.getUsername() << "'" << std::endl;
        std::cout << "  Extracted password: '" << authPacket.getPassword() << "'" << std::endl;
        std::cout << "  Auth format: " << (authPacket.isNewAuthFormat() ? "New (256-byte)" : "Old (128-byte)") << std::endl;
        std::cout << "  Packet valid: " << (authPacket.isValid() ? "Yes" : "No") << std::endl;

        // Step 6: Server can now validate credentials
        std::cout << "\nStep 6: Server validates credentials" << std::endl;
        if (authPacket.getUsername() == username && authPacket.getPassword() == password)
        {
            std::cout << "  ✅ Authentication successful!" << std::endl;
            std::cout << "  Server would now send LoginOk or ServerList packet" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Authentication failed!" << std::endl;
        }

        std::cout << "\n🎉 L2 Authentication Flow Demo completed successfully!" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << "❌ Demo failed with exception: " << e.what() << std::endl;
    }

    std::cout << std::endl;
}

// Debug helper to verify Rust test data positions
void AuthLoginPacket::debugRustTestData()
{
    // EXACT Rust test data from test_read_bytes_login
    std::vector<uint8_t> rustData = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 0, 0, 97, 100, 109, 105, 110, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1};

    std::cout << "=== Rust Test Data Debug ===" << std::endl;
    std::cout << "Data size: " << rustData.size() << " bytes" << std::endl;

    // Check position 0x4E (78)
    std::cout << "At 0x4E (78): ";
    for (int i = 0; i < 10; ++i)
    {
        if (78 + i < rustData.size())
        {
            std::cout << static_cast<int>(rustData[78 + i]) << " ";
        }
    }
    std::cout << std::endl;

    // Check position 0xCE (206)
    std::cout << "At 0xCE (206): ";
    for (int i = 0; i < 10; ++i)
    {
        if (206 + i < rustData.size())
        {
            std::cout << static_cast<int>(rustData[206 + i]) << " ";
        }
    }
    std::cout << std::endl;

    // Check position 0xDC (220)
    std::cout << "At 0xDC (220): ";
    for (int i = 0; i < 10; ++i)
    {
        if (220 + i < rustData.size())
        {
            std::cout << static_cast<int>(rustData[220 + i]) << " ";
        }
    }
    std::cout << std::endl;

    // Test our extraction
    auto [username, password] = AuthLoginPacket::extractCredentials(rustData);
    std::cout << "Extracted username: '" << username << "'" << std::endl;
    std::cout << "Extracted password: '" << password << "'" << std::endl;
    std::cout << std::endl;
}