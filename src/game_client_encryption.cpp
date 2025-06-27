#include "game_client_encryption.hpp"
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <algorithm>

// Helper function to convert bytes to uint32_t (Little Endian)
uint32_t GameClientEncryption::bytes_to_uint32_le(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

// Helper function to convert uint32_t to bytes (Little Endian)
void GameClientEncryption::uint32_to_bytes_le(uint32_t value, uint8_t *bytes)
{
    bytes[0] = static_cast<uint8_t>(value & 0xFF);
    bytes[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    bytes[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    bytes[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

// Constructor (matches Rust GameClientEncryption::new)
GameClientEncryption::GameClientEncryption(const std::vector<uint8_t> &key) : is_enabled(false)
{
    if (key.size() != 16)
    {
        throw std::runtime_error("Key must be 16 bytes");
    }

    // Copy key to both in_key and out_key (matches Rust behavior)
    std::copy(key.begin(), key.end(), in_key.begin());
    std::copy(key.begin(), key.end(), out_key.begin());
}

// Decrypt incoming packets (matches Rust decrypt)
bool GameClientEncryption::decrypt(std::vector<uint8_t> &data)
{
    if (!is_enabled)
    {
        is_enabled = true;
        return true; // First packet is unencrypted
    }

    uint8_t x_or = 0;
    for (size_t i = 0; i < data.size(); ++i)
    {
        uint8_t encrypted = data[i];
        data[i] ^= in_key[i & 15] ^ x_or;
        x_or = encrypted;
    }

    // Shift key efficiently (matches Rust exactly)
    // Extract uint32 from bytes 8-12, add data length, write back
    uint32_t old = bytes_to_uint32_le(&in_key[8]) + static_cast<uint32_t>(data.size());
    uint32_to_bytes_le(old, &in_key[8]);

    return true;
}

// Encrypt outgoing packets (matches Rust encrypt)
bool GameClientEncryption::encrypt(std::vector<uint8_t> &data)
{
    if (!is_enabled)
    {
        is_enabled = true;
        return true; // First packet is unencrypted
    }

    uint8_t encrypted = 0;
    for (size_t i = 0; i < data.size(); ++i)
    {
        encrypted ^= data[i] ^ out_key[i & 15];
        data[i] = encrypted;
    }

    // Shift key efficiently (matches Rust exactly)
    // Extract uint32 from bytes 8-12, add data length, write back
    uint32_t old = bytes_to_uint32_le(&out_key[8]) + static_cast<uint32_t>(data.size());
    uint32_to_bytes_le(old, &out_key[8]);

    return true;
}

// Test function with Rust compatibility test vectors
void GameClientEncryption::runTests()
{
    std::cout << "\n=== Testing Game Client Encryption (Rust Compatibility) ===" << std::endl;

    bool all_passed = true;

    // Test 1: Encrypt works (from Rust encrypt_works)
    std::cout << "Test 1: Encrypt works" << std::endl;
    {
        std::vector<uint8_t> the_key = {23, 17, 0, 1, 78, 198, 12, 8, 56, 110, 10, 9, 121, 34, 6, 8};
        GameClientEncryption encryption(the_key);

        std::vector<uint8_t> data = {0, 12, 34, 56, 78, 198, 12, 32, 56, 0, 1, 9, 12, 34, 56};
        std::vector<uint8_t> unchanged = data; // copy

        // First encryption call - should return unchanged (first packet unencrypted)
        encryption.encrypt(data);
        if (data != unchanged)
        {
            std::cout << "  ❌ Test 1a FAILED! First packet should be unchanged" << std::endl;
            all_passed = false;
        }

        // Second encryption call - should encrypt the data
        encryption.encrypt(data);
        if (data == unchanged)
        {
            std::cout << "  ❌ Test 1b FAILED! Second packet should be encrypted" << std::endl;
            all_passed = false;
        }

        std::vector<uint8_t> expected_second = {23, 10, 40, 17, 17, 17, 17, 57, 57, 87, 92, 92, 41, 41, 23};
        if (data != expected_second)
        {
            std::cout << "  ❌ Test 1c FAILED! Second encryption result doesn't match Rust" << std::endl;
            all_passed = false;
        }

        // Third encryption call
        encryption.encrypt(data);
        std::vector<uint8_t> expected_third = {0, 27, 51, 35, 124, 171, 182, 135, 249, 192, 150, 195, 147, 152, 137};
        if (data != expected_third)
        {
            std::cout << "  ❌ Test 1d FAILED! Third encryption result doesn't match Rust" << std::endl;
            all_passed = false;
        }

        if (data == expected_third)
        {
            std::cout << "  ✅ Test 1 PASSED!" << std::endl;
        }
    }

    // Test 2: Decrypt works (from Rust decrypt_works)
    std::cout << "\nTest 2: Decrypt works" << std::endl;
    {
        std::vector<uint8_t> the_key = {23, 17, 0, 1, 78, 198, 12, 8, 56, 110, 10, 9, 121, 34, 6, 8};
        GameClientEncryption encryption(the_key);

        std::vector<uint8_t> data = {0, 12, 34, 56, 78, 198, 12, 32, 56, 0, 1, 9, 12, 34, 56};
        std::vector<uint8_t> unchanged = data; // copy

        // First decryption call - should return unchanged (first packet unencrypted)
        encryption.decrypt(data);
        if (data != unchanged)
        {
            std::cout << "  ❌ Test 2a FAILED! First packet should be unchanged" << std::endl;
            all_passed = false;
        }

        // Second decryption call - should decrypt the data
        encryption.decrypt(data);
        if (data == unchanged)
        {
            std::cout << "  ❌ Test 2b FAILED! Second packet should be decrypted" << std::endl;
            all_passed = false;
        }

        std::vector<uint8_t> expected_second = {23, 29, 46, 27, 56, 78, 198, 36, 32, 86, 11, 1, 124, 12, 28};
        if (data != expected_second)
        {
            std::cout << "  ❌ Test 2c FAILED! Second decryption result doesn't match Rust" << std::endl;
            all_passed = false;
        }

        // Third decryption call
        encryption.decrypt(data);
        std::vector<uint8_t> expected_third = {0, 27, 51, 52, 109, 176, 132, 234, 67, 24, 87, 3, 4, 82, 22};
        if (data != expected_third)
        {
            std::cout << "  ❌ Test 2d FAILED! Third decryption result doesn't match Rust" << std::endl;
            all_passed = false;
        }

        if (data == expected_third)
        {
            std::cout << "  ✅ Test 2 PASSED!" << std::endl;
        }
    }

    // Test 3: Constructor validation
    std::cout << "\nTest 3: Constructor validation" << std::endl;
    {
        try
        {
            // Valid key (16 bytes)
            std::vector<uint8_t> valid_key(16, 42);
            GameClientEncryption encryption1(valid_key);

            // Invalid key (wrong size)
            std::vector<uint8_t> invalid_key(8, 42);
            try
            {
                GameClientEncryption encryption2(invalid_key);
                std::cout << "  ❌ Test 3 FAILED! Should reject invalid key size" << std::endl;
                all_passed = false;
            }
            catch (const std::runtime_error &)
            {
                // Expected exception
                std::cout << "  ✅ Test 3 PASSED!" << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 3 FAILED! Unexpected exception: " << e.what() << std::endl;
            all_passed = false;
        }
    }

    // Overall result
    if (all_passed)
    {
        std::cout << "\n🎉 ALL Game Client Encryption tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some Game Client Encryption tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}