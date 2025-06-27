#include "blowfish_openssl.hpp"
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <vector>

Blowfish::Blowfish(const std::string &key)
{
    initialize(key);
}

Blowfish::Blowfish(const std::vector<uint8_t> &key)
{
    initialize(key);
}

void Blowfish::initialize(const std::string &key)
{
    BF_set_key(&m_key, static_cast<int>(key.length()),
               reinterpret_cast<const unsigned char *>(key.c_str()));
}

void Blowfish::initialize(const std::vector<uint8_t> &key)
{
    BF_set_key(&m_key, static_cast<int>(key.size()), key.data());
}

void Blowfish::encrypt(uint32_t &xl, uint32_t &xr)
{
    // OpenSSL's BF_encrypt expects BF_LONG array
    BF_LONG data[2];
    data[0] = static_cast<BF_LONG>(xl);
    data[1] = static_cast<BF_LONG>(xr);

    BF_encrypt(data, &m_key);

    xl = static_cast<uint32_t>(data[0]);
    xr = static_cast<uint32_t>(data[1]);
}

void Blowfish::decrypt(uint32_t &xl, uint32_t &xr)
{
    // OpenSSL's BF_decrypt expects BF_LONG array
    BF_LONG data[2];
    data[0] = static_cast<BF_LONG>(xl);
    data[1] = static_cast<BF_LONG>(xr);

    BF_decrypt(data, &m_key);

    xl = static_cast<uint32_t>(data[0]);
    xr = static_cast<uint32_t>(data[1]);
}

// Little Endian conversion helpers (to match Rust BlowfishLE)
uint32_t Blowfish::bytes_to_uint32_le(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

void Blowfish::uint32_to_bytes_le(uint32_t value, uint8_t *bytes)
{
    bytes[0] = static_cast<uint8_t>(value & 0xFF);
    bytes[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    bytes[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    bytes[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

// Little Endian byte array interface (to match Rust BlowfishLE)
void Blowfish::encrypt_bytes(std::vector<uint8_t> &data)
{
    if (data.size() % 8 != 0)
    {
        throw std::runtime_error("Data must be multiple of 8 bytes for Blowfish");
    }

    for (size_t i = 0; i < data.size(); i += 8)
    {
        encrypt_block(&data[i]);
    }
}

void Blowfish::decrypt_bytes(std::vector<uint8_t> &data)
{
    if (data.size() % 8 != 0)
    {
        throw std::runtime_error("Data must be multiple of 8 bytes for Blowfish");
    }

    for (size_t i = 0; i < data.size(); i += 8)
    {
        decrypt_block(&data[i]);
    }
}

// Single block operations (8 bytes) - Little Endian
void Blowfish::encrypt_block(uint8_t *block)
{
    // Convert 8 bytes to two uint32_t (Little Endian)
    uint32_t xl = bytes_to_uint32_le(&block[0]);
    uint32_t xr = bytes_to_uint32_le(&block[4]);

    // Encrypt using existing function
    encrypt(xl, xr);

    // Convert back to bytes (Little Endian)
    uint32_to_bytes_le(xl, &block[0]);
    uint32_to_bytes_le(xr, &block[4]);
}

void Blowfish::decrypt_block(uint8_t *block)
{
    // Convert 8 bytes to two uint32_t (Little Endian)
    uint32_t xl = bytes_to_uint32_le(&block[0]);
    uint32_t xr = bytes_to_uint32_le(&block[4]);

    // Decrypt using existing function
    decrypt(xl, xr);

    // Convert back to bytes (Little Endian)
    uint32_to_bytes_le(xl, &block[0]);
    uint32_to_bytes_le(xr, &block[4]);
}

// Test function for Blowfish functionality
void Blowfish::runTests()
{
    std::cout << "=== Testing OpenSSL Blowfish ===" << std::endl;

    // Test 1: Original uint32_t interface
    std::cout << "Test 1: uint32_t interface" << std::endl;

    // Initialize Blowfish with a key
    std::string key = "MySecretKey123";
    Blowfish bf(key);

    // Test data
    uint32_t left = 0x12345678;
    uint32_t right = 0x90ABCDEF;

    // Make a copy for verification
    uint32_t orig_left = left;
    uint32_t orig_right = right;

    std::cout << "Original: 0x" << std::hex << orig_left << " 0x" << orig_right << std::endl;

    // Encrypt
    bf.encrypt(left, right);
    std::cout << "Encrypted: 0x" << std::hex << left << " 0x" << right << std::endl;

    // Decrypt
    bf.decrypt(left, right);
    std::cout << "Decrypted: 0x" << std::hex << left << " 0x" << right << std::dec << std::endl;

    // Verify
    bool test1_passed = (left == orig_left && right == orig_right);
    if (test1_passed)
    {
        std::cout << "✅ Test 1 PASSED!" << std::endl;
    }
    else
    {
        std::cout << "❌ Test 1 FAILED!" << std::endl;
    }

    // Test 2: Little Endian byte array interface (Rust BlowfishLE compatibility)
    std::cout << "\nTest 2: Little Endian byte array interface (Rust compatibility)" << std::endl;

    // Test data: 16 bytes (2 blocks of 8 bytes each)
    std::vector<uint8_t> test_data = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Block 1
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18  // Block 2
    };

    // Make a copy for verification
    std::vector<uint8_t> original_data = test_data;

    std::cout << "Original data: ";
    for (uint8_t byte : original_data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    // Encrypt using Little Endian interface
    bf.encrypt_bytes(test_data);

    std::cout << "Encrypted data: ";
    for (uint8_t byte : test_data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    // Decrypt using Little Endian interface
    bf.decrypt_bytes(test_data);

    std::cout << "Decrypted data: ";
    for (uint8_t byte : test_data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    // Verify
    bool test2_passed = (test_data == original_data);
    if (test2_passed)
    {
        std::cout << "✅ Test 2 PASSED!" << std::endl;
    }
    else
    {
        std::cout << "❌ Test 2 FAILED!" << std::endl;
    }

    // Overall result
    if (test1_passed && test2_passed)
    {
        std::cout << "🎉 ALL Blowfish tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "⚠️ Some Blowfish tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}