#pragma once

#include <vector>
#include <cstdint>
#include "blowfish_openssl.hpp"
#include "l2_checksum.hpp"

// Lineage 2 Login Encryption - matches Rust implementation
// Provides high-level interface for login packet encryption/decryption
class LoginEncryption
{
private:
    Blowfish m_cipher;

public:
    // Constructor from byte key (matches Rust::from_u8_key)
    explicit LoginEncryption(const std::vector<uint8_t> &key);

    // Decrypt login packet data (matches Rust::decrypt)
    bool decrypt(std::vector<uint8_t> &data);

    // Encrypt login packet data (matches Rust::encrypt)
    void encrypt(std::vector<uint8_t> &data);

    // Checksum functions (matches Rust implementation)
    static bool verify_checksum(const std::vector<uint8_t> &data);
    static void append_checksum(std::vector<uint8_t> &data);

    // XOR password encryption (matches Rust::enc_xor_pass)
    static void enc_xor_pass(std::vector<uint8_t> &data, size_t offset, size_t size, uint32_t key);

    // Test function with Rust compatibility test vectors
    static void runTests();

private:
    // Helper function for checksum calculation (matches Rust::calculate_checksum_block)
    static std::pair<uint32_t, uint32_t> calculate_checksum_block(const std::vector<uint8_t> &data);
};