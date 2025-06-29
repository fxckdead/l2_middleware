#include "game_client_encryption.hpp"
#include <stdexcept>
#include <algorithm>
#include <cstdio>

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
    static int decrypt_count = 0;
    decrypt_count++;
    
    if (!is_enabled)
    {
        // DEBUG: This should NOT happen for game client connections if properly pre-enabled
        printf("[GameClientEncryption] DECRYPT #%d: ERROR - Encryption not enabled! Pre-enable() missing? (size: %zu)\n", decrypt_count, data.size());
        is_enabled = true;
        return true; // First packet is unencrypted
    }

    // DEBUG: Log decryption key state  
    printf("[GameClientEncryption] DECRYPT #%d: Using in_key[0-7]: %02X %02X %02X %02X %02X %02X %02X %02X\n", 
           decrypt_count, in_key[0], in_key[1], in_key[2], in_key[3], in_key[4], in_key[5], in_key[6], in_key[7]);

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

    // DEBUG: Log key after update
    printf("[GameClientEncryption] DECRYPT #%d: Updated in_key[8-11]: %02X %02X %02X %02X (added %zu)\n", 
           decrypt_count, in_key[8], in_key[9], in_key[10], in_key[11], data.size());

    return true;
}

// Encrypt outgoing packets (matches Rust encrypt)
bool GameClientEncryption::encrypt(std::vector<uint8_t> &data)
{
    static int encrypt_count = 0;
    encrypt_count++;
    
    if (!is_enabled)
    {
        // DEBUG: This should NOT happen for game client connections if properly pre-enabled
        printf("[GameClientEncryption] ENCRYPT #%d: ERROR - Encryption not enabled! Pre-enable() missing? (size: %zu)\n", encrypt_count, data.size());
        is_enabled = true;
        return true; // First packet is unencrypted
    }

    // DEBUG: Log encryption key state
    printf("[GameClientEncryption] ENCRYPT #%d: Using out_key[0-7]: %02X %02X %02X %02X %02X %02X %02X %02X\n", 
           encrypt_count, out_key[0], out_key[1], out_key[2], out_key[3], out_key[4], out_key[5], out_key[6], out_key[7]);

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

    // DEBUG: Log key after update
    printf("[GameClientEncryption] ENCRYPT #%d: Updated out_key[8-11]: %02X %02X %02X %02X (added %zu)\n", 
           encrypt_count, out_key[8], out_key[9], out_key[10], out_key[11], data.size());

    return true;
}

