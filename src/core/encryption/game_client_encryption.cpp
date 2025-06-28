#include "game_client_encryption.hpp"
#include <stdexcept>
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

