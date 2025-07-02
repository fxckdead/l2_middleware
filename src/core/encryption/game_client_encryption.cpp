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

bool GameClientEncryption::decrypt(std::vector<uint8_t> &data, bool has_header)
{
    if (!is_enabled)
    {
        is_enabled = true;
        return true; // First packet is unencrypted
    }

    size_t offset = has_header ? 2 : 0;
    
    if (data.size() <= offset)
    {
        return false;
    }

    // L2J/Interlude XOR decryption with chaining
    uint8_t x_or = 0;
    for (size_t i = offset; i < data.size(); ++i)
    {
        uint8_t orig_encrypted = data[i];
        size_t key_idx = (i - offset) % 16;
        uint8_t key_byte = in_key[key_idx];

        data[i] = orig_encrypted ^ key_byte ^ x_or;
        x_or = orig_encrypted; // Chain from original encrypted byte
    }

    // Key rotation: FIXED to match Rust implementation
    uint32_t delta = static_cast<uint32_t>(data.size());
    uint32_t old_key_value = bytes_to_uint32_le(&in_key[8]);
    uint32_t new_key_value = old_key_value + delta;
    uint32_to_bytes_le(new_key_value, &in_key[8]);

    return true;
}

bool GameClientEncryption::encrypt(std::vector<uint8_t> &data, bool has_header)
{
    if (!is_enabled)
    {
        is_enabled = true;
        return true; // First packet is unencrypted
    }

    size_t offset = has_header ? 2 : 0;
    
    if (data.size() <= offset)
    {
        return false;
    }

    // L2J/Interlude XOR encryption
    uint8_t encrypted = 0;
    for (size_t i = offset; i < data.size(); ++i)
    {
        encrypted ^= data[i] ^ out_key[(i - offset) % 16];
        data[i] = encrypted;
    }

    // Key rotation: FIXED to match Rust implementation
    uint32_t delta = static_cast<uint32_t>(data.size());
    uint32_t old_key_value = bytes_to_uint32_le(&out_key[8]);
    uint32_t new_key_value = old_key_value + delta;
    uint32_to_bytes_le(new_key_value, &out_key[8]);

    return true;
}
