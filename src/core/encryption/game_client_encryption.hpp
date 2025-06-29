#pragma once

#include <vector>
#include <array>
#include <cstdint>

// Game Client XOR Encryption for Lineage 2 game server communication
// Matches Rust implementation in l2-core/src/crypt/game.rs
class GameClientEncryption
{
private:
    std::array<uint8_t, 16> in_key;  // For incoming packets (decryption)
    std::array<uint8_t, 16> out_key; // For outgoing packets (encryption)
    bool is_enabled;

    // Helper function to convert bytes to uint32_t (Little Endian)
    static uint32_t bytes_to_uint32_le(const uint8_t *bytes);

    // Helper function to convert uint32_t to bytes (Little Endian)
    static void uint32_to_bytes_le(uint32_t value, uint8_t *bytes);

public:
    // Constructor (matches Rust GameClientEncryption::new)
    explicit GameClientEncryption(const std::vector<uint8_t> &key);

    // Enable encryption immediately (for game server where VersionCheck is sent separately)
    void enable() { is_enabled = true; }

    // Decrypt incoming packets (matches Rust decrypt)
    bool decrypt(std::vector<uint8_t> &data);

    // Encrypt outgoing packets (matches Rust encrypt)
    bool encrypt(std::vector<uint8_t> &data);
};