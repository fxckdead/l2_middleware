#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <openssl/blowfish.h>

class Blowfish
{
private:
    BF_KEY m_key;

    // Little Endian conversion helpers (to match Rust BlowfishLE)
    static uint32_t bytes_to_uint32_le(const uint8_t *bytes);
    static void uint32_to_bytes_le(uint32_t value, uint8_t *bytes);

public:
    Blowfish() {}
    explicit Blowfish(const std::string &key);
    explicit Blowfish(const std::vector<uint8_t> &key);
    Blowfish(const Blowfish &) = delete;

    void initialize(const std::string &key);
    void initialize(const std::vector<uint8_t> &key);

    // Original uint32_t interface
    void encrypt(uint32_t &xl, uint32_t &xr);
    void decrypt(uint32_t &xl, uint32_t &xr);

    // Little Endian byte array interface (to match Rust BlowfishLE)
    void encrypt_bytes(std::vector<uint8_t> &data);
    void decrypt_bytes(std::vector<uint8_t> &data);

    // Single block operations (8 bytes)
    void encrypt_block(uint8_t *block);
    void decrypt_block(uint8_t *block);
};