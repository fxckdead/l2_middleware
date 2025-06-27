#include "blowfish_openssl.hpp"
#include <stdexcept>

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