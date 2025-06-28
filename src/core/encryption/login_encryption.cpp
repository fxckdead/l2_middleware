#include "login_encryption.hpp"
#include <stdexcept>

// Constructor from byte key (matches Rust::from_u8_key)
LoginEncryption::LoginEncryption(const std::vector<uint8_t> &key) : m_cipher(key)
{
}

// Decrypt login packet data (matches Rust::decrypt)
bool LoginEncryption::decrypt(std::vector<uint8_t> &data)
{
    size_t size = data.size();

    // Check if size is valid (must be multiple of 8)
    if (size % 8 != 0)
    {
        return false; // Matches Rust Packet::DecryptBlowfishError
    }

    // Decrypt using Little Endian Blowfish
    m_cipher.decrypt_bytes(data);
    return true;
}

// Encrypt login packet data (matches Rust::encrypt)
void LoginEncryption::encrypt(std::vector<uint8_t> &data)
{
    // Encrypt using Little Endian Blowfish
    m_cipher.encrypt_bytes(data);
}

// Helper function for checksum calculation (matches Rust::calculate_checksum_block)
std::pair<uint32_t, uint32_t> LoginEncryption::calculate_checksum_block(const std::vector<uint8_t> &data)
{
    uint32_t checksum = 0;
    uint32_t check = 0;
    size_t count = data.size();
    size_t offset = 0;

    while (offset < count)
    {
        // Little Endian conversion (matches Rust implementation exactly)
        check = static_cast<uint32_t>(data[offset]) & 0xFF;
        check |= (static_cast<uint32_t>(data[offset + 1]) << 8) & 0xFF00;
        check |= (static_cast<uint32_t>(data[offset + 2]) << 16) & 0x00FF0000;
        check |= (static_cast<uint32_t>(data[offset + 3]) << 24) & 0xFF000000;

        offset += 4;

        if (offset < count)
        {
            checksum ^= check;
        }
    }

    return std::make_pair(check, checksum);
}

// Verify checksum (matches Rust::verify_checksum)
bool LoginEncryption::verify_checksum(const std::vector<uint8_t> &data)
{
    size_t size = data.size();

    // Check size constraints (matches Rust implementation)
    if ((size & 3) != 0 || size <= 4)
    {
        return false;
    }

    auto [check, checksum] = calculate_checksum_block(data);
    return check == checksum;
}

// Append checksum (matches Rust::append_checksum)
void LoginEncryption::append_checksum(std::vector<uint8_t> &data)
{
    auto [_, checksum] = calculate_checksum_block(data);

    // Modify last 4 bytes (matches Rust implementation)
    size_t last = data.size() - 4;
    data[last] = static_cast<uint8_t>(checksum & 0xFF);
    data[last + 1] = static_cast<uint8_t>((checksum >> 8) & 0xFF);
    data[last + 2] = static_cast<uint8_t>((checksum >> 16) & 0xFF);
    data[last + 3] = static_cast<uint8_t>((checksum >> 24) & 0xFF);
}

// XOR password encryption (matches Rust::enc_xor_pass)
void LoginEncryption::enc_xor_pass(std::vector<uint8_t> &data, size_t offset, size_t size, uint32_t key)
{
    size_t stop = size - 8;
    size_t pos = 4 + offset;
    uint32_t ecx = key; // Initial XOR key

    while (pos < stop)
    {
        uint32_t edx = (static_cast<uint32_t>(data[pos]) & 0xFF) |
                       ((static_cast<uint32_t>(data[pos + 1]) & 0xFF) << 8) |
                       ((static_cast<uint32_t>(data[pos + 2]) & 0xFF) << 16) |
                       ((static_cast<uint32_t>(data[pos + 3]) & 0xFF) << 24);

        ecx = ecx + edx; // wrapping add
        uint32_t edx_xor = edx ^ ecx;

        data[pos] = static_cast<uint8_t>(edx_xor & 0xFF);
        data[pos + 1] = static_cast<uint8_t>((edx_xor >> 8) & 0xFF);
        data[pos + 2] = static_cast<uint8_t>((edx_xor >> 16) & 0xFF);
        data[pos + 3] = static_cast<uint8_t>((edx_xor >> 24) & 0xFF);

        pos += 4;
    }

    // Write final XOR key
    data[pos] = static_cast<uint8_t>(ecx & 0xFF);
    data[pos + 1] = static_cast<uint8_t>((ecx >> 8) & 0xFF);
    data[pos + 2] = static_cast<uint8_t>((ecx >> 16) & 0xFF);
    data[pos + 3] = static_cast<uint8_t>((ecx >> 24) & 0xFF);
}

