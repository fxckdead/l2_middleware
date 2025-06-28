#include "l2_checksum.hpp"
#include <stdexcept>

// Convert 4 bytes to uint32_t (Little Endian)
uint32_t L2Checksum::bytes_to_uint32_le(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

// Convert uint32_t to 4 bytes (Little Endian)
void L2Checksum::uint32_to_bytes_le(uint32_t value, uint8_t *bytes)
{
    bytes[0] = static_cast<uint8_t>(value & 0xFF);
    bytes[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    bytes[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    bytes[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

// Calculate checksum for Lineage 2 packet data
ChecksumResult L2Checksum::calculate_checksum(const std::vector<uint8_t> &data)
{
    if (data.size() < 4 || data.size() % 4 != 0)
    {
        throw std::runtime_error("Data size must be a multiple of 4 bytes and at least 4 bytes");
    }

    uint32_t checksum = 0;
    uint32_t last_block = 0;

    // Process data in 4-byte blocks
    for (size_t offset = 0; offset < data.size(); offset += 4)
    {
        // Convert 4 bytes to uint32_t using Little Endian
        uint32_t block = bytes_to_uint32_le(&data[offset]);

        if (offset + 4 < data.size())
        {
            // XOR all blocks except the last one
            checksum ^= block;
        }
        else
        {
            // This is the last block
            last_block = block;
        }
    }

    return ChecksumResult(last_block, checksum);
}

// Verify that packet data has a valid checksum
bool L2Checksum::verify_checksum(const std::vector<uint8_t> &data)
{
    if (data.size() <= 4 || data.size() % 4 != 0)
    {
        return false; // Invalid size for checksum verification
    }

    try
    {
        ChecksumResult result = calculate_checksum(data);
        return result.last_block == result.checksum;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

// Add checksum to packet data (appends 4 bytes)
void L2Checksum::add_checksum(std::vector<uint8_t> &data)
{
    if (data.size() % 4 != 0)
    {
        throw std::runtime_error("Data size must be a multiple of 4 bytes before adding checksum");
    }

    // Calculate checksum of current data
    uint32_t checksum = 0;
    for (size_t offset = 0; offset < data.size(); offset += 4)
    {
        uint32_t block = bytes_to_uint32_le(&data[offset]);
        checksum ^= block;
    }

    // Append checksum as 4 bytes (Little Endian)
    data.resize(data.size() + 4);
    uint32_to_bytes_le(checksum, &data[data.size() - 4]);
}

// Remove and verify checksum from packet data (removes 4 bytes if valid)
bool L2Checksum::remove_and_verify_checksum(std::vector<uint8_t> &data)
{
    if (!verify_checksum(data))
    {
        return false; // Invalid checksum
    }

    // Remove the last 4 bytes (checksum)
    data.resize(data.size() - 4);
    return true;
}

