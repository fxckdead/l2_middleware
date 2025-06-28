#pragma once

#include <vector>
#include <cstdint>

// Lineage 2 packet checksum utility functions
// Essential for packet integrity verification in L2 protocol

struct ChecksumResult
{
    uint32_t last_block;
    uint32_t checksum;

    ChecksumResult(uint32_t last, uint32_t check) : last_block(last), checksum(check) {}
};

class L2Checksum
{
public:
    // Calculate checksum for Lineage 2 packet data
    // Returns the last 4-byte block and the XOR checksum of all previous blocks
    static ChecksumResult calculate_checksum(const std::vector<uint8_t> &data);

    // Verify that packet data has a valid checksum
    // Expects data to include the 4-byte checksum at the end
    static bool verify_checksum(const std::vector<uint8_t> &data);

    // Add checksum to packet data (appends 4 bytes)
    static void add_checksum(std::vector<uint8_t> &data);

    // Remove and verify checksum from packet data (removes 4 bytes if valid)
    static bool remove_and_verify_checksum(std::vector<uint8_t> &data);

    // Test function for L2 checksum functionality
    static void runTests();

private:
    // Convert 4 bytes to uint32_t (Little Endian)
    static uint32_t bytes_to_uint32_le(const uint8_t *bytes);

    // Convert uint32_t to 4 bytes (Little Endian)
    static void uint32_to_bytes_le(uint32_t value, uint8_t *bytes);
};