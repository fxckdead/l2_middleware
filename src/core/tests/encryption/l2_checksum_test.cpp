#include "../../encryption/l2_checksum.hpp"
#include <iostream>
#include <iomanip>

void test_l2_checksum()
{
    std::cout << "\n=== Testing L2 Checksum Functions ===" << std::endl;

    bool all_passed = true;

    // Test 1: Basic checksum calculation and verification
    std::cout << "Test 1: Basic checksum calculation" << std::endl;
    {
        // Create test data: 12 bytes (3 blocks of 4 bytes)
        std::vector<uint8_t> test_data = {
            0x01, 0x02, 0x03, 0x04, // Block 1: 0x04030201
            0x05, 0x06, 0x07, 0x08, // Block 2: 0x08070605
            0x09, 0x0A, 0x0B, 0x0C  // Block 3: 0x0C0B0A09
        };

        ChecksumResult result = L2Checksum::calculate_checksum(test_data);

        // Expected: checksum = 0x04030201 ^ 0x08070605 = 0x0C040804
        // last_block = 0x0C0B0A09
        uint32_t expected_checksum = 0x04030201 ^ 0x08070605;
        uint32_t expected_last = 0x0C0B0A09;

        std::cout << "  Expected checksum: 0x" << std::hex << expected_checksum << std::endl;
        std::cout << "  Calculated checksum: 0x" << std::hex << result.checksum << std::endl;
        std::cout << "  Expected last block: 0x" << std::hex << expected_last << std::endl;
        std::cout << "  Calculated last block: 0x" << std::hex << result.last_block << std::dec << std::endl;

        if (result.checksum == expected_checksum && result.last_block == expected_last)
        {
            std::cout << "  ✅ Test 1 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 1 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Test 2: Add and verify checksum
    std::cout << "\nTest 2: Add and verify checksum" << std::endl;
    {
        std::vector<uint8_t> packet_data = {
            0x01, 0x00, 0x02, 0x00, // Some packet data
            0x03, 0x00, 0x04, 0x00};

        std::cout << "  Original data size: " << packet_data.size() << " bytes" << std::endl;

        // Add checksum
        L2Checksum::add_checksum(packet_data);

        std::cout << "  Data with checksum size: " << packet_data.size() << " bytes" << std::endl;

        // Verify checksum
        bool is_valid = L2Checksum::verify_checksum(packet_data);

        if (is_valid)
        {
            std::cout << "  ✅ Test 2 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 2 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Test 3: Remove and verify checksum
    std::cout << "\nTest 3: Remove and verify checksum" << std::endl;
    {
        std::vector<uint8_t> packet_data = {
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88};

        size_t original_size = packet_data.size();

        // Add checksum
        L2Checksum::add_checksum(packet_data);

        // Remove and verify checksum
        bool removed_successfully = L2Checksum::remove_and_verify_checksum(packet_data);

        if (removed_successfully && packet_data.size() == original_size)
        {
            std::cout << "  ✅ Test 3 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 3 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Test 4: Invalid checksum detection
    std::cout << "\nTest 4: Invalid checksum detection" << std::endl;
    {
        std::vector<uint8_t> invalid_data = {
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0xFF, 0xFF, 0xFF, 0xFF // Wrong checksum
        };

        bool is_valid = L2Checksum::verify_checksum(invalid_data);

        if (!is_valid) // Should be invalid
        {
            std::cout << "  ✅ Test 4 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 4 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Overall result
    if (all_passed)
    {
        std::cout << "\n🎉 ALL L2 Checksum tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some L2 Checksum tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
} 