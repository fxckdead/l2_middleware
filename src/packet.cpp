#include "packet.hpp"
#include "packet_buffer.hpp"
#include <iostream>
#include <iomanip>

// SendablePacket default implementation
std::vector<uint8_t> SendablePacket::serialize(bool withPadding)
{
    SendablePacketBuffer buffer;
    write(buffer);
    return buffer.getData(withPadding);
}

// ReadablePacket factory method (basic implementation)
std::unique_ptr<ReadablePacket> ReadablePacket::createFromData(const std::vector<uint8_t> &data)
{
    if (data.empty())
    {
        throw PacketException("Cannot create packet from empty data");
    }

    // This is a basic implementation - in practice, you'd have a packet registry
    // that maps packet IDs to specific packet types
    throw PacketException("Packet factory not implemented - use specific packet constructors");
}

// PacketUtils implementation
namespace PacketUtils
{
    size_t calculatePaddedSize(size_t dataSize)
    {
        // L2 packets need to be padded to 8-byte boundaries for Blowfish encryption
        size_t padding = (8 - (dataSize % 8)) % 8;
        return dataSize + padding;
    }

    void addPadding(std::vector<uint8_t> &data)
    {
        size_t currentSize = data.size();
        size_t paddedSize = calculatePaddedSize(currentSize);

        // Add zero bytes for padding
        data.resize(paddedSize, 0x00);
    }

    void runTests()
    {
        std::cout << "\n=== Testing Packet Utilities ===" << std::endl;

        bool allPassed = true;

        // Test 1: Padding calculation
        std::cout << "Test 1: Padding calculation" << std::endl;
        {
            // Test various sizes
            struct PaddingTest
            {
                size_t input;
                size_t expected;
            };

            std::vector<PaddingTest> tests = {
                {0, 0},   // 0 % 8 = 0, no padding needed
                {1, 8},   // 1 + 7 = 8
                {7, 8},   // 7 + 1 = 8
                {8, 8},   // 8 % 8 = 0, no padding needed
                {9, 16},  // 9 + 7 = 16
                {15, 16}, // 15 + 1 = 16
                {16, 16}, // 16 % 8 = 0, no padding needed
                {17, 24}  // 17 + 7 = 24
            };

            bool test1Passed = true;
            for (const auto &test : tests)
            {
                size_t result = calculatePaddedSize(test.input);
                if (result != test.expected)
                {
                    std::cout << "  ❌ Failed for input " << test.input
                              << ": expected " << test.expected
                              << ", got " << result << std::endl;
                    test1Passed = false;
                    allPassed = false;
                }
            }

            if (test1Passed)
            {
                std::cout << "  ✅ Test 1 PASSED!" << std::endl;
            }
        }

        // Test 2: Actual padding operation
        std::cout << "\nTest 2: Padding operation" << std::endl;
        {
            std::vector<uint8_t> data = {0x01, 0x02, 0x03}; // 3 bytes
            size_t originalSize = data.size();

            addPadding(data);

            if (data.size() == 8 && data[0] == 0x01 && data[1] == 0x02 && data[2] == 0x03)
            {
                // Check that padding bytes are zero
                bool paddingCorrect = true;
                for (size_t i = originalSize; i < data.size(); ++i)
                {
                    if (data[i] != 0x00)
                    {
                        paddingCorrect = false;
                        break;
                    }
                }

                if (paddingCorrect)
                {
                    std::cout << "  ✅ Test 2 PASSED!" << std::endl;
                }
                else
                {
                    std::cout << "  ❌ Test 2 FAILED: Padding bytes not zero" << std::endl;
                    allPassed = false;
                }
            }
            else
            {
                std::cout << "  ❌ Test 2 FAILED: Incorrect size or data corruption" << std::endl;
                allPassed = false;
            }
        }

        // Test 3: No padding needed case
        std::cout << "\nTest 3: No padding needed" << std::endl;
        {
            std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}; // 8 bytes
            size_t originalSize = data.size();

            addPadding(data);

            if (data.size() == originalSize)
            {
                std::cout << "  ✅ Test 3 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 3 FAILED: Padding added when not needed" << std::endl;
                allPassed = false;
            }
        }

        // Overall result
        if (allPassed)
        {
            std::cout << "\n🎉 ALL Packet Utility tests PASSED!" << std::endl;
        }
        else
        {
            std::cout << "\n⚠️ Some Packet Utility tests FAILED!" << std::endl;
        }
        std::cout << std::endl;
    }
}