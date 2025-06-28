#include "../../packets/packet.hpp"
#include <iostream>
#include <iomanip>

void test_packet_utilities()
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
            size_t result = PacketUtils::calculatePaddedSize(test.input);
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

        PacketUtils::addPadding(data);

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

        PacketUtils::addPadding(data);

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