#include "../../packets/requests/request_auth_gg.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <iostream>
#include <iomanip>

void test_request_auth_gg()
{
    std::cout << "\n=== Testing RequestAuthGG ===" << std::endl;

    bool allPassed = true;

    // Test 1: Basic packet creation and validation
    std::cout << "Test 1: Basic packet creation" << std::endl;
    {
        try
        {
            int32_t testSessionId = 0x12345678;
            RequestAuthGG packet(testSessionId);

            if (packet.getPacketId() == 0x07 &&
                packet.getSessionId() == testSessionId &&
                packet.isValid())
            {
                std::cout << "  ✅ Test 1 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 1 FAILED! Basic properties incorrect" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 1 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 2: Raw data parsing (matches Rust test_read)
    std::cout << "\nTest 2: Raw data parsing (Rust compatibility)" << std::endl;
    {
        try
        {
            // Exact test data from Rust test_read function
            std::vector<uint8_t> testData = {
                1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0};

            RequestAuthGG packet = RequestAuthGG::fromRawData(testData);

            if (packet.getSessionId() == 1) // First int32 should be 1
            {
                std::cout << "  ✅ Test 2 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 2 FAILED! Expected session ID 1, got "
                          << packet.getSessionId() << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 2 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 3: Buffer reading
    std::cout << "\nTest 3: Buffer reading interface" << std::endl;
    {
        try
        {
            std::vector<uint8_t> testData = {
                0x78, 0x56, 0x34, 0x12, // Session ID: 0x12345678 (little-endian)
                0x00, 0x00, 0x00, 0x00, // GameGuard data (ignored)
                0xFF, 0xFF, 0xFF, 0xFF  // More GameGuard data (ignored)
            };

            ReadablePacketBuffer buffer(testData);
            RequestAuthGG packet;
            packet.read(buffer);

            if (packet.getSessionId() == 0x12345678)
            {
                std::cout << "  ✅ Test 3 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 3 FAILED! Expected session ID 0x12345678, got 0x"
                          << std::hex << packet.getSessionId() << std::dec << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 3 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 4: Invalid data handling
    std::cout << "\nTest 4: Invalid data handling" << std::endl;
    {
        try
        {
            // Test with insufficient data
            std::vector<uint8_t> invalidData = {0x01, 0x02}; // Only 2 bytes

            try
            {
                RequestAuthGG packet = RequestAuthGG::fromRawData(invalidData);
                std::cout << "  ❌ Test 4 FAILED! Should have thrown exception for insufficient data" << std::endl;
                allPassed = false;
            }
            catch (const PacketException &)
            {
                // Expected exception
                std::cout << "  ✅ Test 4 PASSED!" << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 4 FAILED! Unexpected exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Overall result
    if (allPassed)
    {
        std::cout << "\n🎉 ALL RequestAuthGG tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some RequestAuthGG tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}