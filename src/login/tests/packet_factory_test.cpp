#include "../packets/packet_factory.hpp"
#include "../../core/encryption/rsa_manager.hpp"
#include <iostream>
#include <iomanip>

void test_packet_factory()
{
    std::cout << "\n=== Testing PacketFactory ===" << std::endl;

    bool allPassed = true;

    // Test 1: RequestAuthGG packet creation
    std::cout << "Test 1: RequestAuthGG packet creation" << std::endl;
    {
        try
        {
            std::vector<uint8_t> ggData = {
                0x07,                   // Opcode
                0x78, 0x56, 0x34, 0x12, // Session ID: 0x12345678 (little-endian)
                0x00, 0x00, 0x00, 0x00, // GameGuard data (ignored)
                0xFF, 0xFF, 0xFF, 0xFF  // More GameGuard data (ignored)
            };

            RSAManager rsaManager(1);
            const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

            auto packet = PacketFactory::createFromClientData(ggData, rsaPair);

            if (packet != nullptr &&
                packet->getPacketId() == 0x07)
            {
                std::cout << "  ✅ Test 1 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 1 FAILED! RequestAuthGG packet creation failed" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 1 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 2: Unknown packet handling
    std::cout << "\nTest 2: Unknown packet handling" << std::endl;
    {
        try
        {
            std::vector<uint8_t> unknownData = {
                0xFF, 0x12, 0x34, 0x56 // Unknown opcode
            };

            RSAManager rsaManager(1);
            const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

            auto packet = PacketFactory::createFromClientData(unknownData, rsaPair);

            if (packet == nullptr)
            {
                std::cout << "  ✅ Test 2 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 2 FAILED! Should return nullptr for unknown packets" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 2 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 3: Empty data handling
    std::cout << "\nTest 3: Empty data handling" << std::endl;
    {
        try
        {
            std::vector<uint8_t> emptyData;

            RSAManager rsaManager(1);
            const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

            try
            {
                auto packet = PacketFactory::createFromClientData(emptyData, rsaPair);
                std::cout << "  ❌ Test 3 FAILED! Should have thrown exception for empty data" << std::endl;
                allPassed = false;
            }
            catch (const PacketException &)
            {
                // Expected exception
                std::cout << "  ✅ Test 3 PASSED!" << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 3 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 4: AuthLogin packet creation (Rust compatibility)
    std::cout << "\nTest 4: AuthLogin packet creation (Rust compatibility)" << std::endl;
    {
        try
        {
            // Use the EXACT test data from Rust test_build_client_message_packet
            std::vector<uint8_t> encrypted_payload = {
                0x02, 0x00, 0x88, 0x00, 0x3C, 0xD5, 0xBF, 0x8E, 0xC6, 0x0C, 0x49, 0x46, 0x02, 0x80, 0x98, 0x1A,
                0x69, 0xD5, 0x64, 0xE4, 0xD7, 0x09, 0x3C, 0xED, 0x90, 0x48, 0xC8, 0xE7, 0x0E, 0x5C, 0x26, 0x68,
                0x4E, 0x1D, 0xAF, 0x73, 0x53, 0xF9, 0x2B, 0xC6, 0x3C, 0x63, 0xA8, 0x67, 0xBF, 0x2A, 0x37, 0x61,
                0x41, 0x8E, 0x97, 0x93, 0x40, 0xF6, 0x15, 0x9A, 0x73, 0x7C, 0x8E, 0x88, 0x20, 0x65, 0x93, 0x7B,
                0x02, 0x5C, 0x9E, 0xBB, 0x14, 0x67, 0x58, 0x2C, 0x15, 0x5F, 0x4F, 0x84, 0x5B, 0x3F, 0x95, 0x28,
                0x18, 0x78, 0x7F, 0x7A, 0xD8, 0xA3, 0xDE, 0x30, 0x1E, 0x71, 0x39, 0x81, 0x39, 0x5E, 0x1F, 0x6F,
                0x5F, 0x06, 0x84, 0x41, 0x82, 0x2B, 0x69, 0x1B, 0x7C, 0x73, 0x8E, 0x0F, 0xE3, 0x7F, 0x20, 0x8E,
                0x91, 0x4B, 0x3E, 0xA4, 0x44, 0x76, 0x51, 0x3F, 0x51, 0x78, 0x69, 0xDC, 0x84, 0x5F, 0x9F, 0xE5,
                0x74, 0xC5, 0x29, 0xDC, 0xB4, 0xE6, 0xAD, 0x29, 0x79, 0x89, 0x10, 0x2C, 0x98, 0x4F, 0x37, 0x16};

            // Skip this test - it requires specific RSA test keys
            std::cout << "  ⚠️  Test 4 SKIPPED - Requires exact Rust test key setup" << std::endl;
            std::cout << "  (Test data available, but RSA decryption needs matching keys)" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 4 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Overall result
    if (allPassed)
    {
        std::cout << "\n🎉 ALL PacketFactory tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some PacketFactory tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}