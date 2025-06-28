#include "../../packets/responses/init_packet.hpp"
#include "../../../core/encryption/rsa_manager.hpp"
#include "../../../core/packets/packet.hpp"
#include <iostream>
#include <iomanip>

void test_init_packet_unit()
{
    std::cout << "\n=== Testing InitPacket ===" << std::endl;

    bool allPassed = true;

    // Test 1: Basic packet creation and validation
    std::cout << "Test 1: Basic packet creation" << std::endl;
    {
        try
        {
            // Create test RSA key pair
            RSAManager rsaManager(1);
            const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

            // Create test Blowfish key
            std::vector<uint8_t> blowfishKey(16);
            for (size_t i = 0; i < 16; ++i)
            {
                blowfishKey[i] = static_cast<uint8_t>(i + 1);
            }

            int32_t sessionId = 0x12345678;

            InitPacket packet(sessionId, rsaPair, blowfishKey);

            // Validate basic properties
            if (packet.getPacketId() == 0x00 &&
                packet.getSessionId() == sessionId &&
                packet.getBlowfishKey() == blowfishKey &&
                packet.getScrambledModulus().size() == 128 &&
                packet.getGameGuardData().size() == 16)
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

    // Test 2: Packet serialization
    std::cout << "\nTest 2: Packet serialization" << std::endl;
    {
        try
        {
            RSAManager rsaManager(1);
            const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

            std::vector<uint8_t> blowfishKey = {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

            int32_t sessionId = 0x87654321;

            InitPacket packet(sessionId, rsaPair, blowfishKey);
            auto serialized = packet.serialize();

            // Check packet size (should be at least header + fixed data)
            size_t expectedMinSize = 1 + 4 + 4 + 128 + 16 + 16 + 1; // 170 bytes + packet length header
            if (serialized.size() >= expectedMinSize)
            {
                // Check packet structure
                if (serialized[2] == 0x00 && // Opcode at position 2 (after length header)
                    serialized.size() == expectedMinSize + 2)
                { // +2 for length header
                    std::cout << "  ✅ Test 2 PASSED!" << std::endl;
                }
                else
                {
                    std::cout << "  ❌ Test 2 FAILED! Packet structure incorrect" << std::endl;
                    std::cout << "    Opcode: 0x" << std::hex << static_cast<int>(serialized[2]) << std::dec << std::endl;
                    std::cout << "    Size: " << serialized.size() << ", expected: " << (expectedMinSize + 2) << std::endl;
                    allPassed = false;
                }
            }
            else
            {
                std::cout << "  ❌ Test 2 FAILED! Packet too small. Size: " << serialized.size()
                          << ", expected at least: " << expectedMinSize << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 2 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 3: Invalid parameters handling
    std::cout << "\nTest 3: Invalid parameters handling" << std::endl;
    {
        try
        {
            RSAManager rsaManager(1);
            const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

            // Test with invalid Blowfish key size
            std::vector<uint8_t> invalidBlowfishKey(8); // Wrong size (should be 16)
            int32_t sessionId = 0x12345678;

            try
            {
                InitPacket packet(sessionId, rsaPair, invalidBlowfishKey);
                std::cout << "  ❌ Test 3 FAILED! Should have thrown exception for invalid key size" << std::endl;
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
            std::cout << "  ❌ Test 3 FAILED! Unexpected exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 4: Factory method
    std::cout << "\nTest 4: Factory method" << std::endl;
    {
        try
        {
            RSAManager rsaManager(1);
            const auto &rsaPair = rsaManager.getRandomRSAKeyPair();

            std::vector<uint8_t> blowfishKey(16, 0xFF);
            int32_t sessionId = 0xABCDEF00;

            InitPacket packet = InitPacket::create(sessionId, rsaPair, blowfishKey);

            if (packet.getSessionId() == sessionId &&
                packet.getBlowfishKey() == blowfishKey)
            {
                std::cout << "  ✅ Test 4 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 4 FAILED! Factory method produced incorrect packet" << std::endl;
                allPassed = false;
            }
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
        std::cout << "\n🎉 ALL InitPacket tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some InitPacket tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}