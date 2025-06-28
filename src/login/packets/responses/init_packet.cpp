#include "init_packet.hpp"
#include <random>
#include <iostream>
#include <iomanip>

// Constructor
InitPacket::InitPacket(int32_t sessionId,
                       const ScrambledRSAKeyPair &rsaPair,
                       const std::vector<uint8_t> &blowfishKey)
    : m_sessionId(sessionId), m_scrambledModulus(rsaPair.getScrambledModulus()), m_gameGuardData(generateDefaultGameGuardData()), m_blowfishKey(blowfishKey)
{
    if (!isValid())
    {
        throw PacketException("Invalid InitPacket parameters");
    }
}

// SendablePacket interface implementation
uint8_t InitPacket::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> InitPacket::getExPacketId() const
{
    return std::nullopt; // Init packet doesn't have extended packet ID
}

void InitPacket::write(SendablePacketBuffer &buffer)
{
    // Write packet structure according to network-steps.md:
    // Opcode + Session ID + Protocol + RSA Key + GameGuard + Blowfish Key + Null

    buffer.writeUInt8(OPCODE);             // Opcode: 0x00 (Init)
    buffer.writeInt32(m_sessionId);        // Session ID: random i32
    buffer.writeInt32(PROTOCOL_REVISION);  // Protocol revision: 0x0000c621
    buffer.writeBytes(m_scrambledModulus); // RSA public key: 128 bytes (scrambled modulus)
    buffer.writeBytes(m_gameGuardData);    // GameGuard data: 16 bytes of constants
    buffer.writeBytes(m_blowfishKey);      // Blowfish key: 16 bytes (random generated)
    buffer.writeUInt8(0x00);               // Null terminator: 1 byte
}

size_t InitPacket::getSize() const
{
    // Calculate total packet size:
    // 1 (opcode) + 4 (session_id) + 4 (protocol) + 128 (rsa) + 16 (gg) + 16 (bf) + 1 (null) = 170 bytes
    return 1 + 4 + 4 + m_scrambledModulus.size() + m_gameGuardData.size() + m_blowfishKey.size() + 1;
}

// Factory method
InitPacket InitPacket::create(int32_t sessionId,
                              const ScrambledRSAKeyPair &rsaPair,
                              const std::vector<uint8_t> &blowfishKey)
{
    return InitPacket(sessionId, rsaPair, blowfishKey);
}

// Generate default GameGuard authentication data (16 bytes of constants)
std::vector<uint8_t> InitPacket::generateDefaultGameGuardData()
{
    // GameGuard magical constants (REQUIRED by L2 client!)
    // These exact values match the working Rust implementation
    return std::vector<uint8_t>{
        // 0x29DD954E (little-endian)
        0x4E, 0x95, 0xDD, 0x29,
        // 0x77C39CFC (little-endian)
        0xFC, 0x9C, 0xC3, 0x77,
        // 0x97ADB620 (little-endian)
        0x20, 0xB6, 0xAD, 0x97,
        // 0x07BDE0F7 (little-endian)
        0xF7, 0xE0, 0xBD, 0x07};
}

// Validate packet data
bool InitPacket::isValid() const
{
    return m_scrambledModulus.size() == 128 && // Scrambled modulus should be 128 bytes
           m_gameGuardData.size() == 16 &&     // GameGuard data should be 16 bytes
           m_blowfishKey.size() == 16;         // Blowfish key should be 16 bytes
}

// Test function
void InitPacket::runTests()
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