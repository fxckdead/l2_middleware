#include "login_ok_response.hpp"
#include <iostream>
#include <iomanip>

// Constructor
LoginOkResponse::LoginOkResponse(const SessionKey &sessionKey)
    : m_sessionKey(sessionKey)
{
}

// SendablePacket interface implementation
uint8_t LoginOkResponse::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> LoginOkResponse::getExPacketId() const
{
    return std::nullopt; // LoginOk response doesn't have extended packet ID
}

void LoginOkResponse::write(SendablePacketBuffer &buffer)
{
    // Write packet structure exactly matching Rust implementation:
    // opcode + login_ok1 + login_ok2 + zeros + 0x03ea + zeros + 16 zero bytes

    buffer.writeUInt8(OPCODE);                 // Opcode: 0x03 (LoginOk)
    buffer.writeInt32(m_sessionKey.login_ok1); // Session key part 1
    buffer.writeInt32(m_sessionKey.login_ok2); // Session key part 2
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x03ea);                 // Constant 1002 (0x03ea)
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x00);                   // Zero padding

    // Write 16 zero bytes (matches Rust: write_bytes(vec![0; 16]))
    for (int i = 0; i < 16; i++)
    {
        buffer.writeUInt8(0x00);
    }
}

size_t LoginOkResponse::getSize() const
{
    // Calculate total packet size (without padding):
    // 1 (opcode) + 4 (login_ok1) + 4 (login_ok2) + 4*6 (zeros/constant) + 16 (zero bytes) = 49 bytes
    return 1 + 4 + 4 + 24 + 16;
}

// Factory method
LoginOkResponse LoginOkResponse::create(const SessionKey &sessionKey)
{
    return LoginOkResponse(sessionKey);
}

// Validate packet data
bool LoginOkResponse::isValid() const
{
    return true; // LoginOk packet is always valid once constructed
}

// Test function
void LoginOkResponse::runTests()
{
    std::cout << "\n=== Testing LoginOkResponse ===" << std::endl;

    bool allPassed = true;

    // Test 1: Basic packet creation and validation
    std::cout << "Test 1: Basic packet creation" << std::endl;
    {
        try
        {
            SessionKey testKey(0xAABBCCDD, 0xDDCCBBAA, 0x12345678, 0x87654321);
            LoginOkResponse packet(testKey);

            if (packet.getPacketId() == 0x03 &&
                packet.getSize() == 49 &&
                packet.getSessionKey().login_ok1 == 0x12345678 &&
                packet.getSessionKey().login_ok2 == 0x87654321 &&
                packet.isValid())
            {
                std::cout << "  ✅ Test 1 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 1 FAILED! Basic properties incorrect" << std::endl;
                std::cout << "    Packet ID: 0x" << std::hex << static_cast<int>(packet.getPacketId()) << std::dec << std::endl;
                std::cout << "    Size: " << packet.getSize() << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 1 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 2: Packet serialization (C++ version with 4-byte alignment padding)
    std::cout << "\nTest 2: Packet serialization (with 4-byte alignment padding)" << std::endl;
    {
        try
        {
            // Use exact test data from Rust test_login_ok
            SessionKey testKey(7, 6, 9, 8); // play_ok1=7, play_ok2=6, login_ok1=9, login_ok2=8
            LoginOkResponse packet(testKey);
            auto serialized = packet.serialize(true, 4); // Use automatic 4-byte padding

            // C++ version with automatic 4-byte padding: [52, 0, 3, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 234, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            // Total size: 52 bytes (2-byte length header + 49 bytes content + 1 byte automatic padding)
            std::vector<uint8_t> expected = {
                52, 0,        // Length: 52 bytes total
                3,            // Opcode: 0x03
                9, 0, 0, 0,   // login_ok1: 9 (little-endian)
                8, 0, 0, 0,   // login_ok2: 8 (little-endian)
                0, 0, 0, 0,   // Zero padding
                0, 0, 0, 0,   // Zero padding
                234, 3, 0, 0, // Constant: 0x03ea = 1002 (little-endian)
                0, 0, 0, 0,   // Zero padding
                0, 0, 0, 0,   // Zero padding
                0, 0, 0, 0,   // Zero padding
                // 16 zero bytes
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                // 1 byte automatic padding for 4-byte alignment (51 -> 52)
                0};

            std::cout << "  Serialized size: " << serialized.size() << " bytes (expected: 52)" << std::endl;
            std::cout << "  Serialized data: ";
            for (size_t i = 0; i < std::min(serialized.size(), size_t(10)); ++i)
            {
                std::cout << static_cast<int>(serialized[i]) << " ";
            }
            std::cout << "..." << std::endl;

            if (serialized.size() == expected.size() && serialized == expected)
            {
                std::cout << "  ✅ Test 2 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 2 FAILED! Serialization doesn't match expected format" << std::endl;
                std::cout << "    Expected size: " << expected.size() << ", got: " << serialized.size() << std::endl;

                // Show detailed comparison for debugging
                if (serialized.size() == expected.size())
                {
                    for (size_t i = 0; i < serialized.size(); ++i)
                    {
                        if (serialized[i] != expected[i])
                        {
                            std::cout << "    Mismatch at byte " << i << ": expected "
                                      << static_cast<int>(expected[i]) << ", got "
                                      << static_cast<int>(serialized[i]) << std::endl;
                            break;
                        }
                    }
                }
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 2 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 3: Factory method
    std::cout << "\nTest 3: Factory method" << std::endl;
    {
        try
        {
            SessionKey testKey(0x33333333, 0x44444444, 0x11111111, 0x22222222);
            LoginOkResponse packet = LoginOkResponse::create(testKey);

            if (packet.getSessionKey().login_ok1 == 0x11111111 &&
                packet.getSessionKey().login_ok2 == 0x22222222)
            {
                std::cout << "  ✅ Test 3 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 3 FAILED! Factory method produced incorrect packet" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "  ❌ Test 3 FAILED! Exception: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // Test 4: Different session keys
    std::cout << "\nTest 4: Different session keys" << std::endl;
    {
        try
        {
            std::vector<SessionKey> testKeys = {
                SessionKey(3, 4, 1, 2),
                SessionKey(0, 0, 0, 0),
                SessionKey(-3, -4, -1, -2),
                SessionKey(0xFFFFFFFF, 0x12345678, 0x7FFFFFFF, 0x80000000)};

            bool test4Passed = true;
            for (const auto &key : testKeys)
            {
                LoginOkResponse packet(key);
                auto serialized = packet.serialize(true, 4); // Use automatic 4-byte padding

                // Should always be 52 bytes total (49 content + 2 header + 1 padding)
                if (serialized.size() != 52)
                {
                    std::cout << "  ❌ Session key (" << key.login_ok1 << ", " << key.login_ok2
                              << ") failed size test" << std::endl;
                    test4Passed = false;
                    break;
                }
            }

            if (test4Passed)
            {
                std::cout << "  ✅ Test 4 PASSED!" << std::endl;
            }
            else
            {
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
        std::cout << "\n🎉 ALL LoginOkResponse tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some LoginOkResponse tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}