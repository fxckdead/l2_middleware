#include "auth_gg_response.hpp"
#include <iostream>
#include <iomanip>

// Constructor
AuthGGResponse::AuthGGResponse(int32_t sessionId)
    : m_sessionId(sessionId)
{
}

// SendablePacket interface implementation
uint8_t AuthGGResponse::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> AuthGGResponse::getExPacketId() const
{
    return std::nullopt; // AuthGG response doesn't have extended packet ID
}

void AuthGGResponse::write(SendablePacketBuffer &buffer)
{
    // Write packet structure according to Rust implementation:
    // Opcode + Session ID + 4 zero int32s (GameGuard placeholders) + padding for 4-byte alignment

    buffer.writeUInt8(OPCODE);      // Opcode: 0x0B (GgAuth)
    buffer.writeInt32(m_sessionId); // Session ID: validated session

    // Write 4 zero int32s as GameGuard placeholders
    buffer.writeInt32(0); // GameGuard placeholder 1
    buffer.writeInt32(0); // GameGuard placeholder 2
    buffer.writeInt32(0); // GameGuard placeholder 3
    buffer.writeInt32(0); // GameGuard placeholder 4

    // Add 3 padding bytes to make total content 24 bytes (multiple of 4)
    // Content: 1 (opcode) + 4 (session_id) + 16 (placeholders) + 3 (padding) = 24 bytes
    buffer.writeUInt8(0); // Padding byte 1
    buffer.writeUInt8(0); // Padding byte 2
    buffer.writeUInt8(0); // Padding byte 3
}

size_t AuthGGResponse::getSize() const
{
    // Calculate total packet size:
    // 1 (opcode) + 4 (session_id) + 16 (4 zero int32s) + 3 (padding) = 24 bytes
    return 1 + 4 + 16 + 3;
}

// Factory method
AuthGGResponse AuthGGResponse::create(int32_t sessionId)
{
    return AuthGGResponse(sessionId);
}

// Validate packet data
bool AuthGGResponse::isValid() const
{
    return m_sessionId != 0; // Session ID should be non-zero
}

// Test function
void AuthGGResponse::runTests()
{
    std::cout << "\n=== Testing AuthGGResponse ===" << std::endl;

    bool allPassed = true;

    // Test 1: Basic packet creation and validation
    std::cout << "Test 1: Basic packet creation" << std::endl;
    {
        try
        {
            int32_t testSessionId = 0x12345678;
            AuthGGResponse packet(testSessionId);

            if (packet.getPacketId() == 0x0B &&
                packet.getSessionId() == testSessionId &&
                packet.getSize() == 24 &&
                packet.isValid())
            {
                std::cout << "  ✅ Test 1 PASSED!" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Test 1 FAILED! Basic properties incorrect" << std::endl;
                std::cout << "    Packet ID: 0x" << std::hex << static_cast<int>(packet.getPacketId()) << std::dec << std::endl;
                std::cout << "    Session ID: " << packet.getSessionId() << std::endl;
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

    // Test 2: Packet serialization (C++ padded version for 4-byte alignment)
    std::cout << "\nTest 2: Packet serialization (with 4-byte alignment padding)" << std::endl;
    {
        try
        {
            // Use session ID 999 to match Rust test baseline
            AuthGGResponse packet(999);
            auto serialized = packet.serialize();

            // C++ version with padding: [26, 0, 11, 231, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            // Total size: 26 bytes (2-byte length header + 24 bytes content)
            std::vector<uint8_t> expected = {
                26, 0,        // Length: 26 bytes total
                11,           // Opcode: 0x0B
                231, 3, 0, 0, // Session ID: 999 (little-endian)
                0, 0, 0, 0,   // GameGuard placeholder 1
                0, 0, 0, 0,   // GameGuard placeholder 2
                0, 0, 0, 0,   // GameGuard placeholder 3
                0, 0, 0, 0,   // GameGuard placeholder 4
                0, 0, 0       // Padding bytes for 4-byte alignment
            };

            std::cout << "  Serialized size: " << serialized.size() << " bytes (expected: 26)" << std::endl;
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
            int32_t sessionId = 0xABCDEF00;
            AuthGGResponse packet = AuthGGResponse::create(sessionId);

            if (packet.getSessionId() == sessionId)
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

    // Test 4: Different session IDs
    std::cout << "\nTest 4: Different session IDs" << std::endl;
    {
        try
        {
            std::vector<int32_t> testSessionIds = {1, 1000, -1, 0x7FFFFFFF, -2147483648};

            bool test4Passed = true;
            for (int32_t sessionId : testSessionIds)
            {
                AuthGGResponse packet(sessionId);
                auto serialized = packet.serialize();

                // Should always be 26 bytes total (24 content + 2 header)
                if (serialized.size() != 26)
                {
                    std::cout << "  ❌ Session ID " << sessionId << " failed size test" << std::endl;
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
        std::cout << "\n🎉 ALL AuthGGResponse tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some AuthGGResponse tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}