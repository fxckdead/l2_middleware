#include "request_auth_gg.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>

// Constructor
RequestAuthGG::RequestAuthGG(int32_t sessionId)
    : m_sessionId(sessionId)
{
}

// ReadablePacket interface implementation
uint8_t RequestAuthGG::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestAuthGG::getExPacketId() const
{
    return std::nullopt;
}

void RequestAuthGG::read(ReadablePacketBuffer &buffer)
{
    // Read session ID from the buffer (first 4 bytes)
    if (buffer.getRemainingLength() >= 4)
    {
        m_sessionId = buffer.readInt32();
        // Note: Remaining bytes are GameGuard data that we ignore for now
        // The Rust implementation mentions they don't know the meaning of the remaining data
    }
    else
    {
        throw PacketException("Not enough data for RequestAuthGG packet");
    }
}

// Factory method for raw data (matches Rust read implementation)
RequestAuthGG RequestAuthGG::fromRawData(const std::vector<uint8_t> &data)
{
    if (data.size() < 4)
    {
        throw PacketException("Not enough data for AuthGG packet - need at least 4 bytes for session ID");
    }

    // Rust implementation checks for > 20 bytes, but we'll be more flexible
    int32_t sessionId = extractSessionId(data);

    return RequestAuthGG(sessionId);
}

// Extract session ID from raw bytes (first 4 bytes, little-endian)
int32_t RequestAuthGG::extractSessionId(const std::vector<uint8_t> &data)
{
    if (data.size() < 4)
    {
        throw PacketException("Insufficient data for session ID extraction");
    }

    // Little-endian conversion (matches your existing pattern)
    return static_cast<int32_t>(data[0]) |
           (static_cast<int32_t>(data[1]) << 8) |
           (static_cast<int32_t>(data[2]) << 16) |
           (static_cast<int32_t>(data[3]) << 24);
}

// Validation
bool RequestAuthGG::isValid() const
{
    // Session ID should be non-zero (basic validation)
    return m_sessionId != 0;
}

// Test function
void RequestAuthGG::runTests()
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