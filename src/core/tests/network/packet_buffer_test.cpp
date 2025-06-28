#include "../../network/packet_buffer.hpp"
#include <iostream>
#include <iomanip>

void test_readable_packet_buffer()
{
    std::cout << "\n=== Testing ReadablePacketBuffer (Basic) ===" << std::endl;

    bool allPassed = true;

    // Test 1: Basic byte reading
    std::cout << "Test 1: Basic byte operations" << std::endl;
    {
        std::vector<uint8_t> testData = {0x01, 0x02, 0x03, 0x04};
        ReadablePacketBuffer buffer(testData);

        if (buffer.readByte() == 0x01 &&
            buffer.readByte() == 0x02 &&
            buffer.getPosition() == 2 &&
            buffer.getRemainingLength() == 2)
        {
            std::cout << "  ✅ Test 1 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 1 FAILED!" << std::endl;
            allPassed = false;
        }
    }

    // Test 2: Integer reading (little-endian)
    std::cout << "\nTest 2: Integer reading" << std::endl;
    {
        std::vector<uint8_t> testData = {
            0x01, 0x02,            // 0x0201 = 513
            0x01, 0x02, 0x03, 0x04 // 0x04030201 = 67305985
        };
        ReadablePacketBuffer buffer(testData);

        uint16_t val16 = buffer.readUInt16();
        uint32_t val32 = buffer.readUInt32();

        if (val16 == 0x0201 && val32 == 0x04030201)
        {
            std::cout << "  ✅ Test 2 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 2 FAILED! val16=" << std::hex << val16
                      << " val32=" << val32 << std::dec << std::endl;
            allPassed = false;
        }
    }

    if (allPassed)
    {
        std::cout << "\n🎉 ALL ReadablePacketBuffer tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some ReadablePacketBuffer tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}

void test_sendable_packet_buffer()
{
    std::cout << "\n=== Testing SendablePacketBuffer (Basic) ===" << std::endl;

    bool allPassed = true;

    // Test 1: Basic writing
    std::cout << "Test 1: Basic writing operations" << std::endl;
    {
        SendablePacketBuffer buffer;
        buffer.write(0x01);
        buffer.writeInt16(0x0302);
        buffer.writeInt32(0x07060504);

        auto data = buffer.getData();

        // Expected: [size_low, size_high, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        if (data.size() == 9 &&
            data[2] == 0x01 && // byte
            data[3] == 0x02 && // int16 low
            data[4] == 0x03 && // int16 high
            data[5] == 0x04 && // int32 byte 0
            data[6] == 0x05 && // int32 byte 1
            data[7] == 0x06 && // int32 byte 2
            data[8] == 0x07)
        { // int32 byte 3
            std::cout << "  ✅ Test 1 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 1 FAILED!" << std::endl;
            allPassed = false;
        }
    }

    if (allPassed)
    {
        std::cout << "\n🎉 ALL SendablePacketBuffer tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some SendablePacketBuffer tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
} 