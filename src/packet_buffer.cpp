#include "packet_buffer.hpp"
#include "packet.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

// =============================================================================
// ReadablePacketBuffer Implementation
// =============================================================================

ReadablePacketBuffer::ReadablePacketBuffer(const std::vector<uint8_t> &bytes)
    : m_bytes(bytes), m_position(0)
{
}

ReadablePacketBuffer::ReadablePacketBuffer(std::vector<uint8_t> &&bytes)
    : m_bytes(std::move(bytes)), m_position(0)
{
}

void ReadablePacketBuffer::checkAndAdvance(size_t length)
{
    if (m_position + length > m_bytes.size())
    {
        throw PacketBufferUnderflowException(
            "Not enough bytes available. Requested: " + std::to_string(length) +
            ", Remaining: " + std::to_string(m_bytes.size() - m_position));
    }
    m_position += length;
}

bool ReadablePacketBuffer::readBoolean()
{
    return readByte() != 0;
}

uint8_t ReadablePacketBuffer::readByte()
{
    if (m_position >= m_bytes.size())
    {
        throw PacketBufferUnderflowException("Buffer underflow");
    }
    return m_bytes[m_position++];
}

int8_t ReadablePacketBuffer::readInt8()
{
    return static_cast<int8_t>(readByte());
}

int16_t ReadablePacketBuffer::readInt16()
{
    checkAndAdvance(2);
    const uint8_t *ptr = &m_bytes[m_position - 2];
    return static_cast<int16_t>(ptr[0] | (ptr[1] << 8));
}

uint16_t ReadablePacketBuffer::readUInt16()
{
    checkAndAdvance(2);
    const uint8_t *ptr = &m_bytes[m_position - 2];
    return static_cast<uint16_t>(ptr[0] | (ptr[1] << 8));
}

int32_t ReadablePacketBuffer::readInt32()
{
    checkAndAdvance(4);
    const uint8_t *ptr = &m_bytes[m_position - 4];
    return static_cast<int32_t>(
        ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24));
}

uint32_t ReadablePacketBuffer::readUInt32()
{
    checkAndAdvance(4);
    const uint8_t *ptr = &m_bytes[m_position - 4];
    return static_cast<uint32_t>(
        ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24));
}

std::vector<uint8_t> ReadablePacketBuffer::readBytes(size_t length)
{
    checkAndAdvance(length);
    auto start = m_bytes.begin() + (m_position - length);
    auto end = m_bytes.begin() + m_position;
    return std::vector<uint8_t>(start, end);
}

size_t ReadablePacketBuffer::getRemainingLength() const
{
    return m_bytes.size() - m_position;
}

size_t ReadablePacketBuffer::getLength() const
{
    return m_bytes.size();
}

size_t ReadablePacketBuffer::getPosition() const
{
    return m_position;
}

// =============================================================================
// SendablePacketBuffer Implementation
// =============================================================================

SendablePacketBuffer::SendablePacketBuffer()
    : m_sizeWritten(false)
{
    m_data.reserve(256);
    // Reserve first 2 bytes for packet length
    m_data.push_back(0);
    m_data.push_back(0);
}

SendablePacketBuffer::SendablePacketBuffer(size_t initialCapacity)
    : m_sizeWritten(false)
{
    m_data.reserve(initialCapacity);
    // Reserve first 2 bytes for packet length
    m_data.push_back(0);
    m_data.push_back(0);
}

void SendablePacketBuffer::write(uint8_t value)
{
    m_data.push_back(value);
}

void SendablePacketBuffer::writeInt8(int8_t value)
{
    write(static_cast<uint8_t>(value));
}

void SendablePacketBuffer::writeUInt8(uint8_t value)
{
    write(value);
}

void SendablePacketBuffer::writeBoolean(bool value)
{
    write(value ? 1 : 0);
}

void SendablePacketBuffer::writeInt16(int16_t value)
{
    uint16_t uval = static_cast<uint16_t>(value);
    write(static_cast<uint8_t>(uval & 0xFF));
    write(static_cast<uint8_t>((uval >> 8) & 0xFF));
}

void SendablePacketBuffer::writeUInt16(uint16_t value)
{
    write(static_cast<uint8_t>(value & 0xFF));
    write(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void SendablePacketBuffer::writeInt32(int32_t value)
{
    uint32_t uval = static_cast<uint32_t>(value);
    write(static_cast<uint8_t>(uval & 0xFF));
    write(static_cast<uint8_t>((uval >> 8) & 0xFF));
    write(static_cast<uint8_t>((uval >> 16) & 0xFF));
    write(static_cast<uint8_t>((uval >> 24) & 0xFF));
}

void SendablePacketBuffer::writeUInt32(uint32_t value)
{
    write(static_cast<uint8_t>(value & 0xFF));
    write(static_cast<uint8_t>((value >> 8) & 0xFF));
    write(static_cast<uint8_t>((value >> 16) & 0xFF));
    write(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void SendablePacketBuffer::writeBytes(const std::vector<uint8_t> &bytes)
{
    m_data.insert(m_data.end(), bytes.begin(), bytes.end());
}

void SendablePacketBuffer::writeBytes(const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        m_data.push_back(data[i]);
    }
}

size_t SendablePacketBuffer::getSize() const
{
    return m_data.size();
}

void SendablePacketBuffer::writePacketSize()
{
    if (m_data.size() < 2)
        return;

    size_t size = m_data.size();
    m_data[0] = static_cast<uint8_t>(size & 0xFF);
    m_data[1] = static_cast<uint8_t>((size >> 8) & 0xFF);
    m_sizeWritten = true;
}

std::vector<uint8_t> SendablePacketBuffer::getData(bool withPadding, size_t alignment)
{
    writePacketSize();
    std::vector<uint8_t> result = m_data;

    if (withPadding && alignment > 0)
    {
        // Calculate padding based on content size (excluding 2-byte header)
        size_t content_size = result.size() - 2; // Remove header size from calculation
        size_t padding = (alignment - (content_size % alignment)) % alignment;

        result.resize(result.size() + padding, 0);
    }

    return result;
}

std::vector<uint8_t> SendablePacketBuffer::take()
{
    writePacketSize();
    return std::move(m_data);
}

// Basic test implementation
void ReadablePacketBuffer::runTests()
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

void SendablePacketBuffer::runTests()
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