#include "packet.hpp"
#include "../network/packet_buffer.hpp"

// SendablePacket default implementation
std::vector<uint8_t> SendablePacket::serialize(bool withPadding)
{
    return serialize(withPadding, 8); // Default to 8-byte alignment for backward compatibility
}

std::vector<uint8_t> SendablePacket::serialize(bool withPadding, size_t alignment)
{
    SendablePacketBuffer buffer;
    write(buffer);
    return buffer.getData(withPadding, alignment);
}

// ReadablePacket factory method (basic implementation)
std::unique_ptr<ReadablePacket> ReadablePacket::createFromData(const std::vector<uint8_t> &data)
{
    if (data.empty())
    {
        throw PacketException("Cannot create packet from empty data");
    }

    // This is a basic implementation - in practice, you'd have a packet registry
    // that maps packet IDs to specific packet types
    throw PacketException("Packet factory not implemented - use specific packet constructors");
}

// PacketUtils implementation
namespace PacketUtils
{
    size_t calculatePaddedSize(size_t dataSize)
    {
        // L2 packets need to be padded to 8-byte boundaries for Blowfish encryption
        size_t padding = (8 - (dataSize % 8)) % 8;
        return dataSize + padding;
    }

    void addPadding(std::vector<uint8_t> &data)
    {
        size_t currentSize = data.size();
        size_t paddedSize = calculatePaddedSize(currentSize);

        // Add zero bytes for padding
        data.resize(paddedSize, 0x00);
    }

}
