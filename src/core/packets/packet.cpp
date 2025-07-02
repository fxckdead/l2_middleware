#include "packet.hpp"
#include "../network/packet_buffer.hpp"
#include <iomanip>
#include <sstream>
#include <iostream>

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

    // ---------------------------------------------------------------------
    // Hex dump helper (offset + 16-byte rows + ASCII view)
    // ---------------------------------------------------------------------

    void hexDump(const std::vector<uint8_t> &data, const std::string &prefix)
    {
        if (data.empty()) {
            std::cout << prefix << "<empty>" << std::endl;
            return;
        }

        for (size_t i = 0; i < data.size(); i += 16) {
            std::ostringstream line;
            line << prefix << std::setw(4) << std::setfill('0') << std::hex << i << ": ";

            // hex bytes
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < data.size()) {
                    line << std::setw(2) << static_cast<int>(data[i + j]) << ' ';
                } else {
                    line << "   ";
                }
            }

            line << " | ";

            // ASCII
            for (size_t j = 0; j < 16 && (i + j) < data.size(); ++j) {
                uint8_t b = data[i + j];
                line << ((b >= 32 && b <= 126) ? static_cast<char>(b) : '.');
            }

            std::cout << line.str() << std::endl;
        }
    }
}
