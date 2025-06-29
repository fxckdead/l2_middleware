#include "protocol_version_packet.hpp"

uint8_t ProtocolVersionPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> ProtocolVersionPacket::getExPacketId() const
{
    return std::nullopt;
}

void ProtocolVersionPacket::read(ReadablePacketBuffer &buffer)
{
    // Read the client's protocol version (typically int32)
    if (buffer.getRemainingLength() >= 4) {
        client_protocol_version_ = buffer.readInt32();
    } else {
        client_protocol_version_ = 0; // Default/unknown
    }
}

bool ProtocolVersionPacket::isValid() const
{
    return true;
}