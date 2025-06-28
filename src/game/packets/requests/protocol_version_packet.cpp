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
    // TODO: Implement protocol version reading
}

bool ProtocolVersionPacket::isValid() const
{
    return true;
}